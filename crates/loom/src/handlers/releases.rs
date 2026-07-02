//! Releases (`/r/{owner}/{name}/releases`) — release metadata + Markdown notes for git tags.
//!
//! Releases are repo metadata stored in `Store`; git objects stay in the bare repo. Notes render
//! through the same sanitising markdown pipeline as README, issues and pull requests. Draft releases
//! are visible only to repo writers (currently owner/admin, matching the existing settings gate).

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use serde::Deserialize;

use crate::auth::{self, Identity};
use crate::error::AppError;
use crate::gitops::TagInfo;
use crate::handlers::repos::{header_with_counts_for, load_visible_repo};
use crate::handlers::{esc, fmt_ts, html_ok, html_with_csrf, page, redirect};
use crate::model::{Release, Repo};
use crate::{now_secs, random_alnum, AppState};

const RELEASE_ID_LEN: usize = 16;
const TITLE_MAX: usize = 200;
const NOTES_MAX: usize = 20_000;

fn can_write(repo: &Repo, who: &Identity, headers: &HeaderMap) -> bool {
    repo.owner_sub == who.subject || auth::is_admin(headers)
}

// GET /r/{owner}/{name}/releases — list visible releases
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let writer = can_write(&repo, &who, &headers);
    let releases = visible_releases(state.store.list_releases_by_repo(&repo.id).await?, writer);
    let header = header_with_counts_for(&state, &repo, "releases", writer).await;
    let body = format!("{header}{}", render_list(&repo, &releases, writer));
    Ok(html_ok(page(
        &format!("{owner}/{name} · Releases"),
        Some(&who.email),
        &body,
    )))
}

// GET /r/{owner}/{name}/releases.json — read-only release metadata
pub async fn list_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let writer = can_write(&repo, &who, &headers);
    let releases = visible_releases(state.store.list_releases_by_repo(&repo.id).await?, writer);
    let rows = releases
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "repo_id": r.repo_id,
                "tag_name": r.tag_name,
                "target_commit": r.target_commit,
                "title": r.title,
                "body_md": r.body_md,
                "is_prerelease": r.is_prerelease,
                "is_draft": r.is_draft,
                "created_by": r.created_by,
                "created_at": r.created_at,
                "published_at": r.published_at,
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(serde_json::json!({ "releases": rows })).into_response())
}

// GET /r/{owner}/{name}/releases/new — release creation form
pub async fn new_release(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    if !can_write(&repo, &who, &headers) {
        return Err(AppError::Forbidden(
            "Only the repository owner or an administrator can create releases.".to_string(),
        ));
    }
    let csrf = auth::new_csrf_token();
    let tags = state.git.tag_infos(&repo.owner_sub, &repo.name).await;
    let body = render_new_page(&state, &repo, &tags, &csrf, None).await;
    Ok(html_with_csrf(
        StatusCode::OK,
        page(
            &format!("{owner}/{name} · New release"),
            Some(&who.email),
            &body,
        ),
        &csrf,
    ))
}

#[derive(Debug, Deserialize)]
pub struct CreateReleaseForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub existing_tag: String,
    #[serde(default)]
    pub new_tag: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub body_md: String,
    #[serde(default)]
    pub is_prerelease: String,
    #[serde(default)]
    pub is_draft: String,
}

// POST /r/{owner}/{name}/releases/new — create release metadata, optionally creating a tag
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
    Form(form): Form<CreateReleaseForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and submit again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    if !can_write(&repo, &who, &headers) {
        return Err(AppError::Forbidden(
            "Only the repository owner or an administrator can create releases.".to_string(),
        ));
    }

    let tags = state.git.tag_infos(&repo.owner_sub, &repo.name).await;
    let (tag_name, target_commit, needs_tag_create) =
        match pick_release_tag(&state, &repo, &tags, &form).await {
            Ok(picked) => picked,
            Err(msg) => return Ok(render_new_error(&state, &who, &repo, &tags, msg).await),
        };

    if needs_tag_create {
        state
            .git
            .create_lightweight_tag(&repo.owner_sub, &repo.name, &tag_name, &target_commit)
            .await
            .map_err(|e| AppError::Internal(format!("git tag create failed: {e}")))?;
    }

    let now = now_secs();
    let title = form
        .title
        .trim()
        .chars()
        .take(TITLE_MAX)
        .collect::<String>();
    let title = if title.is_empty() {
        tag_name.clone()
    } else {
        title
    };
    let is_draft = form.is_draft == "on";
    let release = Release {
        id: format!("rl_{}", random_alnum(RELEASE_ID_LEN)),
        repo_id: repo.id.clone(),
        tag_name: tag_name.clone(),
        target_commit,
        title,
        body_md: form.body_md.trim().chars().take(NOTES_MAX).collect(),
        is_prerelease: form.is_prerelease == "on",
        is_draft,
        created_by: who.subject.clone(),
        created_at: now,
        published_at: if is_draft { 0 } else { now },
    };

    if state.store.create_release(&release).await?.is_none() {
        return Ok(render_new_error(
            &state,
            &who,
            &repo,
            &tags,
            "This tag already has a release.",
        )
        .await);
    }

    tracing::info!(
        repo = repo.id,
        tag = tag_name,
        actor = who.subject,
        draft = release.is_draft,
        prerelease = release.is_prerelease,
        "release created"
    );
    Ok(redirect(&format!(
        "/r/{owner}/{name}/releases/tag/{tag}",
        tag = release.tag_name
    )))
}

// GET /r/{owner}/{name}/releases/{id} — release detail by id
pub async fn detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, id)): Path<(String, String, String)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let writer = can_write(&repo, &who, &headers);
    let release = state
        .store
        .get_release(&repo.id, &id)
        .await?
        .ok_or_else(|| AppError::NotFound("No release exists at that path.".to_string()))?;
    render_detail_response(&state, &who, &repo, &release, writer).await
}

// GET /r/{owner}/{name}/releases/tag/{*tag} — release detail by tag
pub async fn detail_by_tag(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, tag)): Path<(String, String, String)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let writer = can_write(&repo, &who, &headers);
    let tag = tag.trim_start_matches('/');
    let release = state
        .store
        .get_release_by_tag(&repo.id, tag)
        .await?
        .ok_or_else(|| AppError::NotFound("No release exists for that tag.".to_string()))?;
    render_detail_response(&state, &who, &repo, &release, writer).await
}

#[derive(Debug, Deserialize)]
pub struct DeleteReleaseForm {
    #[serde(default)]
    pub csrf_token: String,
}

// POST /r/{owner}/{name}/releases/{id}/delete — delete release metadata
pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, id)): Path<(String, String, String)>,
    Form(form): Form<DeleteReleaseForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and submit again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    if !can_write(&repo, &who, &headers) {
        return Err(AppError::Forbidden(
            "Only the repository owner or an administrator can delete releases.".to_string(),
        ));
    }
    if !state.store.delete_release(&repo.id, &id).await? {
        return Err(AppError::NotFound(
            "No release exists at that path.".to_string(),
        ));
    }
    tracing::info!(
        repo = repo.id,
        release = id,
        actor = who.subject,
        "release deleted"
    );
    Ok(redirect(&format!("/r/{owner}/{name}/releases")))
}

async fn render_detail_response(
    state: &AppState,
    who: &Identity,
    repo: &Repo,
    release: &Release,
    writer: bool,
) -> Result<Response, AppError> {
    if release.is_draft && !writer {
        return Err(AppError::NotFound(
            "No release exists at that path.".to_string(),
        ));
    }
    let csrf = auth::new_csrf_token();
    let header = header_with_counts_for(state, repo, "releases", writer).await;
    let body = format!("{header}{}", render_detail(repo, release, writer, &csrf));
    Ok(html_with_csrf(
        StatusCode::OK,
        page(
            &format!("{}/{} · {}", repo.owner_sub, repo.name, release.title),
            Some(&who.email),
            &body,
        ),
        &csrf,
    ))
}

async fn pick_release_tag(
    state: &AppState,
    repo: &Repo,
    tags: &[TagInfo],
    form: &CreateReleaseForm,
) -> Result<(String, String, bool), &'static str> {
    let new_tag = form.new_tag.trim();
    if !new_tag.is_empty() {
        validate_tag_name(new_tag)?;
        if let Some(existing) = tags.iter().find(|t| t.name == new_tag) {
            return Ok((existing.name.clone(), existing.oid.clone(), false));
        }
        let target = state
            .git
            .head_commit(&repo.owner_sub, &repo.name)
            .await
            .ok_or("This repository has no commits to tag yet.")?;
        return Ok((new_tag.to_string(), target, true));
    }

    let existing_tag = form.existing_tag.trim();
    if existing_tag.is_empty() {
        return Err("Choose an existing tag or enter a new tag.");
    }
    validate_tag_name(existing_tag)?;
    let Some(tag) = tags.iter().find(|t| t.name == existing_tag) else {
        return Err("Choose an existing tag on this repository.");
    };
    Ok((tag.name.clone(), tag.oid.clone(), false))
}

fn visible_releases(mut releases: Vec<Release>, include_drafts: bool) -> Vec<Release> {
    if !include_drafts {
        releases.retain(|r| !r.is_draft);
    }
    releases
}

async fn render_new_error(
    state: &AppState,
    who: &Identity,
    repo: &Repo,
    tags: &[TagInfo],
    msg: &str,
) -> Response {
    let csrf = auth::new_csrf_token();
    let body = render_new_page(state, repo, tags, &csrf, Some(msg)).await;
    html_with_csrf(
        StatusCode::BAD_REQUEST,
        page(
            &format!("{}/{} · New release", repo.owner_sub, repo.name),
            Some(&who.email),
            &body,
        ),
        &csrf,
    )
}

async fn render_new_page(
    state: &AppState,
    repo: &Repo,
    tags: &[TagInfo],
    csrf: &str,
    error: Option<&str>,
) -> String {
    let header = header_with_counts_for(state, repo, "releases", true).await;
    format!("{header}{}", render_new_form(repo, tags, csrf, error))
}

fn render_list(repo: &Repo, releases: &[Release], writer: bool) -> String {
    let new_button = if writer {
        format!(
            "<a class=\"btn btn-primary btn-sm\" href=\"/r/{owner}/{name}/releases/new\">New release</a>",
            owner = esc(&repo.owner_sub),
            name = esc(&repo.name),
        )
    } else {
        String::new()
    };
    let rows = if releases.is_empty() {
        "<div class=\"empty\"><div class=\"empty__title\">No releases yet</div></div>".to_string()
    } else {
        releases
            .iter()
            .map(|r| render_release_card(repo, r, true))
            .collect::<String>()
    };
    format!(
        r##"<section class="card">
  <div class="card__head"><h2>Releases <span class="tab__count">{count}</span></h2>{new_button}</div>
  <div class="card__body release-list">{rows}</div>
</section>"##,
        count = releases.len(),
        new_button = new_button,
        rows = rows,
    )
}

fn render_release_card(repo: &Repo, release: &Release, with_summary: bool) -> String {
    let badges = render_release_badges(release);
    let notes = if with_summary {
        let summary = release_summary(&release.body_md);
        if summary.is_empty() {
            "<p class=\"muted\">No release notes.</p>".to_string()
        } else {
            format!("<p class=\"release-card__summary\">{}</p>", esc(&summary))
        }
    } else {
        String::new()
    };
    let when = if release.is_draft {
        "Draft".to_string()
    } else {
        format!("Published {}", fmt_ts(release.published_at))
    };
    format!(
        r##"<article class="release-card">
  <div class="release-card__head">
    <div>
      <a class="release-card__title" href="/r/{owner}/{name}/releases/tag/{tag}">{title}</a>
      <div class="release-card__meta">
        <span class="release-tag">{tag_name}</span>
        <a href="/r/{owner}/{name}/commit/{target}"><code class="oid">{short}</code></a>
        <span>{when}</span>
      </div>
    </div>
    <div class="release-card__badges">{badges}</div>
  </div>
  {notes}
  <div class="release-assets"><span class="release-asset muted">No assets.</span></div>
</article>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        tag = esc(&release.tag_name),
        title = esc(&release.title),
        tag_name = esc(&release.tag_name),
        target = esc(&release.target_commit),
        short = esc(&crate::handlers::short_oid(&release.target_commit)),
        when = esc(&when),
        badges = badges,
        notes = notes,
    )
}

fn render_detail(repo: &Repo, release: &Release, writer: bool, csrf: &str) -> String {
    let notes = if release.body_md.trim().is_empty() {
        "<p class=\"muted\">No release notes.</p>".to_string()
    } else {
        crate::markdown::render_for_repo(&release.body_md, &repo.owner_sub, &repo.name)
    };
    let delete_form = if writer {
        format!(
            r##"<form class="inline-form" method="post" action="/r/{owner}/{name}/releases/{id}/delete" onsubmit="return confirm('Delete this release? The git tag will remain.');">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <button class="btn btn-danger btn-sm" type="submit">Delete release</button>
</form>"##,
            owner = esc(&repo.owner_sub),
            name = esc(&repo.name),
            id = esc(&release.id),
            csrf = esc(csrf),
        )
    } else {
        String::new()
    };
    format!(
        r##"<section class="card release-card">
  <div class="card__head">
    <div>
      <h2>{title}</h2>
      <div class="release-card__meta">
        <span class="release-tag">{tag}</span>
        <a href="/r/{owner}/{name}/commit/{target}"><code class="oid">{short}</code></a>
        <span>{created}</span>
      </div>
    </div>
    <div class="release-card__badges">{badges}</div>
  </div>
  <div class="card__body markdown-body">{notes}</div>
  <div class="card__body release-assets"><span class="release-asset muted">No assets.</span></div>
  <div class="card__body">{delete_form}</div>
</section>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        title = esc(&release.title),
        tag = esc(&release.tag_name),
        target = esc(&release.target_commit),
        short = esc(&crate::handlers::short_oid(&release.target_commit)),
        created = esc(&fmt_ts(release.created_at)),
        badges = render_release_badges(release),
        notes = notes,
        delete_form = delete_form,
    )
}

fn render_new_form(repo: &Repo, tags: &[TagInfo], csrf: &str, error: Option<&str>) -> String {
    let error_block = error
        .map(|msg| {
            format!(
                "<div class=\"alert alert-danger\" role=\"alert\">{}</div>",
                esc(msg)
            )
        })
        .unwrap_or_default();
    let tag_options = if tags.is_empty() {
        "<option value=\"\">No existing tags</option>".to_string()
    } else {
        let mut out = "<option value=\"\">Choose a tag</option>".to_string();
        for tag in tags {
            out.push_str(&format!(
                "<option value=\"{name}\">{name}</option>",
                name = esc(&tag.name)
            ));
        }
        out
    };
    format!(
        r##"<section class="card">
  <div class="card__head"><h2>New release</h2></div>
  <div class="card__body">
    {error_block}
    <form method="post" action="/r/{owner}/{name}/releases/new">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <div class="field">
        <label for="existing_tag">Existing tag</label>
        <select id="existing_tag" name="existing_tag">{tag_options}</select>
      </div>
      <div class="field">
        <label for="new_tag">New tag</label>
        <input type="text" id="new_tag" name="new_tag" maxlength="128" autocomplete="off" spellcheck="false">
      </div>
      <div class="field">
        <label for="title">Title</label>
        <input type="text" id="title" name="title" maxlength="{title_max}">
      </div>
      <div class="field">
        <label for="body_md">Release notes</label>
        <textarea id="body_md" name="body_md" rows="12" maxlength="{notes_max}"></textarea>
      </div>
      <div class="field field--check">
        <label class="check"><input type="checkbox" name="is_prerelease" value="on"> Pre-release</label>
      </div>
      <div class="field field--check">
        <label class="check"><input type="checkbox" name="is_draft" value="on"> Draft</label>
      </div>
      <div class="actions">
        <button class="btn btn-primary" type="submit">Create release</button>
        <a class="btn btn-ghost" href="/r/{owner}/{name}/releases">Cancel</a>
      </div>
    </form>
  </div>
</section>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        csrf = esc(csrf),
        tag_options = tag_options,
        title_max = TITLE_MAX,
        notes_max = NOTES_MAX,
        error_block = error_block,
    )
}

fn render_release_badges(release: &Release) -> String {
    let mut out = String::new();
    if release.is_prerelease {
        out.push_str("<span class=\"state-badge release-badge release-badge--prerelease\">Pre-release</span>");
    }
    if release.is_draft {
        out.push_str("<span class=\"state-badge release-badge release-badge--draft\">Draft</span>");
    }
    out
}

fn release_summary(body: &str) -> String {
    let one_line = body
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    one_line.chars().take(240).collect()
}

fn validate_tag_name(tag: &str) -> Result<(), &'static str> {
    if tag.is_empty() || tag.len() > 128 {
        return Err("Tag name must be 1-128 characters.");
    }
    if tag.starts_with('-')
        || tag.starts_with('/')
        || tag.ends_with('/')
        || tag.starts_with("refs/")
        || tag.ends_with(".lock")
        || tag.contains("..")
        || tag.contains("//")
        || tag.contains("@{")
    {
        return Err("Invalid tag name.");
    }
    if !tag
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
    {
        return Err("Tag name may only contain letters, digits, '-', '_', '.', '/'.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_validation_accepts_common_release_names() {
        assert!(validate_tag_name("v1.2.3").is_ok());
        assert!(validate_tag_name("release/2026-07").is_ok());
    }

    #[test]
    fn tag_validation_rejects_unsafe_names() {
        assert!(validate_tag_name("").is_err());
        assert!(validate_tag_name("-v1").is_err());
        assert!(validate_tag_name("refs/tags/v1").is_err());
        assert!(validate_tag_name("bad tag").is_err());
        assert!(validate_tag_name("bad..tag").is_err());
        assert!(validate_tag_name("bad.lock").is_err());
    }

    #[test]
    fn release_summary_uses_plain_text_excerpt() {
        assert_eq!(
            release_summary("\n# Title\n\nBody text"),
            "# Title Body text"
        );
        assert_eq!(release_summary(""), "");
    }
}
