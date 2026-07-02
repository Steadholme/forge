//! The SSO web surface: repo list/create, browse (tree/blob), commit history, branches.
//!
//! Mounted behind a Sluice `auth=sso` route: the gateway authenticates the user and injects
//! `X-Auth-Subject` / `X-Auth-Email`, which we trust (Loom is internal-only). The OWNER of a repo
//! is ALWAYS the subject header — never a client field. Private repos are hidden from non-owners
//! (a private repo a viewer cannot see returns 404, so existence does not leak). Every
//! producer-supplied string — repo name, description, file path, commit subject — is HTML-escaped
//! on render; a non-markdown text blob is shown in a line-numbered, escaped monospace view.
//! Markdown (a `.md` blob + the repo README, plus issue bodies) is rendered through the estate's
//! sanitising [`crate::markdown`] pipeline: raw HTML is downgraded to text and unsafe link schemes
//! are defused, so no producer-supplied markup ever executes.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Form;
use serde::Deserialize;

use crate::auth::{self, Identity};
use crate::config::COMMIT_LIMIT;
use crate::error::AppError;
use crate::gitops::{BlameLine, CodeSearchFile, CodeSearchResults, CommitInfo, TreeEntry};
use crate::handlers::{esc, fmt_rel, fmt_ts, html_ok, html_with_csrf, page, redirect, short_oid};
use crate::model::{validate_owner_sub, validate_repo_name, Release, Repo};
use crate::{now_secs, random_alnum, AppState};

/// Length of a repo/issue/pat id (62-symbol alphabet).
const ID_LEN: usize = 16;
const FILE_HISTORY_PER_PAGE: usize = 50;
const CODE_SEARCH_RESULT_LIMIT: usize = 200;
const CODE_SEARCH_FILE_LIMIT: usize = 20;
const CODE_SEARCH_QUERY_MAX_CHARS: usize = 128;

// ===========================================================================
// GET / — repo list + create form
// ===========================================================================

pub async fn index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let who = auth::identity(&headers);
    let csrf = auth::new_csrf_token();
    let repos = state
        .store
        .list_visible_repos(&who.subject)
        .await
        .unwrap_or_default();
    let body = render_index(&who, &csrf, &repos, None);
    html_with_csrf(
        StatusCode::OK,
        page("Repositories", Some(&who.email), &body),
        &csrf,
    )
}

#[derive(Debug, Deserialize)]
pub struct CreateForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub visibility: String,
    #[serde(default)]
    pub default_branch: String,
}

/// `POST /new` — create a repo (DB row + bare repo on disk), then 302 to the repo page.
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and submit again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    validate_owner_sub(&who.subject).map_err(|e| AppError::BadRequest(e.to_string()))?;

    let name = form.name.trim().to_string();
    if let Err(msg) = validate_repo_name(&name) {
        return Ok(render_index_error(&state, &who, msg).await);
    }
    let default_branch = normalize_branch(&form.default_branch);
    if let Err(msg) = validate_branch_name(&default_branch) {
        return Ok(render_index_error(&state, &who, msg).await);
    }
    let is_private = matches!(form.visibility.as_str(), "private");

    let repo = Repo {
        id: format!("rp_{}", random_alnum(ID_LEN)),
        owner_sub: who.subject.clone(),
        name: name.clone(),
        description: form.description.trim().chars().take(500).collect(),
        is_private,
        default_branch: default_branch.clone(),
        require_approval: false,
        required_approvals: 0,
        require_code_owner_reviews: false,
        protect_default_branch: false,
        forked_from_id: String::new(),
        created_at: now_secs(),
    };

    if !state.store.create_repo(&repo).await? {
        return Ok(render_index_error(
            &state,
            &who,
            "You already have a repository with that name.",
        )
        .await);
    }

    // Create the bare repo on disk; on failure roll back the metadata row so the two stay in sync.
    if let Err(e) = state
        .git
        .init_bare(&who.subject, &name, &default_branch)
        .await
    {
        let _ = state.store.delete_repo(&repo.id).await;
        return Err(AppError::Internal(format!("git init failed: {e}")));
    }

    tracing::info!(owner = who.subject, repo = name, "repository created");
    Ok(redirect(&format!("/r/{}/{}", who.subject, name)))
}

// ===========================================================================
// GET /r/{owner}/{name} — code view (root tree + commits + branches)
// ===========================================================================

pub async fn view(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let csrf = auth::new_csrf_token();
    let mut body = render_code_page(&state, &repo, "").await?;
    body.push_str(&render_fork_card(&repo, &who, &csrf));
    Ok(html_with_csrf(
        StatusCode::OK,
        page(&format!("{}/{}", owner, name), Some(&who.email), &body),
        &csrf,
    ))
}

#[derive(Debug, Deserialize)]
pub struct ForkForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub name: String,
}

pub async fn fork(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
    Form(form): Form<ForkForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and submit again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    validate_owner_sub(&who.subject).map_err(|e| AppError::BadRequest(e.to_string()))?;
    let source = load_visible_repo(&state, &who, &owner, &name).await?;
    let fork_name = if form.name.trim().is_empty() {
        source.name.clone()
    } else {
        form.name.trim().to_string()
    };
    validate_repo_name(&fork_name).map_err(|e| AppError::BadRequest(e.to_string()))?;

    let repo = Repo {
        id: format!("rp_{}", random_alnum(ID_LEN)),
        owner_sub: who.subject.clone(),
        name: fork_name.clone(),
        description: format!("Fork of {}/{}", source.owner_sub, source.name),
        is_private: source.is_private,
        default_branch: source.default_branch.clone(),
        require_approval: false,
        required_approvals: 0,
        require_code_owner_reviews: false,
        protect_default_branch: false,
        forked_from_id: source.id.clone(),
        created_at: now_secs(),
    };
    if !state.store.create_repo(&repo).await? {
        return Err(AppError::BadRequest(
            "You already have a repository with that name.".to_string(),
        ));
    }
    if let Err(e) = state
        .git
        .clone_bare(&source.owner_sub, &source.name, &who.subject, &fork_name)
        .await
    {
        let _ = state.store.delete_repo(&repo.id).await;
        state.git.remove_repo(&who.subject, &fork_name).await;
        return Err(AppError::Internal(format!("git clone --bare failed: {e}")));
    }
    tracing::info!(
        source_repo = source.id,
        fork_repo = repo.id,
        actor = who.subject,
        "repository forked"
    );
    Ok(redirect(&format!("/r/{}/{}", who.subject, fork_name)))
}

// ===========================================================================
// GET /r/{owner}/{name}/tree/{*path} — browse a subdirectory
// ===========================================================================

pub async fn tree(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, path)): Path<(String, String, String)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let path = clean_subpath(&path)?;
    let body = render_code_page(&state, &repo, &path).await?;
    Ok(html_ok(page(
        &format!("{}/{}", owner, name),
        Some(&who.email),
        &body,
    )))
}

// ===========================================================================
// GET /r/{owner}/{name}/blob/{*path} — view a file
// ===========================================================================

pub async fn blob(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, path)): Path<(String, String, String)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let (commit, path) = resolve_blob_target(&state, &repo, &path).await?;
    let bytes = state
        .git
        .read_blob(&repo.owner_sub, &repo.name, &commit, &path)
        .await
        .ok_or_else(|| AppError::NotFound("No such file at this ref.".to_string()))?;

    let open_issues = state.store.open_issue_count(&repo.id).await.unwrap_or(0);
    let open_pulls = state.store.open_pull_count(&repo.id).await.unwrap_or(0);
    let release_count = state
        .store
        .release_count(&repo.id, false)
        .await
        .unwrap_or(0);
    let body = render_blob(
        &repo,
        &state.config.public_base_url,
        open_issues,
        open_pulls,
        release_count,
        &commit,
        &path,
        &bytes,
    );
    Ok(html_ok(page(
        &format!("{}/{}", owner, name),
        Some(&who.email),
        &body,
    )))
}

// ===========================================================================
// GET /r/{owner}/{name}/search?q=<query>&ref=<ref> — repository code search
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct CodeSearchQuery {
    #[serde(default)]
    pub q: String,
    #[serde(default, rename = "ref")]
    pub ref_name: String,
    #[serde(default)]
    pub i: Option<String>,
}

impl CodeSearchQuery {
    fn ignore_case(&self) -> bool {
        matches!(self.i.as_deref(), Some("1" | "true" | "on" | "yes"))
    }
}

pub async fn code_search(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
    Query(q): Query<CodeSearchQuery>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let header = header_with_counts(&state, &repo, "code").await;
    let query = q.q.trim().to_string();
    let ref_name = normalize_search_ref(&q.ref_name);
    let ignore_case = q.ignore_case();
    let mut results = None;
    let mut notice = None;

    if query.is_empty() {
        notice = Some("Enter a search term.".to_string());
    } else if query.chars().count() > CODE_SEARCH_QUERY_MAX_CHARS {
        notice = Some(format!(
            "Search terms are limited to {CODE_SEARCH_QUERY_MAX_CHARS} characters."
        ));
    } else {
        match resolve_blame_ref(&state, &repo, &ref_name).await {
            Some(commit) => {
                let found = state
                    .git
                    .code_search(
                        &repo.owner_sub,
                        &repo.name,
                        &commit,
                        &query,
                        ignore_case,
                        CODE_SEARCH_RESULT_LIMIT,
                        CODE_SEARCH_FILE_LIMIT,
                    )
                    .await
                    .map_err(|e| AppError::Internal(format!("git grep failed: {e}")))?;
                results = Some(found);
            }
            None => {
                notice = Some("No such ref in this repository.".to_string());
            }
        }
    }

    let body = render_code_search_page(
        &repo,
        &header,
        &query,
        &ref_name,
        ignore_case,
        results.as_ref(),
        notice.as_deref(),
    );
    Ok(html_ok(page(
        &format!("{owner}/{name} · Code search"),
        Some(&who.email),
        &body,
    )))
}

// ===========================================================================
// GET /r/{owner}/{name}/blame/{ref}/{*path} — line-level blame for a file
// ===========================================================================

pub async fn blame(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, ref_name, path)): Path<(String, String, String, String)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let path = clean_blame_subpath(&path)?;
    let ref_name = ref_name.trim();
    if ref_name.is_empty() {
        return Err(AppError::BadRequest("Invalid ref.".to_string()));
    }

    let header = header_with_counts(&state, &repo, "code").await;
    let title = format!("{owner}/{name} · Blame");
    let Some(commit) = resolve_blame_ref(&state, &repo, ref_name).await else {
        let body = render_blame_notice(
            &repo,
            &header,
            ref_name,
            &path,
            "No such ref in this repository.",
        );
        return Ok(html_ok(page(&title, Some(&who.email), &body)));
    };
    let Some(bytes) = state
        .git
        .read_blob(&repo.owner_sub, &repo.name, &commit, &path)
        .await
    else {
        let body =
            render_blame_notice(&repo, &header, ref_name, &path, "No such file at this ref.");
        return Ok(html_ok(page(&title, Some(&who.email), &body)));
    };

    let body = if bytes.contains(&0) {
        render_blame_notice(
            &repo,
            &header,
            ref_name,
            &path,
            "Binary file blame is not shown.",
        )
    } else if bytes.len() > crate::config::MAX_BLOB_RENDER_BYTES {
        render_blame_notice(
            &repo,
            &header,
            ref_name,
            &path,
            &format!(
                "File is too large to blame inline ({}).",
                human_size(bytes.len() as i64)
            ),
        )
    } else {
        match state
            .git
            .blame(&repo.owner_sub, &repo.name, &commit, &path)
            .await
        {
            Some(lines) => render_blame(&repo, &header, ref_name, &path, &commit, &lines),
            None => render_blame_notice(
                &repo,
                &header,
                ref_name,
                &path,
                "Could not compute blame for this file.",
            ),
        }
    };

    Ok(html_ok(page(&title, Some(&who.email), &body)))
}

// ===========================================================================
// GET /r/{owner}/{name}/history/{ref}/{*path} — single-file commit history
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct FileHistoryQuery {
    /// Keyset anchor: the OID of the last commit on the previous page.
    #[serde(default)]
    pub after: Option<String>,
}

pub async fn file_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, ref_name, path)): Path<(String, String, String, String)>,
    Query(q): Query<FileHistoryQuery>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let path = clean_blame_subpath(&path)?;
    let ref_name = ref_name.trim();
    if ref_name.is_empty() {
        return Err(AppError::BadRequest("Invalid ref.".to_string()));
    }

    let header = header_with_counts(&state, &repo, "code").await;
    let title = format!("{owner}/{name} · File history");
    if path.is_empty() {
        let body = render_file_history_notice(&repo, &header, ref_name, &path, "No file path.");
        return Ok(html_ok(page(&title, Some(&who.email), &body)));
    }

    let Some(commit) = resolve_blame_ref(&state, &repo, ref_name).await else {
        let body = render_file_history_notice(
            &repo,
            &header,
            ref_name,
            &path,
            "No such ref in this repository.",
        );
        return Ok(html_ok(page(&title, Some(&who.email), &body)));
    };

    let after = match q.after.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(a) => {
            if !is_hex_oid(a) {
                return Err(AppError::BadRequest("Invalid commit id.".to_string()));
            }
            Some(
                state
                    .git
                    .resolve_commit(&repo.owner_sub, &repo.name, a)
                    .await
                    .ok_or_else(|| AppError::NotFound("No such commit.".to_string()))?,
            )
        }
        None => None,
    };

    let paged = after.is_some();
    let start = after.as_deref().unwrap_or(&commit);
    let limit = FILE_HISTORY_PER_PAGE + if paged { 2 } else { 1 };
    let mut commits = state
        .git
        .file_log(&repo.owner_sub, &repo.name, start, &path, limit)
        .await;
    if let Some(anchor) = after.as_deref() {
        if commits.first().map(|c| c.oid.as_str()) == Some(anchor) {
            commits.remove(0);
        }
    }
    let has_next = commits.len() > FILE_HISTORY_PER_PAGE;
    commits.truncate(FILE_HISTORY_PER_PAGE);

    let body = format!(
        "{header}{history}",
        history = render_file_history(&repo, ref_name, &path, &commits, paged, has_next),
    );
    Ok(html_ok(page(&title, Some(&who.email), &body)))
}

// ===========================================================================
// Shared loaders
// ===========================================================================

/// Load a repo visible to `who`: a private repo owned by someone else returns 404 (no leak).
pub async fn load_visible_repo(
    state: &AppState,
    who: &Identity,
    owner: &str,
    name: &str,
) -> Result<Repo, AppError> {
    match state.store.get_repo(owner, name).await? {
        Some(r) if !r.is_private || r.owner_sub == who.subject => Ok(r),
        _ => Err(AppError::NotFound(
            "No repository exists at that path.".to_string(),
        )),
    }
}

/// Render the repo header for the `active` tab, fetching the open issue/PR badge counts (the
/// shared entry point for the commits/branches/settings pages).
pub(crate) async fn header_with_counts(state: &AppState, repo: &Repo, active: &str) -> String {
    header_with_counts_for(state, repo, active, false).await
}

pub(crate) async fn header_with_counts_for(
    state: &AppState,
    repo: &Repo,
    active: &str,
    include_drafts: bool,
) -> String {
    let open_issues = state.store.open_issue_count(&repo.id).await.unwrap_or(0);
    let open_pulls = state.store.open_pull_count(&repo.id).await.unwrap_or(0);
    let release_count = state
        .store
        .release_count(&repo.id, include_drafts)
        .await
        .unwrap_or(0);
    let parent = fork_parent(state, repo).await;
    render_repo_header_with_parent(
        repo,
        &state.config.public_base_url,
        open_issues,
        open_pulls,
        release_count,
        active,
        parent.as_ref(),
    )
}

pub(crate) async fn fork_parent(state: &AppState, repo: &Repo) -> Option<Repo> {
    if repo.forked_from_id.is_empty() {
        return None;
    }
    state
        .store
        .get_repo_by_id(&repo.forked_from_id)
        .await
        .ok()
        .flatten()
}

/// Reject a browse subpath that could escape the tree, then normalize it (no leading/trailing `/`).
fn clean_subpath(path: &str) -> Result<String, AppError> {
    let trimmed = path.trim_matches('/');
    for seg in trimmed.split('/') {
        if seg == ".." || seg == "." {
            return Err(AppError::BadRequest("Invalid path.".to_string()));
        }
    }
    Ok(trimmed.to_string())
}

fn clean_blame_subpath(path: &str) -> Result<String, AppError> {
    if path.starts_with('/') {
        return Err(AppError::BadRequest("Invalid path.".to_string()));
    }
    clean_subpath(path)
}

async fn resolve_blob_target(
    state: &AppState,
    repo: &Repo,
    raw_path: &str,
) -> Result<(String, String), AppError> {
    let clean = clean_subpath(raw_path)?;
    if let Some((maybe_oid, rest)) = clean.split_once('/') {
        if is_full_oid(maybe_oid) {
            let path = clean_subpath(rest)?;
            let commit = state
                .git
                .resolve_commit(&repo.owner_sub, &repo.name, maybe_oid)
                .await
                .ok_or_else(|| AppError::NotFound("No such commit.".to_string()))?;
            return Ok((commit, path));
        }
    }

    let commit = state
        .git
        .head_commit(&repo.owner_sub, &repo.name)
        .await
        .ok_or_else(|| AppError::NotFound("This repository has no commits yet.".to_string()))?;
    Ok((commit, clean))
}

fn normalize_search_ref(ref_name: &str) -> String {
    let trimmed = ref_name.trim();
    if trimmed.is_empty() {
        "HEAD".to_string()
    } else {
        trimmed.to_string()
    }
}

async fn resolve_blame_ref(state: &AppState, repo: &Repo, ref_name: &str) -> Option<String> {
    if ref_name == "HEAD" {
        return state.git.head_commit(&repo.owner_sub, &repo.name).await;
    }
    if is_hex_oid(ref_name) {
        if let Some(oid) = state
            .git
            .resolve_commit(&repo.owner_sub, &repo.name, ref_name)
            .await
        {
            return Some(oid);
        }
    }
    let branches = state.git.branches(&repo.owner_sub, &repo.name).await;
    if branches.iter().any(|b| b == ref_name) {
        state
            .git
            .branch_oid(&repo.owner_sub, &repo.name, ref_name)
            .await
    } else {
        None
    }
}

fn is_hex_oid(s: &str) -> bool {
    (4..=64).contains(&s.len()) && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_full_oid(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

// ===========================================================================
// Rendering
// ===========================================================================

fn render_index(who: &Identity, csrf: &str, repos: &[Repo], error: Option<&str>) -> String {
    let error_block = match error {
        Some(msg) => format!(
            "<div class=\"alert alert-danger\" role=\"alert\">{}</div>",
            esc(msg)
        ),
        None => String::new(),
    };
    let list = if repos.is_empty() {
        "<li class=\"repo-item repo-item--empty\">No repositories yet. Create your first one.</li>"
            .to_string()
    } else {
        repos
            .iter()
            .map(|r| {
                let badge = if r.is_private {
                    "<span class=\"vis-badge vis-badge--private\">Private</span>"
                } else {
                    "<span class=\"vis-badge\">Public</span>"
                };
                let desc = if r.description.trim().is_empty() {
                    String::new()
                } else {
                    format!("<p class=\"repo-item__desc\">{}</p>", esc(&r.description))
                };
                format!(
                    "<li class=\"repo-item\">\
                       <div class=\"repo-item__head\">\
                         <a class=\"repo-item__name\" href=\"/r/{owner}/{name}\">{owner_e}/{name_e}</a>\
                         {badge}\
                       </div>\
                       {desc}\
                       <span class=\"repo-item__meta\">created {created}</span>\
                     </li>",
                    owner = esc(&r.owner_sub),
                    name = esc(&r.name),
                    owner_e = esc(&r.owner_sub),
                    name_e = esc(&r.name),
                    created = esc(&fmt_ts(r.created_at)),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    format!(
        r##"<div class="console__head">
  <h1>Repositories</h1>
  <p class="sub">Self-hosted git for the estate. Clone over HTTPS with a personal access token; browse here with single sign-on as {email}.</p>
</div>
<div class="layout">
  <section class="card">
    <div class="card__head"><h2>All repositories</h2></div>
    <div class="card__body">
      <ul class="repo-list">{list}</ul>
    </div>
  </section>
  <section class="card">
    <div class="card__head"><h2>New repository</h2></div>
    <div class="card__body">
      {error_block}
      <form method="post" action="/new">
        <input type="hidden" name="csrf_token" value="{csrf}">
        <div class="field">
          <label for="name">Name</label>
          <input type="text" id="name" name="name" maxlength="64" placeholder="e.g. holdfast-infra" autocomplete="off" spellcheck="false" required>
        </div>
        <div class="field">
          <label for="description">Description</label>
          <input type="text" id="description" name="description" maxlength="500" placeholder="Optional one-line summary">
        </div>
        <div class="field">
          <label for="default_branch">Default branch</label>
          <input type="text" id="default_branch" name="default_branch" maxlength="64" value="main" autocomplete="off" spellcheck="false">
        </div>
        <div class="field field--check">
          <label class="check"><input type="checkbox" name="visibility" value="private"> Private (only you can see and clone)</label>
        </div>
        <div class="actions">
          <button class="btn btn-primary" type="submit">Create repository</button>
        </div>
      </form>
    </div>
  </section>
</div>"##,
        email = esc(&who.email),
        list = list,
        error_block = error_block,
        csrf = esc(csrf),
    )
}

fn render_fork_card(repo: &Repo, who: &Identity, csrf: &str) -> String {
    let default_name = if repo.owner_sub == who.subject {
        format!("{}-fork", repo.name)
    } else {
        repo.name.clone()
    };
    format!(
        r##"<section class="card">
  <div class="card__head"><h2>Fork</h2></div>
  <div class="card__body">
    <form method="post" action="/r/{owner}/{name}/fork">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <div class="field">
        <label for="fork-name">Repository name</label>
        <input type="text" id="fork-name" name="name" maxlength="64" value="{default_name}" autocomplete="off" spellcheck="false" required>
      </div>
      <div class="actions">
        <button class="btn btn-secondary" type="submit">Fork repository</button>
      </div>
    </form>
  </div>
</section>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        csrf = esc(csrf),
        default_name = esc(&default_name),
    )
}

/// Re-render the index with an inline error + a fresh CSRF token (validation failures on create).
async fn render_index_error(state: &AppState, who: &Identity, msg: &str) -> Response {
    let csrf = auth::new_csrf_token();
    let repos = state
        .store
        .list_visible_repos(&who.subject)
        .await
        .unwrap_or_default();
    let body = render_index(who, &csrf, &repos, Some(msg));
    html_with_csrf(
        StatusCode::BAD_REQUEST,
        page("Repositories", Some(&who.email), &body),
        &csrf,
    )
}

/// Render the code page: repo header + clone box + (file browser at `subpath`) + branches +
/// commit history (history/branches shown at the repo root).
async fn render_code_page(
    state: &AppState,
    repo: &Repo,
    subpath: &str,
) -> Result<String, AppError> {
    let open_issues = state.store.open_issue_count(&repo.id).await.unwrap_or(0);
    let open_pulls = state.store.open_pull_count(&repo.id).await.unwrap_or(0);
    let release_count = state
        .store
        .release_count(&repo.id, false)
        .await
        .unwrap_or(0);
    let parent = fork_parent(state, repo).await;
    let header = render_repo_header_with_parent(
        repo,
        &state.config.public_base_url,
        open_issues,
        open_pulls,
        release_count,
        "code",
        parent.as_ref(),
    );
    let search = render_code_search_form(repo, "", "HEAD", false);

    let head = state.git.head_commit(&repo.owner_sub, &repo.name).await;
    let Some(commit) = head else {
        // Empty repo: show how to push the first commit.
        let push = render_empty_repo(repo, &state.config.public_base_url);
        return Ok(format!("{header}{search}{push}"));
    };

    let entries = state
        .git
        .list_tree(&repo.owner_sub, &repo.name, &commit, subpath)
        .await;
    if !subpath.is_empty() && entries.is_empty() {
        return Err(AppError::NotFound("No such directory.".to_string()));
    }

    let files = render_file_browser(repo, subpath, &entries);

    // A rendered README under the file browser at the repo root (GitHub-style), sanitised.
    let readme = if subpath.is_empty() {
        render_readme(state, repo, &commit, &entries).await
    } else {
        String::new()
    };
    let latest_release = if subpath.is_empty() {
        render_latest_release(state, repo).await
    } else {
        String::new()
    };

    // History + branches only at the repo root, to keep subdirectory pages focused.
    let extras = if subpath.is_empty() {
        let branches = state.git.branches(&repo.owner_sub, &repo.name).await;
        let commits = state
            .git
            .log(&repo.owner_sub, &repo.name, &commit, COMMIT_LIMIT)
            .await;
        let branch_html = branches
            .iter()
            .map(|b| {
                let current = if *b == repo.default_branch {
                    " branch-badge--default"
                } else {
                    ""
                };
                format!("<span class=\"branch-badge{current}\">{}</span>", esc(b))
            })
            .collect::<Vec<_>>()
            .join("");
        let commit_html = if commits.is_empty() {
            "<li class=\"commit-item commit-item--empty\">No commits.</li>".to_string()
        } else {
            commits
                .iter()
                .map(|c| {
                    format!(
                        "<li class=\"commit-item\">\
                           <span class=\"commit-item__subject\">{subject}</span>\
                           <span class=\"commit-item__meta\">\
                             <code class=\"oid\">{oid}</code>\
                             <span>{author}</span>\
                             <span>{when}</span>\
                           </span>\
                         </li>",
                        subject = esc(&c.subject),
                        oid = esc(&short_oid(&c.oid)),
                        author = esc(&c.author_name),
                        when = esc(&fmt_ts(c.time)),
                    )
                })
                .collect::<Vec<_>>()
                .join("")
        };
        format!(
            r##"<div class="layout layout--repo">
  <section class="card">
    <div class="card__head"><h2>Recent commits</h2></div>
    <div class="card__body"><ul class="commit-list">{commit_html}</ul></div>
  </section>
  <section class="card">
    <div class="card__head"><h2>Branches</h2></div>
    <div class="card__body"><div class="branch-row">{branch_html}</div></div>
  </section>
</div>"##
        )
    } else {
        String::new()
    };

    Ok(format!(
        "{header}{search}{files}{readme}{latest_release}{extras}"
    ))
}

/// Render a repo-root README as sanitised markdown HTML (GitHub-style), or nothing when there is
/// no README blob (or it is binary / too large to render). The README name is HTML-escaped; the
/// body is rendered through [`crate::markdown::render`], which strips raw HTML and unsafe links.
async fn render_readme(
    state: &AppState,
    repo: &Repo,
    commit: &str,
    entries: &[TreeEntry],
) -> String {
    let Some(entry) = entries.iter().find(|e| !e.is_dir() && is_readme(&e.name)) else {
        return String::new();
    };
    let Some(bytes) = state
        .git
        .read_blob(&repo.owner_sub, &repo.name, commit, &entry.name)
        .await
    else {
        return String::new();
    };
    if bytes.contains(&0) || bytes.len() > crate::config::MAX_BLOB_RENDER_BYTES {
        return String::new();
    }
    let text = String::from_utf8_lossy(&bytes);
    format!(
        r##"<section class="card">
  <div class="card__head"><h2>{name}</h2></div>
  <div class="card__body markdown-body">{html}</div>
</section>"##,
        name = esc(&entry.name),
        html = crate::markdown::render_for_repo(&text, &repo.owner_sub, &repo.name),
    )
}

async fn render_latest_release(state: &AppState, repo: &Repo) -> String {
    let releases = state
        .store
        .list_releases_by_repo(&repo.id)
        .await
        .unwrap_or_default();
    let Some(release) = releases.into_iter().find(|r| !r.is_draft) else {
        return String::new();
    };
    render_latest_release_card(repo, &release)
}

fn render_latest_release_card(repo: &Repo, release: &Release) -> String {
    let prerelease = if release.is_prerelease {
        "<span class=\"state-badge release-badge release-badge--prerelease\">Pre-release</span>"
    } else {
        ""
    };
    let summary = release_notes_summary(&release.body_md);
    let notes = if summary.is_empty() {
        "<p class=\"muted\">No release notes.</p>".to_string()
    } else {
        format!("<p class=\"release-card__summary\">{}</p>", esc(&summary))
    };
    format!(
        r##"<section class="card release-card">
  <div class="card__head">
    <h2>Latest release</h2>
    <a class="btn btn-ghost btn-sm" href="/r/{owner}/{name}/releases">All releases</a>
  </div>
  <div class="card__body">
    <div class="release-card__head">
      <div>
        <a class="release-card__title" href="/r/{owner}/{name}/releases/tag/{tag}">{title}</a>
        <div class="release-card__meta">
          <span class="release-tag">{tag}</span>
          <a href="/r/{owner}/{name}/commit/{target}"><code class="oid">{short}</code></a>
          <span>{published}</span>
        </div>
      </div>
      <div class="release-card__badges">{prerelease}</div>
    </div>
    {notes}
    <div class="release-assets"><span class="release-asset muted">No assets.</span></div>
  </div>
</section>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        tag = esc(&release.tag_name),
        title = esc(&release.title),
        target = esc(&release.target_commit),
        short = esc(&short_oid(&release.target_commit)),
        published = esc(&fmt_ts(release.published_at)),
        prerelease = prerelease,
        notes = notes,
    )
}

fn release_notes_summary(body: &str) -> String {
    body.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(240)
        .collect()
}

/// Repo header: owner/name lockup, visibility badge, clone box, tab strip.
pub(crate) fn render_repo_header(
    repo: &Repo,
    base_url: &str,
    open_issues: i64,
    open_pulls: i64,
    release_count: i64,
    active: &str,
) -> String {
    render_repo_header_with_parent(
        repo,
        base_url,
        open_issues,
        open_pulls,
        release_count,
        active,
        None,
    )
}

pub(crate) fn render_repo_header_with_parent(
    repo: &Repo,
    base_url: &str,
    open_issues: i64,
    open_pulls: i64,
    release_count: i64,
    active: &str,
    forked_from: Option<&Repo>,
) -> String {
    let badge = if repo.is_private {
        "<span class=\"vis-badge vis-badge--private\">Private</span>"
    } else {
        "<span class=\"vis-badge\">Public</span>"
    };
    let desc = if repo.description.trim().is_empty() {
        String::new()
    } else {
        format!("<p class=\"sub\">{}</p>", esc(&repo.description))
    };
    let fork_line = forked_from
        .map(|parent| {
            format!(
                "<p class=\"sub\">Forked from <a href=\"/r/{owner}/{name}\">{owner}/{name}</a></p>",
                owner = esc(&parent.owner_sub),
                name = esc(&parent.name),
            )
        })
        .unwrap_or_default();
    let clone_url = format!(
        "{}/git/{}/{}.git",
        base_url.trim_end_matches('/'),
        repo.owner_sub,
        repo.name
    );
    let tab = |name: &str| if active == name { " tab--active" } else { "" };
    format!(
        r##"<div class="console__head">
  <div class="repo-title">
    <h1>{owner}/{name}</h1>
    {badge}
  </div>
  {desc}
  {fork_line}
  <div class="clone-box">
    <span class="clone-box__label">Clone</span>
    <input class="clone-box__url" type="text" readonly value="{clone}" onclick="this.select()">
  </div>
</div>
<nav class="tabs">
  <a class="tab{code_active}" href="/r/{owner}/{name}">Code</a>
  <a class="tab{commits_active}" href="/r/{owner}/{name}/commits">Commits</a>
  <a class="tab{branches_active}" href="/r/{owner}/{name}/branches">Branches</a>
  <a class="tab{releases_active}" href="/r/{owner}/{name}/releases">Releases <span class="tab__count">{release_count}</span></a>
  <a class="tab{issues_active}" href="/r/{owner}/{name}/issues">Issues <span class="tab__count">{open_issues}</span></a>
  <a class="tab{pulls_active}" href="/r/{owner}/{name}/pulls">Pull requests <span class="tab__count">{open_pulls}</span></a>
  <a class="tab{settings_active}" href="/r/{owner}/{name}/settings">Settings</a>
</nav>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        badge = badge,
        desc = desc,
        fork_line = fork_line,
        clone = esc(&clone_url),
        code_active = tab("code"),
        commits_active = tab("commits"),
        branches_active = tab("branches"),
        releases_active = tab("releases"),
        pulls_active = tab("pulls"),
        issues_active = tab("issues"),
        settings_active = tab("settings"),
        open_issues = open_issues,
        open_pulls = open_pulls,
        release_count = release_count,
    )
}

fn render_code_search_form(repo: &Repo, query: &str, ref_name: &str, ignore_case: bool) -> String {
    let checked = if ignore_case { " checked" } else { "" };
    format!(
        r##"<section class="card code-search">
  <div class="card__body">
    <form class="code-search__form" action="/r/{owner}/{name}/search" method="get" role="search">
      <input class="code-search__input" type="search" name="q" value="{query}" placeholder="Search code">
      <input class="code-search__ref" type="text" name="ref" value="{ref_name}" aria-label="Git ref">
      <label class="code-search__case"><input type="checkbox" name="i" value="1"{checked}> Ignore case</label>
      <button class="btn btn-sm" type="submit">Search</button>
    </form>
  </div>
</section>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        query = esc(query),
        ref_name = esc(ref_name),
        checked = checked,
    )
}

fn render_code_search_page(
    repo: &Repo,
    header: &str,
    query: &str,
    ref_name: &str,
    ignore_case: bool,
    results: Option<&CodeSearchResults>,
    notice: Option<&str>,
) -> String {
    let form = render_code_search_form(repo, query, ref_name, ignore_case);
    let body = if let Some(message) = notice {
        format!("<p class=\"muted code-search__empty\">{}</p>", esc(message))
    } else if let Some(results) = results {
        render_code_search_results(repo, query, ignore_case, results)
    } else {
        String::new()
    };

    format!(
        r##"{header}{form}
<section class="card code-search__results">
  <div class="card__head"><h2>Code search</h2><span class="muted">Ref {ref_name}</span></div>
  <div class="card__body">{body}</div>
</section>"##,
        header = header,
        form = form,
        ref_name = esc(ref_name),
        body = body,
    )
}

fn render_code_search_results(
    repo: &Repo,
    query: &str,
    ignore_case: bool,
    results: &CodeSearchResults,
) -> String {
    if results.total_hits == 0 {
        return "<p class=\"muted code-search__empty\">No code results found.</p>".to_string();
    }

    let mut html = format!(
        "<p class=\"muted code-search__summary\">{} result{} in {} file{}.</p>",
        results.total_hits,
        if results.total_hits == 1 { "" } else { "s" },
        results.files.len(),
        if results.files.len() == 1 { "" } else { "s" },
    );
    if results.limited {
        html.push_str(&format!(
            "<p class=\"muted code-search__limit\">Showing the first {CODE_SEARCH_RESULT_LIMIT} results.</p>"
        ));
    }
    if results.per_file_limited {
        html.push_str(&format!(
            "<p class=\"muted code-search__limit\">Showing up to {CODE_SEARCH_FILE_LIMIT} matches per file.</p>"
        ));
    }
    for file in &results.files {
        html.push_str(&render_code_search_file(repo, file, query, ignore_case));
    }
    html
}

fn render_code_search_file(
    repo: &Repo,
    file: &CodeSearchFile,
    query: &str,
    ignore_case: bool,
) -> String {
    let blob_href = format!("/r/{}/{}/blob/{}", repo.owner_sub, repo.name, file.path);
    let hits = file
        .hits
        .iter()
        .map(|hit| {
            let line_href = format!("{blob_href}#L{}", hit.line);
            format!(
                "<li class=\"code-search__hit\">\
                   <a class=\"code-search__line\" href=\"{href}\">L{line}</a>\
                   <code class=\"code-search__code\">{code}</code>\
                 </li>",
                href = esc(&line_href),
                line = hit.line,
                code = highlight_code_search_hit(&hit.content, query, ignore_case),
            )
        })
        .collect::<String>();

    format!(
        "<div class=\"code-search__file\">\
           <h3><a href=\"{href}\">{path}</a></h3>\
           <ol class=\"code-search__hits\">{hits}</ol>\
         </div>",
        href = esc(&blob_href),
        path = esc(&file.path),
        hits = hits,
    )
}

fn highlight_code_search_hit(content: &str, query: &str, ignore_case: bool) -> String {
    let escaped_content = esc(content);
    let escaped_query = esc(query);
    if escaped_query.is_empty() {
        return escaped_content;
    }

    let haystack = if ignore_case {
        escaped_content.to_ascii_lowercase()
    } else {
        escaped_content.clone()
    };
    let needle = if ignore_case {
        escaped_query.to_ascii_lowercase()
    } else {
        escaped_query
    };
    let mut out = String::with_capacity(escaped_content.len());
    let mut tail = 0usize;
    while let Some(rel) = haystack[tail..].find(&needle) {
        let start = tail + rel;
        let end = start + needle.len();
        out.push_str(&escaped_content[tail..start]);
        out.push_str("<mark class=\"code-search-hit\">");
        out.push_str(&escaped_content[start..end]);
        out.push_str("</mark>");
        tail = end;
    }
    out.push_str(&escaped_content[tail..]);
    out
}

/// Empty-repo helper: the exact commands to seed the first commit + push with a PAT.
fn render_empty_repo(repo: &Repo, base_url: &str) -> String {
    let clone_url = format!(
        "{}/git/{}/{}.git",
        base_url.trim_end_matches('/'),
        repo.owner_sub,
        repo.name
    );
    let quickstart = format!(
        "git clone {url}\ncd {name}\n# add files, then\ngit add .\ngit commit -m \"first commit\"\ngit push origin {branch}",
        url = clone_url,
        name = repo.name,
        branch = repo.default_branch,
    );
    format!(
        r##"<section class="card">
  <div class="card__head"><h2>Quick start</h2></div>
  <div class="card__body">
    <p class="muted">This repository is empty. Push your first commit (authenticate with a <a href="/pats">personal access token</a> as the password):</p>
    <pre class="code-pre"><code>{cmds}</code></pre>
  </div>
</section>"##,
        cmds = esc(&quickstart),
    )
}

/// The file browser card: breadcrumb + tree/blob rows for `entries` at `subpath`.
fn render_file_browser(repo: &Repo, subpath: &str, entries: &[TreeEntry]) -> String {
    let rows = entries
        .iter()
        .map(|e| {
            let child = if subpath.is_empty() {
                e.name.clone()
            } else {
                format!("{subpath}/{}", e.name)
            };
            let (href, icon) = if e.is_dir() {
                (
                    format!("/r/{}/{}/tree/{}", repo.owner_sub, repo.name, child),
                    "dir",
                )
            } else {
                (
                    format!("/r/{}/{}/blob/{}", repo.owner_sub, repo.name, child),
                    "file",
                )
            };
            let size = match e.size {
                Some(n) if !e.is_dir() => human_size(n),
                _ => String::new(),
            };
            format!(
                "<li class=\"tree-row tree-row--{icon}\">\
                   <a class=\"tree-row__name\" href=\"{href}\">{name}</a>\
                   <span class=\"tree-row__size\">{size}</span>\
                 </li>",
                icon = icon,
                href = esc(&href),
                name = esc(&e.name),
                size = esc(&size),
            )
        })
        .collect::<Vec<_>>()
        .join("");

    format!(
        r##"<section class="card">
  <div class="card__head">{breadcrumb}</div>
  <div class="card__body card__body--list">
    <ul class="tree-list">{rows}</ul>
  </div>
</section>"##,
        breadcrumb = render_breadcrumb(repo, subpath, false),
        rows = if rows.is_empty() {
            "<li class=\"tree-row tree-row--empty\">Empty directory.</li>".to_string()
        } else {
            rows
        },
    )
}

fn file_history_href(repo: &Repo, ref_name: &str, path: &str) -> String {
    format!(
        "/r/{}/{}/history/{}/{}",
        repo.owner_sub, repo.name, ref_name, path
    )
}

/// File-view card: repo header + breadcrumb + escaped file content (or a binary/too-large notice).
fn render_blob(
    repo: &Repo,
    base_url: &str,
    open_issues: i64,
    open_pulls: i64,
    release_count: i64,
    commit: &str,
    path: &str,
    bytes: &[u8],
) -> String {
    let header = render_repo_header(
        repo,
        base_url,
        open_issues,
        open_pulls,
        release_count,
        "code",
    );
    let history_href = file_history_href(repo, "HEAD", path);
    let blame_href = format!("/r/{}/{}/blame/HEAD/{}", repo.owner_sub, repo.name, path);
    let permalink_href = format!(
        "/r/{}/{}/blob/{}/{}",
        repo.owner_sub, repo.name, commit, path
    );
    let search = render_code_search_form(repo, "", "HEAD", false);
    let content = if bytes.contains(&0) {
        "<div class=\"card__body\"><p class=\"muted\">Binary file not shown.</p></div>".to_string()
    } else if bytes.len() > crate::config::MAX_BLOB_RENDER_BYTES {
        format!(
            "<div class=\"card__body\"><p class=\"muted\">File is too large to display ({}).</p></div>",
            esc(&human_size(bytes.len() as i64))
        )
    } else {
        let text = String::from_utf8_lossy(bytes);
        if is_markdown_path(path) {
            // A markdown file renders as sanitised HTML (raw HTML/unsafe links defused).
            format!(
                "<div class=\"card__body markdown-body\">{}</div>",
                crate::markdown::render_for_repo(&text, &repo.owner_sub, &repo.name)
            )
        } else {
            // Any other text blob gets a monospace, line-numbered view.
            format!(
                "<div class=\"card__body card__body--code\">{}</div>",
                render_text_blob(&text)
            )
        }
    };
    format!(
        r##"{header}{search}
<section class="card">
  <div class="card__head">{breadcrumb}<span class="blob-actions"><a class="btn btn-ghost btn-sm btn-permalink" href="{permalink_href}" data-permalink="{permalink_href}">Permalink</a><a class="btn btn-ghost btn-sm" href="{history_href}">History</a><a class="btn btn-ghost btn-sm" href="{blame_href}">Blame</a><span class="muted">{size}</span></span></div>
  {content}
</section>"##,
        header = header,
        search = search,
        breadcrumb = render_breadcrumb(repo, path, true),
        history_href = esc(&history_href),
        blame_href = esc(&blame_href),
        permalink_href = esc(&permalink_href),
        size = esc(&human_size(bytes.len() as i64)),
        content = content,
    )
}

fn render_blame_notice(
    repo: &Repo,
    header: &str,
    ref_name: &str,
    path: &str,
    message: &str,
) -> String {
    let history_href = file_history_href(repo, ref_name, path);
    format!(
        r##"{header}
<section class="card">
  <div class="card__head">{breadcrumb}<span class="blob-actions"><a class="btn btn-ghost btn-sm" href="{history_href}">History</a><span class="muted">Blame</span></span></div>
  <div class="card__body"><p class="muted">{message}</p></div>
</section>"##,
        header = header,
        breadcrumb = render_breadcrumb(repo, path, true),
        history_href = esc(&history_href),
        message = esc(message),
    )
}

fn render_blame(
    repo: &Repo,
    header: &str,
    ref_name: &str,
    path: &str,
    commit: &str,
    lines: &[BlameLine],
) -> String {
    let content = if lines.is_empty() {
        "<div class=\"card__body\"><p class=\"muted\">Empty file.</p></div>".to_string()
    } else {
        format!(
            "<div class=\"card__body card__body--code\">{}</div>",
            render_blame_table(repo, lines)
        )
    };
    let history_href = file_history_href(repo, ref_name, path);
    format!(
        r##"{header}
<section class="card">
  <div class="card__head">
    {breadcrumb}
    <span class="blob-actions"><a class="btn btn-ghost btn-sm" href="{history_href}">History</a><span class="muted">Blame {ref_name} at <a href="/r/{owner}/{name}/commit/{commit}"><code class="oid">{short}</code></a></span></span>
  </div>
  {content}
</section>"##,
        header = header,
        breadcrumb = render_breadcrumb(repo, path, true),
        history_href = esc(&history_href),
        ref_name = esc(ref_name),
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        commit = esc(commit),
        short = esc(&short_oid(commit)),
        content = content,
    )
}

fn render_file_history_notice(
    repo: &Repo,
    header: &str,
    ref_name: &str,
    path: &str,
    message: &str,
) -> String {
    format!(
        r##"{header}
<section class="card file-history">
  <div class="card__head">{breadcrumb}<span class="muted">History {ref_name}</span></div>
  <div class="card__body"><p class="muted">{message}</p></div>
</section>"##,
        header = header,
        breadcrumb = render_breadcrumb(repo, path, true),
        ref_name = esc(ref_name),
        message = esc(message),
    )
}

fn render_file_history(
    repo: &Repo,
    ref_name: &str,
    path: &str,
    commits: &[CommitInfo],
    paged: bool,
    has_next: bool,
) -> String {
    let now = now_secs();
    let rows = if commits.is_empty() {
        "<li class=\"commit-item commit-item--empty file-history__item\">No commits found for this file.</li>"
            .to_string()
    } else {
        commits
            .iter()
            .map(|c| {
                format!(
                    "<li class=\"commit-item file-history__item\">\
                       <a class=\"commit-item__subject file-history__message\" href=\"/r/{owner}/{name}/commit/{oid}\">{subject}</a>\
                       <span class=\"commit-item__meta file-history__meta\">\
                         <a href=\"/r/{owner}/{name}/commit/{oid}\"><code class=\"oid\">{short}</code></a>\
                         <span>{author}</span>\
                         <span title=\"{abs}\">{rel}</span>\
                       </span>\
                     </li>",
                    owner = esc(&repo.owner_sub),
                    name = esc(&repo.name),
                    oid = esc(&c.oid),
                    short = esc(&short_oid(&c.oid)),
                    subject = esc(&c.subject),
                    author = esc(&c.author_name),
                    abs = esc(&fmt_ts(c.time)),
                    rel = esc(&fmt_rel(now, c.time)),
                )
            })
            .collect::<String>()
    };

    let base_href = file_history_href(repo, ref_name, path);
    let newest = if paged {
        format!(
            "<a class=\"btn btn-ghost btn-sm\" href=\"{href}\">&larr; Newest</a>",
            href = esc(&base_href),
        )
    } else {
        String::new()
    };
    let older = match (has_next, commits.last()) {
        (true, Some(last)) => format!(
            "<a class=\"btn btn-ghost btn-sm\" href=\"{href}?after={oid}\">Older &rarr;</a>",
            href = esc(&base_href),
            oid = esc(&last.oid),
        ),
        _ => String::new(),
    };
    let pager = if newest.is_empty() && older.is_empty() {
        String::new()
    } else {
        format!(
            "<div class=\"pager file-history__pager\">{newest}<span class=\"spacer\"></span>{older}</div>"
        )
    };

    format!(
        r##"<section class="card file-history">
  <div class="card__head">{breadcrumb}<span class="muted">History {ref_name}</span></div>
  <div class="card__body">
    <ul class="commit-list file-history__list">{rows}</ul>
    {pager}
  </div>
</section>"##,
        breadcrumb = render_breadcrumb(repo, path, true),
        ref_name = esc(ref_name),
        rows = rows,
        pager = pager,
    )
}

fn render_blame_table(repo: &Repo, lines: &[BlameLine]) -> String {
    let now = now_secs();
    let mut rows = String::new();
    let mut i = 0usize;
    while i < lines.len() {
        let line = &lines[i];
        let mut run_len = 1usize;
        while i + run_len < lines.len() && lines[i + run_len].oid == line.oid {
            run_len += 1;
        }
        for offset in 0..run_len {
            let current = &lines[i + offset];
            let commit_cell = if offset == 0 {
                format!(
                    "<td class=\"blame-commit\" rowspan=\"{run_len}\">\
                       <a href=\"/r/{owner}/{name}/commit/{oid}\"><code class=\"oid\">{short}</code></a>\
                       <span class=\"blame-author\">{author}</span>\
                       <span class=\"blame-time\" title=\"{abs}\">{rel}</span>\
                     </td>",
                    run_len = run_len,
                    owner = esc(&repo.owner_sub),
                    name = esc(&repo.name),
                    oid = esc(&current.oid),
                    short = esc(&short_oid(&current.oid)),
                    author = esc(&current.author_name),
                    abs = esc(&fmt_ts(current.time)),
                    rel = esc(&fmt_rel(now, current.time)),
                )
            } else {
                String::new()
            };
            rows.push_str(&format!(
                "<tr class=\"blame-row\">\
                   {commit_cell}\
                   <td class=\"blame-lineno\">{lineno}</td>\
                   <td class=\"blame-code\"><code>{code}</code></td>\
                 </tr>",
                commit_cell = commit_cell,
                lineno = current.lineno,
                code = esc(&current.content),
            ));
        }
        i += run_len;
    }
    format!("<table class=\"blame-table\"><tbody>{rows}</tbody></table>")
}

/// Path breadcrumb. `is_blob` makes the final segment a non-link leaf.
fn render_breadcrumb(repo: &Repo, subpath: &str, is_blob: bool) -> String {
    let mut html = format!(
        "<nav class=\"breadcrumb\"><a href=\"/r/{owner}/{name}\">{name_e}</a>",
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        name_e = esc(&repo.name),
    );
    if subpath.is_empty() {
        html.push_str("</nav>");
        return html;
    }
    let segs: Vec<&str> = subpath.split('/').collect();
    let mut acc = String::new();
    for (i, seg) in segs.iter().enumerate() {
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(seg);
        let last = i + 1 == segs.len();
        html.push_str("<span class=\"breadcrumb__sep\">/</span>");
        if last && is_blob {
            html.push_str(&format!("<span>{}</span>", esc(seg)));
        } else {
            html.push_str(&format!(
                "<a href=\"/r/{owner}/{name}/tree/{acc}\">{seg}</a>",
                owner = esc(&repo.owner_sub),
                name = esc(&repo.name),
                acc = esc(&acc),
                seg = esc(seg),
            ));
        }
    }
    html.push_str("</nav>");
    html
}

// ===========================================================================
// Small helpers
// ===========================================================================

/// Default an empty branch to `main` and trim.
fn normalize_branch(b: &str) -> String {
    let t = b.trim();
    if t.is_empty() {
        "main".to_string()
    } else {
        t.to_string()
    }
}

/// Validate a git branch name (conservative subset; enough for a default branch).
pub(crate) fn validate_branch_name(b: &str) -> Result<(), &'static str> {
    if b.is_empty() || b.len() > 64 {
        return Err("Branch name must be 1–64 characters.");
    }
    if b.starts_with('-') || b.starts_with('/') || b.ends_with('/') || b.contains("..") {
        return Err("Invalid branch name.");
    }
    if !b
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
    {
        return Err("Branch name may only contain letters, digits, '-', '_', '.', '/'.");
    }
    Ok(())
}

/// True when `path`'s final component has a markdown extension (`.md` / `.markdown`).
fn is_markdown_path(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    name.ends_with(".md") || name.ends_with(".markdown")
}

/// True when `name` is a README file (`README`, `README.md`, `README.markdown`, …), case-insensitive.
fn is_readme(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "readme" || lower.starts_with("readme.")
}

/// Render a text blob as a line-numbered, monospace table. Each line's content is HTML-escaped;
/// the number gutter is generated, so it never contains producer input. A single trailing newline
/// is dropped so the last line is not a spurious empty row.
fn render_text_blob(text: &str) -> String {
    let body = text.strip_suffix('\n').unwrap_or(text);
    let mut rows = String::new();
    for (i, raw_line) in body.split('\n').enumerate() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let n = i + 1;
        rows.push_str(&format!(
            "<tr id=\"L{n}\" class=\"blob-line\" data-line=\"{n}\">\
               <td class=\"blob-line__num\"><a href=\"#L{n}\">{n}</a></td>\
               <td class=\"blob-line__code\">{code}</td>\
             </tr>",
            n = n,
            code = esc(line),
        ));
    }
    format!("<table class=\"blob-code\"><tbody>{rows}</tbody></table>")
}

/// Human-readable byte size (B/KiB/MiB).
fn human_size(bytes: i64) -> String {
    const KIB: i64 = 1024;
    const MIB: i64 = 1024 * 1024;
    if bytes < KIB {
        format!("{bytes} B")
    } else if bytes < MIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subpath_rejects_traversal() {
        assert!(clean_subpath("a/../b").is_err());
        assert_eq!(clean_subpath("/src/main.rs/").unwrap(), "src/main.rs");
        assert_eq!(clean_subpath("").unwrap(), "");
        assert!(clean_blame_subpath("/src/main.rs").is_err());
        assert_eq!(clean_blame_subpath("src/main.rs").unwrap(), "src/main.rs");
        assert_eq!(normalize_search_ref(""), "HEAD");
        assert_eq!(normalize_search_ref(" feature/x "), "feature/x");
    }

    #[test]
    fn branch_validation() {
        assert!(validate_branch_name("main").is_ok());
        assert!(validate_branch_name("feature/x-1").is_ok());
        assert!(validate_branch_name("-bad").is_err());
        assert!(validate_branch_name("a..b").is_err());
        assert!(validate_branch_name("with space").is_err());
    }

    #[test]
    fn size_formatting() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(2048), "2.0 KiB");
    }

    #[test]
    fn markdown_path_detection() {
        assert!(is_markdown_path("README.md"));
        assert!(is_markdown_path("docs/GUIDE.Markdown"));
        assert!(!is_markdown_path("src/main.rs"));
        assert!(!is_markdown_path("Makefile"));
    }

    #[test]
    fn readme_detection() {
        assert!(is_readme("README.md"));
        assert!(is_readme("readme"));
        assert!(is_readme("Readme.markdown"));
        assert!(!is_readme("READMEISH.txt"));
        assert!(!is_readme("notes.md"));
    }

    #[test]
    fn text_blob_is_line_numbered_and_escaped() {
        let html = render_text_blob("let x = 1;\n<b>two</b>\n");
        // Two lines, numbered 1 and 2 (the trailing newline does not add a third row).
        assert!(html.contains("id=\"L1\""));
        assert!(html.contains("data-line=\"2\""));
        assert!(html.contains("href=\"#L2\">2</a>"));
        assert!(!html.contains("id=\"L3\""));
        // HTML metacharacters in the content are escaped, never live markup.
        assert!(!html.contains("<b>two</b>"));
        assert!(html.contains("&lt;b&gt;two&lt;/b&gt;"));
    }

    #[test]
    fn code_search_highlight_escapes_before_marking() {
        let html = highlight_code_search_hit("<script>Needle</script>", "<script>", false);
        assert!(!html.contains("<script>"));
        assert!(html.contains(
            "<mark class=\"code-search-hit\">&lt;script&gt;</mark>Needle&lt;/script&gt;"
        ));

        let insensitive = highlight_code_search_hit("Needle needle", "needle", true);
        assert!(insensitive.contains("<mark class=\"code-search-hit\">Needle</mark>"));
        assert!(insensitive.contains("<mark class=\"code-search-hit\">needle</mark>"));
    }

    #[test]
    fn blame_table_groups_commits_and_escapes_code() {
        let repo = Repo {
            id: "rp_test".to_string(),
            owner_sub: "alice".to_string(),
            name: "demo".to_string(),
            description: String::new(),
            is_private: false,
            default_branch: "main".to_string(),
            require_approval: false,
            required_approvals: 0,
            require_code_owner_reviews: false,
            protect_default_branch: false,
            forked_from_id: String::new(),
            created_at: 0,
        };
        let lines = vec![
            BlameLine {
                oid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                author_name: "Ada".to_string(),
                time: 0,
                lineno: 1,
                content: "let x = 1;".to_string(),
            },
            BlameLine {
                oid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                author_name: "Ada".to_string(),
                time: 0,
                lineno: 2,
                content: "<script>".to_string(),
            },
            BlameLine {
                oid: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                author_name: "Bob".to_string(),
                time: 0,
                lineno: 3,
                content: "done".to_string(),
            },
        ];
        let html = render_blame_table(&repo, &lines);
        assert!(html.contains("class=\"blame-table\""));
        assert!(html.contains("rowspan=\"2\""));
        assert!(html.contains("/r/alice/demo/commit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
