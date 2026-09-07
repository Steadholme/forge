//! Commit history + the single-commit page.
//!
//! - `GET /r/{owner}/{name}/commits` — the history of a branch (`?ref=`, default = the repo's
//!   default branch), KEYSET-paginated by commit order: the "Older" link carries
//!   `after=<last-shown OID>` and the next page is `git log <after>` minus the anchor itself, so
//!   a push landing between clicks never shifts the window the way an offset would.
//! - `GET /r/{owner}/{name}/commit/{sha}` — one commit: metadata (author, date, parents), the
//!   full message, the `--shortstat` summary, and the diff rendered with the crate's ONE diff
//!   renderer ([`crate::handlers::pulls::render_diff_card`]).
//!
//! Commit messages and author strings are REMOTE input (they arrive over `git push`), so every
//! rendered field is HTML-escaped. The `sha`/`after` parameters are validated to pure hex before
//! they are handed to git, and branch names are checked against the repo's actual branch list —
//! no user string ever reaches git in option position.

use std::collections::BTreeMap;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use crate::auth;
use crate::error::AppError;
use crate::gitops::{CommitDetail, CommitInfo};
use crate::handlers::pulls::{DiffControls, DiffQuery};
use crate::handlers::repos::{header_with_counts, load_visible_repo};
use crate::handlers::{esc, fmt_day, fmt_rel, fmt_ts, html_ok, initials, page, short_oid};
use crate::model::{CommitStatus, Repo};
use crate::{now_secs, random_alnum, AppState};

/// Commits shown per history page (keyset pagination).
const COMMITS_PER_PAGE: usize = 50;
const STATUS_ID_LEN: usize = 16;
const MAX_CONTEXT_CHARS: usize = 200;
const MAX_STATUS_DESCRIPTION_CHARS: usize = 500;
const MAX_STATUS_TARGET_URL_CHARS: usize = 2000;

/// True for a plausible (abbreviated or full) hex object id — the only shape we hand to git.
fn is_hex_oid(s: &str) -> bool {
    (4..=64).contains(&s.len()) && s.chars().all(|c| c.is_ascii_hexdigit())
}

// ===========================================================================
// GET /r/{owner}/{name}/commits — branch history, keyset-paginated
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    /// Branch to walk (`?ref=`); defaults to the repo's default branch.
    #[serde(default, rename = "ref")]
    pub ref_name: Option<String>,
    /// Keyset anchor: the OID of the last commit on the previous page.
    #[serde(default)]
    pub after: Option<String>,
}

pub async fn history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
    Query(q): Query<HistoryQuery>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let header = header_with_counts(&state, &repo, "commits").await;

    let branches = state.git.branches(&repo.owner_sub, &repo.name).await;
    if branches.is_empty() {
        let body = format!(
            r##"{header}
<section class="card"><div class="card__body">
  <p class="muted">This repository has no commits yet.</p>
</div></section>"##
        );
        return Ok(html_ok(page(
            &format!("{owner}/{name} · Commits"),
            Some(&who.email),
            who.theme,
            &body,
        )));
    }

    // Resolve the branch to walk: an explicit ?ref= must exist (404 otherwise, like a bad path);
    // the default falls back to the first branch when the configured default has no ref yet.
    let ref_name = match q
        .ref_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(r) => {
            if !branches.iter().any(|b| b == r) {
                return Err(AppError::NotFound("No such branch.".to_string()));
            }
            r.to_string()
        }
        None => {
            if branches.contains(&repo.default_branch) {
                repo.default_branch.clone()
            } else {
                branches[0].clone()
            }
        }
    };
    let head_oid = state
        .git
        .branch_oid(&repo.owner_sub, &repo.name, &ref_name)
        .await
        .ok_or_else(|| AppError::NotFound("No such branch.".to_string()))?;

    // Keyset page: from the anchor (exclusive) or the branch head (inclusive).
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
    let mut commits = match &after {
        // `git log <after>` lists `after` first; drop it and keep one extra as the has-next probe.
        Some(anchor) => {
            let mut all = state
                .git
                .log(&repo.owner_sub, &repo.name, anchor, COMMITS_PER_PAGE + 2)
                .await;
            if all.first().map(|c| c.oid.as_str()) == Some(anchor.as_str()) {
                all.remove(0);
            }
            all
        }
        None => {
            state
                .git
                .log(&repo.owner_sub, &repo.name, &head_oid, COMMITS_PER_PAGE + 1)
                .await
        }
    };
    let has_next = commits.len() > COMMITS_PER_PAGE;
    commits.truncate(COMMITS_PER_PAGE);
    let status_by_commit = commit_status_map(&state, &repo, &commits).await?;

    let body = format!(
        "{header}{list}",
        list = render_history(
            &repo,
            &branches,
            &ref_name,
            &commits,
            &status_by_commit,
            after.is_some(),
            has_next
        ),
    );
    Ok(html_ok(page(
        &format!("{owner}/{name} · Commits"),
        Some(&who.email),
        who.theme,
        &body,
    )))
}

/// The history view: a branch picker, date-grouped commit rows, and the keyset pager.
fn render_history(
    repo: &Repo,
    branches: &[String],
    ref_name: &str,
    commits: &[CommitInfo],
    status_by_commit: &BTreeMap<String, String>,
    paged: bool,
    has_next: bool,
) -> String {
    let now = now_secs();
    let opts = branches
        .iter()
        .map(|b| {
            let sel = if b == ref_name { " selected" } else { "" };
            format!(
                "<option value=\"{v}\"{sel}>{v}</option>",
                v = esc(b),
                sel = sel
            )
        })
        .collect::<String>();

    // Keyset pager: "Newest" rewinds to page one; "Older" anchors after the last shown commit.
    let newest = if paged {
        format!(
            "<a class=\"btn btn-ghost btn-sm\" href=\"/r/{owner}/{name}/commits?ref={r}\">&larr; Newest</a>",
            owner = esc(&repo.owner_sub),
            name = esc(&repo.name),
            r = esc(ref_name),
        )
    } else {
        String::new()
    };
    let older = match (has_next, commits.last()) {
        (true, Some(last)) => format!(
            "<a class=\"btn btn-ghost btn-sm\" href=\"/r/{owner}/{name}/commits?ref={r}&amp;after={oid}\">Older &rarr;</a>",
            owner = esc(&repo.owner_sub),
            name = esc(&repo.name),
            r = esc(ref_name),
            oid = esc(&last.oid),
        ),
        _ => String::new(),
    };
    let pager = if newest.is_empty() && older.is_empty() {
        String::new()
    } else {
        format!("<div class=\"pager\">{newest}<span class=\"spacer\"></span>{older}</div>")
    };
    let picker = format!(
        r##"<div class="commits-head">
  <h2 class="commits-head__title">Commits</h2>
  <form class="inline-form compare-picker" method="get" action="/r/{owner}/{name}/commits">
    <span class="compare-picker__label">branch</span>
    <select name="ref" class="compare-picker__select">{opts}</select>
    <button class="btn btn-secondary btn-sm" type="submit">View</button>
  </form>
</div>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        opts = opts,
    );

    if commits.is_empty() {
        return format!(
            r##"{picker}
<div class="empty commits-empty"><div class="empty__title">No commits on this branch</div></div>
{pager}"##
        );
    }

    let mut groups = String::new();
    let mut current_day = String::new();
    let mut group_open = false;
    for c in commits {
        let day = fmt_day(c.time);
        if day != current_day {
            if group_open {
                groups.push_str("</ol></section>");
            }
            current_day = day;
            group_open = true;
            groups.push_str(&format!(
                r##"<section class="commit-group">
  <h3 class="commit-group__date">{day}</h3>
  <ol class="commit-group__list">"##,
                day = esc(&current_day),
            ));
        }
        let status_dot = render_status_dot(status_by_commit.get(&c.oid).map(String::as_str));
        groups.push_str(&format!(
            r##"<li class="commit-row">
  <span class="avatar avatar--sm" aria-hidden="true">{avatar}</span>
  <div class="commit-row__main">
    <div class="commit-row__title">{status}<a class="commit-row__subject" href="/r/{owner}/{name}/commit/{oid}">{subject}</a></div>
    <div class="commit-row__meta">{author} committed <span title="{abs}">{rel}</span></div>
  </div>
  <div class="commit-row__actions">
    <div class="sha-group">
      <a class="sha-group__oid" href="/r/{owner}/{name}/commit/{oid}"><code>{short}</code></a>
      <button class="sha-group__copy" type="button" data-copy="{oid}" aria-label="Copy full SHA"><svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor"><path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 0 1 0 1.5h-1.5a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-1.5a.75.75 0 0 1 1.5 0v1.5A1.75 1.75 0 0 1 9.25 16h-7.5A1.75 1.75 0 0 1 0 14.25Z"/><path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0 1 14.25 11h-7.5A1.75 1.75 0 0 1 5 9.25Zm1.75-.25a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-7.5a.25.25 0 0 0-.25-.25Z"/></svg></button>
    </div>
    <a class="iconbtn iconbtn--sm" href="/r/{owner}/{name}/tree/{oid}" aria-label="Browse repository at this commit" title="Browse files"><svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor"><path d="M2 2.75A.75.75 0 0 1 2.75 2h4.5a.75.75 0 0 1 .53.22l1.28 1.28h4.19A1.75 1.75 0 0 1 15 5.25v6.5A1.75 1.75 0 0 1 13.25 13H2.75A1.75 1.75 0 0 1 1 11.25v-8.5A.75.75 0 0 1 1.75 2Zm.5.75v7.75c0 .138.112.25.25.25h10.5a.25.25 0 0 0 .25-.25v-6a.25.25 0 0 0-.25-.25H8.75a.75.75 0 0 1-.53-.22L6.94 3.5H2.5Z"/></svg></a>
  </div>
</li>"##,
            avatar = esc(&initials(&c.author_email)),
            status = status_dot,
            owner = esc(&repo.owner_sub),
            name = esc(&repo.name),
            oid = esc(&c.oid),
            short = esc(&short_oid(&c.oid)),
            subject = esc(&c.subject),
            author = esc(&c.author_name),
            abs = esc(&fmt_ts(c.time)),
            rel = esc(&fmt_rel(now, c.time)),
        ));
    }
    if group_open {
        groups.push_str("</ol></section>");
    }

    format!(
        r##"{picker}
<div class="commit-groups">{groups}</div>
{pager}"##,
        picker = picker,
        groups = groups,
        pager = pager,
    )
}

// ===========================================================================
// GET /r/{owner}/{name}/commit/{sha} — one commit: metadata + stat + diff
// ===========================================================================

pub async fn detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, sha)): Path<(String, String, String)>,
    Query(q): Query<DiffQuery>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let diff_options = q.options();
    if !is_hex_oid(sha.trim()) {
        return Err(AppError::BadRequest("Invalid commit id.".to_string()));
    }
    let oid = state
        .git
        .resolve_commit(&repo.owner_sub, &repo.name, sha.trim())
        .await
        .ok_or_else(|| AppError::NotFound("No such commit.".to_string()))?;
    let detail = state
        .git
        .commit_detail(&repo.owner_sub, &repo.name, &oid)
        .await
        .ok_or_else(|| AppError::NotFound("No such commit.".to_string()))?;
    let stat = state
        .git
        .commit_stat(&repo.owner_sub, &repo.name, &oid)
        .await;
    let patch = state
        .git
        .commit_patch(
            &repo.owner_sub,
            &repo.name,
            &oid,
            diff_options.ignore_whitespace(),
        )
        .await
        .unwrap_or_default();
    let aggregate = state
        .store
        .aggregate_state_for_commit(&repo.id, &oid)
        .await?;

    let header = header_with_counts(&state, &repo, "commits").await;
    let body = format!(
        "{header}{commit}",
        commit = render_commit(
            &repo,
            &detail,
            &stat,
            &patch,
            aggregate.as_deref(),
            diff_options,
        ),
    );
    Ok(html_ok(page(
        &format!("{owner}/{name} · {short}", short = short_oid(&oid)),
        Some(&who.email),
        who.theme,
        &body,
    )))
}

/// The commit card (subject + metadata rows + full message) followed by the shared diff card.
fn render_commit(
    repo: &Repo,
    detail: &CommitDetail,
    stat: &str,
    patch: &str,
    aggregate: Option<&str>,
    diff_options: crate::handlers::pulls::DiffOptions,
) -> String {
    let now = now_secs();
    let parents = if detail.parents.is_empty() {
        "<span class=\"muted\">root commit</span>".to_string()
    } else {
        detail
            .parents
            .iter()
            .map(|p| {
                format!(
                    "parent <a href=\"/r/{owner}/{name}/commit/{oid}\"><code class=\"oid\">{short}</code></a>",
                    owner = esc(&repo.owner_sub),
                    name = esc(&repo.name),
                    oid = esc(p),
                    short = esc(&short_oid(p)),
                )
            })
            .collect::<Vec<_>>()
            .join(" ")
    };
    let stat_html = if stat.is_empty() {
        "<span class=\"muted\">no combined changes</span>".to_string()
    } else {
        esc(stat.trim())
    };
    // Show the full message below the subject only when it says more than the subject line.
    let body = detail.message.trim();
    let subject = detail.subject().trim();
    let message_block = if body != subject {
        let rest = body.strip_prefix(subject).unwrap_or(body).trim();
        format!("<p class=\"commit-head__body\">{}</p>", esc(rest))
    } else {
        String::new()
    };
    let status_dot = render_status_dot(aggregate);

    format!(
        r##"<header class="commit-head">
  <h1 class="commit-head__title pr-title">{status}{subject}</h1>
  {message_block}
  <div class="commit-head__meta">
    <span class="avatar avatar--sm" aria-hidden="true">{avatar}</span>
    <b>{author}</b>
    <span class="muted">&lt;{email}&gt;</span>
    <span title="{when}">{rel}</span>
    <span class="dot">·</span>
    <code class="oid">{short}</code>
    <span class="dot">·</span>
    {parents}
  </div>
  <div class="commit-head__stats">
    <span>{stat}</span>
    <a class="btn btn-secondary btn-sm" href="/r/{owner}/{name}/tree/{oid}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m16 18 6-6-6-6M8 6l-6 6 6 6"/></svg>Browse files</a>
  </div>
</header>
{diff}"##,
        subject = esc(subject),
        status = status_dot,
        message_block = message_block,
        avatar = esc(&initials(&detail.author_email)),
        author = esc(&detail.author_name),
        email = esc(&detail.author_email),
        when = esc(&fmt_ts(detail.time)),
        rel = esc(&fmt_rel(now, detail.time)),
        short = esc(&short_oid(&detail.oid)),
        parents = parents,
        stat = stat_html,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        oid = esc(&detail.oid),
        diff = crate::handlers::pulls::render_diff_card(
            patch,
            diff_options,
            DiffControls::new(format!(
                "/r/{owner}/{name}/commit/{oid}",
                owner = repo.owner_sub,
                name = repo.name,
                oid = detail.oid,
            )),
        ),
    )
}

// ===========================================================================
// Commit Status API
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct StatusRequest {
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub context: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub target_url: String,
}

/// POST /r/{owner}/{name}/statuses/{sha} — internal CI status write path.
pub async fn upsert_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, sha)): Path<(String, String, String)>,
    Json(input): Json<StatusRequest>,
) -> Result<Response, AppError> {
    if !auth::bearer_token_ok(&headers, &state.config.status_token) {
        return Ok(unauthorized_status_api());
    }
    let repo = state
        .store
        .get_repo(&owner, &name)
        .await?
        .ok_or_else(|| AppError::NotFound("No such repository.".to_string()))?;
    if !is_hex_oid(sha.trim()) {
        return Err(AppError::BadRequest("Invalid commit id.".to_string()));
    }
    let oid = state
        .git
        .resolve_commit(&repo.owner_sub, &repo.name, sha.trim())
        .await
        .ok_or_else(|| AppError::NotFound("No such commit.".to_string()))?;
    let status = clean_status_request(input)?;
    let now = now_secs();
    let stored = state
        .store
        .upsert_commit_status(&CommitStatus {
            id: format!("cs_{}", random_alnum(STATUS_ID_LEN)),
            repo_id: repo.id.clone(),
            commit_sha: oid.clone(),
            state: status.state,
            context: status.context,
            description: status.description,
            target_url: status.target_url,
            created_at: now,
            updated_at: now,
        })
        .await?;
    let statuses = state.store.list_commit_statuses(&repo.id, &oid).await?;
    let aggregate = state
        .store
        .aggregate_state_for_commit(&repo.id, &oid)
        .await?;
    tracing::info!(
        repo = repo.id,
        commit = oid,
        context = stored.context,
        state = stored.state,
        "commit status updated"
    );
    Ok((
        StatusCode::OK,
        Json(status_response_json(&oid, aggregate.as_deref(), &statuses)),
    )
        .into_response())
}

/// GET /r/{owner}/{name}/commits/{sha}/status — aggregate + per-context status JSON.
pub async fn status_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, sha)): Path<(String, String, String)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    if !is_hex_oid(sha.trim()) {
        return Err(AppError::BadRequest("Invalid commit id.".to_string()));
    }
    let oid = state
        .git
        .resolve_commit(&repo.owner_sub, &repo.name, sha.trim())
        .await
        .ok_or_else(|| AppError::NotFound("No such commit.".to_string()))?;
    let statuses = state.store.list_commit_statuses(&repo.id, &oid).await?;
    let aggregate = state
        .store
        .aggregate_state_for_commit(&repo.id, &oid)
        .await?;
    Ok(Json(status_response_json(&oid, aggregate.as_deref(), &statuses)).into_response())
}

struct CleanStatusRequest {
    state: String,
    context: String,
    description: String,
    target_url: String,
}

fn clean_status_request(input: StatusRequest) -> Result<CleanStatusRequest, AppError> {
    let state = match input.state.trim() {
        "pending" => "pending",
        "success" => "success",
        "failure" => "failure",
        "error" => "error",
        _ => {
            return Err(AppError::BadRequest(
                "state must be one of pending, success, failure, error.".to_string(),
            ));
        }
    };
    let context = input.context.trim();
    if context.is_empty() {
        return Err(AppError::BadRequest("context cannot be empty.".to_string()));
    }
    if context.chars().count() > MAX_CONTEXT_CHARS {
        return Err(AppError::BadRequest(
            "context is too long (200 characters maximum).".to_string(),
        ));
    }
    Ok(CleanStatusRequest {
        state: state.to_string(),
        context: context.to_string(),
        description: input
            .description
            .trim()
            .chars()
            .take(MAX_STATUS_DESCRIPTION_CHARS)
            .collect(),
        target_url: input
            .target_url
            .trim()
            .chars()
            .take(MAX_STATUS_TARGET_URL_CHARS)
            .collect(),
    })
}

async fn commit_status_map(
    state: &AppState,
    repo: &Repo,
    commits: &[CommitInfo],
) -> Result<BTreeMap<String, String>, AppError> {
    let mut out = BTreeMap::new();
    for commit in commits {
        if let Some(status) = state
            .store
            .aggregate_state_for_commit(&repo.id, &commit.oid)
            .await?
        {
            out.insert(commit.oid.clone(), status);
        }
    }
    Ok(out)
}

pub(crate) fn render_status_dot(state: Option<&str>) -> String {
    let Some(state) = state else {
        return String::new();
    };
    let class = status_class(state);
    let label = status_label(state);
    format!(
        "<span class=\"commit-status commit-status--{class}\" title=\"Checks: {label}\" aria-label=\"Checks: {label}\"><span class=\"status-dot status-dot--{class}\" aria-hidden=\"true\"></span></span>",
        class = class,
        label = label,
    )
}

pub(crate) fn status_class(state: &str) -> &'static str {
    match state {
        "success" => "success",
        "pending" => "pending",
        _ => "failure",
    }
}

pub(crate) fn status_label(state: &str) -> &'static str {
    match state {
        "success" => "success",
        "pending" => "pending",
        "error" => "error",
        _ => "failure",
    }
}

pub(crate) fn safe_status_url(url: &str) -> bool {
    url.starts_with("https://") || url.starts_with("http://") || url.starts_with('/')
}

fn status_response_json(
    commit_sha: &str,
    aggregate: Option<&str>,
    statuses: &[CommitStatus],
) -> serde_json::Value {
    serde_json::json!({
        "commit_sha": commit_sha,
        "state": aggregate,
        "statuses": statuses.iter().map(status_json_value).collect::<Vec<_>>(),
    })
}

fn status_json_value(status: &CommitStatus) -> serde_json::Value {
    serde_json::json!({
        "id": &status.id,
        "state": &status.state,
        "context": &status.context,
        "description": &status.description,
        "target_url": &status.target_url,
        "created_at": status.created_at,
        "updated_at": status.updated_at,
    })
}

fn unauthorized_status_api() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        "authentication required",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_oid_validation() {
        assert!(is_hex_oid("deadbeef"));
        assert!(is_hex_oid(&"a".repeat(40)));
        assert!(!is_hex_oid("abc")); // too short
        assert!(!is_hex_oid(&"a".repeat(65))); // too long
        assert!(!is_hex_oid("--upload-pack=/x")); // never option-like
        assert!(!is_hex_oid("main")); // branch names are not hex
        assert!(!is_hex_oid("dead beef"));
    }
}
