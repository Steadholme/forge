//! Pull requests: branch compare (commits ahead + unified diff), the PR entity (list/detail/
//! create), and a gated server-side merge.
//!
//! Mounted behind the same Sluice `auth=sso` route as the rest of the web UI: the gateway injects
//! `X-Auth-Subject` / `X-Auth-Email`, which we trust (Loom is internal-only). A PR belongs to one
//! repository and asks to merge its `head` branch into its `base` branch. Compare + diff are read
//! views of the on-disk bare repo via git plumbing (see [`crate::gitops`]); the merge writes to
//! the bare repo (fast-forward or a two-parent merge commit) and is gated to the repo owner
//! (maintainer) or the PR author, CSRF-checked, and audit-logged. Every producer-supplied string
//! (title, branch names, commit subjects, diff bytes) is HTML-escaped on render; PR bodies go
//! through the sanitising [`crate::markdown`] pipeline.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Form;
use serde::Deserialize;

use crate::auth::{self, Identity};
use crate::config::{COMMIT_LIMIT, MAX_BLOB_RENDER_BYTES};
use crate::error::AppError;
use crate::gitops::CommitInfo;
use crate::handlers::repos::{load_visible_repo, render_repo_header, validate_branch_name};
use crate::handlers::{esc, fmt_ts, html_with_csrf, page, redirect, short_oid};
use crate::model::{Pull, Repo};
use crate::{now_secs, random_alnum, AppState};

const PULL_ID_LEN: usize = 16;

// ===========================================================================
// Shared helpers
// ===========================================================================

/// Render the repo header on the "Pull requests" tab (fetches the open issue/PR badge counts).
async fn pr_header(state: &AppState, repo: &Repo, active: &str) -> String {
    let open_issues = state.store.open_issue_count(&repo.id).await.unwrap_or(0);
    let open_pulls = state.store.open_pull_count(&repo.id).await.unwrap_or(0);
    render_repo_header(repo, &state.config.public_base_url, open_issues, open_pulls, active)
}

/// True when `who` may merge/close a PR on `repo`: the repo owner (maintainer) or the PR author.
fn can_gate(repo: &Repo, pull: &Pull, who: &Identity) -> bool {
    repo.owner_sub == who.subject || pull.author_sub == who.subject
}

// ===========================================================================
// GET /r/{owner}/{name}/compare — pick base+head, show commits ahead + diff
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct CompareQuery {
    #[serde(default)]
    pub base: Option<String>,
    #[serde(default)]
    pub head: Option<String>,
}

pub async fn compare(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
    Query(q): Query<CompareQuery>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let csrf = auth::new_csrf_token();

    let branches = state.git.branches(&repo.owner_sub, &repo.name).await;
    let base = pick_base(&repo, &branches, q.base.as_deref());
    let head = q.head.unwrap_or_default();

    let body = render_compare(&state, &repo, &branches, &base, &head, &csrf, None).await;
    Ok(html_with_csrf(
        StatusCode::OK,
        page(&format!("{owner}/{name} · Compare"), Some(&who.email), &body),
        &csrf,
    ))
}

/// Choose the base branch: the requested one if it exists, else the repo default, else the first
/// branch (or empty when the repo has none).
fn pick_base(repo: &Repo, branches: &[String], requested: Option<&str>) -> String {
    if let Some(r) = requested {
        if branches.iter().any(|b| b == r) {
            return r.to_string();
        }
    }
    if branches.iter().any(|b| *b == repo.default_branch) {
        return repo.default_branch.clone();
    }
    branches.first().cloned().unwrap_or_default()
}

// ===========================================================================
// GET /r/{owner}/{name}/pulls — list
// ===========================================================================

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let pulls = state.store.list_pulls(&repo.id).await?;
    let header = pr_header(&state, &repo, "pulls").await;
    let body = render_list(&repo, &header, &pulls);
    Ok(crate::handlers::html_ok(page(
        &format!("{owner}/{name} · Pull requests"),
        Some(&who.email),
        &body,
    )))
}

// ===========================================================================
// POST /r/{owner}/{name}/pulls — create (from the compare page)
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct CreateForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub base: String,
    #[serde(default)]
    pub head: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub body: String,
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
    Form(form): Form<CreateForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and submit again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;

    let base = form.base.trim().to_string();
    let head = form.head.trim().to_string();
    let branches = state.git.branches(&repo.owner_sub, &repo.name).await;

    // Both branches must be well-formed and actually exist on this repo.
    if validate_branch_name(&base).is_err()
        || validate_branch_name(&head).is_err()
        || !branches.iter().any(|b| *b == base)
        || !branches.iter().any(|b| *b == head)
    {
        return Err(AppError::BadRequest(
            "Choose two existing branches to compare.".to_string(),
        ));
    }
    if base == head {
        return Err(AppError::BadRequest(
            "The base and head branches must be different.".to_string(),
        ));
    }

    let title = form.title.trim();
    if title.is_empty() {
        // Re-render the compare page with the error and the user's branch selection intact.
        let csrf = auth::new_csrf_token();
        let body = render_compare(
            &state,
            &repo,
            &branches,
            &base,
            &head,
            &csrf,
            Some("Pull request title cannot be empty."),
        )
        .await;
        return Ok(html_with_csrf(
            StatusCode::BAD_REQUEST,
            page(&format!("{owner}/{name} · Compare"), Some(&who.email), &body),
            &csrf,
        ));
    }

    let pull = state
        .store
        .create_pull(
            &format!("pl_{}", random_alnum(PULL_ID_LEN)),
            &repo.id,
            &title.chars().take(300).collect::<String>(),
            &form.body.trim().chars().take(20_000).collect::<String>(),
            &base,
            &head,
            &who.subject,
            now_secs(),
        )
        .await?;

    // Audit: no dedicated AuditSink in this crate — tracing is the audit surface (as with repo
    // create / issue open / PAT mint).
    tracing::info!(
        repo = repo.id,
        number = pull.number,
        base = base,
        head = head,
        author = who.subject,
        "pull request opened"
    );
    Ok(redirect(&format!("/r/{owner}/{name}/pulls/{}", pull.number)))
}

// ===========================================================================
// GET /r/{owner}/{name}/pulls/{number} — detail (body + commits + diff + actions)
// ===========================================================================

pub async fn detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, number)): Path<(String, String, i64)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let pull = state
        .store
        .get_pull(&repo.id, number)
        .await?
        .ok_or_else(|| AppError::NotFound("No such pull request.".to_string()))?;
    let csrf = auth::new_csrf_token();
    let header = pr_header(&state, &repo, "pulls").await;
    let body = render_detail(&state, &repo, &pull, &header, &who, &csrf, None).await;
    Ok(html_with_csrf(
        StatusCode::OK,
        page(
            &format!("{owner}/{name} · PR #{number}"),
            Some(&who.email),
            &body,
        ),
        &csrf,
    ))
}

// ===========================================================================
// POST /r/{owner}/{name}/pulls/{number}/merge — gated server-side merge
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct MergeForm {
    #[serde(default)]
    pub csrf_token: String,
}

pub async fn merge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, number)): Path<(String, String, i64)>,
    Form(form): Form<MergeForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let pull = state
        .store
        .get_pull(&repo.id, number)
        .await?
        .ok_or_else(|| AppError::NotFound("No such pull request.".to_string()))?;

    // Author/maintainer gate.
    if !can_gate(&repo, &pull, &who) {
        return Err(AppError::Forbidden(
            "Only the repository owner or the pull-request author can merge this.".to_string(),
        ));
    }
    if !pull.is_open() {
        return Err(AppError::BadRequest(
            "This pull request is no longer open.".to_string(),
        ));
    }

    let message = format!(
        "Merge pull request #{number} from {head}\n\n{title}",
        head = pull.head,
        title = pull.title,
    );
    // Perform the on-disk merge FIRST; only mark the PR merged once git has advanced the ref.
    match state
        .git
        .merge(
            &repo.owner_sub,
            &repo.name,
            &pull.base,
            &pull.head,
            &message,
            &who.subject,
            &who.email,
        )
        .await
    {
        Ok(outcome) => {
            let _ = state.store.merge_pull(&pull.id, now_secs()).await?;
            tracing::info!(
                repo = repo.id,
                number = pull.number,
                base = pull.base,
                head = pull.head,
                actor = who.subject,
                outcome = ?outcome,
                "pull request merged"
            );
            Ok(redirect(&format!("/r/{owner}/{name}/pulls/{number}")))
        }
        Err(reason) => {
            // Expected user-facing failure (conflicts / racing push): re-render with the reason.
            let csrf = auth::new_csrf_token();
            let header = pr_header(&state, &repo, "pulls").await;
            let body = render_detail(
                &state,
                &repo,
                &pull,
                &header,
                &who,
                &csrf,
                Some(&format!("Could not merge automatically: {reason}")),
            )
            .await;
            Ok(html_with_csrf(
                StatusCode::CONFLICT,
                page(
                    &format!("{owner}/{name} · PR #{number}"),
                    Some(&who.email),
                    &body,
                ),
                &csrf,
            ))
        }
    }
}

// ===========================================================================
// POST /r/{owner}/{name}/pulls/{number}/toggle — open <-> closed (never a merged PR)
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct ToggleForm {
    #[serde(default)]
    pub csrf_token: String,
}

pub async fn toggle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, number)): Path<(String, String, i64)>,
    Form(form): Form<ToggleForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let pull = state
        .store
        .get_pull(&repo.id, number)
        .await?
        .ok_or_else(|| AppError::NotFound("No such pull request.".to_string()))?;

    if !can_gate(&repo, &pull, &who) {
        return Err(AppError::Forbidden(
            "Only the repository owner or the pull-request author can change this.".to_string(),
        ));
    }
    // A merged PR is terminal; only open<->closed toggles.
    if pull.is_merged() {
        return Err(AppError::BadRequest(
            "A merged pull request cannot be reopened or closed.".to_string(),
        ));
    }
    let next = if pull.is_open() { "closed" } else { "open" };
    state.store.set_pull_state(&pull.id, next).await?;
    tracing::info!(repo = repo.id, number, state = next, "pull request state changed");
    Ok(redirect(&format!("/r/{owner}/{name}/pulls/{number}")))
}

// ===========================================================================
// Rendering
// ===========================================================================

/// State badge (class, label) for a PR.
fn state_badge(pull: &Pull) -> (&'static str, &'static str) {
    match pull.state.as_str() {
        "merged" => ("state-badge--merged", "Merged"),
        "closed" => ("state-badge--closed", "Closed"),
        _ => ("state-badge--open", "Open"),
    }
}

/// The compare page: a base/head picker + (when a valid head is chosen) the commits ahead, the
/// unified diff, and a "Create pull request" form.
async fn render_compare(
    state: &AppState,
    repo: &Repo,
    branches: &[String],
    base: &str,
    head: &str,
    csrf: &str,
    error: Option<&str>,
) -> String {
    let header = pr_header(state, repo, "pulls").await;
    let error_block = error_block(error);

    if branches.is_empty() {
        return format!(
            r##"{header}
<section class="card"><div class="card__body">
  <p class="muted">This repository has no branches yet. Push a commit before opening a pull request.</p>
</div></section>"##
        );
    }

    let base_select = render_branch_select("base", branches, base);
    let head_select = render_branch_select("head", branches, head);

    // The comparison body appears only when a valid, distinct head branch is chosen.
    let head_valid = branches.iter().any(|b| b == head);
    let comparison = if !head_valid {
        "<section class=\"card\"><div class=\"card__body\">\
           <p class=\"muted\">Choose a head branch to compare.</p>\
         </div></section>"
            .to_string()
    } else if head == base {
        "<section class=\"card\"><div class=\"card__body\">\
           <p class=\"muted\">The base and head branches are the same — nothing to compare.</p>\
         </div></section>"
            .to_string()
    } else {
        let commits = state
            .git
            .commits_between(&repo.owner_sub, &repo.name, base, head, COMMIT_LIMIT)
            .await;
        let diff = state
            .git
            .diff(&repo.owner_sub, &repo.name, base, head)
            .await
            .unwrap_or_default();

        let commits_card = render_commits_card(&commits);
        let diff_card = render_diff_card(&diff);

        // Prefill the title from the single/top commit subject, else "head into base".
        let default_title = commits
            .first()
            .map(|c| c.subject.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("Merge {head} into {base}"));

        let create_form = format!(
            r##"<section class="card">
  <div class="card__head"><h2>Open a pull request</h2></div>
  <div class="card__body">
    {error_block}
    <form method="post" action="/r/{owner}/{name}/pulls">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <input type="hidden" name="base" value="{base_v}">
      <input type="hidden" name="head" value="{head_v}">
      <div class="field">
        <label for="pr-title">Title</label>
        <input type="text" id="pr-title" name="title" maxlength="300" value="{title}" required>
      </div>
      <div class="field">
        <label for="pr-body">Description</label>
        <textarea id="pr-body" name="body" class="issue-input" placeholder="Optional details…"></textarea>
      </div>
      <div class="actions">
        <button class="btn btn-primary" type="submit">Create pull request</button>
      </div>
    </form>
  </div>
</section>"##,
            owner = esc(&repo.owner_sub),
            name = esc(&repo.name),
            csrf = esc(csrf),
            base_v = esc(base),
            head_v = esc(head),
            title = esc(&default_title),
        );
        format!("{commits_card}{diff_card}{create_form}")
    };

    format!(
        r##"{header}
<section class="card">
  <div class="card__head"><h2>Compare branches</h2></div>
  <div class="card__body">
    <form method="get" action="/r/{owner}/{name}/compare" class="compare-picker">
      <span class="compare-picker__label">base</span>
      {base_select}
      <span class="compare-picker__arrow">&larr;</span>
      <span class="compare-picker__label">head</span>
      {head_select}
      <button class="btn btn-secondary btn-sm" type="submit">Compare</button>
    </form>
  </div>
</section>
{comparison}"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
    )
}

/// A `<select>` of branch names with `selected` set on `current`.
fn render_branch_select(field: &str, branches: &[String], current: &str) -> String {
    let opts = branches
        .iter()
        .map(|b| {
            let sel = if b == current { " selected" } else { "" };
            format!("<option value=\"{v}\"{sel}>{v}</option>", v = esc(b), sel = sel)
        })
        .collect::<String>();
    format!("<select name=\"{field}\" class=\"compare-picker__select\">{opts}</select>")
}

/// The PR list card.
fn render_list(repo: &Repo, header: &str, pulls: &[Pull]) -> String {
    let list = if pulls.is_empty() {
        "<li class=\"pr-item pr-item--empty\">No pull requests yet.</li>".to_string()
    } else {
        pulls.iter().map(|p| render_pr_row(repo, p)).collect::<String>()
    };
    format!(
        r##"{header}
<div class="layout layout--repo">
  <section class="card">
    <div class="card__head">
      <h2>Pull requests</h2>
      <a class="btn btn-primary btn-sm" href="/r/{owner}/{name}/compare">New pull request</a>
    </div>
    <div class="card__body"><ul class="pr-list">{list}</ul></div>
  </section>
</div>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
    )
}

fn render_pr_row(repo: &Repo, pull: &Pull) -> String {
    let (cls, label) = state_badge(pull);
    format!(
        r##"<li class="pr-item">
  <div class="pr-item__head">
    <span class="state-badge {cls}">{label}</span>
    <a class="pr-item__title" href="/r/{owner}/{name}/pulls/{number}">#{number} {title}</a>
  </div>
  <span class="pr-item__meta">{head} &rarr; {base} · opened {when} by {author}</span>
</li>"##,
        cls = cls,
        label = label,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        number = pull.number,
        title = esc(&pull.title),
        head = esc(&pull.head),
        base = esc(&pull.base),
        when = esc(&fmt_ts(pull.created_at)),
        author = esc(&pull.author_sub),
    )
}

/// The PR detail page.
async fn render_detail(
    state: &AppState,
    repo: &Repo,
    pull: &Pull,
    header: &str,
    who: &Identity,
    csrf: &str,
    error: Option<&str>,
) -> String {
    let (cls, label) = state_badge(pull);
    let error_block = error_block(error);

    let body_html = if pull.body.trim().is_empty() {
        "<p class=\"muted\">No description provided.</p>".to_string()
    } else {
        format!(
            "<div class=\"markdown-body\">{}</div>",
            crate::markdown::render(&pull.body)
        )
    };

    // Commits + diff for the (still current) base..head range.
    let commits = state
        .git
        .commits_between(&repo.owner_sub, &repo.name, &pull.base, &pull.head, COMMIT_LIMIT)
        .await;
    let diff = state
        .git
        .diff(&repo.owner_sub, &repo.name, &pull.base, &pull.head)
        .await
        .unwrap_or_default();
    let commits_card = render_commits_card(&commits);
    let diff_card = render_diff_card(&diff);

    // Action strip: merge + open/close, shown only to a gated user on an OPEN PR.
    let actions = if pull.is_open() && can_gate(repo, pull, who) {
        format!(
            r##"<div class="pr-actions">
  <form class="inline-form" method="post" action="/r/{owner}/{name}/pulls/{number}/merge">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <button class="btn btn-primary" type="submit">Merge pull request</button>
  </form>
  <form class="inline-form" method="post" action="/r/{owner}/{name}/pulls/{number}/toggle">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <button class="btn btn-ghost" type="submit">Close</button>
  </form>
</div>"##,
            owner = esc(&repo.owner_sub),
            name = esc(&repo.name),
            number = pull.number,
            csrf = esc(csrf),
        )
    } else if pull.is_merged() {
        format!(
            "<p class=\"pr-status pr-status--merged\">Merged {} into <code>{}</code>.</p>",
            esc(&fmt_ts(pull.merged_at)),
            esc(&pull.base),
        )
    } else if !pull.is_open() && can_gate(repo, pull, who) {
        // Closed (not merged): allow reopen.
        format!(
            r##"<p class="pr-status">This pull request is closed.</p>
<form class="inline-form" method="post" action="/r/{owner}/{name}/pulls/{number}/toggle">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <button class="btn btn-secondary btn-sm" type="submit">Reopen</button>
</form>"##,
            owner = esc(&repo.owner_sub),
            name = esc(&repo.name),
            number = pull.number,
            csrf = esc(csrf),
        )
    } else {
        format!("<p class=\"pr-status\">This pull request is {}.</p>", esc(label))
    };

    format!(
        r##"{header}
<div class="console__head">
  <div class="repo-title">
    <span class="state-badge {cls}">{label}</span>
    <h1 class="pr-title">#{number} {title}</h1>
  </div>
  <p class="sub"><code>{head}</code> &rarr; <code>{base}</code> · opened {when} by {author}</p>
</div>
<section class="card">
  <div class="card__head"><h2>Description</h2></div>
  <div class="card__body">{body_html}</div>
</section>
{commits_card}
{diff_card}
<section class="card">
  <div class="card__body">
    {error_block}
    {actions}
  </div>
</section>"##,
        cls = cls,
        label = label,
        number = pull.number,
        title = esc(&pull.title),
        head = esc(&pull.head),
        base = esc(&pull.base),
        when = esc(&fmt_ts(pull.created_at)),
        author = esc(&pull.author_sub),
        body_html = body_html,
    )
}

/// Card listing the commits a PR would add (newest first).
fn render_commits_card(commits: &[CommitInfo]) -> String {
    let rows = if commits.is_empty() {
        "<li class=\"commit-item commit-item--empty\">No commits — the branches are level.</li>"
            .to_string()
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
            .collect::<String>()
    };
    format!(
        r##"<section class="card">
  <div class="card__head"><h2>Commits <span class="tab__count">{n}</span></h2></div>
  <div class="card__body"><ul class="commit-list">{rows}</ul></div>
</section>"##,
        n = commits.len(),
    )
}

/// Card rendering the unified diff as a colored, escaped table. Large diffs show a size notice.
/// Shared with the commit page (`pub(crate)`) — the ONE diff renderer in the crate.
pub(crate) fn render_diff_card(diff: &str) -> String {
    let inner = if diff.trim().is_empty() {
        "<div class=\"card__body\"><p class=\"muted\">No file changes.</p></div>".to_string()
    } else if diff.len() > MAX_BLOB_RENDER_BYTES {
        "<div class=\"card__body\"><p class=\"muted\">The diff is too large to display. \
         Fetch the branches locally to review it.</p></div>"
            .to_string()
    } else {
        format!("<div class=\"card__body card__body--code\">{}</div>", render_diff(diff))
    };
    format!(
        r##"<section class="card">
  <div class="card__head"><h2>Diff</h2></div>
  {inner}
</section>"##
    )
}

/// Render a unified diff into a line-classified, HTML-escaped table (row background fills width).
fn render_diff(diff: &str) -> String {
    let text = diff.strip_suffix('\n').unwrap_or(diff);
    let mut rows = String::new();
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let (row_cls, gutter) = classify_diff_line(line);
        rows.push_str(&format!(
            "<tr class=\"diff-row {row_cls}\">\
               <td class=\"diff-gutter\">{gutter}</td>\
               <td class=\"diff-code\">{code}</td>\
             </tr>",
            row_cls = row_cls,
            gutter = gutter,
            code = esc(line),
        ));
    }
    format!("<table class=\"diff\"><tbody>{rows}</tbody></table>")
}

/// Classify one diff line → (row CSS class, single-char gutter). File-header lines (`diff`,
/// `index`, `+++`, `---`, `new file`, `Binary files`, …) and hunk headers are styled as meta.
fn classify_diff_line(line: &str) -> (&'static str, &'static str) {
    if line.starts_with("@@") {
        ("diff-row--hunk", " ")
    } else if line.starts_with("+++") || line.starts_with("---") {
        ("diff-row--meta", " ")
    } else if line.starts_with("diff ")
        || line.starts_with("index ")
        || line.starts_with("new file")
        || line.starts_with("deleted file")
        || line.starts_with("old mode")
        || line.starts_with("new mode")
        || line.starts_with("rename ")
        || line.starts_with("copy ")
        || line.starts_with("similarity ")
        || line.starts_with("dissimilarity ")
        || line.starts_with("Binary files")
        || line.starts_with("\\ No newline")
    {
        ("diff-row--meta", " ")
    } else if line.starts_with('+') {
        ("diff-row--add", "+")
    } else if line.starts_with('-') {
        ("diff-row--del", "-")
    } else {
        ("diff-row--ctx", " ")
    }
}

/// A danger alert block for an inline error message (or empty).
fn error_block(error: Option<&str>) -> String {
    match error {
        Some(msg) => format!(
            "<div class=\"alert alert-danger\" role=\"alert\">{}</div>",
            esc(msg)
        ),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_lines_are_classified() {
        assert_eq!(classify_diff_line("@@ -1,2 +1,3 @@").0, "diff-row--hunk");
        assert_eq!(classify_diff_line("+added").0, "diff-row--add");
        assert_eq!(classify_diff_line("-removed").0, "diff-row--del");
        assert_eq!(classify_diff_line(" context").0, "diff-row--ctx");
        assert_eq!(classify_diff_line("+++ b/file").0, "diff-row--meta");
        assert_eq!(classify_diff_line("diff --git a/f b/f").0, "diff-row--meta");
    }

    #[test]
    fn diff_render_escapes_content() {
        let html = render_diff("+<script>alert(1)</script>\n context\n");
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("diff-row--add"));
    }

    #[test]
    fn base_pick_prefers_default_then_first() {
        let repo = Repo {
            id: "r".into(),
            owner_sub: "u".into(),
            name: "n".into(),
            description: String::new(),
            is_private: false,
            default_branch: "main".into(),
            created_at: 0,
        };
        let branches = vec!["dev".to_string(), "main".to_string()];
        assert_eq!(pick_base(&repo, &branches, Some("dev")), "dev");
        assert_eq!(pick_base(&repo, &branches, Some("nope")), "main");
        assert_eq!(pick_base(&repo, &branches, None), "main");
        // No default present -> first branch.
        assert_eq!(pick_base(&repo, &["dev".to_string()], None), "dev");
    }
}
