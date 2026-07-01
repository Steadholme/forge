//! The per-repo issue tracker: list (open/closed filter + pagination), detail + comments,
//! create, comment, and open/close.
//!
//! Issues live on any repo the viewer can see. Any signed-in user may open an issue or comment on a
//! visible repo; an issue's state can be toggled only by the issue's author, the repo's owner, or an
//! estate admin (an [`crate::auth::ADMIN_GROUPS`] member). Titles, bodies and comments are rendered
//! through the sanitising [`crate::markdown`] pipeline / HTML-escaped on render. State-changing POSTs
//! carry the double-submit CSRF token, exactly like the rest of the web surface.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Form;
use serde::Deserialize;

use crate::auth::{self, Identity};
use crate::error::AppError;
use crate::handlers::repos::{load_visible_repo, render_repo_header};
use crate::handlers::{esc, fmt_ts, html_with_csrf, page, redirect};
use crate::model::{Issue, IssueComment, Repo};
use crate::{now_secs, random_alnum, AppState};

const ISSUE_ID_LEN: usize = 16;
const COMMENT_ID_LEN: usize = 16;
/// Issues shown per list page (simple offset pagination).
const ISSUES_PER_PAGE: i64 = 25;
/// Hard caps on the stored text so a single request cannot store an unbounded blob.
const MAX_TITLE_CHARS: usize = 300;
const MAX_BODY_CHARS: usize = 20_000;

// ===========================================================================
// Shared helpers
// ===========================================================================

/// Normalise the `?state=` filter to one of `""` (all), `"open"`, `"closed"`. Anything else is
/// treated as "all", so a crafted value never reaches the store as an unexpected filter.
fn normalize_filter(raw: Option<&str>) -> &'static str {
    match raw.map(str::trim) {
        Some("open") => "open",
        Some("closed") => "closed",
        _ => "",
    }
}

/// True when `who` may change an issue's state: the issue author, the repo owner, or an estate
/// admin (group-based). Admin membership is read from the HMAC-verified `X-Auth-Groups` header.
fn can_moderate(repo: &Repo, issue: &Issue, who: &Identity, headers: &HeaderMap) -> bool {
    issue.author_sub == who.subject
        || repo.owner_sub == who.subject
        || auth::is_admin(headers)
}

/// Render the repo header on the "Issues" tab (fetches the open issue/PR badge counts).
async fn issue_header(state: &AppState, repo: &Repo) -> String {
    let open_issues = state.store.open_issue_count(&repo.id).await.unwrap_or(0);
    let open_pulls = state.store.open_pull_count(&repo.id).await.unwrap_or(0);
    render_repo_header(repo, &state.config.public_base_url, open_issues, open_pulls, "issues")
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

/// Build a list URL preserving the active filter + page, HTML-escaped for use in an `href` (the
/// escape covers `owner`/`name` and the `&` between query params). `filter` is a known-safe literal
/// and `page` is numeric.
fn list_url(owner: &str, name: &str, filter: &str, page: i64) -> String {
    let mut url = format!("/r/{owner}/{name}/issues");
    let mut q: Vec<String> = Vec::new();
    if !filter.is_empty() {
        q.push(format!("state={filter}"));
    }
    if page > 1 {
        q.push(format!("page={page}"));
    }
    if !q.is_empty() {
        url.push('?');
        url.push_str(&q.join("&"));
    }
    esc(&url)
}

// ===========================================================================
// GET /r/{owner}/{name}/issues — list (open/closed filter + pagination)
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub page: Option<i64>,
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
    Query(q): Query<ListQuery>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let csrf = auth::new_csrf_token();

    let filter = normalize_filter(q.state.as_deref());
    let page_num = q.page.unwrap_or(1).max(1);
    let offset = (page_num - 1) * ISSUES_PER_PAGE;
    let issues = state
        .store
        .list_issues_page(&repo.id, filter, ISSUES_PER_PAGE, offset)
        .await?;

    let body = render_list(&state, &repo, &issues, filter, page_num, &csrf, None).await;
    Ok(html_with_csrf(
        StatusCode::OK,
        page(&format!("{owner}/{name} · Issues"), Some(&who.email), &body),
        &csrf,
    ))
}

// ===========================================================================
// POST /r/{owner}/{name}/issues — create
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct CreateForm {
    #[serde(default)]
    pub csrf_token: String,
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

    let title = form.title.trim();
    if title.is_empty() {
        // Re-render the first page (all issues) with the error.
        let csrf = auth::new_csrf_token();
        let issues = state
            .store
            .list_issues_page(&repo.id, "", ISSUES_PER_PAGE, 0)
            .await?;
        let body = render_list(
            &state,
            &repo,
            &issues,
            "",
            1,
            &csrf,
            Some("Issue title cannot be empty."),
        )
        .await;
        return Ok(html_with_csrf(
            StatusCode::BAD_REQUEST,
            page(&format!("{owner}/{name} · Issues"), Some(&who.email), &body),
            &csrf,
        ));
    }

    let issue = state
        .store
        .create_issue(
            &format!("is_{}", random_alnum(ISSUE_ID_LEN)),
            &repo.id,
            &title.chars().take(MAX_TITLE_CHARS).collect::<String>(),
            &form.body.trim().chars().take(MAX_BODY_CHARS).collect::<String>(),
            &who.subject,
            now_secs(),
        )
        .await?;

    tracing::info!(repo = repo.id, number = issue.number, author = who.subject, "issue opened");
    Ok(redirect(&format!("/r/{owner}/{name}/issues/{}", issue.number)))
}

// ===========================================================================
// GET /r/{owner}/{name}/issues/{number} — detail + comments
// ===========================================================================

pub async fn detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, number)): Path<(String, String, i64)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let issue = state
        .store
        .get_issue(&repo.id, number)
        .await?
        .ok_or_else(|| AppError::NotFound("No such issue.".to_string()))?;
    let comments = state.store.list_comments(&issue.id).await?;
    let csrf = auth::new_csrf_token();

    let can_toggle = can_moderate(&repo, &issue, &who, &headers);
    let header = issue_header(&state, &repo).await;
    let body = render_detail(&repo, &issue, &comments, &header, can_toggle, &csrf, None);
    Ok(html_with_csrf(
        StatusCode::OK,
        page(
            &format!("{owner}/{name} · Issue #{number}"),
            Some(&who.email),
            &body,
        ),
        &csrf,
    ))
}

// ===========================================================================
// POST /r/{owner}/{name}/issues/{number}/comment — add a comment
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct CommentForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub body: String,
}

pub async fn comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, number)): Path<(String, String, i64)>,
    Form(form): Form<CommentForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and submit again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let issue = state
        .store
        .get_issue(&repo.id, number)
        .await?
        .ok_or_else(|| AppError::NotFound("No such issue.".to_string()))?;

    let body_text = form.body.trim();
    if body_text.is_empty() {
        // Re-render the detail with an inline error (comment intact input dropped, matching create).
        let csrf = auth::new_csrf_token();
        let comments = state.store.list_comments(&issue.id).await?;
        let can_toggle = can_moderate(&repo, &issue, &who, &headers);
        let header = issue_header(&state, &repo).await;
        let body = render_detail(
            &repo,
            &issue,
            &comments,
            &header,
            can_toggle,
            &csrf,
            Some("Comment cannot be empty."),
        );
        return Ok(html_with_csrf(
            StatusCode::BAD_REQUEST,
            page(
                &format!("{owner}/{name} · Issue #{number}"),
                Some(&who.email),
                &body,
            ),
            &csrf,
        ));
    }

    state
        .store
        .create_comment(
            &format!("ic_{}", random_alnum(COMMENT_ID_LEN)),
            &issue.id,
            &who.subject,
            &body_text.chars().take(MAX_BODY_CHARS).collect::<String>(),
            now_secs(),
        )
        .await?;

    tracing::info!(repo = repo.id, number, author = who.subject, "issue comment added");
    Ok(redirect(&format!("/r/{owner}/{name}/issues/{number}")))
}

// ===========================================================================
// POST /r/{owner}/{name}/issues/{number}/toggle — open/close
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

    let issue = state
        .store
        .get_issue(&repo.id, number)
        .await?
        .ok_or_else(|| AppError::NotFound("No such issue.".to_string()))?;

    // Only the issue author, the repo owner, or an estate admin may change an issue's state.
    if !can_moderate(&repo, &issue, &who, &headers) {
        return Err(AppError::Forbidden(
            "Only the issue author, the repository owner, or an administrator can change this issue."
                .to_string(),
        ));
    }

    let next = if issue.is_open() { "closed" } else { "open" };
    state.store.set_issue_state(&issue.id, next, now_secs()).await?;
    tracing::info!(repo = repo.id, number, state = next, actor = who.subject, "issue toggled");
    Ok(redirect(&format!("/r/{owner}/{name}/issues/{number}")))
}

// ===========================================================================
// Rendering
// ===========================================================================

/// State badge (class, label) for an issue.
fn state_badge(issue: &Issue) -> (&'static str, &'static str) {
    if issue.is_open() {
        ("state-badge--open", "Open")
    } else {
        ("state-badge--closed", "Closed")
    }
}

/// The issue list: filter tabs (Open/Closed/All with counts), the page of rows, a pager, and the
/// "New issue" form.
async fn render_list(
    state: &AppState,
    repo: &Repo,
    issues: &[Issue],
    filter: &str,
    page: i64,
    csrf: &str,
    error: Option<&str>,
) -> String {
    let header = issue_header(state, repo).await;
    let error_block = error_block(error);

    // Counts for the filter tabs (closed = all - open, no extra query).
    let open_count = state.store.open_issue_count(&repo.id).await.unwrap_or(0);
    let all_count = state.store.count_issues(&repo.id, "").await.unwrap_or(0);
    let closed_count = (all_count - open_count).max(0);
    let filter_total = match filter {
        "open" => open_count,
        "closed" => closed_count,
        _ => all_count,
    };

    let tabs = render_filter_tabs(repo, filter, open_count, closed_count, all_count);

    let list = if issues.is_empty() {
        "<li class=\"issue-item issue-item--empty\">No issues to show.</li>".to_string()
    } else {
        issues
            .iter()
            .map(|i| render_issue_row(repo, i))
            .collect::<Vec<_>>()
            .join("")
    };

    let pager = render_pager(repo, filter, page, issues.len() as i64, filter_total);

    format!(
        r##"{header}
<div class="layout layout--repo">
  <section class="card">
    <div class="card__head"><h2>Issues</h2></div>
    <div class="card__body">
      {tabs}
      <ul class="issue-list">{list}</ul>
      {pager}
    </div>
  </section>
  <section class="card">
    <div class="card__head"><h2>New issue</h2></div>
    <div class="card__body">
      {error_block}
      <form method="post" action="/r/{owner}/{name}/issues">
        <input type="hidden" name="csrf_token" value="{csrf}">
        <div class="field">
          <label for="title">Title</label>
          <input type="text" id="title" name="title" maxlength="300" placeholder="Short summary" required>
        </div>
        <div class="field">
          <label for="body">Description</label>
          <textarea id="body" name="body" class="issue-input" placeholder="Optional details…"></textarea>
        </div>
        <div class="actions">
          <button class="btn btn-primary" type="submit">Open issue</button>
        </div>
      </form>
    </div>
  </section>
</div>"##,
        header = header,
        tabs = tabs,
        list = list,
        pager = pager,
        error_block = error_block,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        csrf = esc(csrf),
    )
}

/// Open/Closed/All filter tabs with counts; the active filter is marked.
fn render_filter_tabs(
    repo: &Repo,
    filter: &str,
    open_count: i64,
    closed_count: i64,
    all_count: i64,
) -> String {
    let tab = |f: &str, label: &str, count: i64| {
        let active = if f == filter { " tab--active" } else { "" };
        format!(
            "<a class=\"tab{active}\" href=\"{href}\">{label} <span class=\"tab__count\">{count}</span></a>",
            active = active,
            href = list_url(&repo.owner_sub, &repo.name, f, 1),
            label = label,
            count = count,
        )
    };
    format!(
        "<nav class=\"tabs tabs--filter\">{}{}{}</nav>",
        tab("open", "Open", open_count),
        tab("closed", "Closed", closed_count),
        tab("", "All", all_count),
    )
}

/// A single issue row on the list, linking to the detail page.
fn render_issue_row(repo: &Repo, issue: &Issue) -> String {
    let (state_class, state_label) = state_badge(issue);
    format!(
        r##"<li class="issue-item">
  <div class="issue-item__head">
    <span class="state-badge {state_class}">{state_label}</span>
    <a class="issue-item__title" href="/r/{owner}/{name}/issues/{number}">#{number} {title}</a>
  </div>
  <div class="issue-item__meta">
    <span>opened {when} by {author}</span>
  </div>
</li>"##,
        state_class = state_class,
        state_label = state_label,
        number = issue.number,
        title = esc(&issue.title),
        when = esc(&fmt_ts(issue.created_at)),
        author = esc(&issue.author_sub),
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
    )
}

/// Prev/Next pager (simple offset pagination). Prev shows from page 2; Next shows while the current
/// page filled up to the filter total.
fn render_pager(repo: &Repo, filter: &str, page: i64, shown: i64, filter_total: i64) -> String {
    let has_prev = page > 1;
    let has_next = page * ISSUES_PER_PAGE < filter_total && shown > 0;
    if !has_prev && !has_next {
        return String::new();
    }
    let prev = if has_prev {
        format!(
            "<a class=\"btn btn-ghost btn-sm\" href=\"{}\">&larr; Newer</a>",
            list_url(&repo.owner_sub, &repo.name, filter, page - 1)
        )
    } else {
        String::new()
    };
    let next = if has_next {
        format!(
            "<a class=\"btn btn-ghost btn-sm\" href=\"{}\">Older &rarr;</a>",
            list_url(&repo.owner_sub, &repo.name, filter, page + 1)
        )
    } else {
        String::new()
    };
    format!("<div class=\"pager\">{prev}{next}</div>")
}

/// The issue detail page: title + state, the (markdown) body, the comment thread, a comment form,
/// and the close/reopen action for a moderator.
fn render_detail(
    repo: &Repo,
    issue: &Issue,
    comments: &[IssueComment],
    header: &str,
    can_toggle: bool,
    csrf: &str,
    error: Option<&str>,
) -> String {
    let (cls, label) = state_badge(issue);
    let error_block = error_block(error);

    let body_html = if issue.body.trim().is_empty() {
        "<p class=\"muted\">No description provided.</p>".to_string()
    } else {
        format!(
            "<div class=\"markdown-body\">{}</div>",
            crate::markdown::render(&issue.body)
        )
    };

    let updated = if issue.updated_at > issue.created_at {
        format!(" · updated {}", esc(&fmt_ts(issue.updated_at)))
    } else {
        String::new()
    };

    let comment_list = if comments.is_empty() {
        "<li class=\"issue-item issue-item--empty\">No comments yet.</li>".to_string()
    } else {
        comments.iter().map(render_comment).collect::<String>()
    };

    // Moderator action: close (open issue) / reopen (closed issue). Its own <form> — NEVER nested
    // inside the comment form (nested forms are invalid HTML).
    let actions = if can_toggle {
        let action_label = if issue.is_open() { "Close issue" } else { "Reopen issue" };
        format!(
            r##"<section class="card">
  <div class="card__body">
    <form class="inline-form" method="post" action="/r/{owner}/{name}/issues/{number}/toggle">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <button class="btn btn-secondary" type="submit">{action_label}</button>
    </form>
  </div>
</section>"##,
            owner = esc(&repo.owner_sub),
            name = esc(&repo.name),
            number = issue.number,
            csrf = esc(csrf),
            action_label = action_label,
        )
    } else {
        String::new()
    };

    format!(
        r##"{header}
<div class="console__head">
  <div class="repo-title">
    <span class="state-badge {cls}">{label}</span>
    <h1 class="issue-title">#{number} {title}</h1>
  </div>
  <p class="sub">opened {when} by {author}{updated}</p>
</div>
<section class="card">
  <div class="card__head"><h2>Description</h2></div>
  <div class="card__body">{body_html}</div>
</section>
<section class="card">
  <div class="card__head"><h2>Comments <span class="tab__count">{ncomments}</span></h2></div>
  <div class="card__body"><ul class="issue-list">{comment_list}</ul></div>
</section>
<section class="card">
  <div class="card__head"><h2>Add a comment</h2></div>
  <div class="card__body">
    {error_block}
    <form method="post" action="/r/{owner}/{name}/issues/{number}/comment">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <div class="field">
        <label for="comment-body">Comment</label>
        <textarea id="comment-body" name="body" class="issue-input" placeholder="Leave a comment…" required></textarea>
      </div>
      <div class="actions">
        <button class="btn btn-primary" type="submit">Comment</button>
      </div>
    </form>
  </div>
</section>
{actions}"##,
        header = header,
        cls = cls,
        label = label,
        number = issue.number,
        title = esc(&issue.title),
        when = esc(&fmt_ts(issue.created_at)),
        author = esc(&issue.author_sub),
        updated = updated,
        body_html = body_html,
        ncomments = comments.len(),
        comment_list = comment_list,
        error_block = error_block,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        csrf = esc(csrf),
        actions = actions,
    )
}

/// One comment in the thread (author + timestamp meta, then the sanitised markdown body).
fn render_comment(comment: &IssueComment) -> String {
    let body_html = if comment.body.trim().is_empty() {
        String::new()
    } else {
        format!(
            "<div class=\"issue-item__body markdown-body\">{}</div>",
            crate::markdown::render(&comment.body)
        )
    };
    format!(
        r##"<li class="issue-item">
  <div class="issue-item__meta"><span>{author}</span> commented {when}</div>
  {body_html}
</li>"##,
        author = esc(&comment.author_sub),
        when = esc(&fmt_ts(comment.created_at)),
        body_html = body_html,
    )
}
