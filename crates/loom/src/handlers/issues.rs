//! The per-repo issue tracker: list, create, open/close.
//!
//! Issues live on any repo the viewer can see. Any signed-in user may open an issue on a visible
//! repo; an issue's state can be toggled only by the issue's author or the repo's owner. Titles
//! and bodies are HTML-escaped on render. State-changing POSTs carry the double-submit CSRF token.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Form;
use serde::Deserialize;

use crate::auth;
use crate::error::AppError;
use crate::handlers::repos::{load_visible_repo, render_repo_header};
use crate::handlers::{esc, fmt_ts, html_with_csrf, page, redirect};
use crate::model::{Issue, Repo};
use crate::{now_secs, random_alnum, AppState};

const ISSUE_ID_LEN: usize = 16;

// ===========================================================================
// GET /r/{owner}/{name}/issues
// ===========================================================================

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let csrf = auth::new_csrf_token();
    let issues = state.store.list_issues(&repo.id).await?;
    let body = render_issues(&state, &repo, &issues, &csrf, None).await;
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
        let csrf = auth::new_csrf_token();
        let issues = state.store.list_issues(&repo.id).await?;
        let body = render_issues(
            &state,
            &repo,
            &issues,
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
            &title.chars().take(300).collect::<String>(),
            &form.body.trim().chars().take(20_000).collect::<String>(),
            &who.subject,
            now_secs(),
        )
        .await?;

    tracing::info!(repo = repo.id, number = issue.number, "issue opened");
    Ok(redirect(&format!("/r/{owner}/{name}/issues")))
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

    // Only the issue author or the repo owner may change an issue's state.
    if issue.author_sub != who.subject && repo.owner_sub != who.subject {
        return Err(AppError::Forbidden(
            "Only the issue author or the repository owner can change this issue.".to_string(),
        ));
    }

    let next = if issue.is_open() { "closed" } else { "open" };
    state.store.set_issue_state(&issue.id, next).await?;
    tracing::info!(repo = repo.id, number, state = next, "issue toggled");
    Ok(redirect(&format!("/r/{owner}/{name}/issues")))
}

// ===========================================================================
// Rendering
// ===========================================================================

async fn render_issues(
    state: &AppState,
    repo: &Repo,
    issues: &[Issue],
    csrf: &str,
    error: Option<&str>,
) -> String {
    let open_issues = state.store.open_issue_count(&repo.id).await.unwrap_or(0);
    let header = render_repo_header(repo, &state.config.public_base_url, open_issues, "issues");

    let error_block = match error {
        Some(msg) => format!(
            "<div class=\"alert alert-danger\" role=\"alert\">{}</div>",
            esc(msg)
        ),
        None => String::new(),
    };

    let list = if issues.is_empty() {
        "<li class=\"issue-item issue-item--empty\">No issues yet.</li>".to_string()
    } else {
        issues
            .iter()
            .map(|i| render_issue_row(repo, i, csrf))
            .collect::<Vec<_>>()
            .join("")
    };

    format!(
        r##"{header}
<div class="layout layout--repo">
  <section class="card">
    <div class="card__head"><h2>Issues</h2></div>
    <div class="card__body"><ul class="issue-list">{list}</ul></div>
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
        list = list,
        error_block = error_block,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        csrf = esc(csrf),
    )
}

fn render_issue_row(repo: &Repo, issue: &Issue, csrf: &str) -> String {
    let (state_class, state_label, action_label) = if issue.is_open() {
        ("state-badge--open", "Open", "Close")
    } else {
        ("state-badge--closed", "Closed", "Reopen")
    };
    let body = if issue.body.trim().is_empty() {
        String::new()
    } else {
        format!("<p class=\"issue-item__body\">{}</p>", esc(&issue.body))
    };
    format!(
        r##"<li class="issue-item">
  <div class="issue-item__head">
    <span class="state-badge {state_class}">{state_label}</span>
    <span class="issue-item__title">#{number} {title}</span>
  </div>
  {body}
  <div class="issue-item__meta">
    <span>opened {when} by {author}</span>
    <form class="inline-form" method="post" action="/r/{owner}/{name}/issues/{number}/toggle">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <button class="btn btn-ghost btn-sm" type="submit">{action_label}</button>
    </form>
  </div>
</li>"##,
        state_class = state_class,
        state_label = state_label,
        number = issue.number,
        title = esc(&issue.title),
        body = body,
        when = esc(&fmt_ts(issue.created_at)),
        author = esc(&issue.author_sub),
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        csrf = esc(csrf),
        action_label = action_label,
    )
}
