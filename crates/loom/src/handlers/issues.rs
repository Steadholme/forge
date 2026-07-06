//! The per-repo issue tracker: list (open/closed filter + pagination), detail + comments,
//! create, comment, and open/close.
//!
//! Issues live on any repo the viewer can see. Any signed-in user may open an issue or comment on a
//! visible repo; an issue's state can be toggled only by the issue's author, the repo's owner, or an
//! estate admin (an [`crate::auth::ADMIN_GROUPS`] member). Titles, bodies and comments are rendered
//! through the sanitising [`crate::markdown`] pipeline / HTML-escaped on render. State-changing POSTs
//! carry the double-submit CSRF token, exactly like the rest of the web surface.

use std::collections::BTreeMap;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use serde::Deserialize;

use crate::auth::{self, Identity};
use crate::error::AppError;
use crate::handlers::repos::{can_write_repo, load_visible_repo, render_repo_header};
use crate::handlers::{
    accepts_json, esc, fmt_rel, fmt_ts, html_with_csrf, is_valid_reaction_emoji, page,
    reaction_summaries_json, redirect, render_reactions, state_icon, REACTION_TARGET_COMMENT,
    REACTION_TARGET_ISSUE,
};
use crate::model::{Issue, IssueComment, Label, Milestone, ReactionSummary, Repo};
use crate::webhooks;
use crate::{now_secs, random_alnum, AppState};

const ISSUE_ID_LEN: usize = 16;
const COMMENT_ID_LEN: usize = 16;
const REACTION_ID_LEN: usize = 16;
/// Issues shown per list page (simple offset pagination).
const ISSUES_PER_PAGE: i64 = 25;
/// Hard caps on the stored text so a single request cannot store an unbounded blob.
const MAX_TITLE_CHARS: usize = 300;
const MAX_BODY_CHARS: usize = 20_000;
const KLAXON_SOURCE: &str = "loom";
const NOTIFY_TITLE_CHARS: usize = 96;
const NOTIFY_BODY_CHARS: usize = 240;

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

/// True when `who` may change issue metadata/state: the issue author, a repo writer, or an estate
/// admin (group-based). Admin membership is read from the HMAC-verified `X-Auth-Groups` header.
async fn can_moderate(
    state: &AppState,
    repo: &Repo,
    issue: &Issue,
    who: &Identity,
    headers: &HeaderMap,
) -> Result<bool, AppError> {
    Ok(issue.author_sub == who.subject || can_write_repo(state, repo, who, headers).await?)
}

fn truncate_notify(s: &str, max: usize) -> String {
    let mut iter = s.trim().chars();
    let mut out: String = iter.by_ref().take(max).collect();
    if iter.next().is_some() {
        out.push_str("...");
    }
    out
}

fn issue_notify_url(state: &AppState, repo: &Repo, number: i64) -> String {
    format!(
        "{}/r/{}/{}/issues/{number}",
        state.config.public_base_url.trim_end_matches('/'),
        repo.owner_sub,
        repo.name,
    )
}

fn notify_issue_assigned(
    state: &AppState,
    actor_sub: &str,
    recipient_sub: &str,
    repo: &Repo,
    issue: &Issue,
) {
    if recipient_sub.is_empty() || recipient_sub == actor_sub {
        return;
    }
    let Some(k) = &state.klaxon else {
        return;
    };
    let title = format!(
        "{actor_sub} assigned you issue: {}",
        truncate_notify(&issue.title, NOTIFY_TITLE_CHARS)
    );
    let body = truncate_notify(&issue.title, NOTIFY_BODY_CHARS);
    let url = issue_notify_url(state, repo, issue.number);
    k.notify(KLAXON_SOURCE, recipient_sub, &title, &body, &url);
}

/// Render the repo header on the "Issues" tab (fetches the open issue/PR badge counts).
async fn issue_header(state: &AppState, repo: &Repo) -> String {
    let open_issues = state.store.open_issue_count(&repo.id).await.unwrap_or(0);
    let open_pulls = state.store.open_pull_count(&repo.id).await.unwrap_or(0);
    let release_count = state
        .store
        .release_count(&repo.id, false)
        .await
        .unwrap_or(0);
    render_repo_header(
        repo,
        &state.config.public_base_url,
        open_issues,
        open_pulls,
        release_count,
        "issues",
    )
}

type ReactionMap = BTreeMap<String, Vec<ReactionSummary>>;

async fn load_issue_reactions(
    state: &AppState,
    issue: &Issue,
    comments: &[IssueComment],
    viewer_sub: &str,
) -> Result<(Vec<ReactionSummary>, ReactionMap), AppError> {
    let issue_reactions = state
        .store
        .list_reactions_for_target(REACTION_TARGET_ISSUE, &issue.id, viewer_sub)
        .await?;
    let mut comment_reactions = ReactionMap::new();
    for comment in comments {
        comment_reactions.insert(
            comment.id.clone(),
            state
                .store
                .list_reactions_for_target(REACTION_TARGET_COMMENT, &comment.id, viewer_sub)
                .await?,
        );
    }
    Ok((issue_reactions, comment_reactions))
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
fn list_url(
    owner: &str,
    name: &str,
    filter: &str,
    label_filter: &str,
    milestone_filter: &str,
    page: i64,
) -> String {
    let mut url = format!("/r/{owner}/{name}/issues");
    let mut q: Vec<String> = Vec::new();
    if !filter.is_empty() {
        q.push(format!("state={filter}"));
    }
    if !label_filter.is_empty() {
        q.push(format!("label={label_filter}"));
    }
    if !milestone_filter.is_empty() {
        q.push(format!("milestone={milestone_filter}"));
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
    pub label: Option<String>,
    #[serde(default)]
    pub milestone: Option<String>,
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
    let label_filter = q.label.unwrap_or_default();
    let milestone_filter = q.milestone.unwrap_or_default();
    let page_num = q.page.unwrap_or(1).max(1);
    let offset = (page_num - 1) * ISSUES_PER_PAGE;
    let issues = state
        .store
        .list_issues_page(
            &repo.id,
            filter,
            &label_filter,
            &milestone_filter,
            ISSUES_PER_PAGE,
            offset,
        )
        .await?;

    let body = render_list(
        &state,
        &repo,
        &issues,
        filter,
        &label_filter,
        &milestone_filter,
        page_num,
        &csrf,
        None,
    )
    .await;
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
    #[serde(default)]
    pub assignee: String,
    #[serde(default)]
    pub milestone_id: String,
    #[serde(default, deserialize_with = "crate::handlers::form_vec")]
    pub labels: Vec<String>,
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
            .list_issues_page(&repo.id, "", "", "", ISSUES_PER_PAGE, 0)
            .await?;
        let body = render_list(
            &state,
            &repo,
            &issues,
            "",
            "",
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

    let (assignee, milestone_id, label_ids, label_names) = clean_issue_metadata(
        &state,
        &repo,
        &form.assignee,
        &form.milestone_id,
        &form.labels,
    )
    .await?;

    let issue = state
        .store
        .create_issue(
            &format!("is_{}", random_alnum(ISSUE_ID_LEN)),
            &repo.id,
            &title.chars().take(MAX_TITLE_CHARS).collect::<String>(),
            &form
                .body
                .trim()
                .chars()
                .take(MAX_BODY_CHARS)
                .collect::<String>(),
            &who.subject,
            now_secs(),
        )
        .await?;
    state
        .store
        .set_issue_metadata(&issue.id, &assignee, &milestone_id, &label_ids)
        .await?;
    notify_issue_assigned(&state, &who.subject, &assignee, &repo, &issue);
    webhooks::emit_issue(&state, &repo, "opened", &who.subject, &issue, &label_names);

    tracing::info!(
        repo = repo.id,
        number = issue.number,
        author = who.subject,
        "issue opened"
    );
    Ok(redirect(&format!(
        "/r/{owner}/{name}/issues/{}",
        issue.number
    )))
}

async fn clean_issue_metadata(
    state: &AppState,
    repo: &Repo,
    assignee: &str,
    milestone_id: &str,
    labels: &[String],
) -> Result<(String, String, Vec<String>, Vec<String>), AppError> {
    let assignee = assignee.trim().chars().take(128).collect::<String>();
    let milestones = state.store.list_milestones(&repo.id).await?;
    let clean_milestone = if milestone_id.trim().is_empty()
        || milestones.iter().any(|m| m.id == milestone_id.trim())
    {
        milestone_id.trim().to_string()
    } else {
        return Err(AppError::BadRequest(
            "Choose an existing milestone.".to_string(),
        ));
    };
    let repo_labels = state.store.list_labels(&repo.id).await?;
    let mut clean_labels = Vec::new();
    for label in labels {
        let id = label.trim();
        if id.is_empty() {
            continue;
        }
        if repo_labels.iter().any(|l| l.id == id) && !clean_labels.iter().any(|l| l == id) {
            clean_labels.push(id.to_string());
        }
    }
    let label_names = clean_labels
        .iter()
        .filter_map(|id| repo_labels.iter().find(|label| label.id == *id))
        .map(|label| label.name.clone())
        .collect();
    Ok((assignee, clean_milestone, clean_labels, label_names))
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
    let labels = state.store.list_labels(&repo.id).await?;
    let issue_labels = state.store.issue_labels(&issue.id).await?;
    let milestones = state.store.list_milestones(&repo.id).await?;
    let (issue_reactions, comment_reactions) =
        load_issue_reactions(&state, &issue, &comments, &who.subject).await?;
    let csrf = auth::new_csrf_token();

    let can_toggle = can_moderate(&state, &repo, &issue, &who, &headers).await?;
    let header = issue_header(&state, &repo).await;
    let body = render_detail(
        &repo,
        &issue,
        &comments,
        &labels,
        &issue_labels,
        &milestones,
        &issue_reactions,
        &comment_reactions,
        &header,
        can_toggle,
        &csrf,
        None,
    );
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
        let labels = state.store.list_labels(&repo.id).await?;
        let issue_labels = state.store.issue_labels(&issue.id).await?;
        let milestones = state.store.list_milestones(&repo.id).await?;
        let (issue_reactions, comment_reactions) =
            load_issue_reactions(&state, &issue, &comments, &who.subject).await?;
        let can_toggle = can_moderate(&state, &repo, &issue, &who, &headers).await?;
        let header = issue_header(&state, &repo).await;
        let body = render_detail(
            &repo,
            &issue,
            &comments,
            &labels,
            &issue_labels,
            &milestones,
            &issue_reactions,
            &comment_reactions,
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

    tracing::info!(
        repo = repo.id,
        number,
        author = who.subject,
        "issue comment added"
    );
    Ok(redirect(&format!("/r/{owner}/{name}/issues/{number}")))
}

// ===========================================================================
// POST /r/{owner}/{name}/issues/{number}/reactions — toggle issue reaction
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct ReactionForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub emoji: String,
}

pub async fn react_issue(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, number)): Path<(String, String, i64)>,
    Form(form): Form<ReactionForm>,
) -> Result<Response, AppError> {
    let (target_id, emoji, selected, reactions) =
        apply_issue_reaction(&state, &headers, &owner, &name, number, &form).await?;
    if accepts_json(&headers) {
        return Ok(Json(serde_json::json!({
            "ok": true,
            "target_type": REACTION_TARGET_ISSUE,
            "target_id": target_id,
            "emoji": emoji,
            "selected": selected,
            "reactions": reaction_summaries_json(&reactions),
        }))
        .into_response());
    }
    Ok(redirect(&format!("/r/{owner}/{name}/issues/{number}")))
}

async fn apply_issue_reaction(
    state: &AppState,
    headers: &HeaderMap,
    owner: &str,
    name: &str,
    number: i64,
    form: &ReactionForm,
) -> Result<(String, String, bool, Vec<ReactionSummary>), AppError> {
    let emoji = clean_reaction_form(headers, form)?;
    let who = auth::identity(headers);
    let repo = load_visible_repo(state, &who, owner, name).await?;
    let issue = state
        .store
        .get_issue(&repo.id, number)
        .await?
        .ok_or_else(|| AppError::NotFound("No such issue.".to_string()))?;
    let selected = state
        .store
        .toggle_reaction(
            &format!("rx_{}", random_alnum(REACTION_ID_LEN)),
            REACTION_TARGET_ISSUE,
            &issue.id,
            &who.subject,
            &emoji,
            now_secs(),
        )
        .await?;
    let reactions = state
        .store
        .list_reactions_for_target(REACTION_TARGET_ISSUE, &issue.id, &who.subject)
        .await?;
    tracing::info!(
        repo = repo.id,
        number,
        target = issue.id,
        emoji = emoji,
        selected,
        actor = who.subject,
        "issue reaction toggled"
    );
    Ok((issue.id, emoji, selected, reactions))
}

// ===========================================================================
// POST /r/{owner}/{name}/issues/{number}/comments/{comment_id}/reactions
// ===========================================================================

pub async fn react_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, number, comment_id)): Path<(String, String, i64, String)>,
    Form(form): Form<ReactionForm>,
) -> Result<Response, AppError> {
    let (target_id, emoji, selected, reactions) =
        apply_issue_comment_reaction(&state, &headers, &owner, &name, number, &comment_id, &form)
            .await?;
    if accepts_json(&headers) {
        return Ok(Json(serde_json::json!({
            "ok": true,
            "target_type": REACTION_TARGET_COMMENT,
            "target_id": target_id,
            "emoji": emoji,
            "selected": selected,
            "reactions": reaction_summaries_json(&reactions),
        }))
        .into_response());
    }
    Ok(redirect(&format!("/r/{owner}/{name}/issues/{number}")))
}

async fn apply_issue_comment_reaction(
    state: &AppState,
    headers: &HeaderMap,
    owner: &str,
    name: &str,
    number: i64,
    comment_id: &str,
    form: &ReactionForm,
) -> Result<(String, String, bool, Vec<ReactionSummary>), AppError> {
    let emoji = clean_reaction_form(headers, form)?;
    let who = auth::identity(headers);
    let repo = load_visible_repo(state, &who, owner, name).await?;
    let issue = state
        .store
        .get_issue(&repo.id, number)
        .await?
        .ok_or_else(|| AppError::NotFound("No such issue.".to_string()))?;
    let comments = state.store.list_comments(&issue.id).await?;
    if !comments.iter().any(|comment| comment.id == comment_id) {
        return Err(AppError::NotFound("No such comment.".to_string()));
    }
    let selected = state
        .store
        .toggle_reaction(
            &format!("rx_{}", random_alnum(REACTION_ID_LEN)),
            REACTION_TARGET_COMMENT,
            comment_id,
            &who.subject,
            &emoji,
            now_secs(),
        )
        .await?;
    let reactions = state
        .store
        .list_reactions_for_target(REACTION_TARGET_COMMENT, comment_id, &who.subject)
        .await?;
    tracing::info!(
        repo = repo.id,
        number,
        target = comment_id,
        emoji = emoji,
        selected,
        actor = who.subject,
        "issue comment reaction toggled"
    );
    Ok((comment_id.to_string(), emoji, selected, reactions))
}

fn clean_reaction_form(headers: &HeaderMap, form: &ReactionForm) -> Result<String, AppError> {
    if !auth::verify_csrf(headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let emoji = form.emoji.trim();
    if !is_valid_reaction_emoji(emoji) {
        return Err(AppError::BadRequest(
            "Choose a supported reaction.".to_string(),
        ));
    }
    Ok(emoji.to_string())
}

// ===========================================================================
// POST /r/{owner}/{name}/issues/{number}/metadata — assignee/labels/milestone
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct MetadataForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub assignee: String,
    #[serde(default)]
    pub milestone_id: String,
    #[serde(default, deserialize_with = "crate::handlers::form_vec")]
    pub labels: Vec<String>,
}

pub async fn metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, number)): Path<(String, String, i64)>,
    Form(form): Form<MetadataForm>,
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
    if !can_moderate(&state, &repo, &issue, &who, &headers).await? {
        return Err(AppError::Forbidden(
            "Only the issue author, the repository owner, or an administrator can edit metadata."
                .to_string(),
        ));
    }
    let (assignee, milestone_id, label_ids, _label_names) = clean_issue_metadata(
        &state,
        &repo,
        &form.assignee,
        &form.milestone_id,
        &form.labels,
    )
    .await?;
    state
        .store
        .set_issue_metadata(&issue.id, &assignee, &milestone_id, &label_ids)
        .await?;
    if assignee != issue.assignee_sub {
        notify_issue_assigned(&state, &who.subject, &assignee, &repo, &issue);
    }
    tracing::info!(
        repo = repo.id,
        number,
        actor = who.subject,
        "issue metadata updated"
    );
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
    apply_issue_toggle(&state, &headers, &owner, &name, number, &form).await?;
    Ok(redirect(&format!("/r/{owner}/{name}/issues/{number}")))
}

/// JSON sibling of [`toggle`] backing the optimistic, no-reload open/close control on the issue
/// page. Same CSRF (double-submit), same author/owner/admin gate, same audit; returns the new state
/// plus the badge/button labels the page should show. The form route above is unchanged for no-JS
/// clients (progressive enhancement).
pub async fn toggle_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, number)): Path<(String, String, i64)>,
    Form(form): Form<ToggleForm>,
) -> Result<Response, AppError> {
    let next = apply_issue_toggle(&state, &headers, &owner, &name, number, &form).await?;
    let (badge_class, badge_label, button_label, message) = if next == "closed" {
        (
            "state-badge--closed",
            "Closed",
            "Reopen issue",
            "Issue closed",
        )
    } else {
        ("state-badge--open", "Open", "Close issue", "Issue reopened")
    };
    Ok(Json(serde_json::json!({
        "ok": true,
        "state": next,
        "badge_class": badge_class,
        "badge_label": badge_label,
        "button_label": button_label,
        "message": message,
    }))
    .into_response())
}

/// Shared core for both issue-toggle routes: CSRF-check, load + authorize, flip the state, audit.
/// Returns the new state (`"open"` / `"closed"`).
async fn apply_issue_toggle(
    state: &AppState,
    headers: &HeaderMap,
    owner: &str,
    name: &str,
    number: i64,
    form: &ToggleForm,
) -> Result<&'static str, AppError> {
    if !auth::verify_csrf(headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(headers);
    let repo = load_visible_repo(state, &who, owner, name).await?;

    let issue = state
        .store
        .get_issue(&repo.id, number)
        .await?
        .ok_or_else(|| AppError::NotFound("No such issue.".to_string()))?;

    // Only the issue author, the repo owner, or an estate admin may change an issue's state.
    if !can_moderate(state, &repo, &issue, &who, headers).await? {
        return Err(AppError::Forbidden(
            "Only the issue author, the repository owner, or an administrator can change this issue."
                .to_string(),
        ));
    }

    let next = if issue.is_open() { "closed" } else { "open" };
    state
        .store
        .set_issue_state(&issue.id, next, now_secs())
        .await?;
    let action = if next == "closed" {
        "closed"
    } else {
        "reopened"
    };
    let label_names = match state.store.issue_labels(&issue.id).await {
        Ok(labels) => labels
            .into_iter()
            .map(|label| label.name)
            .collect::<Vec<_>>(),
        Err(e) => {
            tracing::warn!(
                error = %e,
                repo = repo.id,
                number,
                "issue labels lookup failed for webhook payload"
            );
            Vec::new()
        }
    };
    webhooks::emit_issue_state(
        state,
        &repo,
        action,
        &who.subject,
        &issue,
        next,
        &label_names,
    );
    tracing::info!(
        repo = repo.id,
        number,
        state = next,
        actor = who.subject,
        "issue toggled"
    );
    Ok(next)
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
    label_filter: &str,
    milestone_filter: &str,
    page: i64,
    csrf: &str,
    error: Option<&str>,
) -> String {
    let header = issue_header(state, repo).await;
    let error_block = error_block(error);
    let labels = state.store.list_labels(&repo.id).await.unwrap_or_default();
    let milestones = state
        .store
        .list_milestones(&repo.id)
        .await
        .unwrap_or_default();
    let issue_labels = state
        .store
        .list_issue_labels(&repo.id)
        .await
        .unwrap_or_default();

    // Counts for the filter tabs (closed = all - open, no extra query).
    let open_count = state
        .store
        .count_issues(&repo.id, "open", label_filter, milestone_filter)
        .await
        .unwrap_or(0);
    let all_count = state
        .store
        .count_issues(&repo.id, "", label_filter, milestone_filter)
        .await
        .unwrap_or(0);
    let closed_count = (all_count - open_count).max(0);
    let filter_total = match filter {
        "open" => open_count,
        "closed" => closed_count,
        _ => all_count,
    };

    let tabs = render_filter_tabs(
        repo,
        filter,
        label_filter,
        milestone_filter,
        open_count,
        closed_count,
        all_count,
    );
    let filters = render_metadata_filters(
        repo,
        &labels,
        &milestones,
        filter,
        label_filter,
        milestone_filter,
    );

    let list = if issues.is_empty() {
        format!(
            "<li class=\"issue-item issue-item--empty\">\
               <div class=\"empty\">\
                 <svg class=\"empty__icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M12 8v4M12 16h.01\"/></svg>\
                 <div class=\"empty__title\">No issues to show</div>\
                 <div class=\"empty__text\">Nothing matches this view yet. Open one from the form, or clear the filters.</div>\
                 <a class=\"btn btn-secondary btn-sm\" href=\"/r/{owner}/{name}/issues\">View all issues</a>\
               </div>\
             </li>",
            owner = esc(&repo.owner_sub),
            name = esc(&repo.name),
        )
    } else {
        issues
            .iter()
            .map(|i| {
                let labels_for_issue: Vec<Label> = issue_labels
                    .iter()
                    .filter(|(issue_id, _)| issue_id == &i.id)
                    .map(|(_, label)| label.clone())
                    .collect();
                render_issue_row(repo, i, &labels_for_issue, &milestones)
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let pager = render_pager(
        repo,
        filter,
        label_filter,
        milestone_filter,
        page,
        issues.len() as i64,
        filter_total,
    );
    let metadata_fields = render_metadata_fields(&labels, &milestones, "", "", &[]);
    let open_attr = if error.is_some() { " open" } else { "" };

    format!(
        r##"{header}
	<div class="list-toolbar">
	  <span class="list-toolbar__fill"></span>
	  {filters}
	  <details class="popbtn popbtn--new"{open_attr}>
    <summary class="btn btn-primary btn-sm">New issue</summary>
    <div class="popbtn__pop popbtn__pop--wide">
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
        {metadata_fields}
        <div class="actions">
          <button class="btn btn-primary" type="submit">Open issue</button>
        </div>
      </form>
    </div>
	  </details>
	</div>
	<section class="card">
	  <div class="card__head card__head--list">{tabs}</div>
	  <div class="card__body card__body--list">
	    <ul class="issue-list">{list}</ul>
	    {pager}
  </div>
</section>"##,
        header = header,
        tabs = tabs,
        filters = filters,
        list = list,
        pager = pager,
        metadata_fields = metadata_fields,
        error_block = error_block,
        open_attr = open_attr,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        csrf = esc(csrf),
    )
}

/// Open/Closed/All filter tabs with counts; the active filter is marked.
fn render_filter_tabs(
    repo: &Repo,
    filter: &str,
    label_filter: &str,
    milestone_filter: &str,
    open_count: i64,
    closed_count: i64,
    all_count: i64,
) -> String {
    let tab = |f: &str, label: &str, count: i64| {
        let active = if f == filter { " tab--active" } else { "" };
        format!(
            "<a class=\"tab{active}\" href=\"{href}\">{label} <span class=\"tab__count\">{count}</span></a>",
            active = active,
            href = list_url(
                &repo.owner_sub,
                &repo.name,
                f,
                label_filter,
                milestone_filter,
                1,
            ),
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

fn render_metadata_filters(
    repo: &Repo,
    labels: &[Label],
    milestones: &[Milestone],
    filter: &str,
    label_filter: &str,
    milestone_filter: &str,
) -> String {
    if labels.is_empty() && milestones.is_empty() {
        return String::new();
    }
    let chips = render_label_filter_chips(repo, labels, filter, label_filter, milestone_filter);
    let label_opts = render_label_options(labels, label_filter, "All labels");
    let milestone_opts = render_milestone_options(milestones, milestone_filter, "All milestones");
    format!(
        r##"{chips}<form method="get" action="/r/{owner}/{name}/issues" class="compare-picker">
  <input type="hidden" name="state" value="">
  <span class="compare-picker__label">label</span>
  <select name="label" class="compare-picker__select">{label_opts}</select>
  <span class="compare-picker__label">milestone</span>
  <select name="milestone" class="compare-picker__select">{milestone_opts}</select>
  <button class="btn btn-secondary btn-sm" type="submit">Filter</button>
</form>"##,
        chips = chips,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        label_opts = label_opts,
        milestone_opts = milestone_opts,
    )
}

/// One-tap **filter chips** for the issue list: an "All" chip that clears the label filter plus one
/// chip per label (the active label marked). Each links to the list preserving the state + milestone
/// filters, so filtering is a single click — the `<select>` filter form below remains for no-JS/
/// keyboard-form users.
fn render_label_filter_chips(
    repo: &Repo,
    labels: &[Label],
    filter: &str,
    label_filter: &str,
    milestone_filter: &str,
) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let all_active = if label_filter.is_empty() {
        " filter-chip--active"
    } else {
        ""
    };
    let mut chips = format!(
        "<a class=\"filter-chip{all_active}\" href=\"{href}\">All</a>",
        all_active = all_active,
        href = list_url(&repo.owner_sub, &repo.name, filter, "", milestone_filter, 1),
    );
    for label in labels {
        let active = if label.id == label_filter {
            " filter-chip--active"
        } else {
            ""
        };
        chips.push_str(&format!(
            "<a class=\"filter-chip{active}\" style=\"--label-color: #{color}\" href=\"{href}\">{name}</a>",
            active = active,
            color = esc(&label.color),
            href = list_url(&repo.owner_sub, &repo.name, filter, &label.id, milestone_filter, 1),
            name = esc(&label.name),
        ));
    }
    format!(
        "<div class=\"chip-row\" role=\"list\" aria-label=\"Filter issues by label\">{chips}</div>",
        chips = chips,
    )
}

fn render_label_options(labels: &[Label], selected: &str, empty_label: &str) -> String {
    let mut out = format!("<option value=\"\">{}</option>", esc(empty_label));
    for label in labels {
        let sel = if label.id == selected {
            " selected"
        } else {
            ""
        };
        out.push_str(&format!(
            "<option value=\"{id}\"{sel}>{name}</option>",
            id = esc(&label.id),
            sel = sel,
            name = esc(&label.name),
        ));
    }
    out
}

fn render_milestone_options(milestones: &[Milestone], selected: &str, empty_label: &str) -> String {
    let mut out = format!("<option value=\"\">{}</option>", esc(empty_label));
    for milestone in milestones {
        let sel = if milestone.id == selected {
            " selected"
        } else {
            ""
        };
        let suffix = if milestone.is_open() { "" } else { " (closed)" };
        out.push_str(&format!(
            "<option value=\"{id}\"{sel}>{title}{suffix}</option>",
            id = esc(&milestone.id),
            sel = sel,
            title = esc(&milestone.title),
            suffix = suffix,
        ));
    }
    out
}

fn render_label_chips(labels: &[Label]) -> String {
    labels
        .iter()
        .map(|label| {
            format!(
                "<span class=\"label-chip\" style=\"--label-color: #{color}\">{name}</span>",
                color = esc(&label.color),
                name = esc(&label.name),
            )
        })
        .collect::<String>()
}

fn render_metadata_fields(
    labels: &[Label],
    milestones: &[Milestone],
    assignee: &str,
    milestone_id: &str,
    selected_labels: &[Label],
) -> String {
    let label_checks = if labels.is_empty() {
        "<p class=\"hint hint--muted\">No labels yet.</p>".to_string()
    } else {
        labels
            .iter()
            .map(|label| {
                let checked = if selected_labels.iter().any(|l| l.id == label.id) {
                    " checked"
                } else {
                    ""
                };
                format!(
                    "<label class=\"check\"><input type=\"checkbox\" name=\"labels\" value=\"{id}\"{checked}> {name}</label>",
                    id = esc(&label.id),
                    checked = checked,
                    name = esc(&label.name),
                )
            })
            .collect::<String>()
    };
    format!(
        r##"<div class="field">
  <label for="assignee">Assignee</label>
  <input type="text" id="assignee" name="assignee" maxlength="128" value="{assignee}" autocomplete="off" spellcheck="false">
</div>
<div class="field">
  <label for="milestone_id">Milestone</label>
  <select id="milestone_id" name="milestone_id">{milestones}</select>
</div>
<div class="field">
  <label>Labels</label>
  <div class="check-list">{label_checks}</div>
</div>"##,
        assignee = esc(assignee),
        milestones = render_milestone_options(milestones, milestone_id, "No milestone"),
        label_checks = label_checks,
    )
}

/// A single issue row on the list, linking to the detail page.
fn render_issue_row(
    repo: &Repo,
    issue: &Issue,
    labels: &[Label],
    milestones: &[Milestone],
) -> String {
    let (_, state_label) = state_badge(issue);
    let (icon_class, icon_kind) = if issue.is_open() {
        ("state-ico--open", "issue-open")
    } else {
        ("state-ico--closed", "issue-closed")
    };
    let label_chips = render_label_chips(labels);
    let assignee = if issue.assignee_sub.is_empty() {
        String::new()
    } else {
        format!(" · assigned to {}", esc(&issue.assignee_sub))
    };
    let milestone = milestones
        .iter()
        .find(|m| m.id == issue.milestone_id)
        .map(|m| format!(" · milestone {}", esc(&m.title)))
        .unwrap_or_default();
    format!(
        r##"<li class="issue-item">
  <span class="state-ico {icon_class}" title="{state_label}">{icon}</span>
  <div class="issue-item__main">
    <div class="issue-item__head">
      <a class="issue-item__title" href="/r/{owner}/{name}/issues/{number}">#{number} {title}</a>
    </div>
    <div class="label-row">{label_chips}</div>
    <div class="issue-item__meta">
      <span>opened {when} by {author}{assignee}{milestone}</span>
    </div>
  </div>
</li>"##,
        icon_class = icon_class,
        state_label = state_label,
        icon = state_icon(icon_kind),
        number = issue.number,
        title = esc(&issue.title),
        label_chips = label_chips,
        when = esc(&fmt_ts(issue.created_at)),
        author = esc(&issue.author_sub),
        assignee = assignee,
        milestone = milestone,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
    )
}

/// Prev/Next pager (simple offset pagination). Prev shows from page 2; Next shows while the current
/// page filled up to the filter total.
fn render_pager(
    repo: &Repo,
    filter: &str,
    label_filter: &str,
    milestone_filter: &str,
    page: i64,
    shown: i64,
    filter_total: i64,
) -> String {
    let has_prev = page > 1;
    let has_next = page * ISSUES_PER_PAGE < filter_total && shown > 0;
    if !has_prev && !has_next {
        return String::new();
    }
    let prev = if has_prev {
        format!(
            "<a class=\"btn btn-ghost btn-sm\" href=\"{}\">&larr; Newer</a>",
            list_url(
                &repo.owner_sub,
                &repo.name,
                filter,
                label_filter,
                milestone_filter,
                page - 1,
            )
        )
    } else {
        String::new()
    };
    let next = if has_next {
        format!(
            "<a class=\"btn btn-ghost btn-sm\" href=\"{}\">Older &rarr;</a>",
            list_url(
                &repo.owner_sub,
                &repo.name,
                filter,
                label_filter,
                milestone_filter,
                page + 1,
            )
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
    labels: &[Label],
    issue_labels: &[Label],
    milestones: &[Milestone],
    issue_reactions: &[ReactionSummary],
    comment_reactions: &ReactionMap,
    header: &str,
    can_toggle: bool,
    csrf: &str,
    error: Option<&str>,
) -> String {
    let (cls, label) = state_badge(issue);
    let error_block = error_block(error);
    let now = now_secs();

    let body_html = if issue.body.trim().is_empty() {
        "<p class=\"muted\">No description provided.</p>".to_string()
    } else {
        format!(
            "<div class=\"markdown-body\">{}</div>",
            crate::markdown::render_for_repo(&issue.body, &repo.owner_sub, &repo.name)
        )
    };

    let updated = if issue.updated_at > issue.created_at {
        format!(
            " · updated <span title=\"{}\">{}</span>",
            esc(&fmt_ts(issue.updated_at)),
            esc(&fmt_rel(now, issue.updated_at))
        )
    } else {
        String::new()
    };
    let label_chips = render_label_chips(issue_labels);
    let labels_value = if label_chips.is_empty() {
        "<span class=\"side__empty\">None yet</span>".to_string()
    } else {
        label_chips
    };
    let assignee_value = if issue.assignee_sub.is_empty() {
        "<span class=\"side__empty\">No assignee</span>".to_string()
    } else {
        esc(&issue.assignee_sub)
    };
    let milestone_value = milestones
        .iter()
        .find(|m| m.id == issue.milestone_id)
        .map(|m| esc(&m.title))
        .unwrap_or_else(|| "<span class=\"side__empty\">No milestone</span>".to_string());

    let comment_list = if comments.is_empty() {
        "<li class=\"issue-item issue-item--empty\">No comments yet.</li>".to_string()
    } else {
        comments
            .iter()
            .map(|c| {
                let reactions = comment_reactions
                    .get(&c.id)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                render_comment(repo, issue, c, reactions, csrf)
            })
            .collect::<String>()
    };
    let issue_reactions = render_reactions(
        &format!(
            "/r/{}/{}/issues/{}/reactions",
            repo.owner_sub, repo.name, issue.number
        ),
        REACTION_TARGET_ISSUE,
        &issue.id,
        issue_reactions,
        csrf,
    );

    let metadata_edit = if can_toggle {
        let metadata_fields = render_metadata_fields(
            labels,
            milestones,
            &issue.assignee_sub,
            &issue.milestone_id,
            issue_labels,
        );
        format!(
            r##"<section class="side__block side__block--edit">
  <details class="side-edit">
    <summary class="btn btn-ghost btn-sm">Edit details</summary>
    <form method="post" action="/r/{owner}/{name}/issues/{number}/metadata">
      <input type="hidden" name="csrf_token" value="{csrf}">
      {metadata_fields}
      <div class="actions"><button class="btn btn-secondary btn-sm" type="submit">Save metadata</button></div>
    </form>
  </details>
</section>"##,
            owner = esc(&repo.owner_sub),
            name = esc(&repo.name),
            number = issue.number,
            csrf = esc(csrf),
            metadata_fields = metadata_fields,
        )
    } else {
        String::new()
    };

    // Moderator action: close (open issue) / reopen (closed issue). Its own <form> — NEVER nested
    // inside the comment form (nested forms are invalid HTML).
    let toggle_form = if can_toggle {
        let action_label = if issue.is_open() {
            "Close issue"
        } else {
            "Reopen issue"
        };
        format!(
            r##"<form class="inline-form composer__toggle" method="post" action="/r/{owner}/{name}/issues/{number}/toggle" data-json>
  <input type="hidden" name="csrf_token" value="{csrf}">
  <button class="btn btn-secondary" type="submit">{action_label}</button>
</form>"##,
            owner = esc(&repo.owner_sub),
            name = esc(&repo.name),
            number = issue.number,
            csrf = esc(csrf),
            action_label = action_label,
        )
    } else {
        String::new()
    };

    let sidebar = format!(
        r##"<section class="side__block"><h3 class="side__label">Assignee</h3><div class="side__value">{assignee}</div></section>
<section class="side__block"><h3 class="side__label">Labels</h3><div class="side__value label-row">{labels}</div></section>
<section class="side__block"><h3 class="side__label">Milestone</h3><div class="side__value">{milestone}</div></section>
{metadata_edit}"##,
        assignee = assignee_value,
        labels = labels_value,
        milestone = milestone_value,
        metadata_edit = metadata_edit,
    );

    format!(
        r##"{header}
<div class="detail-head detail-head--issue">
  <div class="detail-head__badges"><span class="state-badge {cls}" id="state-badge-main">{label}</span></div>
  <h1 class="detail-head__title">{title} <span class="detail-head__number">#{number}</span></h1>
  <p class="detail-head__meta">opened <span title="{created_abs}">{created_rel}</span> by <b>{author}</b>{updated}</p>
</div>
{error_block}
<div class="detail-layout">
  <div class="detail-layout__main">
    <section class="card comment-box">
      <div class="comment-box__meta"><b>{author}</b> <span>opened this issue</span> <span title="{created_abs}">{created_rel}</span></div>
      <div class="comment-box__body">{body_html}{issue_reactions}</div>
    </section>
    <ul class="issue-list timeline">{comment_list}</ul>
    <section class="card composer">
      <div class="card__body">
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
        {toggle_form}
      </div>
    </section>
  </div>
  <aside class="side">{sidebar}</aside>
</div>"##,
        header = header,
        cls = cls,
        label = label,
        number = issue.number,
        title = esc(&issue.title),
        created_abs = esc(&fmt_ts(issue.created_at)),
        created_rel = esc(&fmt_rel(now, issue.created_at)),
        author = esc(&issue.author_sub),
        updated = updated,
        body_html = body_html,
        issue_reactions = issue_reactions,
        comment_list = comment_list,
        error_block = error_block,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        csrf = esc(csrf),
        toggle_form = toggle_form,
        sidebar = sidebar,
    )
}

/// One comment in the thread (author + timestamp meta, then the sanitised markdown body).
fn render_comment(
    repo: &Repo,
    issue: &Issue,
    comment: &IssueComment,
    reactions: &[ReactionSummary],
    csrf: &str,
) -> String {
    let body_html = if comment.body.trim().is_empty() {
        String::new()
    } else {
        format!(
            "<div class=\"issue-item__body markdown-body\">{}</div>",
            crate::markdown::render_for_repo(&comment.body, &repo.owner_sub, &repo.name)
        )
    };
    let reactions = render_reactions(
        &format!(
            "/r/{}/{}/issues/{}/comments/{}/reactions",
            repo.owner_sub, repo.name, issue.number, comment.id
        ),
        REACTION_TARGET_COMMENT,
        &comment.id,
        reactions,
        csrf,
    );
    format!(
        r##"<li class="issue-item">
  <div class="issue-item__meta"><span>{author}</span> commented {when}</div>
  {body_html}
  {reactions}
</li>"##,
        author = esc(&comment.author_sub),
        when = esc(&fmt_ts(comment.created_at)),
        body_html = body_html,
        reactions = reactions,
    )
}
