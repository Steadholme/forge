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

use std::collections::{BTreeMap, BTreeSet};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use serde::Deserialize;

use crate::auth::{self, Identity};
use crate::config::{COMMIT_LIMIT, MAX_BLOB_RENDER_BYTES};
use crate::error::AppError;
use crate::gitops::CommitInfo;
use crate::handlers::repos::{load_visible_repo, render_repo_header, validate_branch_name};
use crate::handlers::{esc, fmt_ts, html_with_csrf, link_issue_refs, page, redirect, short_oid};
use crate::model::{CommitStatus, Label, Milestone, Pull, PullReview, PullReviewComment, Repo};
use crate::{now_secs, random_alnum, AppState};

const PULL_ID_LEN: usize = 16;
const REVIEW_ID_LEN: usize = 16;
const REVIEW_COMMENT_ID_LEN: usize = 16;
const KLAXON_SOURCE: &str = "loom";
const NOTIFY_TITLE_CHARS: usize = 96;
const NOTIFY_BODY_CHARS: usize = 240;

// ===========================================================================
// Shared helpers
// ===========================================================================

/// Render the repo header on the "Pull requests" tab (fetches the open issue/PR badge counts).
async fn pr_header(state: &AppState, repo: &Repo, active: &str) -> String {
    let open_issues = state.store.open_issue_count(&repo.id).await.unwrap_or(0);
    let open_pulls = state.store.open_pull_count(&repo.id).await.unwrap_or(0);
    render_repo_header(
        repo,
        &state.config.public_base_url,
        open_issues,
        open_pulls,
        active,
    )
}

/// True when `who` may merge/close a PR on `repo`: the repo owner (maintainer) or the PR author.
fn can_gate(repo: &Repo, pull: &Pull, who: &Identity) -> bool {
    repo.owner_sub == who.subject || pull.author_sub == who.subject
}

fn can_review(repo: &Repo, pull: &Pull, who: &Identity, headers: &HeaderMap) -> bool {
    can_gate(repo, pull, who) || auth::is_admin(headers)
}

fn truncate_notify(s: &str, max: usize) -> String {
    let mut iter = s.trim().chars();
    let mut out: String = iter.by_ref().take(max).collect();
    if iter.next().is_some() {
        out.push_str("...");
    }
    out
}

fn pull_notify_url(state: &AppState, repo: &Repo, number: i64) -> String {
    format!(
        "{}/r/{}/{}/pulls/{number}",
        state.config.public_base_url.trim_end_matches('/'),
        repo.owner_sub,
        repo.name,
    )
}

fn notify_pull_author(state: &AppState, actor_sub: &str, repo: &Repo, pull: &Pull, summary: &str) {
    if pull.author_sub == actor_sub {
        return;
    }
    let Some(k) = &state.klaxon else {
        return;
    };
    let title = format!("{actor_sub} 评论了你的 PR");
    let body = if summary.trim().is_empty() {
        truncate_notify(&pull.title, NOTIFY_BODY_CHARS)
    } else {
        truncate_notify(summary, NOTIFY_BODY_CHARS)
    };
    let url = pull_notify_url(state, repo, pull.number);
    k.notify(KLAXON_SOURCE, &pull.author_sub, &title, &body, &url);
}

fn notify_pull_assigned(
    state: &AppState,
    actor_sub: &str,
    recipient_sub: &str,
    repo: &Repo,
    pull: &Pull,
) {
    if recipient_sub.is_empty() || recipient_sub == actor_sub {
        return;
    }
    let Some(k) = &state.klaxon else {
        return;
    };
    let title = format!(
        "{actor_sub} 请你 review PR:{}",
        truncate_notify(&pull.title, NOTIFY_TITLE_CHARS)
    );
    let body = truncate_notify(&pull.title, NOTIFY_BODY_CHARS);
    let url = pull_notify_url(state, repo, pull.number);
    k.notify(KLAXON_SOURCE, recipient_sub, &title, &body, &url);
}

fn notify_pull_assignment_changes(
    state: &AppState,
    actor_sub: &str,
    repo: &Repo,
    pull: &Pull,
    old_assignee: &str,
    new_assignee: &str,
    old_reviewer: &str,
    new_reviewer: &str,
) {
    let mut recipients = BTreeSet::new();
    for (old, new) in [(old_assignee, new_assignee), (old_reviewer, new_reviewer)] {
        if old != new && recipients.insert(new) {
            notify_pull_assigned(state, actor_sub, new, repo, pull);
        }
    }
}

fn clean_subject_field(raw: &str) -> String {
    raw.trim().chars().take(128).collect()
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
        page(
            &format!("{owner}/{name} · Compare"),
            Some(&who.email),
            &body,
        ),
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

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub milestone: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
    Query(q): Query<ListQuery>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let label_filter = q.label.unwrap_or_default();
    let milestone_filter = q.milestone.unwrap_or_default();
    let pulls = state
        .store
        .list_pulls_filtered(&repo.id, &label_filter, &milestone_filter)
        .await?;
    let labels = state.store.list_labels(&repo.id).await?;
    let milestones = state.store.list_milestones(&repo.id).await?;
    let pull_labels = state.store.list_pull_labels(&repo.id).await?;
    let header = pr_header(&state, &repo, "pulls").await;
    let body = render_list(
        &repo,
        &header,
        &pulls,
        &labels,
        &milestones,
        &pull_labels,
        &label_filter,
        &milestone_filter,
    );
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
    #[serde(default)]
    pub assignee: String,
    #[serde(default)]
    pub reviewer: String,
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
            page(
                &format!("{owner}/{name} · Compare"),
                Some(&who.email),
                &body,
            ),
            &csrf,
        ));
    }
    let (milestone_id, label_ids) =
        clean_pull_metadata(&state, &repo, &form.milestone_id, &form.labels).await?;
    let assignee = clean_subject_field(&form.assignee);
    let reviewer = clean_subject_field(&form.reviewer);

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
    state
        .store
        .set_pull_metadata(&pull.id, &assignee, &reviewer, &milestone_id, &label_ids)
        .await?;
    notify_pull_assignment_changes(
        &state,
        &who.subject,
        &repo,
        &pull,
        "",
        &assignee,
        "",
        &reviewer,
    );

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
    Ok(redirect(&format!(
        "/r/{owner}/{name}/pulls/{}",
        pull.number
    )))
}

async fn clean_pull_metadata(
    state: &AppState,
    repo: &Repo,
    milestone_id: &str,
    labels: &[String],
) -> Result<(String, Vec<String>), AppError> {
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
    Ok((clean_milestone, clean_labels))
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
    let labels = state.store.list_labels(&repo.id).await?;
    let pull_labels = state.store.pull_labels(&pull.id).await?;
    let milestones = state.store.list_milestones(&repo.id).await?;
    let reviews = state.store.list_pull_reviews(&pull.id).await?;
    let review_comments = state.store.list_pull_review_comments(&pull.id).await?;
    let header = pr_header(&state, &repo, "pulls").await;
    let body = render_detail(
        &state,
        &repo,
        &pull,
        &labels,
        &pull_labels,
        &milestones,
        &reviews,
        &review_comments,
        &header,
        &who,
        &headers,
        &csrf,
        None,
    )
    .await?;
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
    let reviews = state.store.list_pull_reviews(&pull.id).await?;
    let review_summary = review_summary(&reviews);
    if repo.require_approval && review_summary.approvals.is_empty() {
        let csrf = auth::new_csrf_token();
        let header = pr_header(&state, &repo, "pulls").await;
        let body = render_detail_with_fresh_metadata(
            &state,
            &repo,
            &pull,
            &header,
            &who,
            &headers,
            &csrf,
            Some("This repository requires at least one approval before merge."),
        )
        .await?;
        return Ok(html_with_csrf(
            StatusCode::BAD_REQUEST,
            page(
                &format!("{owner}/{name} · PR #{number}"),
                Some(&who.email),
                &body,
            ),
            &csrf,
        ));
    }
    let closing_commits = commits_for_closing(&state, &repo, &pull).await;
    let closing_issues = closing_issue_numbers(&pull.body, &closing_commits);

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
            close_linked_issues(&state, &repo, &closing_issues).await?;
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
            let body = render_detail_with_fresh_metadata(
                &state,
                &repo,
                &pull,
                &header,
                &who,
                &headers,
                &csrf,
                Some(&format!("Could not merge automatically: {reason}")),
            )
            .await?;
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

async fn render_detail_with_fresh_metadata(
    state: &AppState,
    repo: &Repo,
    pull: &Pull,
    header: &str,
    who: &Identity,
    headers: &HeaderMap,
    csrf: &str,
    error: Option<&str>,
) -> Result<String, AppError> {
    let labels = state.store.list_labels(&repo.id).await?;
    let pull_labels = state.store.pull_labels(&pull.id).await?;
    let milestones = state.store.list_milestones(&repo.id).await?;
    let reviews = state.store.list_pull_reviews(&pull.id).await?;
    let review_comments = state.store.list_pull_review_comments(&pull.id).await?;
    render_detail(
        state,
        repo,
        pull,
        &labels,
        &pull_labels,
        &milestones,
        &reviews,
        &review_comments,
        header,
        who,
        headers,
        csrf,
        error,
    )
    .await
}

async fn commits_for_closing(state: &AppState, repo: &Repo, pull: &Pull) -> Vec<CommitInfo> {
    state
        .git
        .commits_between(
            &repo.owner_sub,
            &repo.name,
            &pull.base,
            &pull.head,
            COMMIT_LIMIT,
        )
        .await
}

fn closing_issue_numbers(body: &str, commits: &[CommitInfo]) -> Vec<i64> {
    let mut found = BTreeSet::new();
    collect_closing_numbers(body, &mut found);
    for commit in commits {
        collect_closing_numbers(&commit.subject, &mut found);
    }
    found.into_iter().collect()
}

fn collect_closing_numbers(text: &str, out: &mut BTreeSet<i64>) {
    let words: Vec<&str> = text.split_whitespace().collect();
    for pair in words.windows(2) {
        let keyword = pair[0]
            .trim_matches(|c: char| !c.is_ascii_alphabetic())
            .to_ascii_lowercase();
        if !matches!(
            keyword.as_str(),
            "fix"
                | "fixes"
                | "fixed"
                | "close"
                | "closes"
                | "closed"
                | "resolve"
                | "resolves"
                | "resolved"
        ) {
            continue;
        }
        let issue = pair[1].trim_matches(|c: char| c == '.' || c == ',' || c == ';' || c == ')');
        if let Some(num) = issue.strip_prefix('#').and_then(|n| n.parse::<i64>().ok()) {
            out.insert(num);
        }
    }
}

async fn close_linked_issues(
    state: &AppState,
    repo: &Repo,
    numbers: &[i64],
) -> Result<(), AppError> {
    for number in numbers {
        let Some(issue) = state.store.get_issue(&repo.id, *number).await? else {
            continue;
        };
        if issue.is_open() {
            state
                .store
                .set_issue_state(&issue.id, "closed", now_secs())
                .await?;
            tracing::info!(
                repo = repo.id,
                issue = number,
                "issue auto-closed by pull merge"
            );
        }
    }
    Ok(())
}

// ===========================================================================
// POST /r/{owner}/{name}/pulls/{number}/review — add a review verdict
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct ReviewForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub verdict: String,
    #[serde(default)]
    pub body: String,
}

pub async fn review(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, number)): Path<(String, String, i64)>,
    Form(form): Form<ReviewForm>,
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
    if !can_review(&repo, &pull, &who, &headers) {
        return Err(AppError::Forbidden(
            "Only the repository owner, pull-request author, or an administrator can review."
                .to_string(),
        ));
    }
    let verdict = normalize_verdict(&form.verdict)?;
    let review_body = form.body.trim().chars().take(20_000).collect::<String>();
    state
        .store
        .create_pull_review(
            &format!("rv_{}", random_alnum(REVIEW_ID_LEN)),
            &pull.id,
            &who.subject,
            verdict,
            &review_body,
            now_secs(),
        )
        .await?;
    tracing::info!(
        repo = repo.id,
        number,
        reviewer = who.subject,
        verdict,
        "pull request reviewed"
    );
    let summary = if review_body.is_empty() {
        format!("Review verdict: {}", verdict.replace('_', " "))
    } else {
        review_body
    };
    notify_pull_author(&state, &who.subject, &repo, &pull, &summary);
    Ok(redirect(&format!("/r/{owner}/{name}/pulls/{number}")))
}

fn normalize_verdict(raw: &str) -> Result<&'static str, AppError> {
    match raw.trim() {
        "comment" => Ok("comment"),
        "approve" => Ok("approve"),
        "request_changes" => Ok("request_changes"),
        _ => Err(AppError::BadRequest(
            "Choose a valid review verdict.".to_string(),
        )),
    }
}

// ===========================================================================
// POST /r/{owner}/{name}/pulls/{number}/inline-comment — add anchored comment
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct InlineCommentForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub line: i64,
    #[serde(default)]
    pub body: String,
}

pub async fn inline_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, number)): Path<(String, String, i64)>,
    Form(form): Form<InlineCommentForm>,
) -> Result<Response, AppError> {
    add_inline_comment(&state, &headers, &owner, &name, number, &form).await?;
    Ok(redirect(&format!("/r/{owner}/{name}/pulls/{number}")))
}

/// JSON sibling of [`inline_comment`] backing the optimistic "click a diff line → comment" UX. Same
/// CSRF (double-submit), same reviewer/owner/admin gate, same audit; returns the stored comment so
/// the page can insert it without a reload. The form route above is unchanged for no-JS clients.
pub async fn inline_comment_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, number)): Path<(String, String, i64)>,
    Form(form): Form<InlineCommentForm>,
) -> Result<Response, AppError> {
    let comment = add_inline_comment(&state, &headers, &owner, &name, number, &form).await?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "path": comment.0,
        "line": comment.1,
        "author": comment.2,
        "body": comment.3,
    }))
    .into_response())
}

/// Shared core for both inline-comment routes: CSRF-check, load + authorize, validate, persist, and
/// audit. Returns `(path, line, author, body)` of the stored comment.
async fn add_inline_comment(
    state: &AppState,
    headers: &HeaderMap,
    owner: &str,
    name: &str,
    number: i64,
    form: &InlineCommentForm,
) -> Result<(String, i64, String, String), AppError> {
    if !auth::verify_csrf(headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(headers);
    let repo = load_visible_repo(state, &who, owner, name).await?;
    let pull = state
        .store
        .get_pull(&repo.id, number)
        .await?
        .ok_or_else(|| AppError::NotFound("No such pull request.".to_string()))?;
    if !can_review(&repo, &pull, &who, headers) {
        return Err(AppError::Forbidden(
            "Only the repository owner, pull-request author, or an administrator can comment."
                .to_string(),
        ));
    }
    let path = form.path.trim().chars().take(500).collect::<String>();
    let body = form.body.trim().chars().take(20_000).collect::<String>();
    if path.is_empty() || body.is_empty() {
        return Err(AppError::BadRequest(
            "Inline comments need a file path and a comment body.".to_string(),
        ));
    }
    let line = form.line.max(0);
    state
        .store
        .create_pull_review_comment(
            &format!("rc_{}", random_alnum(REVIEW_COMMENT_ID_LEN)),
            &pull.id,
            "",
            &path,
            line,
            &who.subject,
            &body,
            now_secs(),
        )
        .await?;
    tracing::info!(
        repo = repo.id,
        number,
        actor = who.subject,
        "pull inline comment added"
    );
    let summary = if line > 0 {
        format!("{path}:{line}: {body}")
    } else {
        format!("{path}: {body}")
    };
    notify_pull_author(state, &who.subject, &repo, &pull, &summary);
    Ok((path, line, who.subject, body))
}

// ===========================================================================
// POST /r/{owner}/{name}/pulls/{number}/metadata — labels/milestone
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct MetadataForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub assignee: String,
    #[serde(default)]
    pub reviewer: String,
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
    let pull = state
        .store
        .get_pull(&repo.id, number)
        .await?
        .ok_or_else(|| AppError::NotFound("No such pull request.".to_string()))?;
    if !can_gate(&repo, &pull, &who) && !auth::is_admin(&headers) {
        return Err(AppError::Forbidden(
            "Only the repository owner, pull-request author, or an administrator can edit metadata."
                .to_string(),
        ));
    }
    let (milestone_id, label_ids) =
        clean_pull_metadata(&state, &repo, &form.milestone_id, &form.labels).await?;
    let assignee = clean_subject_field(&form.assignee);
    let reviewer = clean_subject_field(&form.reviewer);
    state
        .store
        .set_pull_metadata(&pull.id, &assignee, &reviewer, &milestone_id, &label_ids)
        .await?;
    notify_pull_assignment_changes(
        &state,
        &who.subject,
        &repo,
        &pull,
        &pull.assignee_sub,
        &assignee,
        &pull.reviewer_sub,
        &reviewer,
    );
    tracing::info!(
        repo = repo.id,
        number,
        actor = who.subject,
        "pull metadata updated"
    );
    Ok(redirect(&format!("/r/{owner}/{name}/pulls/{number}")))
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
    tracing::info!(
        repo = repo.id,
        number,
        state = next,
        "pull request state changed"
    );
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
        let labels = state.store.list_labels(&repo.id).await.unwrap_or_default();
        let milestones = state
            .store
            .list_milestones(&repo.id)
            .await
            .unwrap_or_default();
        let metadata_fields = render_pull_metadata_fields(&labels, &milestones, "", "", "", &[]);

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
      {metadata_fields}
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
            metadata_fields = metadata_fields,
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
            format!(
                "<option value=\"{v}\"{sel}>{v}</option>",
                v = esc(b),
                sel = sel
            )
        })
        .collect::<String>();
    format!("<select name=\"{field}\" class=\"compare-picker__select\">{opts}</select>")
}

/// The PR list card.
fn render_list(
    repo: &Repo,
    header: &str,
    pulls: &[Pull],
    labels: &[Label],
    milestones: &[Milestone],
    pull_labels: &[(String, Label)],
    label_filter: &str,
    milestone_filter: &str,
) -> String {
    let filters = render_pr_filters(repo, labels, milestones, label_filter, milestone_filter);
    let list = if pulls.is_empty() {
        format!(
            "<li class=\"pr-item pr-item--empty\">\
               <div class=\"empty\">\
                 <svg class=\"empty__icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><circle cx=\"6\" cy=\"6\" r=\"3\"/><circle cx=\"6\" cy=\"18\" r=\"3\"/><path d=\"M18 9a9 9 0 0 1-9 9\"/><circle cx=\"18\" cy=\"6\" r=\"3\"/></svg>\
                 <div class=\"empty__title\">No pull requests yet</div>\
                 <div class=\"empty__text\">Compare two branches to open the first pull request.</div>\
                 <a class=\"btn btn-primary btn-sm\" href=\"/r/{owner}/{name}/compare\">New pull request</a>\
               </div>\
             </li>",
            owner = esc(&repo.owner_sub),
            name = esc(&repo.name),
        )
    } else {
        pulls
            .iter()
            .map(|p| {
                let labels_for_pull: Vec<Label> = pull_labels
                    .iter()
                    .filter(|(pull_id, _)| pull_id == &p.id)
                    .map(|(_, label)| label.clone())
                    .collect();
                render_pr_row(repo, p, &labels_for_pull, milestones)
            })
            .collect::<String>()
    };
    format!(
        r##"{header}
<div class="layout layout--repo">
  <section class="card">
    <div class="card__head">
      <h2>Pull requests</h2>
      <a class="btn btn-primary btn-sm" href="/r/{owner}/{name}/compare">New pull request</a>
    </div>
    <div class="card__body">{filters}<ul class="pr-list">{list}</ul></div>
  </section>
</div>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        filters = filters,
        list = list,
    )
}

fn render_pr_row(repo: &Repo, pull: &Pull, labels: &[Label], milestones: &[Milestone]) -> String {
    let (cls, label) = state_badge(pull);
    let label_chips = render_label_chips(labels);
    let milestone = milestones
        .iter()
        .find(|m| m.id == pull.milestone_id)
        .map(|m| format!(" · milestone {}", esc(&m.title)))
        .unwrap_or_default();
    let assignee = if pull.assignee_sub.is_empty() {
        String::new()
    } else {
        format!(" · assigned to {}", esc(&pull.assignee_sub))
    };
    let reviewer = if pull.reviewer_sub.is_empty() {
        String::new()
    } else {
        format!(" · reviewer {}", esc(&pull.reviewer_sub))
    };
    format!(
        r##"<li class="pr-item">
  <div class="pr-item__head">
    <span class="state-badge {cls}">{label}</span>
    <a class="pr-item__title" href="/r/{owner}/{name}/pulls/{number}">#{number} {title}</a>
  </div>
  <div class="label-row">{label_chips}</div>
  <span class="pr-item__meta">{head} &rarr; {base} · opened {when} by {author}{assignee}{reviewer}{milestone}</span>
</li>"##,
        cls = cls,
        label = label,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        number = pull.number,
        title = esc(&pull.title),
        label_chips = label_chips,
        head = esc(&pull.head),
        base = esc(&pull.base),
        when = esc(&fmt_ts(pull.created_at)),
        author = esc(&pull.author_sub),
        assignee = assignee,
        reviewer = reviewer,
        milestone = milestone,
    )
}

fn render_pr_filters(
    repo: &Repo,
    labels: &[Label],
    milestones: &[Milestone],
    label_filter: &str,
    milestone_filter: &str,
) -> String {
    if labels.is_empty() && milestones.is_empty() {
        return String::new();
    }
    format!(
        r##"<form method="get" action="/r/{owner}/{name}/pulls" class="compare-picker">
  <span class="compare-picker__label">label</span>
  <select name="label" class="compare-picker__select">{label_opts}</select>
  <span class="compare-picker__label">milestone</span>
  <select name="milestone" class="compare-picker__select">{milestone_opts}</select>
  <button class="btn btn-secondary btn-sm" type="submit">Filter</button>
</form>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        label_opts = render_label_options(labels, label_filter, "All labels"),
        milestone_opts = render_milestone_options(milestones, milestone_filter, "All milestones"),
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

fn render_pull_metadata_fields(
    labels: &[Label],
    milestones: &[Milestone],
    assignee: &str,
    reviewer: &str,
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
  <label for="pr-assignee">Assignee</label>
  <input type="text" id="pr-assignee" name="assignee" maxlength="128" value="{assignee}" autocomplete="off" spellcheck="false">
</div>
<div class="field">
  <label for="pr-reviewer">Reviewer</label>
  <input type="text" id="pr-reviewer" name="reviewer" maxlength="128" value="{reviewer}" autocomplete="off" spellcheck="false">
</div>
<div class="field">
  <label for="pr-milestone-id">Milestone</label>
  <select id="pr-milestone-id" name="milestone_id">{milestones}</select>
</div>
<div class="field">
  <label>Labels</label>
  <div class="check-list">{label_checks}</div>
</div>"##,
        assignee = esc(assignee),
        reviewer = esc(reviewer),
        milestones = render_milestone_options(milestones, milestone_id, "No milestone"),
        label_checks = label_checks,
    )
}

/// The PR detail page.
async fn render_detail(
    state: &AppState,
    repo: &Repo,
    pull: &Pull,
    labels: &[Label],
    pull_labels: &[Label],
    milestones: &[Milestone],
    reviews: &[PullReview],
    review_comments: &[PullReviewComment],
    header: &str,
    who: &Identity,
    headers: &HeaderMap,
    csrf: &str,
    error: Option<&str>,
) -> Result<String, AppError> {
    let (cls, label) = state_badge(pull);
    let error_block = error_block(error);
    let summary = review_summary(reviews);
    let review_badges = render_review_badges(&summary);
    let label_chips = render_label_chips(pull_labels);
    let milestone = milestones
        .iter()
        .find(|m| m.id == pull.milestone_id)
        .map(|m| esc(&m.title))
        .unwrap_or_else(|| "No milestone".to_string());
    let assignee = if pull.assignee_sub.is_empty() {
        "Unassigned".to_string()
    } else {
        esc(&pull.assignee_sub)
    };
    let reviewer = if pull.reviewer_sub.is_empty() {
        "No reviewer".to_string()
    } else {
        esc(&pull.reviewer_sub)
    };

    let body_html = if pull.body.trim().is_empty() {
        "<p class=\"muted\">No description provided.</p>".to_string()
    } else {
        format!(
            "<div class=\"markdown-body\">{}</div>",
            link_issue_refs(
                &crate::markdown::render(&pull.body),
                &repo.owner_sub,
                &repo.name,
            )
        )
    };

    // Commits + diff for the (still current) base..head range.
    let commits = state
        .git
        .commits_between(
            &repo.owner_sub,
            &repo.name,
            &pull.base,
            &pull.head,
            COMMIT_LIMIT,
        )
        .await;
    let diff = state
        .git
        .diff(&repo.owner_sub, &repo.name, &pull.base, &pull.head)
        .await
        .unwrap_or_default();
    let checks_card = match state
        .git
        .branch_oid(&repo.owner_sub, &repo.name, &pull.head)
        .await
    {
        Some(head_oid) => {
            let statuses = state
                .store
                .list_commit_statuses(&repo.id, &head_oid)
                .await?;
            let aggregate = state
                .store
                .aggregate_state_for_commit(&repo.id, &head_oid)
                .await?;
            render_checks_card(&head_oid, aggregate.as_deref(), &statuses)
        }
        None => String::new(),
    };
    let commits_card = render_commits_card(&commits);
    let diff_card = render_diff_card(&diff);
    let reviews_card =
        render_reviews_card(repo, reviews, review_comments, csrf, pull, who, headers);
    let metadata_form = if can_gate(repo, pull, who) || auth::is_admin(headers) {
        let fields = render_pull_metadata_fields(
            labels,
            milestones,
            &pull.assignee_sub,
            &pull.reviewer_sub,
            &pull.milestone_id,
            pull_labels,
        );
        format!(
            r##"<section class="card">
  <div class="card__head"><h2>Metadata</h2></div>
  <div class="card__body">
    <form method="post" action="/r/{owner}/{name}/pulls/{number}/metadata">
      <input type="hidden" name="csrf_token" value="{csrf}">
      {fields}
      <div class="actions">
        <button class="btn btn-secondary" type="submit">Save metadata</button>
      </div>
    </form>
  </div>
</section>"##,
            owner = esc(&repo.owner_sub),
            name = esc(&repo.name),
            number = pull.number,
            csrf = esc(csrf),
            fields = fields,
        )
    } else {
        String::new()
    };

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
        format!(
            "<p class=\"pr-status\">This pull request is {}.</p>",
            esc(label)
        )
    };

    // Progressive-enhancement config for the inline-comment affordance on diff lines. Read by the
    // JS layer; ignored (and hidden) when JavaScript is off — the standalone inline-comment form
    // below still posts to the form route.
    let pr_inline = format!(
        "<div id=\"pr-inline\" data-endpoint=\"/r/{owner}/{name}/pulls/{number}/inline-comment.json\" hidden></div>",
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        number = pull.number,
    );

    Ok(format!(
        r##"{header}
{pr_inline}
<div class="console__head">
  <div class="repo-title">
    <span class="state-badge {cls}" id="state-badge-main">{label}</span>
    <h1 class="pr-title">#{number} {title}</h1>
  </div>
  <p class="sub"><code>{head}</code> &rarr; <code>{base}</code> · opened {when} by {author} · assignee {assignee} · reviewer {reviewer} · milestone {milestone}</p>
  <div class="label-row">{label_chips}{review_badges}</div>
</div>
<section class="card">
  <div class="card__head"><h2>Description</h2></div>
  <div class="card__body">{body_html}</div>
</section>
{checks_card}
{commits_card}
{diff_card}
{reviews_card}
{metadata_form}
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
        assignee = assignee,
        reviewer = reviewer,
        milestone = milestone,
        label_chips = label_chips,
        review_badges = review_badges,
        body_html = body_html,
        checks_card = checks_card,
        reviews_card = reviews_card,
        metadata_form = metadata_form,
        error_block = error_block,
        actions = actions,
        pr_inline = pr_inline,
    ))
}

fn render_checks_card(
    head_oid: &str,
    aggregate: Option<&str>,
    statuses: &[CommitStatus],
) -> String {
    if statuses.is_empty() {
        return String::new();
    }
    let aggregate_dot = crate::handlers::commits::render_status_dot(aggregate);
    let rows = statuses
        .iter()
        .map(|status| {
            let dot = crate::handlers::commits::render_status_dot(Some(&status.state));
            let label = crate::handlers::commits::status_label(&status.state);
            let target = if !status.target_url.trim().is_empty()
                && crate::handlers::commits::safe_status_url(&status.target_url)
            {
                format!(
                    " · <a href=\"{url}\" rel=\"noopener noreferrer\">details</a>",
                    url = esc(&status.target_url)
                )
            } else {
                String::new()
            };
            let description = if status.description.trim().is_empty() {
                String::new()
            } else {
                format!(
                    "<div class=\"issue-item__body\">{}</div>",
                    esc(&status.description)
                )
            };
            format!(
                r##"<li class="issue-item commit-status-row">
  <div class="issue-item__meta">{dot}<span class="strong">{context}</span> · {state}{target}</div>
  {description}
</li>"##,
                dot = dot,
                context = esc(&status.context),
                state = esc(label),
                target = target,
                description = description,
            )
        })
        .collect::<String>();
    format!(
        r##"<section class="card">
  <div class="card__head"><h2>Checks {aggregate}</h2></div>
  <div class="card__body">
    <p class="muted">Head commit <code class="oid">{head}</code></p>
    <ul class="issue-list">{rows}</ul>
  </div>
</section>"##,
        aggregate = aggregate_dot,
        head = esc(&short_oid(head_oid)),
        rows = rows,
    )
}

struct ReviewSummary {
    approvals: Vec<String>,
    changes_requested: Vec<String>,
}

fn review_summary(reviews: &[PullReview]) -> ReviewSummary {
    let mut latest: BTreeMap<String, &PullReview> = BTreeMap::new();
    for review in reviews {
        latest.insert(review.reviewer_sub.clone(), review);
    }
    let mut approvals = Vec::new();
    let mut changes_requested = Vec::new();
    for (reviewer, review) in latest {
        match review.verdict.as_str() {
            "approve" => approvals.push(reviewer),
            "request_changes" => changes_requested.push(reviewer),
            _ => {}
        }
    }
    ReviewSummary {
        approvals,
        changes_requested,
    }
}

fn render_review_badges(summary: &ReviewSummary) -> String {
    let mut out = String::new();
    for reviewer in &summary.approvals {
        out.push_str(&format!(
            "<span class=\"state-badge state-badge--open verdict-pill verdict-pill--approve\">approved by {}</span>",
            esc(reviewer)
        ));
    }
    for reviewer in &summary.changes_requested {
        out.push_str(&format!(
            "<span class=\"state-badge state-badge--closed verdict-pill verdict-pill--changes\">changes requested by {}</span>",
            esc(reviewer)
        ));
    }
    out
}

fn render_reviews_card(
    repo: &Repo,
    reviews: &[PullReview],
    comments: &[PullReviewComment],
    csrf: &str,
    pull: &Pull,
    who: &Identity,
    headers: &HeaderMap,
) -> String {
    let review_rows = if reviews.is_empty() {
        "<li class=\"issue-item issue-item--empty\">No reviews yet.</li>".to_string()
    } else {
        reviews
            .iter()
            .map(|review| {
                let body = if review.body.trim().is_empty() {
                    String::new()
                } else {
                    format!(
                        "<div class=\"issue-item__body markdown-body\">{}</div>",
                        link_issue_refs(
                            &crate::markdown::render(&review.body),
                            &repo.owner_sub,
                            &repo.name,
                        )
                    )
                };
                format!(
                    r##"<li class="issue-item">
  <div class="issue-item__meta"><span>{reviewer}</span> {verdict} {when}</div>
  {body}
</li>"##,
                    reviewer = esc(&review.reviewer_sub),
                    verdict = esc(&review.verdict.replace('_', " ")),
                    when = esc(&fmt_ts(review.created_at)),
                    body = body,
                )
            })
            .collect::<String>()
    };
    let inline_rows = render_inline_threads(repo, comments);
    let forms = if can_review(repo, pull, who, headers) {
        format!(
            r##"<div class="layout layout--repo">
  <form method="post" action="/r/{owner}/{name}/pulls/{number}/review">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <div class="field">
      <label id="review-verdict-label">Verdict</label>
      <div class="verdict-picker" role="radiogroup" aria-labelledby="review-verdict-label">
        <label class="verdict-pill verdict-pill--comment"><input type="radio" name="verdict" value="comment" checked> Comment</label>
        <label class="verdict-pill verdict-pill--approve"><input type="radio" name="verdict" value="approve"> Approve</label>
        <label class="verdict-pill verdict-pill--changes"><input type="radio" name="verdict" value="request_changes"> Request changes</label>
      </div>
    </div>
    <div class="field">
      <label for="review-body">Review comment</label>
      <textarea id="review-body" name="body" class="issue-input"></textarea>
    </div>
    <div class="actions"><button class="btn btn-secondary" type="submit">Submit review</button></div>
  </form>
  <form method="post" action="/r/{owner}/{name}/pulls/{number}/inline-comment">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <div class="field">
      <label for="inline-path">File</label>
      <input type="text" id="inline-path" name="path" maxlength="500" required>
    </div>
    <div class="field">
      <label for="inline-line">Line</label>
      <input type="number" id="inline-line" name="line" min="0" value="0">
    </div>
    <div class="field">
      <label for="inline-body">Comment</label>
      <textarea id="inline-body" name="body" class="issue-input" required></textarea>
    </div>
    <div class="actions"><button class="btn btn-secondary" type="submit">Add inline comment</button></div>
  </form>
</div>"##,
            owner = esc(&repo.owner_sub),
            name = esc(&repo.name),
            number = pull.number,
            csrf = esc(csrf),
        )
    } else {
        String::new()
    };
    format!(
        r##"<section class="card">
  <div class="card__head"><h2>Reviews <span class="tab__count">{nreviews}</span></h2></div>
  <div class="card__body">
    <ul class="issue-list">{review_rows}</ul>
    <h3 class="section-subhead">Inline comments</h3>
    <ul class="issue-list" id="pr-inline-thread">{inline_rows}</ul>
    {forms}
  </div>
</section>"##,
        nreviews = reviews.len(),
        review_rows = review_rows,
        inline_rows = inline_rows,
        forms = forms,
    )
}

fn render_inline_threads(repo: &Repo, comments: &[PullReviewComment]) -> String {
    if comments.is_empty() {
        return "<li class=\"issue-item issue-item--empty\">No inline comments yet.</li>"
            .to_string();
    }
    comments
        .iter()
        .map(|comment| {
            format!(
                r##"<li class="issue-item">
  <div class="issue-item__meta"><span>{path}:{line}</span> · {author} commented {when}</div>
  <div class="issue-item__body markdown-body">{body}</div>
</li>"##,
                path = esc(&comment.path),
                line = comment.line,
                author = esc(&comment.author_sub),
                when = esc(&fmt_ts(comment.created_at)),
                body = link_issue_refs(
                    &crate::markdown::render(&comment.body),
                    &repo.owner_sub,
                    &repo.name,
                ),
            )
        })
        .collect::<String>()
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
        format!(
            "<div class=\"card__body card__body--code\">{}</div>",
            render_diff(diff)
        )
    };
    format!(
        r##"<section class="card">
  <div class="card__head"><h2>Diff</h2></div>
  {inner}
</section>"##
    )
}

/// One file's slice of a unified diff (its header line + body lines).
struct DiffFile {
    path: String,
    lines: Vec<String>,
}

/// Render a unified diff into per-file **collapsible** blocks, each a line-classified, HTML-escaped
/// table. Code rows carry `data-line` (their line number in the new file, tracked from the hunk
/// headers) so the progressive-enhancement layer can anchor an inline comment to a line — with
/// JavaScript off the standalone inline-comment form still works. Every byte is HTML-escaped.
fn render_diff(diff: &str) -> String {
    let text = diff.strip_suffix('\n').unwrap_or(diff);

    // Group into files. A new file starts at a `diff --git ` line; any preamble before the first
    // such line forms an initial unnamed group so nothing is ever dropped.
    let mut files: Vec<DiffFile> = Vec::new();
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw).to_string();
        if line.starts_with("diff --git ") {
            files.push(DiffFile {
                path: path_from_diff_header(&line),
                lines: vec![line],
            });
        } else {
            if files.is_empty() {
                files.push(DiffFile {
                    path: String::new(),
                    lines: Vec::new(),
                });
            }
            let f = files.last_mut().expect("a file group exists");
            if f.path.is_empty() {
                if let Some(p) = path_from_plus_header(&line) {
                    f.path = p;
                }
            }
            f.lines.push(line);
        }
    }

    let mut out = String::from(
        "<div class=\"diff-toolbar\" data-diff-toolbar></div><div class=\"diff-files\">",
    );
    for f in &files {
        out.push_str(&render_diff_file(f));
    }
    out.push_str("</div>");
    out
}

/// Render one file block: a `<details>` with the file path + add/del counts in its summary, then the
/// line-classified table.
fn render_diff_file(file: &DiffFile) -> String {
    let mut rows = String::new();
    let mut new_line: Option<i64> = None; // current line number in the new file (inside a hunk)
    let mut adds = 0i64;
    let mut dels = 0i64;
    for line in &file.lines {
        let (row_cls, gutter) = classify_diff_line(line);
        let mut attr = String::new();
        if line.starts_with("@@") {
            new_line = parse_hunk_new_start(line);
        } else if row_cls == "diff-row--add" {
            adds += 1;
            if let Some(n) = new_line {
                attr = format!(" data-line=\"{n}\"");
                new_line = Some(n + 1);
            }
        } else if row_cls == "diff-row--ctx" {
            if let Some(n) = new_line {
                attr = format!(" data-line=\"{n}\"");
                new_line = Some(n + 1);
            }
        } else if row_cls == "diff-row--del" {
            dels += 1;
        }
        rows.push_str(&format!(
            "<tr class=\"diff-row {row_cls}\"{attr}>\
               <td class=\"diff-gutter\">{gutter}</td>\
               <td class=\"diff-code\">{code}</td>\
             </tr>",
            row_cls = row_cls,
            attr = attr,
            gutter = gutter,
            code = esc(line),
        ));
    }
    let display = if file.path.is_empty() {
        "changed file".to_string()
    } else {
        file.path.clone()
    };
    format!(
        "<details class=\"diff-file\" data-path=\"{path}\" open>\
           <summary class=\"diff-file__summary\">\
             <span class=\"diff-file__path\">{path}</span>\
             <span class=\"diff-file__stat\"><span class=\"diff-add\">+{adds}</span> <span class=\"diff-del\">-{dels}</span></span>\
           </summary>\
           <table class=\"diff\"><tbody>{rows}</tbody></table>\
         </details>",
        path = esc(&display),
        adds = adds,
        dels = dels,
        rows = rows,
    )
}

/// Extract the new-file path from a `diff --git a/x b/y` header (the `b/` side; the post-change name).
fn path_from_diff_header(line: &str) -> String {
    line.split_whitespace()
        .last()
        .map(|s| s.strip_prefix("b/").unwrap_or(s).to_string())
        .unwrap_or_default()
}

/// Extract the new-file path from a `+++ b/path` header (ignoring `/dev/null` deletions).
fn path_from_plus_header(line: &str) -> Option<String> {
    let rest = line.strip_prefix("+++ ")?;
    let rest = rest.strip_prefix("b/").unwrap_or(rest).trim();
    if rest.is_empty() || rest == "/dev/null" {
        return None;
    }
    Some(rest.to_string())
}

/// Parse the new-file starting line from a `@@ -a,b +c,d @@` hunk header (returns `c`).
fn parse_hunk_new_start(line: &str) -> Option<i64> {
    let plus = line.split_whitespace().find(|t| t.starts_with('+'))?;
    plus.trim_start_matches('+')
        .split(',')
        .next()?
        .parse::<i64>()
        .ok()
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
            require_approval: false,
            protect_default_branch: false,
            forked_from_id: String::new(),
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
