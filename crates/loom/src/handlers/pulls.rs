//! Pull requests: branch compare (commits ahead + diff), the PR entity (list/detail/
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
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use serde::Deserialize;

use crate::auth::{self, Identity};
use crate::config::{COMMIT_LIMIT, MAX_BLOB_RENDER_BYTES};
use crate::error::AppError;
use crate::gitops::{CommitInfo, MergeStrategy, Mergeability as GitMergeability};
use crate::handlers::repos::{
    can_write_repo, load_visible_repo, render_repo_header, validate_branch_name,
};
use crate::handlers::{
    accepts_json, esc, fmt_rel, fmt_ts, html_with_csrf, is_valid_reaction_emoji, page,
    reaction_summaries_json, redirect, render_reactions, short_oid, state_icon,
    REACTION_TARGET_COMMENT, REACTION_TARGET_PULL,
};
use crate::model::{
    CommitStatus, Label, Milestone, PrFileViewed, PrThreadResolved, Pull, PullReview,
    PullReviewComment, ReactionSummary, Repo,
};
use crate::webhooks;
use crate::{now_secs, random_alnum, AppState};

const PULL_ID_LEN: usize = 16;
const REVIEW_ID_LEN: usize = 16;
const REVIEW_COMMENT_ID_LEN: usize = 16;
const REACTION_ID_LEN: usize = 16;
const KLAXON_SOURCE: &str = "loom";
const NOTIFY_TITLE_CHARS: usize = 96;
const NOTIFY_BODY_CHARS: usize = 240;
const MERGEABILITY_TIMEOUT_SECS: u64 = 3;
const CODEOWNERS_PATHS: [&str; 3] = ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrMergeability {
    Clean,
    Conflicting,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CodeOwnerRule {
    pattern: String,
    owners: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CodeOwnerFile {
    path: String,
    rules: Vec<CodeOwnerRule>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CodeOwnerMatchedGroup {
    pattern: String,
    owners: Vec<String>,
    paths: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CodeOwnerEvaluation {
    enabled: bool,
    source_path: Option<String>,
    matched_groups: Vec<CodeOwnerMatchedGroup>,
    pending_groups: Vec<CodeOwnerMatchedGroup>,
}

impl CodeOwnerEvaluation {
    fn disabled() -> Self {
        Self {
            enabled: false,
            source_path: None,
            matched_groups: Vec::new(),
            pending_groups: Vec::new(),
        }
    }

    fn satisfied(&self) -> bool {
        !self.enabled || self.pending_groups.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReviewRequirements {
    approval_count: usize,
    required_approvals: usize,
    approval_satisfied: bool,
    codeowners: CodeOwnerEvaluation,
}

impl ReviewRequirements {
    fn satisfied(&self) -> bool {
        self.approval_satisfied && self.codeowners.satisfied()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DiffView {
    Unified,
    Split,
}

impl DiffView {
    fn from_param(raw: Option<&str>) -> Self {
        match raw.unwrap_or_default().trim() {
            "split" => Self::Split,
            _ => Self::Unified,
        }
    }

    fn as_param(self) -> &'static str {
        match self {
            Self::Unified => "unified",
            Self::Split => "split",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DiffOptions {
    view: DiffView,
    ignore_whitespace: bool,
}

impl DiffOptions {
    pub(crate) fn ignore_whitespace(self) -> bool {
        self.ignore_whitespace
    }
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self {
            view: DiffView::Unified,
            ignore_whitespace: false,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct DiffQuery {
    #[serde(default)]
    pub diff: Option<String>,
    #[serde(default)]
    pub w: Option<String>,
}

impl DiffQuery {
    pub(crate) fn options(&self) -> DiffOptions {
        DiffOptions {
            view: DiffView::from_param(self.diff.as_deref()),
            ignore_whitespace: truthy_query_flag(self.w.as_deref()),
        }
    }
}

pub(crate) struct DiffControls {
    action: String,
    hidden: Vec<(String, String)>,
}

impl DiffControls {
    pub(crate) fn new(action: String) -> Self {
        Self {
            action,
            hidden: Vec::new(),
        }
    }

    fn with_hidden(mut self, name: &str, value: &str) -> Self {
        self.hidden.push((name.to_string(), value.to_string()));
        self
    }
}

fn truthy_query_flag(raw: Option<&str>) -> bool {
    matches!(raw.unwrap_or_default().trim(), "1" | "true" | "on" | "yes")
}

// ===========================================================================
// Shared helpers
// ===========================================================================

/// Render the repo header on the "Pull requests" tab (fetches the open issue/PR badge counts).
async fn pr_header(state: &AppState, repo: &Repo, active: &str) -> String {
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
        active,
    )
}

type ReactionMap = BTreeMap<String, Vec<ReactionSummary>>;

async fn load_pull_reactions(
    state: &AppState,
    pull: &Pull,
    comments: &[PullReviewComment],
    viewer_sub: &str,
) -> Result<(Vec<ReactionSummary>, ReactionMap), AppError> {
    let pull_reactions = state
        .store
        .list_reactions_for_target(REACTION_TARGET_PULL, &pull.id, viewer_sub)
        .await?;
    let mut comment_reactions = ReactionMap::new();
    for comment in comments.iter().filter(|comment| !comment.pending) {
        comment_reactions.insert(
            comment.id.clone(),
            state
                .store
                .list_reactions_for_target(REACTION_TARGET_COMMENT, &comment.id, viewer_sub)
                .await?,
        );
    }
    Ok((pull_reactions, comment_reactions))
}

/// True when `who` may merge/close a PR: a repo writer or the PR author.
fn can_gate(pull: &Pull, who: &Identity, repo_writer: bool) -> bool {
    repo_writer || pull.author_sub == who.subject
}

fn can_review(pull: &Pull, who: &Identity, repo_writer: bool) -> bool {
    can_gate(pull, who, repo_writer)
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
    #[serde(default)]
    pub diff: Option<String>,
    #[serde(default)]
    pub w: Option<String>,
}

impl CompareQuery {
    fn diff_options(&self) -> DiffOptions {
        DiffQuery {
            diff: self.diff.clone(),
            w: self.w.clone(),
        }
        .options()
    }
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
    let diff_options = q.diff_options();
    let head = q.head.unwrap_or_default();

    let body = render_compare(
        &state,
        &repo,
        &branches,
        &base,
        &head,
        diff_options,
        &csrf,
        None,
    )
    .await;
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
    pub state: Option<String>,
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
    let state_filter = normalize_pull_state_filter(q.state.as_deref());
    let label_filter = q.label.unwrap_or_default();
    let milestone_filter = q.milestone.unwrap_or_default();
    let pulls = state
        .store
        .list_pulls_filtered(&repo.id, &label_filter, &milestone_filter)
        .await?;
    let pulls = filter_pulls_by_state(pulls, &state_filter);
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
        &state_filter,
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
    #[serde(default)]
    pub is_draft: String,
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
            DiffOptions::default(),
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
    let is_draft = form.is_draft == "on";

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
            is_draft,
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
    webhooks::emit_pull_request(&state, &repo, "opened", &who.subject, &pull, &pull.state);

    // Audit: no dedicated AuditSink in this crate — tracing is the audit surface (as with repo
    // create / issue open / PAT mint).
    tracing::info!(
        repo = repo.id,
        number = pull.number,
        base = base,
        head = head,
        author = who.subject,
        draft = is_draft,
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
    Query(q): Query<DiffQuery>,
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
    let review_comments = state
        .store
        .list_pull_review_comments_for_viewer(&pull.id, &who.subject)
        .await?;
    let (pull_reactions, comment_reactions) =
        load_pull_reactions(&state, &pull, &review_comments, &who.subject).await?;
    let thread_resolutions = state.store.list_pr_thread_resolved(&pull.id).await?;
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
        &pull_reactions,
        &comment_reactions,
        &thread_resolutions,
        &header,
        &who,
        &headers,
        &csrf,
        q.options(),
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
    #[serde(default)]
    pub merge_method: String,
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
    let strategy = parse_merge_strategy(&form.merge_method)?;
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let pull = state
        .store
        .get_pull(&repo.id, number)
        .await?
        .ok_or_else(|| AppError::NotFound("No such pull request.".to_string()))?;

    let repo_writer = can_write_repo(&state, &repo, &who, &headers).await?;
    // Author/maintainer gate.
    if !can_gate(&pull, &who, repo_writer) {
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
    let review_requirements =
        evaluate_review_requirements(&state, &repo, &pull, &review_summary, None).await;
    let mergeability = preflight_mergeability(&state, &repo, &pull).await;
    let blockers = merge_blockers(&pull, &review_requirements, mergeability);
    if !blockers.is_empty() {
        let csrf = auth::new_csrf_token();
        let header = pr_header(&state, &repo, "pulls").await;
        let message = merge_blocker_message(&blockers);
        let body = render_detail_with_fresh_metadata(
            &state,
            &repo,
            &pull,
            &header,
            &who,
            &headers,
            &csrf,
            Some(&message),
        )
        .await?;
        let status = if matches!(mergeability, PrMergeability::Conflicting) {
            StatusCode::CONFLICT
        } else {
            StatusCode::BAD_REQUEST
        };
        return Ok(html_with_csrf(
            status,
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

    let message = merge_message(&pull, strategy);
    // Perform the on-disk merge FIRST; only mark the PR merged once git has advanced the ref.
    match state
        .git
        .merge_with_strategy(
            &repo.owner_sub,
            &repo.name,
            &pull.base,
            &pull.head,
            &message,
            &who.subject,
            &who.email,
            strategy,
        )
        .await
    {
        Ok(outcome) => {
            let merged_at = now_secs();
            let _ = state.store.merge_pull(&pull.id, merged_at).await?;
            close_linked_issues(&state, &repo, &closing_issues).await?;
            webhooks::emit_pull_request(&state, &repo, "merged", &who.subject, &pull, "merged");
            tracing::info!(
                repo = repo.id,
                number = pull.number,
                base = pull.base,
                head = pull.head,
                strategy = ?strategy,
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

fn parse_merge_strategy(raw: &str) -> Result<MergeStrategy, AppError> {
    match raw.trim() {
        "" | "merge" => Ok(MergeStrategy::Merge),
        "squash" => Ok(MergeStrategy::Squash),
        "rebase" => Ok(MergeStrategy::Rebase),
        _ => Err(AppError::BadRequest(
            "Choose a valid merge method.".to_string(),
        )),
    }
}

fn merge_message(pull: &Pull, strategy: MergeStrategy) -> String {
    match strategy {
        MergeStrategy::Merge => format!(
            "Merge pull request #{} from {}\n\n{}",
            pull.number, pull.head, pull.title,
        ),
        MergeStrategy::Squash => {
            let title = pull.title.trim();
            let body = pull.body.trim();
            if body.is_empty() {
                title.to_string()
            } else {
                format!("{title}\n\n{body}")
            }
        }
        MergeStrategy::Rebase => String::new(),
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
    let review_comments = state
        .store
        .list_pull_review_comments_for_viewer(&pull.id, &who.subject)
        .await?;
    let (pull_reactions, comment_reactions) =
        load_pull_reactions(state, pull, &review_comments, &who.subject).await?;
    let thread_resolutions = state.store.list_pr_thread_resolved(&pull.id).await?;
    render_detail(
        state,
        repo,
        pull,
        &labels,
        &pull_labels,
        &milestones,
        &reviews,
        &review_comments,
        &pull_reactions,
        &comment_reactions,
        &thread_resolutions,
        header,
        who,
        headers,
        csrf,
        DiffOptions::default(),
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

async fn preflight_mergeability(state: &AppState, repo: &Repo, pull: &Pull) -> PrMergeability {
    match state
        .git
        .mergeability(
            &repo.owner_sub,
            &repo.name,
            &pull.base,
            &pull.head,
            Duration::from_secs(MERGEABILITY_TIMEOUT_SECS),
        )
        .await
    {
        Ok(GitMergeability::Clean) => PrMergeability::Clean,
        Ok(GitMergeability::Conflicting) => PrMergeability::Conflicting,
        Err(reason) => {
            tracing::warn!(
                repo = repo.id.as_str(),
                number = pull.number,
                base = pull.base.as_str(),
                head = pull.head.as_str(),
                reason = reason.as_str(),
                "pull request mergeability check unavailable"
            );
            PrMergeability::Unknown
        }
    }
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
    let repo_writer = can_write_repo(&state, &repo, &who, &headers).await?;
    if !can_review(&pull, &who, repo_writer) {
        return Err(AppError::Forbidden(
            "Only the repository owner, pull-request author, or an administrator can review."
                .to_string(),
        ));
    }
    let verdict = normalize_verdict(&form.verdict)?;
    let review_body = form.body.trim().chars().take(20_000).collect::<String>();
    let (_review, published_pending) = state
        .store
        .create_pull_review_with_pending_comments(
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
        published_pending,
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
    #[serde(default)]
    pub mode: String,
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
        "path": comment.path,
        "line": comment.line,
        "author": comment.author_sub,
        "body": comment.body,
        "pending": comment.pending,
    }))
    .into_response())
}

/// Shared core for both inline-comment routes: CSRF-check, load + authorize, validate, persist, and
/// audit. Returns the stored comment.
async fn add_inline_comment(
    state: &AppState,
    headers: &HeaderMap,
    owner: &str,
    name: &str,
    number: i64,
    form: &InlineCommentForm,
) -> Result<PullReviewComment, AppError> {
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
    let repo_writer = can_write_repo(state, &repo, &who, headers).await?;
    if !can_review(&pull, &who, repo_writer) {
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
    let anchor = inline_comment_anchor(state, &repo, &pull, &path, line).await;
    let pending = form.mode.trim() == "pending";
    let mut comment = if pending {
        state
            .store
            .create_pending_pull_review_comment(
                &format!("rc_{}", random_alnum(REVIEW_COMMENT_ID_LEN)),
                &pull.id,
                &path,
                line,
                &who.subject,
                &body,
                now_secs(),
            )
            .await?
    } else {
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
            .await?
    };
    if let Some((anchor_head_oid, anchor_text)) = anchor {
        if state
            .store
            .set_pull_review_comment_anchor(&comment.id, &anchor_head_oid, &anchor_text)
            .await?
        {
            comment.anchor_head_oid = anchor_head_oid;
            comment.anchor_text = anchor_text;
        }
    }
    tracing::info!(
        repo = repo.id,
        number,
        actor = who.subject,
        pending,
        "pull inline comment added"
    );
    if !pending {
        let summary = if line > 0 {
            format!("{path}:{line}: {body}")
        } else {
            format!("{path}: {body}")
        };
        notify_pull_author(state, &who.subject, &repo, &pull, &summary);
    }
    Ok(comment)
}

async fn inline_comment_anchor(
    state: &AppState,
    repo: &Repo,
    pull: &Pull,
    path: &str,
    line: i64,
) -> Option<(String, String)> {
    if line <= 0 {
        return None;
    }
    let head_oid = state
        .git
        .branch_oid(&repo.owner_sub, &repo.name, &pull.head)
        .await?;
    let blob = state
        .git
        .read_blob(&repo.owner_sub, &repo.name, &head_oid, path)
        .await?;
    let text = line_text_from_blob(&blob, line)?;
    Some((head_oid, text))
}

fn line_text_from_blob(blob: &[u8], line: i64) -> Option<String> {
    if line <= 0 {
        return None;
    }
    let text = std::str::from_utf8(blob).ok()?;
    text.lines()
        .nth(line as usize - 1)
        .map(|line| line.trim_end_matches('\r').to_string())
}

#[derive(Debug, Deserialize)]
pub struct ApplySuggestionForm {
    #[serde(default)]
    pub csrf_token: String,
}

pub async fn apply_suggestion(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, number, comment_id)): Path<(String, String, i64, String)>,
    Form(form): Form<ApplySuggestionForm>,
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
    let repo_writer = can_write_repo(&state, &repo, &who, &headers).await?;
    if !can_gate(&pull, &who, repo_writer) {
        return Err(AppError::Forbidden(
            "Only the pull-request author, a repository writer, or an administrator can apply suggestions."
                .to_string(),
        ));
    }
    if !pull.is_open() {
        return Err(AppError::BadRequest(
            "This pull request is no longer open.".to_string(),
        ));
    }

    let comment = state
        .store
        .list_pull_review_comments(&pull.id)
        .await?
        .into_iter()
        .find(|comment| comment.id == comment_id)
        .ok_or_else(|| AppError::NotFound("No such review comment.".to_string()))?;
    if comment.applied {
        return Err(AppError::BadRequest(
            "This suggestion has already been applied.".to_string(),
        ));
    }
    if comment.line <= 0 || comment.anchor_head_oid.is_empty() {
        return Err(AppError::BadRequest(
            "This suggestion is missing a stable line anchor. Add a new review comment and try again."
                .to_string(),
        ));
    }
    let suggestion = crate::markdown::extract_first_suggestion(&comment.body).ok_or_else(|| {
        AppError::BadRequest("This review comment does not contain a suggestion.".to_string())
    })?;

    let commit = state
        .git
        .apply_suggestion(
            &repo.owner_sub,
            &repo.name,
            &pull.head,
            &comment.path,
            comment.line as usize,
            &comment.anchor_head_oid,
            &comment.anchor_text,
            &suggestion,
            "Apply suggestion from code review",
            &who.subject,
            &who.email,
        )
        .await
        .map_err(AppError::Conflict)?;
    if !state
        .store
        .mark_pull_review_comment_applied(&comment.id)
        .await?
    {
        return Err(AppError::NotFound("No such review comment.".to_string()));
    }
    webhooks::emit_push(&state, &repo, &who.subject);
    tracing::info!(
        repo = repo.id,
        number,
        comment = comment.id,
        commit,
        actor = who.subject,
        "pull suggestion applied"
    );
    Ok(redirect(&format!("/r/{owner}/{name}/pulls/{number}")))
}

// ===========================================================================
// POST /r/{owner}/{name}/pulls/{number}/reactions — toggle PR reaction
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct ReactionForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub emoji: String,
}

pub async fn react_pull(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, number)): Path<(String, String, i64)>,
    Form(form): Form<ReactionForm>,
) -> Result<Response, AppError> {
    let (target_id, emoji, selected, reactions) =
        apply_pull_reaction(&state, &headers, &owner, &name, number, &form).await?;
    if accepts_json(&headers) {
        return Ok(Json(serde_json::json!({
            "ok": true,
            "target_type": REACTION_TARGET_PULL,
            "target_id": target_id,
            "emoji": emoji,
            "selected": selected,
            "reactions": reaction_summaries_json(&reactions),
        }))
        .into_response());
    }
    Ok(redirect(&format!("/r/{owner}/{name}/pulls/{number}")))
}

async fn apply_pull_reaction(
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
    let pull = state
        .store
        .get_pull(&repo.id, number)
        .await?
        .ok_or_else(|| AppError::NotFound("No such pull request.".to_string()))?;
    let selected = state
        .store
        .toggle_reaction(
            &format!("rx_{}", random_alnum(REACTION_ID_LEN)),
            REACTION_TARGET_PULL,
            &pull.id,
            &who.subject,
            &emoji,
            now_secs(),
        )
        .await?;
    let reactions = state
        .store
        .list_reactions_for_target(REACTION_TARGET_PULL, &pull.id, &who.subject)
        .await?;
    tracing::info!(
        repo = repo.id,
        number,
        target = pull.id,
        emoji = emoji,
        selected,
        actor = who.subject,
        "pull reaction toggled"
    );
    Ok((pull.id, emoji, selected, reactions))
}

// ===========================================================================
// POST /r/{owner}/{name}/pulls/{number}/comments/{comment_id}/reactions
// ===========================================================================

pub async fn react_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, number, comment_id)): Path<(String, String, i64, String)>,
    Form(form): Form<ReactionForm>,
) -> Result<Response, AppError> {
    let (target_id, emoji, selected, reactions) =
        apply_pull_comment_reaction(&state, &headers, &owner, &name, number, &comment_id, &form)
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
    Ok(redirect(&format!("/r/{owner}/{name}/pulls/{number}")))
}

async fn apply_pull_comment_reaction(
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
    let pull = state
        .store
        .get_pull(&repo.id, number)
        .await?
        .ok_or_else(|| AppError::NotFound("No such pull request.".to_string()))?;
    let comments = state.store.list_pull_review_comments(&pull.id).await?;
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
        "pull comment reaction toggled"
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
// POST /r/{owner}/{name}/pulls/{number}/file-viewed — per-user file viewed state
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct FileViewedForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub file_path: String,
    #[serde(default)]
    pub viewed: String,
}

pub async fn file_viewed(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, number)): Path<(String, String, i64)>,
    Form(form): Form<FileViewedForm>,
) -> Result<Response, AppError> {
    let viewed = apply_file_viewed(&state, &headers, &owner, &name, number, &form).await?;
    if accepts_json(&headers) {
        return Ok(Json(serde_json::json!({
            "ok": true,
            "file_path": viewed.file_path,
            "viewed": viewed.viewed,
            "updated_at": viewed.updated_at,
        }))
        .into_response());
    }
    Ok(redirect(&format!("/r/{owner}/{name}/pulls/{number}")))
}

async fn apply_file_viewed(
    state: &AppState,
    headers: &HeaderMap,
    owner: &str,
    name: &str,
    number: i64,
    form: &FileViewedForm,
) -> Result<PrFileViewed, AppError> {
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
    let file_path = form
        .file_path
        .trim()
        .chars()
        .take(1_000)
        .collect::<String>();
    if file_path.is_empty() {
        return Err(AppError::BadRequest(
            "Viewed state needs a file path.".to_string(),
        ));
    }
    let viewed = matches!(form.viewed.as_str(), "true" | "on" | "1" | "yes");
    let row = state
        .store
        .set_pr_file_viewed(&pull.id, &who.subject, &file_path, viewed, now_secs())
        .await?;
    tracing::info!(
        repo = repo.id,
        number,
        actor = who.subject,
        file_path = file_path,
        viewed = viewed,
        "pull file viewed state changed"
    );
    Ok(row)
}

// ===========================================================================
// POST /r/{owner}/{name}/pulls/{number}/thread/(un)resolve — conversation state
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct ThreadResolveForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub thread_key: String,
}

pub async fn resolve_thread(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, number)): Path<(String, String, i64)>,
    Form(form): Form<ThreadResolveForm>,
) -> Result<Response, AppError> {
    thread_resolution_response(&state, &headers, &owner, &name, number, &form, true).await
}

pub async fn unresolve_thread(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, number)): Path<(String, String, i64)>,
    Form(form): Form<ThreadResolveForm>,
) -> Result<Response, AppError> {
    thread_resolution_response(&state, &headers, &owner, &name, number, &form, false).await
}

async fn thread_resolution_response(
    state: &AppState,
    headers: &HeaderMap,
    owner: &str,
    name: &str,
    number: i64,
    form: &ThreadResolveForm,
    resolved: bool,
) -> Result<Response, AppError> {
    let (row, unresolved_count) =
        apply_thread_resolution(state, headers, owner, name, number, form, resolved).await?;
    if accepts_json(headers) {
        return Ok(Json(serde_json::json!({
            "ok": true,
            "thread_key": row.thread_key,
            "resolved": row.resolved,
            "resolved_by": row.resolved_by,
            "resolved_at": row.resolved_at,
            "unresolved_count": unresolved_count,
        }))
        .into_response());
    }
    Ok(redirect(&format!("/r/{owner}/{name}/pulls/{number}")))
}

async fn apply_thread_resolution(
    state: &AppState,
    headers: &HeaderMap,
    owner: &str,
    name: &str,
    number: i64,
    form: &ThreadResolveForm,
    resolved: bool,
) -> Result<(PrThreadResolved, usize), AppError> {
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
    let repo_writer = can_write_repo(state, &repo, &who, headers).await?;
    if !can_review(&pull, &who, repo_writer) {
        return Err(AppError::Forbidden(
            "Only the repository owner, pull-request author, or an administrator can resolve conversations."
                .to_string(),
        ));
    }

    let thread_key = form.thread_key.trim().chars().take(700).collect::<String>();
    if thread_key.is_empty() {
        return Err(AppError::BadRequest(
            "Choose an inline conversation to update.".to_string(),
        ));
    }
    let published_comments = state.store.list_pull_review_comments(&pull.id).await?;
    if !published_comments
        .iter()
        .any(|comment| inline_thread_key(comment) == thread_key)
    {
        return Err(AppError::BadRequest(
            "Choose an existing inline conversation.".to_string(),
        ));
    }

    let row = state
        .store
        .set_pr_thread_resolved(&pull.id, &thread_key, resolved, &who.subject, now_secs())
        .await?;
    let resolutions = state.store.list_pr_thread_resolved(&pull.id).await?;
    let unresolved_count = unresolved_thread_count(&published_comments, &resolutions);
    tracing::info!(
        repo = repo.id,
        number,
        actor = who.subject,
        thread_key = thread_key,
        resolved,
        "pull inline conversation resolution changed"
    );
    Ok((row, unresolved_count))
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
    let repo_writer = can_write_repo(&state, &repo, &who, &headers).await?;
    if !can_gate(&pull, &who, repo_writer) {
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

    let repo_writer = can_write_repo(&state, &repo, &who, &headers).await?;
    if !can_gate(&pull, &who, repo_writer) {
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
    let action = if next == "closed" {
        "closed"
    } else {
        "reopened"
    };
    webhooks::emit_pull_request(&state, &repo, action, &who.subject, &pull, next);
    tracing::info!(
        repo = repo.id,
        number,
        state = next,
        "pull request state changed"
    );
    Ok(redirect(&format!("/r/{owner}/{name}/pulls/{number}")))
}

// ===========================================================================
// POST /r/{owner}/{name}/pulls/{number}/ready|draft — draft state
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct DraftForm {
    #[serde(default)]
    pub csrf_token: String,
}

pub async fn ready_for_review(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, number)): Path<(String, String, i64)>,
    Form(form): Form<DraftForm>,
) -> Result<Response, AppError> {
    set_draft_state(state, headers, owner, name, number, form.csrf_token, false).await
}

pub async fn convert_to_draft(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, number)): Path<(String, String, i64)>,
    Form(form): Form<DraftForm>,
) -> Result<Response, AppError> {
    set_draft_state(state, headers, owner, name, number, form.csrf_token, true).await
}

async fn set_draft_state(
    state: AppState,
    headers: HeaderMap,
    owner: String,
    name: String,
    number: i64,
    csrf_token: String,
    is_draft: bool,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &csrf_token) {
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

    let repo_writer = can_write_repo(&state, &repo, &who, &headers).await?;
    if !can_gate(&pull, &who, repo_writer) {
        return Err(AppError::Forbidden(
            "Only the repository owner or the pull-request author can change this.".to_string(),
        ));
    }
    if !pull.is_open() {
        return Err(AppError::BadRequest(
            "Only open pull requests can change draft state.".to_string(),
        ));
    }
    if pull.is_draft != is_draft {
        state.store.set_pull_draft(&pull.id, is_draft).await?;
    }
    tracing::info!(
        repo = repo.id,
        number,
        draft = is_draft,
        actor = who.subject,
        "pull request draft state changed"
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

fn draft_badge(pull: &Pull) -> &'static str {
    if pull.is_draft {
        "<span class=\"state-badge pr-draft-badge\">Draft</span>"
    } else {
        ""
    }
}

/// The compare page: a base/head picker + (when a valid head is chosen) the commits ahead, the
/// diff, and a "Create pull request" form.
async fn render_compare(
    state: &AppState,
    repo: &Repo,
    branches: &[String],
    base: &str,
    head: &str,
    diff_options: DiffOptions,
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
            .diff(
                &repo.owner_sub,
                &repo.name,
                base,
                head,
                diff_options.ignore_whitespace(),
            )
            .await
            .unwrap_or_default();

        let commits_card = render_commits_card(&commits);
        let diff_card = render_diff_card(
            &diff,
            diff_options,
            DiffControls::new(format!(
                "/r/{owner}/{name}/compare",
                owner = repo.owner_sub,
                name = repo.name,
            ))
            .with_hidden("base", base)
            .with_hidden("head", head),
        );
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
      <div class="field field--check">
        <label class="check"><input type="checkbox" name="is_draft" value="on"> Create as draft</label>
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
            metadata_fields = metadata_fields,
        );
        format!("{commits_card}{diff_card}{create_form}")
    };
    let diff_query_inputs = render_diff_query_hidden_inputs(diff_options);

    format!(
        r##"{header}
<section class="card">
  <div class="card__head"><h2>Compare branches</h2></div>
  <div class="card__body">
    <form method="get" action="/r/{owner}/{name}/compare" class="compare-picker">
      {diff_query_inputs}
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
        diff_query_inputs = diff_query_inputs,
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
    state_filter: &str,
    label_filter: &str,
    milestone_filter: &str,
) -> String {
    let tabs = render_pr_state_tabs(repo, state_filter, label_filter, milestone_filter);
    let filters = render_pr_filters(
        repo,
        labels,
        milestones,
        state_filter,
        label_filter,
        milestone_filter,
    );
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
	<div class="list-toolbar">
	  <span class="list-toolbar__fill"></span>
	  {filters}
	  <a class="btn btn-primary btn-sm" href="/r/{owner}/{name}/compare">New pull request</a>
	</div>
	<section class="card">
	  <div class="card__head card__head--list">{tabs}</div>
	  <div class="card__body card__body--list"><ul class="pr-list">{list}</ul></div>
	</section>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        tabs = tabs,
        filters = filters,
        list = list,
    )
}

fn normalize_pull_state_filter(raw: Option<&str>) -> String {
    match raw.unwrap_or_default() {
        "open" => "open".to_string(),
        "closed" => "closed".to_string(),
        "all" | "" => "all".to_string(),
        _ => "all".to_string(),
    }
}

fn filter_pulls_by_state(pulls: Vec<Pull>, state_filter: &str) -> Vec<Pull> {
    match state_filter {
        "open" => pulls.into_iter().filter(Pull::is_open).collect(),
        "closed" => pulls.into_iter().filter(|pull| !pull.is_open()).collect(),
        _ => pulls,
    }
}

fn render_pr_row(repo: &Repo, pull: &Pull, labels: &[Label], milestones: &[Milestone]) -> String {
    let (_, label) = state_badge(pull);
    let (icon_class, icon_kind) = if pull.state == "merged" {
        ("state-ico--merged", "merged")
    } else if pull.state == "closed" {
        ("state-ico--closed", "pull")
    } else if pull.is_draft {
        ("state-ico--draft", "pull")
    } else {
        ("state-ico--open", "pull")
    };
    let draft_badge_html = draft_badge(pull);
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
  <span class="state-ico {icon_class}" title="{label}">{icon}</span>
  <div class="pr-item__main">
    <div class="pr-item__head">
      <a class="pr-item__title" href="/r/{owner}/{name}/pulls/{number}">#{number} {title}</a>
      {draft_badge_html}
    </div>
    <div class="label-row">{label_chips}</div>
    <span class="pr-item__meta">{head} &rarr; {base} · opened {when} by {author}{assignee}{reviewer}{milestone}</span>
  </div>
</li>"##,
        icon_class = icon_class,
        label = label,
        icon = state_icon(icon_kind),
        draft_badge_html = draft_badge_html,
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
    state_filter: &str,
    label_filter: &str,
    milestone_filter: &str,
) -> String {
    if labels.is_empty() && milestones.is_empty() {
        return String::new();
    }
    format!(
        r##"<form method="get" action="/r/{owner}/{name}/pulls" class="compare-picker">
  <input type="hidden" name="state" value="{state_filter}">
  <span class="compare-picker__label">label</span>
  <select name="label" class="compare-picker__select">{label_opts}</select>
  <span class="compare-picker__label">milestone</span>
  <select name="milestone" class="compare-picker__select">{milestone_opts}</select>
  <button class="btn btn-secondary btn-sm" type="submit">Filter</button>
</form>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        state_filter = esc(state_filter),
        label_opts = render_label_options(labels, label_filter, "All labels"),
        milestone_opts = render_milestone_options(milestones, milestone_filter, "All milestones"),
    )
}

fn render_pr_state_tabs(
    repo: &Repo,
    state_filter: &str,
    label_filter: &str,
    milestone_filter: &str,
) -> String {
    let tab = |state: &str, label: &str| {
        let active = if state == state_filter {
            " tab--active"
        } else {
            ""
        };
        format!(
            "<a class=\"tab{active}\" href=\"{href}\">{label}</a>",
            active = active,
            href = pulls_list_url(repo, state, label_filter, milestone_filter),
            label = label,
        )
    };
    format!(
        "<nav class=\"tabs tabs--filter\">{}{}{}</nav>",
        tab("open", "Open"),
        tab("closed", "Closed"),
        tab("all", "All"),
    )
}

fn pulls_list_url(repo: &Repo, state: &str, label_filter: &str, milestone_filter: &str) -> String {
    let mut q = vec![format!("state={}", esc(state))];
    if !label_filter.is_empty() {
        q.push(format!("label={}", esc(label_filter)));
    }
    if !milestone_filter.is_empty() {
        q.push(format!("milestone={}", esc(milestone_filter)));
    }
    format!(
        "/r/{}/{}/pulls?{}",
        esc(&repo.owner_sub),
        esc(&repo.name),
        q.join("&")
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
    pull_reactions: &[ReactionSummary],
    comment_reactions: &ReactionMap,
    thread_resolutions: &[PrThreadResolved],
    header: &str,
    who: &Identity,
    headers: &HeaderMap,
    csrf: &str,
    diff_options: DiffOptions,
    error: Option<&str>,
) -> Result<String, AppError> {
    let (cls, label) = state_badge(pull);
    let draft_badge_html = draft_badge(pull);
    let error_block = error_block(error);
    let now = now_secs();
    let summary = review_summary(reviews);
    let review_badges = render_review_badges(&summary);
    let label_chips = render_label_chips(pull_labels);

    let body_html = if pull.body.trim().is_empty() {
        "<p class=\"muted\">No description provided.</p>".to_string()
    } else {
        format!(
            "<div class=\"markdown-body\">{}</div>",
            crate::markdown::render_for_repo(&pull.body, &repo.owner_sub, &repo.name)
        )
    };
    let pull_reactions = render_reactions(
        &format!(
            "/r/{}/{}/pulls/{}/reactions",
            repo.owner_sub, repo.name, pull.number
        ),
        REACTION_TARGET_PULL,
        &pull.id,
        pull_reactions,
        csrf,
    );

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
        .diff(
            &repo.owner_sub,
            &repo.name,
            &pull.base,
            &pull.head,
            diff_options.ignore_whitespace(),
        )
        .await
        .unwrap_or_default();
    let viewed_files = state
        .store
        .list_pr_file_viewed_for_pr(&pull.id, &who.subject)
        .await?;
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
    let diff_card = render_pr_diff_card(
        &diff,
        &viewed_files,
        repo,
        pull,
        csrf,
        diff_options,
        DiffControls::new(format!(
            "/r/{owner}/{name}/pulls/{number}",
            owner = repo.owner_sub,
            name = repo.name,
            number = pull.number,
        )),
    );
    let review_requirements =
        evaluate_review_requirements(state, repo, pull, &summary, Some(&diff)).await;
    let review_requirements_html = render_review_requirements(&review_requirements);
    let repo_writer = can_write_repo(state, repo, who, headers).await?;
    let can_gate_user = can_gate(pull, who, repo_writer);
    let can_review_user = can_review(pull, who, repo_writer);
    let reviews_card = render_reviews_card(
        repo,
        reviews,
        review_comments,
        comment_reactions,
        thread_resolutions,
        csrf,
        pull,
        can_review_user,
    );
    let mergeability = if pull.is_open() {
        Some(preflight_mergeability(state, repo, pull).await)
    } else {
        None
    };
    let mergeability_bar = mergeability
        .map(render_mergeability_bar)
        .unwrap_or_default();
    let metadata_edit = if can_gate_user {
        let fields = render_pull_metadata_fields(
            labels,
            milestones,
            &pull.assignee_sub,
            &pull.reviewer_sub,
            &pull.milestone_id,
            pull_labels,
        );
        format!(
            r##"<section class="side__block side__block--edit">
  <details class="side-edit">
    <summary class="btn btn-ghost btn-sm">Edit metadata</summary>
    <form method="post" action="/r/{owner}/{name}/pulls/{number}/metadata">
      <input type="hidden" name="csrf_token" value="{csrf}">
      {fields}
      <div class="actions"><button class="btn btn-secondary btn-sm" type="submit">Save metadata</button></div>
    </form>
  </details>
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
    let reviewer_value = if pull.reviewer_sub.is_empty() {
        "<span class=\"side__empty\">No reviewer</span>".to_string()
    } else {
        esc(&pull.reviewer_sub)
    };
    let assignee_value = if pull.assignee_sub.is_empty() {
        "<span class=\"side__empty\">No assignee</span>".to_string()
    } else {
        esc(&pull.assignee_sub)
    };
    let labels_value = if label_chips.is_empty() {
        "<span class=\"side__empty\">None yet</span>".to_string()
    } else {
        label_chips
    };
    let milestone_value = milestones
        .iter()
        .find(|m| m.id == pull.milestone_id)
        .map(|m| esc(&m.title))
        .unwrap_or_else(|| "<span class=\"side__empty\">No milestone</span>".to_string());
    let sidebar = format!(
        r##"<section class="side__block"><h3 class="side__label">Reviewers</h3><div class="side__value">{reviewer}{review_badges}</div></section>
<section class="side__block"><h3 class="side__label">Assignee</h3><div class="side__value">{assignee}</div></section>
<section class="side__block"><h3 class="side__label">Labels</h3><div class="side__value label-row">{labels}</div></section>
<section class="side__block"><h3 class="side__label">Milestone</h3><div class="side__value">{milestone}</div></section>
{metadata_edit}"##,
        reviewer = reviewer_value,
        review_badges = review_badges,
        assignee = assignee_value,
        labels = labels_value,
        milestone = milestone_value,
        metadata_edit = metadata_edit,
    );

    // Action strip: merge/draft + open/close, shown only to a gated user on an OPEN PR.
    let actions = if pull.is_open() && pull.is_draft && can_gate_user {
        format!(
            r##"<div class="pr-actions">
  <p class="pr-status pr-status--draft">Draft pull requests cannot be merged. Mark this pull request ready for review before merging.</p>
  <form class="inline-form" method="post" action="/r/{owner}/{name}/pulls/{number}/ready">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <button class="btn btn-primary btn-ready-review" type="submit">Ready for review</button>
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
    } else if pull.is_open() && can_gate_user {
        let has_conflicts = matches!(mergeability, Some(PrMergeability::Conflicting));
        let review_blocked = !review_requirements.satisfied();
        let merge_button = render_merge_button(has_conflicts || review_blocked);
        let merge_note = render_merge_action_note(&review_requirements, has_conflicts);
        format!(
            r##"<div class="pr-actions">
  <form class="inline-form merge-strategy" method="post" action="/r/{owner}/{name}/pulls/{number}/merge">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <label class="merge-strategy__label" for="merge-method-{number}">Merge method</label>
    <select id="merge-method-{number}" class="merge-method-select" name="merge_method">
      <option value="merge" selected>Merge commit</option>
      <option value="squash">Squash and merge</option>
      <option value="rebase">Rebase and merge</option>
    </select>
    {merge_button}
  </form>
  <p class="muted merge-strategy__note">{merge_note}</p>
  <form class="inline-form" method="post" action="/r/{owner}/{name}/pulls/{number}/draft">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <button class="btn btn-secondary btn-convert-draft" type="submit">Convert to draft</button>
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
            merge_button = merge_button,
            merge_note = esc(&merge_note),
        )
    } else if pull.is_merged() {
        format!(
            "<p class=\"pr-status pr-status--merged\">Merged {} into <code>{}</code>.</p>",
            esc(&fmt_ts(pull.merged_at)),
            esc(&pull.base),
        )
    } else if !pull.is_open() && can_gate_user {
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
    } else if pull.is_open() && pull.is_draft {
        "<p class=\"pr-status pr-status--draft\">Draft pull requests cannot be merged yet.</p>"
            .to_string()
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
    let merge_panel = format!(
        r##"<section class="card merge-panel">
  <div class="card__body">
    {checks_card}
    {review_requirements_html}
    {mergeability_bar}
    {actions}
  </div>
</section>"##,
        checks_card = checks_card,
        review_requirements_html = review_requirements_html,
        mergeability_bar = mergeability_bar,
        actions = actions,
    );

    Ok(format!(
        r##"{header}
{pr_inline}
<div class="detail-head detail-head--pr">
  <div class="detail-head__badges"><span class="state-badge {cls}" id="state-badge-main">{label}</span>{draft_badge_html}</div>
  <h1 class="detail-head__title">{title} <span class="detail-head__number">#{number}</span></h1>
  <p class="detail-head__meta"><code>{head}</code> &rarr; <code>{base}</code> · opened <span title="{created_abs}">{created_rel}</span> by <b>{author}</b></p>
</div>
{error_block}
<div class="detail-layout">
  <div class="detail-layout__main">
    <section class="card comment-box">
      <div class="comment-box__meta"><b>{author}</b> <span>opened this pull request</span> <span title="{created_abs}">{created_rel}</span></div>
      <div class="comment-box__body">{body_html}{pull_reactions}</div>
    </section>
    {commits_card}
  </div>
  <aside class="side">{sidebar}</aside>
</div>
{diff_card}
{reviews_card}
{merge_panel}"##,
        cls = cls,
        label = label,
        draft_badge_html = draft_badge_html,
        number = pull.number,
        title = esc(&pull.title),
        head = esc(&pull.head),
        base = esc(&pull.base),
        created_abs = esc(&fmt_ts(pull.created_at)),
        created_rel = esc(&fmt_rel(now, pull.created_at)),
        author = esc(&pull.author_sub),
        body_html = body_html,
        pull_reactions = pull_reactions,
        commits_card = commits_card,
        reviews_card = reviews_card,
        sidebar = sidebar,
        error_block = error_block,
        pr_inline = pr_inline,
        diff_card = diff_card,
        merge_panel = merge_panel,
    ))
}

fn render_mergeability_bar(mergeability: PrMergeability) -> String {
    match mergeability {
        PrMergeability::Clean => {
            r#"<div class="pr-mergeability able-to-merge" role="status">
  <strong>Ready to merge</strong>
  <span>These branches can be cleanly merged.</span>
</div>"#
                .to_string()
        }
        PrMergeability::Conflicting => {
            r#"<div class="pr-mergeability has-conflicts pr-conflicts" role="status">
  <strong>This branch has conflicts</strong>
  <span>Resolve the conflicts manually before merging this pull request.</span>
</div>"#
                .to_string()
        }
        PrMergeability::Unknown => {
            r#"<div class="pr-mergeability unknown" role="status">
  <strong>Mergeability check unavailable</strong>
  <span>Loom could not determine this right now; submitting a merge still runs the server-side check.</span>
</div>"#
                .to_string()
        }
    }
}

fn render_merge_button(disabled: bool) -> &'static str {
    if disabled {
        r#"<button class="btn btn-primary" type="submit" disabled aria-disabled="true">Merge pull request</button>"#
    } else {
        r#"<button class="btn btn-primary" type="submit">Merge pull request</button>"#
    }
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
        r##"<div class="merge-panel__checks">
  <div class="merge-panel__checks-head">Checks {aggregate} <code class="oid">{head}</code></div>
    <ul class="issue-list">{rows}</ul>
</div>"##,
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

fn effective_required_approvals(repo: &Repo) -> usize {
    let required = if repo.required_approvals > 0 {
        repo.required_approvals
    } else if repo.require_approval {
        1
    } else {
        0
    };
    required.max(0) as usize
}

async fn evaluate_review_requirements(
    state: &AppState,
    repo: &Repo,
    pull: &Pull,
    summary: &ReviewSummary,
    diff: Option<&str>,
) -> ReviewRequirements {
    let approval_count = summary.approvals.len();
    let required_approvals = effective_required_approvals(repo);
    let codeowners = if repo.require_code_owner_reviews {
        let owned_diff;
        let diff_text = match diff {
            Some(diff) => diff,
            None => {
                owned_diff = state
                    .git
                    .diff(&repo.owner_sub, &repo.name, &pull.base, &pull.head, false)
                    .await
                    .unwrap_or_default();
                owned_diff.as_str()
            }
        };
        let changed_paths = changed_paths_from_diff(diff_text);
        evaluate_codeowners_for_pull(state, repo, pull, &changed_paths, &summary.approvals).await
    } else {
        CodeOwnerEvaluation::disabled()
    };
    ReviewRequirements {
        approval_count,
        required_approvals,
        approval_satisfied: approval_count >= required_approvals,
        codeowners,
    }
}

async fn evaluate_codeowners_for_pull(
    state: &AppState,
    repo: &Repo,
    pull: &Pull,
    changed_paths: &[String],
    approvals: &[String],
) -> CodeOwnerEvaluation {
    let Some(file) = load_codeowners_file(state, repo, &pull.base).await else {
        return CodeOwnerEvaluation {
            enabled: true,
            source_path: None,
            matched_groups: Vec::new(),
            pending_groups: Vec::new(),
        };
    };
    let (matched_groups, pending_groups) =
        evaluate_codeowner_rules(&file.rules, changed_paths, approvals);
    CodeOwnerEvaluation {
        enabled: true,
        source_path: Some(file.path),
        matched_groups,
        pending_groups,
    }
}

async fn load_codeowners_file(
    state: &AppState,
    repo: &Repo,
    base_branch: &str,
) -> Option<CodeOwnerFile> {
    let base_oid = state
        .git
        .branch_oid(&repo.owner_sub, &repo.name, base_branch)
        .await?;
    for path in CODEOWNERS_PATHS {
        let Some(bytes) = state
            .git
            .read_blob(&repo.owner_sub, &repo.name, &base_oid, path)
            .await
        else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        return Some(CodeOwnerFile {
            path: path.to_string(),
            rules: parse_codeowners(&text),
        });
    }
    None
}

fn parse_codeowners(text: &str) -> Vec<CodeOwnerRule> {
    let mut rules = Vec::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(pattern) = parts.next() else {
            continue;
        };
        let owners: Vec<String> = parts.filter_map(normalize_codeowner_token).collect();
        if owners.is_empty() {
            continue;
        }
        rules.push(CodeOwnerRule {
            pattern: pattern.to_string(),
            owners,
        });
    }
    rules
}

fn normalize_codeowner_token(raw: &str) -> Option<String> {
    let owner = raw.trim().trim_start_matches('@');
    if owner.is_empty() {
        return None;
    }
    Some(owner.to_string())
}

fn evaluate_codeowner_rules(
    rules: &[CodeOwnerRule],
    changed_paths: &[String],
    approvals: &[String],
) -> (Vec<CodeOwnerMatchedGroup>, Vec<CodeOwnerMatchedGroup>) {
    let approval_subjects: BTreeSet<String> = approvals
        .iter()
        .filter_map(|approval| normalize_codeowner_token(approval))
        .collect();
    let mut matched_groups = Vec::new();
    let mut pending_groups = Vec::new();
    for rule in rules {
        let paths: Vec<String> = changed_paths
            .iter()
            .filter(|path| codeowner_pattern_matches(&rule.pattern, path))
            .cloned()
            .collect();
        if paths.is_empty() {
            continue;
        }
        let group = CodeOwnerMatchedGroup {
            pattern: rule.pattern.clone(),
            owners: rule.owners.clone(),
            paths,
        };
        if !rule
            .owners
            .iter()
            .any(|owner| approval_subjects.contains(owner))
        {
            pending_groups.push(group.clone());
        }
        matched_groups.push(group);
    }
    (matched_groups, pending_groups)
}

fn changed_paths_from_diff(diff: &str) -> Vec<String> {
    let mut paths = BTreeSet::new();
    for file in parse_diff_files(diff) {
        if !file.path.is_empty() {
            paths.insert(file.path);
        }
    }
    paths.into_iter().collect()
}

fn codeowner_pattern_matches(pattern: &str, path: &str) -> bool {
    let path = path.trim_start_matches('/');
    let raw = pattern.trim();
    if raw.is_empty() || path.is_empty() {
        return false;
    }
    let anchored = raw.starts_with('/');
    let pattern = raw.trim_start_matches('/');
    if pattern.is_empty() {
        return false;
    }
    if pattern.ends_with('/') {
        let dir = pattern.trim_end_matches('/');
        return codeowner_dir_pattern_matches(dir, path, anchored || dir.contains('/'));
    }
    if anchored || pattern.contains('/') {
        return glob_match_path(pattern, path);
    }
    path.split('/')
        .any(|segment| glob_match_path(pattern, segment))
}

fn codeowner_dir_pattern_matches(pattern: &str, path: &str, rooted: bool) -> bool {
    if rooted {
        return path == pattern
            || path
                .strip_prefix(pattern)
                .map(|rest| rest.starts_with('/'))
                .unwrap_or(false);
    }
    let parts: Vec<&str> = path.split('/').collect();
    for idx in 0..parts.len() {
        let suffix = parts[idx..].join("/");
        if suffix == pattern
            || suffix
                .strip_prefix(pattern)
                .map(|rest| rest.starts_with('/'))
                .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

fn glob_match_path(pattern: &str, text: &str) -> bool {
    glob_match_bytes(pattern.as_bytes(), text.as_bytes())
}

fn glob_match_bytes(pattern: &[u8], text: &[u8]) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }
    if pattern.starts_with(b"**/") {
        if glob_match_bytes(&pattern[3..], text) {
            return true;
        }
        for idx in 0..text.len() {
            if text[idx] == b'/' && glob_match_bytes(&pattern[3..], &text[idx + 1..]) {
                return true;
            }
        }
        return false;
    }
    if pattern.starts_with(b"**") {
        if glob_match_bytes(&pattern[2..], text) {
            return true;
        }
        return !text.is_empty() && glob_match_bytes(pattern, &text[1..]);
    }
    match pattern[0] {
        b'*' => {
            glob_match_bytes(&pattern[1..], text)
                || (!text.is_empty() && text[0] != b'/' && glob_match_bytes(pattern, &text[1..]))
        }
        b'?' => !text.is_empty() && text[0] != b'/' && glob_match_bytes(&pattern[1..], &text[1..]),
        b => !text.is_empty() && text[0] == b && glob_match_bytes(&pattern[1..], &text[1..]),
    }
}

fn merge_blockers(
    pull: &Pull,
    requirements: &ReviewRequirements,
    mergeability: PrMergeability,
) -> Vec<String> {
    let mut blockers = Vec::new();
    if pull.is_draft {
        blockers.push(
            "Draft pull requests cannot be merged. Mark this pull request ready for review before merging."
                .to_string(),
        );
    }
    blockers.extend(review_requirement_blockers(requirements));
    if matches!(mergeability, PrMergeability::Conflicting) {
        blockers.push(conflict_blocker_text());
    }
    blockers
}

fn review_requirement_blockers(requirements: &ReviewRequirements) -> Vec<String> {
    let mut blockers = Vec::new();
    if !requirements.approval_satisfied {
        if requirements.required_approvals == 1 {
            blockers
                .push("This repository requires at least one approval before merge.".to_string());
        } else {
            blockers.push(format!(
                "This repository requires {} approvals before merge; {} approvals are present.",
                requirements.required_approvals, requirements.approval_count
            ));
        }
    }
    if requirements.codeowners.enabled && !requirements.codeowners.satisfied() {
        blockers.push(format!(
            "Code owner review is required from {}.",
            pending_codeowner_groups_text(&requirements.codeowners.pending_groups)
        ));
    }
    blockers
}

fn merge_blocker_message(blockers: &[String]) -> String {
    format!("Cannot merge yet: {}", blockers.join(" "))
}

fn render_merge_action_note(requirements: &ReviewRequirements, has_conflicts: bool) -> String {
    let mut blockers = review_requirement_blockers(requirements);
    if has_conflicts {
        blockers.push(conflict_blocker_text());
    }
    if blockers.is_empty() {
        "All merge methods are enabled for this repository.".to_string()
    } else {
        blockers.join(" ")
    }
}

fn conflict_blocker_text() -> String {
    "Could not merge automatically: resolve the conflicts manually before merging this pull request."
        .to_string()
}

fn render_review_requirements(requirements: &ReviewRequirements) -> String {
    let approval_state = if requirements.approval_satisfied {
        "approval-status--satisfied"
    } else {
        "approval-status--blocked"
    };
    let codeowners = render_codeowners_requirement(&requirements.codeowners);
    format!(
        r#"<div class="approval-status {approval_state}">
  <strong>Approvals</strong>
  <span class="approval-count">{approvals} of {required} approvals</span>
</div>
{codeowners}"#,
        approval_state = approval_state,
        approvals = requirements.approval_count,
        required = requirements.required_approvals,
        codeowners = codeowners,
    )
}

fn render_codeowners_requirement(evaluation: &CodeOwnerEvaluation) -> String {
    let state = if evaluation.satisfied() {
        "codeowners-req--satisfied"
    } else {
        "codeowners-req--blocked"
    };
    let text = if !evaluation.enabled {
        "Code owner reviews not required.".to_string()
    } else if evaluation.source_path.is_none() {
        "Code owner reviews required, but no CODEOWNERS file was found.".to_string()
    } else if evaluation.matched_groups.is_empty() {
        format!(
            "Code owner reviews satisfied; no changed files match {}.",
            evaluation.source_path.as_deref().unwrap_or("CODEOWNERS")
        )
    } else if evaluation.pending_groups.is_empty() {
        format!(
            "Code owner reviews satisfied from {}.",
            evaluation.source_path.as_deref().unwrap_or("CODEOWNERS")
        )
    } else {
        format!(
            "Waiting for code owners: {}.",
            pending_codeowner_groups_text(&evaluation.pending_groups)
        )
    };
    format!(
        r#"<div class="codeowners-req {state}">{text}</div>"#,
        state = state,
        text = esc(&text),
    )
}

fn pending_codeowner_groups_text(groups: &[CodeOwnerMatchedGroup]) -> String {
    groups
        .iter()
        .map(|group| owner_group_text(&group.owners))
        .collect::<Vec<_>>()
        .join("; ")
}

fn owner_group_text(owners: &[String]) -> String {
    owners
        .iter()
        .map(|owner| format!("@{}", owner.trim_start_matches('@')))
        .collect::<Vec<_>>()
        .join(" or ")
}

fn render_reviews_card(
    repo: &Repo,
    reviews: &[PullReview],
    comments: &[PullReviewComment],
    comment_reactions: &ReactionMap,
    thread_resolutions: &[PrThreadResolved],
    csrf: &str,
    pull: &Pull,
    can_resolve: bool,
) -> String {
    let pending_count = comments.iter().filter(|comment| comment.pending).count();
    let unresolved_count = unresolved_thread_count(comments, thread_resolutions);
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
                        crate::markdown::render_for_repo(&review.body, &repo.owner_sub, &repo.name)
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
    let inline_rows = render_inline_threads(
        repo,
        comments,
        comment_reactions,
        thread_resolutions,
        csrf,
        pull,
        can_resolve,
    );
    let forms = if can_resolve {
        let pending_review = if pending_count == 0 {
            String::new()
        } else {
            format!(
                r##"<div class="pending-review">
  <span class="review-pending-count">{pending_count} pending</span>
</div>"##
            )
        };
        let submit_label = if pending_count == 0 {
            "Submit review"
        } else {
            "Finish your review"
        };
        let submit_class = if pending_count == 0 {
            "btn btn-secondary"
        } else {
            "btn btn-primary btn-finish-review"
        };
        format!(
            r##"<div class="review-forms">
  <form method="post" action="/r/{owner}/{name}/pulls/{number}/review">
    <input type="hidden" name="csrf_token" value="{csrf}">
    {pending_review}
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
    <div class="actions"><button class="{submit_class}" type="submit">{submit_label}</button></div>
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
    <div class="actions">
      <button class="btn btn-secondary" type="submit">Add inline comment</button>
      <button class="btn btn-secondary" type="submit" name="mode" value="pending">Add pending comment</button>
    </div>
  </form>
</div>"##,
            owner = esc(&repo.owner_sub),
            name = esc(&repo.name),
            number = pull.number,
            csrf = esc(csrf),
            pending_review = pending_review,
            submit_class = submit_class,
            submit_label = submit_label,
        )
    } else {
        String::new()
    };
    format!(
        r##"<section class="card">
  <div class="card__head card__head--slim">Reviews <span class="tab__count">{nreviews}</span></div>
  <div class="card__body">
    <ul class="issue-list timeline">{review_rows}</ul>
    <h3 class="section-subhead">Inline comments <span class="review-unresolved-count">{unresolved_count} unresolved</span></h3>
    <ul class="issue-list timeline" id="pr-inline-thread">{inline_rows}</ul>
    {forms}
  </div>
</section>"##,
        nreviews = reviews.len(),
        unresolved_count = unresolved_count,
        review_rows = review_rows,
        inline_rows = inline_rows,
        forms = forms,
    )
}

struct InlineThreadGroup<'a> {
    key: String,
    path: String,
    line: i64,
    comments: Vec<&'a PullReviewComment>,
}

fn inline_thread_key(comment: &PullReviewComment) -> String {
    inline_thread_key_for(&comment.path, comment.line)
}

fn inline_thread_key_for(path: &str, line: i64) -> String {
    format!("{path}:{line}")
}

fn inline_thread_groups(comments: &[PullReviewComment]) -> Vec<InlineThreadGroup<'_>> {
    let mut by_anchor: BTreeMap<(String, i64), Vec<&PullReviewComment>> = BTreeMap::new();
    for comment in comments {
        by_anchor
            .entry((comment.path.clone(), comment.line))
            .or_default()
            .push(comment);
    }
    by_anchor
        .into_iter()
        .map(|((path, line), comments)| InlineThreadGroup {
            key: inline_thread_key_for(&path, line),
            path,
            line,
            comments,
        })
        .collect()
}

fn resolved_thread<'a>(
    thread_key: &str,
    resolutions: &'a [PrThreadResolved],
) -> Option<&'a PrThreadResolved> {
    resolutions
        .iter()
        .find(|row| row.thread_key == thread_key && row.resolved)
}

fn unresolved_thread_count(
    comments: &[PullReviewComment],
    resolutions: &[PrThreadResolved],
) -> usize {
    let mut thread_keys = BTreeSet::new();
    for comment in comments.iter().filter(|comment| !comment.pending) {
        thread_keys.insert(inline_thread_key(comment));
    }
    thread_keys
        .iter()
        .filter(|thread_key| resolved_thread(thread_key, resolutions).is_none())
        .count()
}

fn render_inline_threads(
    repo: &Repo,
    comments: &[PullReviewComment],
    comment_reactions: &ReactionMap,
    thread_resolutions: &[PrThreadResolved],
    csrf: &str,
    pull: &Pull,
    can_resolve: bool,
) -> String {
    if comments.is_empty() {
        return "<li class=\"issue-item issue-item--empty\">No inline comments yet.</li>"
            .to_string();
    }
    inline_thread_groups(comments)
        .into_iter()
        .map(|thread| {
            let has_published = thread.comments.iter().any(|comment| !comment.pending);
            let resolution = resolved_thread(&thread.key, thread_resolutions);
            let comments_html = render_inline_thread_comments(
                repo,
                pull,
                &thread.comments,
                comment_reactions,
                csrf,
                can_resolve,
            );
            let count_label = comment_count_label(thread.comments.len());
            let anchor = format!("{}:{}", esc(&thread.path), thread.line);
            let form = if can_resolve && has_published {
                render_thread_resolution_form(repo, pull, csrf, &thread.key, resolution.is_some())
            } else {
                String::new()
            };

            if let Some(resolution) = resolution {
                let resolved_by = if resolution.resolved_by.is_empty() {
                    "unknown".to_string()
                } else {
                    esc(&resolution.resolved_by)
                };
                return format!(
                    r##"<li class="issue-item thread-resolved" data-thread-key="{thread_key}">
  <details class="thread-resolved__details">
    <summary class="thread-summary"><span>{anchor}</span> · Resolved by {resolved_by} {resolved_at} · {count_label}</summary>
    <div class="thread-comments">{comments_html}</div>
    {form}
  </details>
</li>"##,
                    thread_key = esc(&thread.key),
                    anchor = anchor,
                    resolved_by = resolved_by,
                    resolved_at = esc(&fmt_ts(resolution.resolved_at)),
                    count_label = count_label,
                    comments_html = comments_html,
                    form = form,
                );
            }

            let item_class = if has_published {
                "issue-item thread-unresolved"
            } else {
                "issue-item thread-unresolved pending-review"
            };
            format!(
                r##"<li class="{item_class}" data-thread-key="{thread_key}">
  <div class="issue-item__meta"><span>{anchor}</span> · {count_label}</div>
  <div class="thread-comments">{comments_html}</div>
  {form}
</li>"##,
                item_class = item_class,
                thread_key = esc(&thread.key),
                anchor = anchor,
                count_label = count_label,
                comments_html = comments_html,
                form = form,
            )
        })
        .collect::<String>()
}

fn render_inline_thread_comments(
    repo: &Repo,
    pull: &Pull,
    comments: &[&PullReviewComment],
    comment_reactions: &ReactionMap,
    csrf: &str,
    can_apply_suggestions: bool,
) -> String {
    comments
        .iter()
        .map(|comment| {
            let item_class = if comment.pending {
                "thread-comment pending-review"
            } else {
                "thread-comment"
            };
            let action = if comment.pending {
                "pending"
            } else {
                "commented"
            };
            let reactions = if comment.pending {
                String::new()
            } else {
                let summaries = comment_reactions
                    .get(&comment.id)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                render_reactions(
                    &format!(
                        "/r/{}/{}/pulls/{}/comments/{}/reactions",
                        repo.owner_sub, repo.name, pull.number, comment.id
                    ),
                    REACTION_TARGET_COMMENT,
                    &comment.id,
                    summaries,
                    csrf,
                )
            };
            let suggestion = crate::markdown::extract_first_suggestion(&comment.body);
            let body = if suggestion.is_some() {
                crate::markdown::render_for_repo_with_suggestion(
                    &comment.body,
                    &repo.owner_sub,
                    &repo.name,
                    crate::markdown::SuggestionContext {
                        old: &comment.anchor_text,
                    },
                )
            } else {
                crate::markdown::render_for_repo(&comment.body, &repo.owner_sub, &repo.name)
            };
            let suggestion_action = render_suggestion_action(
                repo,
                pull,
                comment,
                csrf,
                can_apply_suggestions && pull.is_open(),
                suggestion.is_some(),
            );
            format!(
                r##"<div class="{item_class}">
  <div class="issue-item__meta">{author} {action} {when}</div>
  <div class="issue-item__body markdown-body">{body}</div>
  {suggestion_action}
  {reactions}
</div>"##,
                item_class = item_class,
                author = esc(&comment.author_sub),
                action = action,
                when = esc(&fmt_ts(comment.created_at)),
                body = body,
                suggestion_action = suggestion_action,
                reactions = reactions,
            )
        })
        .collect::<String>()
}

fn render_suggestion_action(
    repo: &Repo,
    pull: &Pull,
    comment: &PullReviewComment,
    csrf: &str,
    can_apply: bool,
    has_suggestion: bool,
) -> String {
    if !has_suggestion || comment.pending {
        return String::new();
    }
    if comment.applied {
        return "<div class=\"suggestion__status\">Suggestion applied.</div>".to_string();
    }
    if !can_apply {
        return String::new();
    }
    format!(
        r##"<form class="inline-form suggestion__actions" method="post" action="/r/{owner}/{name}/pulls/{number}/comments/{comment_id}/suggestion/apply">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <button class="btn btn-secondary btn-sm btn-apply-suggestion" type="submit">Apply suggestion</button>
</form>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        number = pull.number,
        comment_id = esc(&comment.id),
        csrf = esc(csrf),
    )
}

fn comment_count_label(count: usize) -> String {
    if count == 1 {
        "1 comment".to_string()
    } else {
        format!("{count} comments")
    }
}

fn render_thread_resolution_form(
    repo: &Repo,
    pull: &Pull,
    csrf: &str,
    thread_key: &str,
    resolved: bool,
) -> String {
    let (action, label, class) = if resolved {
        (
            "unresolve",
            "Unresolve",
            "btn btn-secondary btn-sm btn-unresolve",
        )
    } else {
        ("resolve", "Resolve", "btn btn-secondary btn-sm btn-resolve")
    };
    format!(
        r##"<form class="inline-form thread-resolution-form" method="post" action="/r/{owner}/{name}/pulls/{number}/thread/{action}">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <input type="hidden" name="thread_key" value="{thread_key}">
  <button class="{class}" type="submit">{label}</button>
</form>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        number = pull.number,
        action = action,
        csrf = esc(csrf),
        thread_key = esc(thread_key),
        class = class,
        label = label,
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
  <div class="card__head card__head--slim">Commits <span class="tab__count">{n}</span></div>
  <div class="card__body"><ul class="commit-list">{rows}</ul></div>
</section>"##,
        n = commits.len(),
    )
}

/// Card rendering the diff as colored, escaped tables. Large diffs show a size notice.
/// Shared with the commit page (`pub(crate)`) — the ONE diff renderer in the crate.
pub(crate) fn render_diff_card(diff: &str, options: DiffOptions, controls: DiffControls) -> String {
    let inner = if diff.trim().is_empty() {
        "<div class=\"card__body\"><p class=\"muted\">No file changes.</p></div>".to_string()
    } else if diff.len() > MAX_BLOB_RENDER_BYTES {
        "<div class=\"card__body\"><p class=\"muted\">The diff is too large to display. \
         Fetch the branches locally to review it.</p></div>"
            .to_string()
    } else {
        format!(
            "<div class=\"card__body card__body--code\">{}</div>",
            render_diff_with_options(diff, options)
        )
    };
    let controls = render_diff_controls(options, &controls);
    format!(
        r##"<section class="card">
  <div class="card__head"><h2>Diff</h2>{controls}</div>
  {inner}
</section>"##
    )
}

fn render_pr_diff_card(
    diff: &str,
    viewed: &[PrFileViewed],
    repo: &Repo,
    pull: &Pull,
    csrf: &str,
    options: DiffOptions,
    controls: DiffControls,
) -> String {
    let viewed_by_path: BTreeMap<String, bool> = viewed
        .iter()
        .map(|row| (row.file_path.clone(), row.viewed))
        .collect();
    let files = if diff.trim().is_empty() || diff.len() > MAX_BLOB_RENDER_BYTES {
        Vec::new()
    } else {
        parse_diff_files(diff)
    };
    let metas = diff_file_metas(&files, &viewed_by_path);
    let n_files = metas.len();
    let additions: i64 = metas.iter().map(|meta| meta.additions).sum();
    let deletions: i64 = metas.iter().map(|meta| meta.deletions).sum();
    let inner = if diff.trim().is_empty() {
        "<div class=\"card__body\"><p class=\"muted\">No file changes.</p></div>".to_string()
    } else if diff.len() > MAX_BLOB_RENDER_BYTES {
        "<div class=\"card__body\"><p class=\"muted\">The diff is too large to display. \
         Fetch the branches locally to review it.</p></div>"
            .to_string()
    } else {
        format!(
            "<div class=\"card__body card__body--code\">{}</div>",
            render_pr_diff(&files, &metas, repo, pull, csrf, options)
        )
    };
    let controls = render_diff_controls(options, &controls);
    format!(
        r##"<section class="card diff-card" id="files">
  <div class="diff-card__bar">
    <span class="diff-card__summary"><b>{n_files} files changed</b> <span class="diff-add">+{additions}</span> <span class="diff-del">&minus;{deletions}</span></span>
    <span class="diff-card__fill"></span>
    {controls}
  </div>
  {inner}
</section>"##,
        n_files = n_files,
        additions = additions,
        deletions = deletions,
        controls = controls,
        inner = inner,
    )
}

fn render_diff_controls(options: DiffOptions, controls: &DiffControls) -> String {
    let unified_checked = if options.view == DiffView::Unified {
        " checked"
    } else {
        ""
    };
    let split_checked = if options.view == DiffView::Split {
        " checked"
    } else {
        ""
    };
    let whitespace_checked = if options.ignore_whitespace {
        " checked"
    } else {
        ""
    };
    let hidden = controls
        .hidden
        .iter()
        .map(|(name, value)| {
            format!(
                "<input type=\"hidden\" name=\"{name}\" value=\"{value}\">",
                name = esc(name),
                value = esc(value),
            )
        })
        .collect::<String>();
    format!(
        r#"<form class="diff-toggle" method="get" action="{action}">
  {hidden}
  <span class="segmented" role="radiogroup" aria-label="Diff view">
    <label class="segmented__opt"><input type="radio" name="diff" value="unified"{unified_checked}><span>Unified</span></label>
    <label class="segmented__opt"><input type="radio" name="diff" value="split"{split_checked}><span>Split</span></label>
  </span>
  <label class="diff-toggle__whitespace"><input type="checkbox" name="w" value="1"{whitespace_checked}> Hide whitespace</label>
  <button class="btn btn-ghost btn-sm" type="submit">Apply</button>
</form>"#,
        action = esc(&controls.action),
        hidden = hidden,
        unified_checked = unified_checked,
        split_checked = split_checked,
        whitespace_checked = whitespace_checked,
    )
}

fn render_diff_query_hidden_inputs(options: DiffOptions) -> String {
    let mut out = format!(
        "<input type=\"hidden\" name=\"diff\" value=\"{}\">",
        options.view.as_param()
    );
    if options.ignore_whitespace {
        out.push_str("<input type=\"hidden\" name=\"w\" value=\"1\">");
    }
    out
}

/// One file's slice of a unified diff (its header line + body lines).
struct DiffFile {
    path: String,
    lines: Vec<String>,
}

struct DiffFileMeta {
    anchor: String,
    display_path: String,
    additions: i64,
    deletions: i64,
    viewed: bool,
}

struct FileViewedRenderContext<'a> {
    repo: &'a Repo,
    pull: &'a Pull,
    csrf: &'a str,
}

/// Render a unified diff into per-file **collapsible** blocks, each a line-classified, HTML-escaped
/// table. Code rows carry `data-line` (their line number in the new file, tracked from the hunk
/// headers) so the progressive-enhancement layer can anchor an inline comment to a line — with
/// JavaScript off the standalone inline-comment form still works. Every byte is HTML-escaped.
fn render_diff_with_options(diff: &str, options: DiffOptions) -> String {
    let files = parse_diff_files(diff);
    let metas = diff_file_metas(&files, &BTreeMap::new());
    render_diff_files(&files, &metas, None, options)
}

fn render_pr_diff(
    files: &[DiffFile],
    metas: &[DiffFileMeta],
    repo: &Repo,
    pull: &Pull,
    csrf: &str,
    options: DiffOptions,
) -> String {
    let ctx = FileViewedRenderContext { repo, pull, csrf };
    format!(
        "<div class=\"pr-diff\">{}<div class=\"pr-diff__files\">{}</div></div>",
        render_pr_file_tree(metas, &ctx),
        render_diff_files(files, metas, Some(&ctx), options),
    )
}

fn parse_diff_files(diff: &str) -> Vec<DiffFile> {
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
    files
}

fn diff_file_metas(
    files: &[DiffFile],
    viewed_by_path: &BTreeMap<String, bool>,
) -> Vec<DiffFileMeta> {
    files
        .iter()
        .enumerate()
        .map(|(idx, file)| {
            let display_path = display_diff_path(file);
            let (additions, deletions) = diff_file_counts(file);
            DiffFileMeta {
                anchor: format!("diff-file-{}", idx + 1),
                viewed: viewed_by_path.get(&display_path).copied().unwrap_or(false),
                display_path,
                additions,
                deletions,
            }
        })
        .collect()
}

fn display_diff_path(file: &DiffFile) -> String {
    if file.path.is_empty() {
        "changed file".to_string()
    } else {
        file.path.clone()
    }
}

fn diff_file_counts(file: &DiffFile) -> (i64, i64) {
    let mut additions = 0i64;
    let mut deletions = 0i64;
    for line in &file.lines {
        match classify_diff_line(line).0 {
            "diff-row--add" => additions += 1,
            "diff-row--del" => deletions += 1,
            _ => {}
        }
    }
    (additions, deletions)
}

fn render_diff_files(
    files: &[DiffFile],
    metas: &[DiffFileMeta],
    ctx: Option<&FileViewedRenderContext<'_>>,
    options: DiffOptions,
) -> String {
    let mut out = String::from(
        "<div class=\"diff-toolbar\" data-diff-toolbar></div><div class=\"diff-files\">",
    );
    for (file, meta) in files.iter().zip(metas.iter()) {
        out.push_str(&render_diff_file(file, meta, ctx, options));
    }
    out.push_str("</div>");
    out
}

fn render_pr_file_tree(metas: &[DiffFileMeta], ctx: &FileViewedRenderContext<'_>) -> String {
    let total = metas.len();
    if total == 0 {
        return String::new();
    }
    let viewed_count = metas.iter().filter(|meta| meta.viewed).count();
    let mut items = String::new();
    for meta in metas {
        let viewed_cls = if meta.viewed {
            " pr-filetree__item--viewed"
        } else {
            ""
        };
        items.push_str(&format!(
            "<li class=\"pr-filetree__item{viewed_cls}\" data-path=\"{path}\" data-viewed=\"{viewed}\">\
               {form}\
               <a class=\"pr-filetree__link\" href=\"#{anchor}\">\
                 <span class=\"pr-filetree__path\">{path}</span>\
                 <span class=\"pr-filetree__stat\"><span class=\"diff-add\">+{adds}</span> <span class=\"diff-del\">-{dels}</span></span>\
               </a>\
             </li>",
            viewed_cls = viewed_cls,
            path = esc(&meta.display_path),
            viewed = meta.viewed,
            form = render_file_viewed_form(ctx, &meta.display_path, meta.viewed, "pr-file-viewed--tree"),
            anchor = meta.anchor,
            adds = meta.additions,
            dels = meta.deletions,
        ));
    }
    format!(
        "<aside class=\"pr-filetree\" aria-label=\"Pull request files\">\
           <div class=\"pr-filetree__summary\">Viewed {viewed_count}/{total}</div>\
           <ol class=\"pr-filetree__list\">{items}</ol>\
         </aside>",
        viewed_count = viewed_count,
        total = total,
        items = items,
    )
}

/// Render one file block: a `<details>` with the file path + add/del counts in its summary, then the
/// line-classified table.
fn render_diff_file(
    file: &DiffFile,
    meta: &DiffFileMeta,
    ctx: Option<&FileViewedRenderContext<'_>>,
    options: DiffOptions,
) -> String {
    let rows = match options.view {
        DiffView::Unified => render_unified_diff_rows(file),
        DiffView::Split => render_split_diff_rows(file),
    };
    let table_class = match options.view {
        DiffView::Unified => "diff diff--unified",
        DiffView::Split => "diff diff--split",
    };
    let viewed_cls = if meta.viewed {
        " diff-file--viewed"
    } else {
        ""
    };
    let open_attr = if meta.viewed { "" } else { " open" };
    let controls = ctx
        .map(|ctx| {
            format!(
                "<div class=\"diff-file__controls\">{}</div>",
                render_file_viewed_form(
                    ctx,
                    &meta.display_path,
                    meta.viewed,
                    "pr-file-viewed--diff"
                )
            )
        })
        .unwrap_or_default();
    format!(
        "<details id=\"{anchor}\" class=\"diff-file{viewed_cls}\" data-path=\"{path}\" data-viewed=\"{viewed}\"{open_attr}>\
           <summary class=\"diff-file__summary\">\
             <span class=\"diff-file__path\">{path}</span>\
             <span class=\"diff-file__stat\"><span class=\"diff-add\">+{adds}</span> <span class=\"diff-del\">-{dels}</span></span>\
           </summary>\
           {controls}\
           <table class=\"{table_class}\"><tbody>{rows}</tbody></table>\
         </details>",
        anchor = meta.anchor,
        viewed_cls = viewed_cls,
        path = esc(&meta.display_path),
        viewed = meta.viewed,
        open_attr = open_attr,
        adds = meta.additions,
        dels = meta.deletions,
        controls = controls,
        table_class = table_class,
        rows = rows,
    )
}

fn render_unified_diff_rows(file: &DiffFile) -> String {
    let mut rows = String::new();
    let mut new_line: Option<i64> = None; // current line number in the new file (inside a hunk)
    for line in &file.lines {
        let (row_cls, gutter) = classify_diff_line(line);
        let mut attr = String::new();
        if line.starts_with("@@") {
            new_line = parse_hunk_new_start(line);
        } else if row_cls == "diff-row--add" {
            if let Some(n) = new_line {
                attr = format!(" data-line=\"{n}\"");
                new_line = Some(n + 1);
            }
        } else if row_cls == "diff-row--ctx" {
            if let Some(n) = new_line {
                attr = format!(" data-line=\"{n}\"");
                new_line = Some(n + 1);
            }
        }
        rows.push_str(&render_unified_diff_row(
            row_cls,
            attr.as_str(),
            gutter,
            line,
        ));
    }
    rows
}

fn render_unified_diff_row(row_cls: &str, attr: &str, gutter: &str, line: &str) -> String {
    format!(
        "<tr class=\"diff-row {row_cls}\"{attr}>\
           <td class=\"diff-gutter\">{gutter}</td>\
           <td class=\"diff-code\">{code}</td>\
         </tr>",
        row_cls = row_cls,
        attr = attr,
        gutter = gutter,
        code = esc(line),
    )
}

fn render_split_diff_rows(file: &DiffFile) -> String {
    let mut rows = String::new();
    let mut old_line: Option<i64> = None;
    let mut new_line: Option<i64> = None;
    let mut idx = 0usize;

    while idx < file.lines.len() {
        let line = &file.lines[idx];
        let (row_cls, gutter) = classify_diff_line(line);
        if line.starts_with("@@") {
            old_line = parse_hunk_old_start(line);
            new_line = parse_hunk_new_start(line);
            rows.push_str(&render_unified_diff_row(row_cls, "", gutter, line));
            idx += 1;
        } else if row_cls == "diff-row--del" {
            let del_start = idx;
            while idx < file.lines.len()
                && classify_diff_line(&file.lines[idx]).0 == "diff-row--del"
            {
                idx += 1;
            }
            let add_start = idx;
            while idx < file.lines.len()
                && classify_diff_line(&file.lines[idx]).0 == "diff-row--add"
            {
                idx += 1;
            }
            rows.push_str(&render_split_change_rows(
                &file.lines[del_start..add_start],
                &file.lines[add_start..idx],
                &mut old_line,
                &mut new_line,
            ));
        } else if row_cls == "diff-row--add" {
            let add_start = idx;
            while idx < file.lines.len()
                && classify_diff_line(&file.lines[idx]).0 == "diff-row--add"
            {
                idx += 1;
            }
            rows.push_str(&render_split_change_rows(
                &[],
                &file.lines[add_start..idx],
                &mut old_line,
                &mut new_line,
            ));
        } else if row_cls == "diff-row--ctx" {
            let old_no = old_line;
            let new_no = new_line;
            let attr = data_line_attr(new_no);
            let code = context_diff_content(line);
            rows.push_str(&render_split_diff_row(
                "diff-row--ctx",
                &attr,
                old_no,
                new_no,
                "diff-side--old",
                code,
                "diff-side--new",
                code,
            ));
            old_line = old_line.map(|n| n + 1);
            new_line = new_line.map(|n| n + 1);
            idx += 1;
        } else {
            rows.push_str(&render_unified_diff_row(row_cls, "", gutter, line));
            idx += 1;
        }
    }

    rows
}

fn render_split_change_rows(
    deletions: &[String],
    additions: &[String],
    old_line: &mut Option<i64>,
    new_line: &mut Option<i64>,
) -> String {
    let mut rows = String::new();
    let count = deletions.len().max(additions.len());
    for idx in 0..count {
        let old_raw = deletions.get(idx).map(String::as_str);
        let new_raw = additions.get(idx).map(String::as_str);
        let old_no = old_raw.and(*old_line);
        let new_no = new_raw.and(*new_line);
        let attr = data_line_attr(new_no);
        let row_cls = match (old_raw.is_some(), new_raw.is_some()) {
            (true, true) => "diff-row--change",
            (true, false) => "diff-row--del",
            (false, true) => "diff-row--add",
            (false, false) => "diff-row--ctx",
        };
        let old_cls = if old_raw.is_some() {
            "diff-side--old diff-side--del"
        } else {
            "diff-side--old diff-side--empty"
        };
        let new_cls = if new_raw.is_some() {
            "diff-side--new diff-side--add"
        } else {
            "diff-side--new diff-side--empty"
        };
        rows.push_str(&render_split_diff_row(
            row_cls,
            &attr,
            old_no,
            new_no,
            old_cls,
            old_raw.map(changed_diff_content).unwrap_or(""),
            new_cls,
            new_raw.map(changed_diff_content).unwrap_or(""),
        ));
        if old_raw.is_some() {
            *old_line = (*old_line).map(|n| n + 1);
        }
        if new_raw.is_some() {
            *new_line = (*new_line).map(|n| n + 1);
        }
    }
    rows
}

fn render_split_diff_row(
    row_cls: &str,
    attr: &str,
    old_no: Option<i64>,
    new_no: Option<i64>,
    old_cls: &str,
    old_code: &str,
    new_cls: &str,
    new_code: &str,
) -> String {
    format!(
        "<tr class=\"diff-row {row_cls}\"{attr}>\
           <td class=\"diff-gutter diff-gutter--split\">\
             <span class=\"diff-side diff-side--old\">{old_no}</span>\
             <span class=\"diff-side diff-side--new\">{new_no}</span>\
           </td>\
           <td class=\"diff-code diff-code--split\">\
             <span class=\"diff-side {old_cls}\">{old_code}</span>\
             <span class=\"diff-side {new_cls}\">{new_code}</span>\
           </td>\
         </tr>",
        row_cls = row_cls,
        attr = attr,
        old_no = old_no.map(|n| n.to_string()).unwrap_or_default(),
        new_no = new_no.map(|n| n.to_string()).unwrap_or_default(),
        old_cls = old_cls,
        old_code = esc(old_code),
        new_cls = new_cls,
        new_code = esc(new_code),
    )
}

fn data_line_attr(line: Option<i64>) -> String {
    line.map(|n| format!(" data-line=\"{n}\""))
        .unwrap_or_default()
}

fn context_diff_content(line: &str) -> &str {
    line.strip_prefix(' ').unwrap_or(line)
}

fn changed_diff_content(line: &str) -> &str {
    line.get(1..).unwrap_or("")
}

fn render_file_viewed_form(
    ctx: &FileViewedRenderContext<'_>,
    file_path: &str,
    viewed: bool,
    class: &str,
) -> String {
    let checked = if viewed { " checked" } else { "" };
    format!(
        r#"<form class="pr-file-viewed {class}" method="post" action="/r/{owner}/{name}/pulls/{number}/file-viewed">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <input type="hidden" name="file_path" value="{path}">
  <label class="pr-file-viewed__label"><input class="pr-file-viewed__checkbox" type="checkbox" name="viewed" value="true"{checked}> Viewed</label>
  <button class="btn btn-ghost btn-sm pr-file-viewed__submit" type="submit">Save</button>
</form>"#,
        class = class,
        owner = esc(&ctx.repo.owner_sub),
        name = esc(&ctx.repo.name),
        number = ctx.pull.number,
        csrf = esc(ctx.csrf),
        path = esc(file_path),
        checked = checked,
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

/// Parse the old-file starting line from a `@@ -a,b +c,d @@` hunk header (returns `a`).
fn parse_hunk_old_start(line: &str) -> Option<i64> {
    parse_hunk_start(line, '-')
}

/// Parse the new-file starting line from a `@@ -a,b +c,d @@` hunk header (returns `c`).
fn parse_hunk_new_start(line: &str) -> Option<i64> {
    parse_hunk_start(line, '+')
}

fn parse_hunk_start(line: &str, marker: char) -> Option<i64> {
    let token = line.split_whitespace().find(|t| t.starts_with(marker))?;
    token
        .trim_start_matches(marker)
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
        let html = render_diff_with_options(
            "+<script>alert(1)</script>\n context\n",
            DiffOptions::default(),
        );
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("diff-row--add"));
    }

    #[test]
    fn diff_query_defaults_to_unified_without_whitespace_ignore() {
        let options = DiffQuery::default().options();
        assert_eq!(options.view, DiffView::Unified);
        assert!(!options.ignore_whitespace());

        let options = DiffQuery {
            diff: Some("split".to_string()),
            w: Some("1".to_string()),
        }
        .options();
        assert_eq!(options.view, DiffView::Split);
        assert!(options.ignore_whitespace());

        let options = DiffQuery {
            diff: Some("sideways".to_string()),
            w: Some("no".to_string()),
        }
        .options();
        assert_eq!(options.view, DiffView::Unified);
        assert!(!options.ignore_whitespace());
    }

    #[test]
    fn split_diff_render_aligns_old_and_new_sides() {
        let diff = "diff --git a/file.txt b/file.txt\n\
--- a/file.txt\n\
+++ b/file.txt\n\
@@ -1,3 +1,4 @@\n\
 one\n\
-two\n\
+two <changed>\n\
 three\n\
+four\n";
        let html = render_diff_with_options(
            diff,
            DiffOptions {
                view: DiffView::Split,
                ignore_whitespace: false,
            },
        );
        assert!(html.contains("class=\"diff diff--split\""));
        assert!(html.contains("diff-side--old diff-side--del"));
        assert!(html.contains("diff-side--new diff-side--add"));
        assert!(html.contains("data-line=\"2\""));
        assert!(html.contains("data-line=\"4\""));
        assert!(html.contains("&lt;changed&gt;"));
        assert!(!html.contains("<changed>"));
    }

    #[test]
    fn diff_card_renders_query_controls() {
        let html = render_diff_card(
            "",
            DiffOptions {
                view: DiffView::Split,
                ignore_whitespace: true,
            },
            DiffControls::new("/r/alice/proj/compare".to_string())
                .with_hidden("base", "main")
                .with_hidden("head", "feature"),
        );
        assert!(html.contains("class=\"diff-toggle\""));
        assert!(html.contains("name=\"base\" value=\"main\""));
        assert!(html.contains("name=\"head\" value=\"feature\""));
        assert!(html.contains("name=\"diff\" value=\"split\" checked"));
        assert!(html.contains("name=\"w\" value=\"1\" checked"));
    }

    #[test]
    fn effective_required_approvals_keeps_legacy_boolean() {
        let mut repo = Repo {
            id: "r".into(),
            owner_sub: "u".into(),
            name: "n".into(),
            description: String::new(),
            is_private: false,
            default_branch: "main".into(),
            require_approval: true,
            required_approvals: 0,
            require_code_owner_reviews: false,
            protect_default_branch: false,
            forked_from_id: String::new(),
            created_at: 0,
        };
        assert_eq!(effective_required_approvals(&repo), 1);
        repo.required_approvals = 3;
        assert_eq!(effective_required_approvals(&repo), 3);
        repo.require_approval = false;
        repo.required_approvals = 0;
        assert_eq!(effective_required_approvals(&repo), 0);
    }

    #[test]
    fn codeowners_parser_ignores_comments_and_requires_owners() {
        let rules = parse_codeowners(
            "\n\
# ignored\n\
*.rs @alice @bob # rust owners\n\
docs/ @docs\n\
missing-owner\n",
        );
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].pattern, "*.rs");
        assert_eq!(
            rules[0].owners,
            vec!["alice".to_string(), "bob".to_string()]
        );
        assert_eq!(rules[1].pattern, "docs/");
        assert_eq!(rules[1].owners, vec!["docs".to_string()]);
    }

    #[test]
    fn codeowner_patterns_match_common_paths() {
        assert!(codeowner_pattern_matches("*.rs", "src/lib.rs"));
        assert!(codeowner_pattern_matches("/src/*.rs", "src/lib.rs"));
        assert!(!codeowner_pattern_matches("/src/*.rs", "src/bin/main.rs"));
        assert!(codeowner_pattern_matches("src/**", "src/bin/main.rs"));
        assert!(codeowner_pattern_matches("docs/", "guide/docs/intro.md"));
        assert!(codeowner_pattern_matches("/docs/", "docs/intro.md"));
        assert!(!codeowner_pattern_matches("/docs/", "guide/docs/intro.md"));
    }

    #[test]
    fn codeowner_evaluation_requires_each_matching_group() {
        let rules = parse_codeowners(
            "*.rs @alice @bob\n\
docs/ @docs\n",
        );
        let changed = vec!["src/lib.rs".to_string(), "docs/intro.md".to_string()];
        let approvals = vec!["bob".to_string()];
        let (matched, pending) = evaluate_codeowner_rules(&rules, &changed, &approvals);
        assert_eq!(matched.len(), 2);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].owners, vec!["docs".to_string()]);

        let approvals = vec!["bob".to_string(), "docs".to_string()];
        let (_matched, pending) = evaluate_codeowner_rules(&rules, &changed, &approvals);
        assert!(pending.is_empty());
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
            required_approvals: 0,
            require_code_owner_reviews: false,
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
