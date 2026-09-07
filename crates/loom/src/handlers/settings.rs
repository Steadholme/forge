//! Repository settings (`GET`/`POST /r/{owner}/{name}/settings`) — owner or estate/product admin
//! only.
//!
//! Two editable fields: the free-text description (shown on the repo list + repo home) and the
//! default branch. A default-branch change is validated against the repo's ACTUAL branch list
//! (when the repo has any branches; an empty repo may pre-set any well-formed name) and is applied
//! to BOTH the metadata row and the bare repo's HEAD (`git symbolic-ref`), so fresh clones check
//! out the chosen branch. Writes are double-submit CSRF-checked and audit-logged via `tracing`
//! (the crate's audit surface — same as repo create / PR merge / PAT mint).
//!
//! Access: the repo owner, or a member of [`crate::auth::admin_groups`] (the two global admin
//! groups + the `git-admins` product group). Anyone else gets 403 on a public repo; on a private
//! repo the visibility loader 404s first, so existence never leaks.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Form;
use serde::Deserialize;

use crate::auth::{self, Identity};
use crate::error::AppError;
use crate::handlers::repos::{
    can_admin_repo, header_with_counts, load_visible_repo, validate_branch_name,
};
use crate::handlers::{esc, fmt_ts, html_with_csrf, page, redirect};
use crate::model::{
    normalize_repo_role, validate_label_color, validate_label_name, validate_milestone_due,
    validate_milestone_title, validate_owner_sub, Label, Milestone, Repo, RepoCollaborator,
    Webhook,
};
use crate::webhooks::{
    normalize_event_csv, validate_webhook_url, EVENT_ISSUES, EVENT_OPTIONS, EVENT_PULL_REQUEST,
    EVENT_PUSH,
};
use crate::{now_secs, random_alnum, AppState};

const LABEL_ID_LEN: usize = 16;
const MILESTONE_ID_LEN: usize = 16;
const COLLABORATOR_ID_LEN: usize = 16;
const WEBHOOK_ID_LEN: usize = 16;
const WEBHOOK_SECRET_CHARS: usize = 512;

/// Whether `who` may edit this repo's settings: the owner, a repo admin collaborator, or an
/// estate/product admin.
async fn can_edit(
    state: &AppState,
    repo: &Repo,
    who: &Identity,
    headers: &HeaderMap,
) -> Result<bool, AppError> {
    can_admin_repo(state, repo, who, headers).await
}

// ===========================================================================
// GET /r/{owner}/{name}/settings — the settings form
// ===========================================================================

pub async fn show(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    if !can_edit(&state, &repo, &who, &headers).await? {
        return Err(AppError::Forbidden(
            "Only the repository owner or an administrator can change settings.".to_string(),
        ));
    }
    let csrf = auth::new_csrf_token();
    let body = render_settings(&state, &repo, &who, &csrf, None).await;
    Ok(html_with_csrf(
        StatusCode::OK,
        page(
            &format!("{owner}/{name} · Settings"),
            Some(&who.email),
            who.theme,
            &body,
        ),
        &csrf,
    ))
}

// ===========================================================================
// POST /r/{owner}/{name}/settings — apply description + default branch
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct SettingsForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub default_branch: String,
    #[serde(default)]
    pub require_approval: String,
    #[serde(default)]
    pub required_approvals: String,
    #[serde(default)]
    pub require_code_owner_reviews: String,
    #[serde(default)]
    pub protect_default_branch: String,
}

pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
    Form(form): Form<SettingsForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and submit again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    if !can_edit(&state, &repo, &who, &headers).await? {
        return Err(AppError::Forbidden(
            "Only the repository owner or an administrator can change settings.".to_string(),
        ));
    }

    let description: String = form.description.trim().chars().take(500).collect();
    let default_branch = form.default_branch.trim().to_string();
    let required_approvals =
        match parse_required_approvals(&form.required_approvals, form.require_approval == "on") {
            Ok(n) => n,
            Err(msg) => {
                let csrf = auth::new_csrf_token();
                let body = render_settings(&state, &repo, &who, &csrf, Some(&msg)).await;
                return Ok(html_with_csrf(
                    StatusCode::BAD_REQUEST,
                    page(
                        &format!("{owner}/{name} · Settings"),
                        Some(&who.email),
                        who.theme,
                        &body,
                    ),
                    &csrf,
                ));
            }
        };

    // The default branch must be well-formed AND actually exist (when the repo has branches; an
    // empty repo may pre-set any valid name so the first push lands on it).
    let branches = state.git.branches(&repo.owner_sub, &repo.name).await;
    let branch_ok = validate_branch_name(&default_branch).is_ok()
        && (branches.is_empty() || branches.contains(&default_branch));
    if !branch_ok {
        let csrf = auth::new_csrf_token();
        let body = render_settings(
            &state,
            &repo,
            &who,
            &csrf,
            Some("Choose an existing branch as the default."),
        )
        .await;
        return Ok(html_with_csrf(
            StatusCode::BAD_REQUEST,
            page(
                &format!("{owner}/{name} · Settings"),
                Some(&who.email),
                who.theme,
                &body,
            ),
            &csrf,
        ));
    }

    state
        .store
        .update_repo_settings(
            &repo.id,
            &description,
            &default_branch,
            required_approvals,
            form.require_code_owner_reviews == "on",
            form.protect_default_branch == "on",
        )
        .await?;
    // Keep the bare repo's HEAD in step so `git clone` checks out the new default.
    if default_branch != repo.default_branch {
        if let Err(e) = state
            .git
            .set_head(&repo.owner_sub, &repo.name, &default_branch)
            .await
        {
            return Err(AppError::Internal(format!("git symbolic-ref failed: {e}")));
        }
    }

    tracing::info!(
        repo = repo.id,
        actor = who.subject,
        default_branch = default_branch,
        required_approvals = required_approvals,
        require_code_owner_reviews = form.require_code_owner_reviews == "on",
        protect_default_branch = form.protect_default_branch == "on",
        "repository settings updated"
    );
    Ok(redirect(&format!("/r/{owner}/{name}/settings")))
}

fn parse_required_approvals(raw: &str, legacy_require_approval: bool) -> Result<i64, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(if legacy_require_approval { 1 } else { 0 });
    }
    let parsed = trimmed
        .parse::<i64>()
        .map_err(|_| "Required approvals must be a number from 0 to 100.".to_string())?;
    if !(0..=100).contains(&parsed) {
        return Err("Required approvals must be a number from 0 to 100.".to_string());
    }
    Ok(parsed)
}

#[derive(Debug, Deserialize)]
pub struct CollaboratorForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub user_sub: String,
    #[serde(default)]
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct RemoveCollaboratorForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub user_sub: String,
}

pub async fn add_collaborator(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
    Form(form): Form<CollaboratorForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and submit again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    if !can_edit(&state, &repo, &who, &headers).await? {
        return Err(AppError::Forbidden(
            "Only the repository owner, a repository admin, or an administrator can manage collaborators."
                .to_string(),
        ));
    }
    let user_sub = clean_collaborator_subject(&form.user_sub)?;
    if user_sub == repo.owner_sub {
        return Err(AppError::BadRequest(
            "The repository owner already has admin access.".to_string(),
        ));
    }
    let role = clean_collaborator_role(&form.role)?;
    state
        .store
        .upsert_repo_collaborator(
            &format!("rc_{}", random_alnum(COLLABORATOR_ID_LEN)),
            &repo.id,
            &user_sub,
            role,
            now_secs(),
        )
        .await?;
    tracing::info!(
        repo = repo.id,
        actor = who.subject,
        collaborator = user_sub,
        role,
        "repository collaborator upserted"
    );
    Ok(redirect(&format!("/r/{owner}/{name}/settings")))
}

pub async fn update_collaborator_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
    Form(form): Form<CollaboratorForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and submit again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    if !can_edit(&state, &repo, &who, &headers).await? {
        return Err(AppError::Forbidden(
            "Only the repository owner, a repository admin, or an administrator can manage collaborators."
                .to_string(),
        ));
    }
    let user_sub = clean_collaborator_subject(&form.user_sub)?;
    if user_sub == repo.owner_sub {
        return Err(AppError::BadRequest(
            "The repository owner cannot be downgraded.".to_string(),
        ));
    }
    let role = clean_collaborator_role(&form.role)?;
    if !state
        .store
        .update_repo_collaborator_role(&repo.id, &user_sub, role)
        .await?
    {
        return Err(AppError::NotFound("No such collaborator.".to_string()));
    }
    tracing::info!(
        repo = repo.id,
        actor = who.subject,
        collaborator = user_sub,
        role,
        "repository collaborator role updated"
    );
    Ok(redirect(&format!("/r/{owner}/{name}/settings")))
}

pub async fn remove_collaborator(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
    Form(form): Form<RemoveCollaboratorForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    if !can_edit(&state, &repo, &who, &headers).await? {
        return Err(AppError::Forbidden(
            "Only the repository owner, a repository admin, or an administrator can manage collaborators."
                .to_string(),
        ));
    }
    let user_sub = clean_collaborator_subject(&form.user_sub)?;
    if user_sub == repo.owner_sub {
        return Err(AppError::BadRequest(
            "The repository owner cannot be removed.".to_string(),
        ));
    }
    if !state
        .store
        .remove_repo_collaborator(&repo.id, &user_sub)
        .await?
    {
        return Err(AppError::NotFound("No such collaborator.".to_string()));
    }
    tracing::info!(
        repo = repo.id,
        actor = who.subject,
        collaborator = user_sub,
        "repository collaborator removed"
    );
    Ok(redirect(&format!("/r/{owner}/{name}/settings")))
}

#[derive(Debug, Deserialize)]
pub struct DeleteRepoForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub confirm_name: String,
}

pub async fn delete_repository(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
    Form(form): Form<DeleteRepoForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    if repo.owner_sub != who.subject {
        return Err(AppError::Forbidden(
            "Only the repository owner can delete this repository.".to_string(),
        ));
    }
    if form.confirm_name.trim() != repo.name {
        return Err(AppError::BadRequest(
            "Repository name confirmation did not match.".to_string(),
        ));
    }
    if !state.store.delete_repo_cascade(&repo.id).await? {
        return Err(AppError::NotFound("No such repository.".to_string()));
    }
    if let Err(e) = state.git.delete_repo_dir(&repo.owner_sub, &repo.name).await {
        tracing::warn!(
            repo = repo.id,
            owner = repo.owner_sub,
            name = repo.name,
            error = %e,
            "repository metadata deleted but bare repo removal failed"
        );
    }
    tracing::info!(repo = repo.id, actor = who.subject, "repository deleted");
    Ok(redirect("/"))
}

fn clean_collaborator_subject(raw: &str) -> Result<String, AppError> {
    let user_sub = raw.trim().chars().take(128).collect::<String>();
    validate_owner_sub(&user_sub).map_err(|e| AppError::BadRequest(e.to_string()))?;
    Ok(user_sub)
}

fn clean_collaborator_role(raw: &str) -> Result<&'static str, AppError> {
    normalize_repo_role(raw).ok_or_else(|| {
        AppError::BadRequest("Collaborator role must be read, write, or admin.".to_string())
    })
}

#[derive(Debug, Deserialize)]
pub struct LabelForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub color: String,
}

pub async fn create_label(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
    Form(form): Form<LabelForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and submit again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    if !can_edit(&state, &repo, &who, &headers).await? {
        return Err(AppError::Forbidden(
            "Only the repository owner or an administrator can change settings.".to_string(),
        ));
    }
    let label_name = form.name.trim().chars().take(40).collect::<String>();
    validate_label_name(&label_name).map_err(|e| AppError::BadRequest(e.to_string()))?;
    let color = form
        .color
        .trim()
        .trim_start_matches('#')
        .to_ascii_lowercase();
    validate_label_color(&color).map_err(|e| AppError::BadRequest(e.to_string()))?;
    let created = state
        .store
        .create_label(
            &format!("lb_{}", random_alnum(LABEL_ID_LEN)),
            &repo.id,
            &label_name,
            &color,
            now_secs(),
        )
        .await?;
    if created.is_none() {
        return Err(AppError::BadRequest(
            "A label with that name already exists.".to_string(),
        ));
    }
    tracing::info!(
        repo = repo.id,
        actor = who.subject,
        label = label_name,
        "label created"
    );
    Ok(redirect(&format!("/r/{owner}/{name}/settings")))
}

#[derive(Debug, Deserialize)]
pub struct MilestoneForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub due: String,
}

pub async fn create_milestone(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
    Form(form): Form<MilestoneForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and submit again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    if !can_edit(&state, &repo, &who, &headers).await? {
        return Err(AppError::Forbidden(
            "Only the repository owner or an administrator can change settings.".to_string(),
        ));
    }
    let title = form.title.trim().chars().take(120).collect::<String>();
    let due = form.due.trim().to_string();
    validate_milestone_title(&title).map_err(|e| AppError::BadRequest(e.to_string()))?;
    validate_milestone_due(&due).map_err(|e| AppError::BadRequest(e.to_string()))?;
    let created = state
        .store
        .create_milestone(
            &format!("ms_{}", random_alnum(MILESTONE_ID_LEN)),
            &repo.id,
            &title,
            &due,
            now_secs(),
        )
        .await?;
    if created.is_none() {
        return Err(AppError::BadRequest(
            "A milestone with that title already exists.".to_string(),
        ));
    }
    tracing::info!(
        repo = repo.id,
        actor = who.subject,
        milestone = title,
        "milestone created"
    );
    Ok(redirect(&format!("/r/{owner}/{name}/settings")))
}

#[derive(Debug, Deserialize)]
pub struct ToggleMilestoneForm {
    #[serde(default)]
    pub csrf_token: String,
}

pub async fn toggle_milestone(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, id)): Path<(String, String, String)>,
    Form(form): Form<ToggleMilestoneForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    if !can_edit(&state, &repo, &who, &headers).await? {
        return Err(AppError::Forbidden(
            "Only the repository owner or an administrator can change settings.".to_string(),
        ));
    }
    let milestones = state.store.list_milestones(&repo.id).await?;
    let milestone = milestones
        .iter()
        .find(|m| m.id == id)
        .ok_or_else(|| AppError::NotFound("No such milestone.".to_string()))?;
    let next = if milestone.is_open() {
        "closed"
    } else {
        "open"
    };
    state.store.set_milestone_state(&id, next).await?;
    tracing::info!(
        repo = repo.id,
        actor = who.subject,
        milestone = id,
        state = next,
        "milestone toggled"
    );
    Ok(redirect(&format!("/r/{owner}/{name}/settings")))
}

#[derive(Debug, Deserialize)]
pub struct WebhookForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub event_push: String,
    #[serde(default)]
    pub event_pull_request: String,
    #[serde(default)]
    pub event_issues: String,
    #[serde(default)]
    pub active: String,
}

pub async fn create_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
    Form(form): Form<WebhookForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and submit again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    if !can_edit(&state, &repo, &who, &headers).await? {
        return Err(AppError::Forbidden(
            "Only the repository owner or an administrator can change settings.".to_string(),
        ));
    }

    let url = validate_webhook_url(&form.url).map_err(AppError::BadRequest)?;
    let secret = clean_webhook_secret(&form.secret, true)?.expect("required webhook secret");
    let events = webhook_events_from_form(&form)?;
    let webhook = Webhook {
        id: format!("wh_{}", random_alnum(WEBHOOK_ID_LEN)),
        repo_id: repo.id.clone(),
        url,
        secret,
        events,
        active: form.active == "on",
        created_at: now_secs(),
    };
    if !state.store.create_webhook(&webhook).await? {
        return Err(AppError::Internal("webhook id collision".to_string()));
    }
    tracing::info!(
        repo = repo.id,
        actor = who.subject,
        webhook = webhook.id,
        active = webhook.active,
        "webhook created"
    );
    Ok(redirect(&format!("/r/{owner}/{name}/settings")))
}

pub async fn update_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, id)): Path<(String, String, String)>,
    Form(form): Form<WebhookForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and submit again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    if !can_edit(&state, &repo, &who, &headers).await? {
        return Err(AppError::Forbidden(
            "Only the repository owner or an administrator can change settings.".to_string(),
        ));
    }
    let existing = state
        .store
        .get_webhook(&repo.id, &id)
        .await?
        .ok_or_else(|| AppError::NotFound("No such webhook.".to_string()))?;
    let url = validate_webhook_url(&form.url).map_err(AppError::BadRequest)?;
    let secret = match clean_webhook_secret(&form.secret, false)? {
        Some(secret) => secret,
        None => existing.secret,
    };
    let events = webhook_events_from_form(&form)?;
    state
        .store
        .update_webhook(&repo.id, &id, &url, &secret, &events, form.active == "on")
        .await?;
    tracing::info!(
        repo = repo.id,
        actor = who.subject,
        webhook = id,
        active = form.active == "on",
        "webhook updated"
    );
    Ok(redirect(&format!("/r/{owner}/{name}/settings")))
}

#[derive(Debug, Deserialize)]
pub struct DeleteWebhookForm {
    #[serde(default)]
    pub csrf_token: String,
}

pub async fn delete_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, id)): Path<(String, String, String)>,
    Form(form): Form<DeleteWebhookForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    if !can_edit(&state, &repo, &who, &headers).await? {
        return Err(AppError::Forbidden(
            "Only the repository owner or an administrator can change settings.".to_string(),
        ));
    }
    if !state.store.delete_webhook(&repo.id, &id).await? {
        return Err(AppError::NotFound("No such webhook.".to_string()));
    }
    tracing::info!(
        repo = repo.id,
        actor = who.subject,
        webhook = id,
        "webhook deleted"
    );
    Ok(redirect(&format!("/r/{owner}/{name}/settings")))
}

fn clean_webhook_secret(raw: &str, required: bool) -> Result<Option<String>, AppError> {
    let secret: String = raw.trim().chars().take(WEBHOOK_SECRET_CHARS).collect();
    if secret.is_empty() {
        if required {
            Err(AppError::BadRequest(
                "Webhook secret cannot be empty.".to_string(),
            ))
        } else {
            Ok(None)
        }
    } else {
        Ok(Some(secret))
    }
}

fn webhook_events_from_form(form: &WebhookForm) -> Result<String, AppError> {
    let mut events = Vec::new();
    if form.event_push == "on" {
        events.push(EVENT_PUSH.to_string());
    }
    if form.event_pull_request == "on" {
        events.push(EVENT_PULL_REQUEST.to_string());
    }
    if form.event_issues == "on" {
        events.push(EVENT_ISSUES.to_string());
    }
    normalize_event_csv(&events).map_err(AppError::BadRequest)
}

// ===========================================================================
// Rendering
// ===========================================================================

/// The settings form card (the PRG redirect re-loads the repo row, so a just-saved value renders).
/// The default branch offers the existing branches in a select — a free-text input when the repo
/// has no branches yet.
async fn render_settings(
    state: &AppState,
    repo: &Repo,
    who: &Identity,
    csrf: &str,
    error: Option<&str>,
) -> String {
    let header = header_with_counts(state, repo, "settings").await;
    let error_block = match error {
        Some(msg) => format!(
            "<div class=\"alert alert-danger\" role=\"alert\">{}</div>",
            esc(msg)
        ),
        None => String::new(),
    };

    let branches = state.git.branches(&repo.owner_sub, &repo.name).await;
    let branch_field = if branches.is_empty() {
        format!(
            "<input type=\"text\" id=\"default_branch\" name=\"default_branch\" maxlength=\"64\" value=\"{}\" autocomplete=\"off\" spellcheck=\"false\">",
            esc(&repo.default_branch)
        )
    } else {
        let opts = branches
            .iter()
            .map(|b| {
                let sel = if *b == repo.default_branch {
                    " selected"
                } else {
                    ""
                };
                format!(
                    "<option value=\"{v}\"{sel}>{v}</option>",
                    v = esc(b),
                    sel = sel
                )
            })
            .collect::<String>();
        format!("<select id=\"default_branch\" name=\"default_branch\">{opts}</select>")
    };
    let required_approvals = if repo.required_approvals > 0 {
        repo.required_approvals
    } else if repo.require_approval {
        1
    } else {
        0
    };
    let codeowners_checked = if repo.require_code_owner_reviews {
        " checked"
    } else {
        ""
    };
    let protect_checked = if repo.protect_default_branch {
        " checked"
    } else {
        ""
    };
    let labels = state.store.list_labels(&repo.id).await.unwrap_or_default();
    let milestones = state
        .store
        .list_milestones(&repo.id)
        .await
        .unwrap_or_default();
    let collaborators = state
        .store
        .list_repo_collaborators(&repo.id)
        .await
        .unwrap_or_default();
    let webhooks = state
        .store
        .list_webhooks(&repo.id)
        .await
        .unwrap_or_default();
    let deploy = state.store.get_deploy(&repo.id).await.unwrap_or_default();
    let collaborators_card = render_collaborators_card(repo, csrf, &collaborators);
    let labels_card = render_labels_card(repo, csrf, &labels);
    let milestones_card = render_milestones_card(state, repo, csrf, &milestones).await;
    let webhooks_card = render_webhooks_card(repo, csrf, &webhooks);
    let deploy_card =
        crate::handlers::deploy::render_deploy_card(state, repo, csrf, deploy.as_ref());
    let danger_zone = render_danger_zone(repo, who, csrf);

    format!(
        r##"{header}
<div class="settings">
<nav class="settings-nav" aria-label="Repository settings">
  <a class="is-active" href="#settings-general"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z"/></svg>General</a>
  <a href="#settings-collaborators"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8"/></svg>Collaborators</a>
  <a href="#settings-webhooks"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 16.98h-5.99c-1.1 0-1.95.94-2.48 1.9A4 4 0 0 1 2 17c.01-.7.2-1.4.57-2M6 8a6 6 0 0 1 11.5-2.4M13.3 8.9 9.7 15"/><circle cx="18" cy="17" r="3"/></svg>Webhooks</a>
  <a href="#settings-deploy"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4.5 16.5 12 3l7.5 13.5"/><path d="M8 16.5h8"/><path d="M12 3v18"/></svg>Deploy</a>
  <a href="#settings-labels"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20.6 13.4 13.4 20.6a2 2 0 0 1-2.8 0L3 13V3h10l7.6 7.6a2 2 0 0 1 0 2.8Z"/><circle cx="7.5" cy="7.5" r="1.5"/></svg>Labels</a>
  <a href="#settings-milestones"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 21V4h13l-3 4 3 4H5"/></svg>Milestones</a>
  <a class="settings-nav__danger" href="#settings-danger"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></svg>Danger zone</a>
</nav>
<div class="settings-main">
<section class="card" id="settings-general">
  <div class="card__head"><h2>General</h2></div>
  <div class="card__body">
    {error_block}
    <form method="post" action="/r/{owner}/{name}/settings">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <div class="field">
        <label for="description">Description</label>
        <input type="text" id="description" name="description" maxlength="500" value="{desc}">
        <p class="hint hint--muted">Shown on the repository list and home page</p>
      </div>
      <div class="field">
        <label for="default_branch">Default branch</label>
        {branch_field}
        <p class="hint hint--muted">Where pull requests merge</p>
      </div>
      <div class="field field--check">
        <label for="required_approvals">Required approvals before web merge</label>
        <input class="approval-count" type="number" id="required_approvals" name="required_approvals" min="0" max="100" value="{required_approvals}">
      </div>
      <div class="field field--check">
        <label class="check"><input class="codeowners-req" type="checkbox" name="require_code_owner_reviews" value="on"{codeowners_checked}> Require CODEOWNERS reviews before web merge</label>
      </div>
      <div class="field field--check">
        <label class="check"><input type="checkbox" name="protect_default_branch" value="on"{protect_checked}> Protect the default branch from direct git push</label>
      </div>
      <div class="actions">
        <button class="btn btn-primary" type="submit">Save changes</button>
      </div>
    </form>
  </div>
</section>
{collaborators_card}
{webhooks_card}
<div id="settings-deploy">{deploy_card}</div>
{labels_card}
{milestones_card}
{danger_zone}
</div>
</div>"##,
        header = header,
        error_block = error_block,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        csrf = esc(csrf),
        desc = esc(&repo.description),
        branch_field = branch_field,
        required_approvals = required_approvals,
        codeowners_checked = codeowners_checked,
        protect_checked = protect_checked,
        collaborators_card = collaborators_card,
        webhooks_card = webhooks_card,
        deploy_card = deploy_card,
        labels_card = labels_card,
        milestones_card = milestones_card,
        danger_zone = danger_zone,
    )
}

fn render_collaborators_card(
    repo: &Repo,
    csrf: &str,
    collaborators: &[RepoCollaborator],
) -> String {
    let rows = if collaborators.is_empty() {
        "<li class=\"collaborator-item collaborator-item--empty\">No collaborators yet.</li>"
            .to_string()
    } else {
        collaborators
            .iter()
            .map(|collaborator| render_collaborator_item(repo, csrf, collaborator))
            .collect::<String>()
    };
    let role_options = render_role_options("write");
    format!(
        r##"<section class="card collaborator-settings" id="settings-collaborators">
  <div class="card__head"><h2>Collaborators</h2><span class="tab__count">{count}</span></div>
  <div class="card__body">
    <ul class="collaborator-list">{rows}</ul>
    <form class="collaborator-form collaborator-form--new" method="post" action="/r/{owner}/{name}/settings/collaborators">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <div class="field">
        <label for="collaborator-user-sub">User</label>
        <input type="text" id="collaborator-user-sub" name="user_sub" maxlength="128" autocomplete="off" spellcheck="false" required>
      </div>
      <div class="field">
        <label for="collaborator-role">Role</label>
        <select id="collaborator-role" class="collab-role" name="role">{role_options}</select>
      </div>
      <div class="actions">
        <button class="btn btn-secondary btn-add-collaborator" type="submit">Add collaborator</button>
      </div>
    </form>
  </div>
</section>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        csrf = esc(csrf),
        count = collaborators.len(),
        rows = rows,
        role_options = role_options,
    )
}

fn render_collaborator_item(repo: &Repo, csrf: &str, collaborator: &RepoCollaborator) -> String {
    let options = render_role_options(&collaborator.role);
    format!(
        r##"<li class="collaborator-item">
  <div class="issue-item__head">
    <span class="issue-item__title">{user_sub}</span>
    <span class="state-badge collab-role">{role}</span>
  </div>
  <div class="issue-item__meta">Added {created}</div>
  <form class="inline-form collaborator-role-form" method="post" action="/r/{owner}/{name}/settings/collaborators/role">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <input type="hidden" name="user_sub" value="{user_sub}">
    <select class="collab-role" name="role">{options}</select>
    <button class="btn btn-secondary btn-sm" type="submit">Update role</button>
  </form>
  <form class="inline-form collaborator-remove-form" method="post" action="/r/{owner}/{name}/settings/collaborators/remove">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <input type="hidden" name="user_sub" value="{user_sub}">
    <button class="btn btn-ghost btn-sm btn-remove-collaborator" type="submit">Remove</button>
  </form>
</li>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        csrf = esc(csrf),
        user_sub = esc(&collaborator.user_sub),
        role = esc(&collaborator.role),
        options = options,
        created = esc(&fmt_ts(collaborator.created_at)),
    )
}

fn render_role_options(selected: &str) -> String {
    ["read", "write", "admin"]
        .iter()
        .map(|role| {
            let selected_attr = if *role == selected { " selected" } else { "" };
            format!(
                "<option value=\"{role}\"{selected_attr}>{role}</option>",
                role = role,
                selected_attr = selected_attr,
            )
        })
        .collect::<String>()
}

fn render_danger_zone(repo: &Repo, who: &Identity, csrf: &str) -> String {
    if repo.owner_sub != who.subject {
        return String::new();
    }
    format!(
        r##"<section class="card danger-zone" id="settings-danger">
  <div class="card__head"><h2>Delete repository</h2></div>
  <div class="card__body">
    <form class="delete-repo-form" method="post" action="/r/{owner}/{name}/settings/delete" data-delete-confirm="{name}">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <div class="field">
        <label for="delete-repo-confirm">Type <code>{name}</code> to confirm</label>
        <input type="text" id="delete-repo-confirm" name="confirm_name" maxlength="64" autocomplete="off" spellcheck="false" data-delete-confirm-input required>
      </div>
      <div class="actions">
        <button class="btn btn-danger btn-delete-repo" type="submit" data-delete-confirm-button disabled>Delete repository</button>
      </div>
    </form>
  </div>
</section>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        csrf = esc(csrf),
    )
}

fn render_webhooks_card(repo: &Repo, csrf: &str, webhooks: &[Webhook]) -> String {
    let rows = if webhooks.is_empty() {
        "<li class=\"webhook-item webhook-item--empty\">No webhooks configured.</li>".to_string()
    } else {
        webhooks
            .iter()
            .map(|webhook| render_webhook_item(repo, csrf, webhook))
            .collect::<String>()
    };
    let create_events = render_webhook_event_checks("new", "push");
    format!(
        r##"<section class="card webhook-settings" id="settings-webhooks">
  <div class="card__head"><h2>Webhooks</h2><span class="tab__count">{count}</span></div>
  <div class="card__body">
    <ul class="webhook-list">{rows}</ul>
    <form class="webhook-form webhook-form--new" method="post" action="/r/{owner}/{name}/settings/webhooks">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <div class="field">
        <label for="webhook-new-url">Payload URL</label>
        <input type="url" id="webhook-new-url" name="url" maxlength="2048" placeholder="https://example.com/loom" required>
      </div>
      <div class="field">
        <label for="webhook-new-secret">Secret</label>
        <input type="password" id="webhook-new-secret" name="secret" maxlength="512" autocomplete="new-password" required>
      </div>
      <div class="field webhook-events">
        <span class="field-label">Events</span>
        {create_events}
      </div>
      <div class="field field--check">
        <label class="check"><input type="checkbox" name="active" value="on" checked> Active</label>
      </div>
      <div class="actions">
        <button class="btn btn-secondary btn-add-webhook" type="submit">Add webhook</button>
      </div>
    </form>
  </div>
</section>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        csrf = esc(csrf),
        count = webhooks.len(),
        rows = rows,
        create_events = create_events,
    )
}

fn render_webhook_item(repo: &Repo, csrf: &str, webhook: &Webhook) -> String {
    let active_checked = if webhook.active { " checked" } else { "" };
    let active_label = if webhook.active { "Active" } else { "Paused" };
    let active_class = if webhook.active {
        "state-badge--open"
    } else {
        "state-badge--closed"
    };
    let event_checks = render_webhook_event_checks(&webhook.id, &webhook.events);
    let event_summary = render_webhook_event_summary(&webhook.events);
    format!(
        r##"<li class="webhook-item">
  <div class="issue-item__head">
    <span class="issue-item__title">{url}</span>
    <span class="state-badge {active_class}">{active_label}</span>
  </div>
  <div class="issue-item__meta">{event_summary} · created {created}</div>
  <details class="webhook-edit">
  <summary>Edit</summary>
  <form class="webhook-form webhook-form--edit" method="post" action="/r/{owner}/{name}/settings/webhooks/{id}/update">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <div class="field">
      <label for="webhook-{id}-url">Payload URL</label>
      <input type="url" id="webhook-{id}-url" name="url" maxlength="2048" value="{url}" required>
    </div>
    <div class="field">
      <label for="webhook-{id}-secret">Secret</label>
      <input type="password" id="webhook-{id}-secret" name="secret" maxlength="512" autocomplete="new-password" placeholder="Leave blank to keep existing secret">
    </div>
    <div class="field webhook-events">
      <span class="field-label">Events</span>
      {event_checks}
    </div>
    <div class="field field--check">
      <label class="check"><input type="checkbox" name="active" value="on"{active_checked}> Active</label>
    </div>
    <div class="actions">
      <button class="btn btn-secondary btn-update-webhook" type="submit">Save webhook</button>
      <form class="inline-form webhook-delete-form" method="post" action="/r/{owner}/{name}/settings/webhooks/{id}/delete">
        <input type="hidden" name="csrf_token" value="{csrf}">
        <button class="btn btn-ghost btn-sm btn-delete-webhook" type="submit">Delete webhook</button>
      </form>
    </div>
  </form>
  </details>
</li>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        id = esc(&webhook.id),
        csrf = esc(csrf),
        url = esc(&webhook.url),
        active_checked = active_checked,
        active_class = active_class,
        active_label = active_label,
        event_checks = event_checks,
        event_summary = event_summary,
        created = esc(&fmt_ts(webhook.created_at)),
    )
}

fn render_webhook_event_checks(id: &str, events: &str) -> String {
    EVENT_OPTIONS
        .iter()
        .map(|(name, label)| {
            let checked = if event_configured(events, name) {
                " checked"
            } else {
                ""
            };
            let input_id = format!("webhook-{id}-event-{name}");
            let input_name = format!("event_{name}");
            format!(
                r#"<label class="check" for="{input_id}"><input type="checkbox" id="{input_id}" name="{input_name}" value="on"{checked}> {label}</label>"#,
                input_id = esc(&input_id),
                input_name = esc(&input_name),
                checked = checked,
                label = esc(label),
            )
        })
        .collect::<String>()
}

fn render_webhook_event_summary(events: &str) -> String {
    let labels: Vec<&str> = EVENT_OPTIONS
        .iter()
        .filter_map(|(name, label)| event_configured(events, name).then_some(*label))
        .collect();
    if labels.is_empty() {
        "none".to_string()
    } else {
        labels.join(", ")
    }
}

fn event_configured(events: &str, event: &str) -> bool {
    events
        .split(',')
        .any(|configured| configured.trim() == event)
}

fn render_labels_card(repo: &Repo, csrf: &str, labels: &[Label]) -> String {
    let list = if labels.is_empty() {
        "<li class=\"issue-item issue-item--empty\">No labels yet.</li>".to_string()
    } else {
        labels
            .iter()
            .map(|label| {
                format!(
                    r##"<li class="issue-item">
  <div class="issue-item__head">
    <span class="label-chip" style="--label-color: #{color}">{name}</span>
  </div>
</li>"##,
                    color = esc(&label.color),
                    name = esc(&label.name),
                )
            })
            .collect::<String>()
    };
    format!(
        r##"<section class="card" id="settings-labels">
  <div class="card__head"><h2>Labels</h2><span class="tab__count">{count}</span></div>
  <div class="card__body">
    <ul class="issue-list">{list}</ul>
    <form method="post" action="/r/{owner}/{name}/settings/labels">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <div class="field">
        <label for="label-name">Name</label>
        <input type="text" id="label-name" name="name" maxlength="40" required>
      </div>
      <div class="field">
        <label for="label-color">Color</label>
        <input type="text" id="label-color" name="color" maxlength="7" value="4f46e5" autocomplete="off" spellcheck="false" required>
      </div>
      <div class="actions">
        <button class="btn btn-secondary" type="submit">Create label</button>
      </div>
    </form>
  </div>
</section>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        csrf = esc(csrf),
        count = labels.len(),
        list = list,
    )
}

async fn render_milestones_card(
    state: &AppState,
    repo: &Repo,
    csrf: &str,
    milestones: &[Milestone],
) -> String {
    let list = if milestones.is_empty() {
        "<li class=\"issue-item issue-item--empty\">No milestones yet.</li>".to_string()
    } else {
        let mut rows = String::new();
        for milestone in milestones {
            let (closed, total) = state
                .store
                .milestone_progress(&repo.id, &milestone.id)
                .await
                .unwrap_or((0, 0));
            let pct = if total == 0 {
                0
            } else {
                (closed * 100 / total).clamp(0, 100)
            };
            let action = if milestone.is_open() {
                "Close"
            } else {
                "Reopen"
            };
            let due = if milestone.due.is_empty() {
                String::new()
            } else {
                format!(" · due {}", esc(&milestone.due))
            };
            rows.push_str(&format!(
                r##"<li class="issue-item">
  <div class="issue-item__head">
    <span class="state-badge {state_class}">{state}</span>
    <span class="issue-item__title">{title}</span>
  </div>
  <div class="progress"><span style="width:{pct}%"></span></div>
  <div class="issue-item__meta">
    <span>{closed}/{total} closed{due}</span>
    <form class="inline-form" method="post" action="/r/{owner}/{name}/settings/milestones/{id}/toggle">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <button class="btn btn-ghost btn-sm" type="submit">{action}</button>
    </form>
  </div>
</li>"##,
                state_class = if milestone.is_open() {
                    "state-badge--open"
                } else {
                    "state-badge--closed"
                },
                state = esc(&milestone.state),
                title = esc(&milestone.title),
                pct = pct,
                closed = closed,
                total = total,
                due = due,
                owner = esc(&repo.owner_sub),
                name = esc(&repo.name),
                id = esc(&milestone.id),
                csrf = esc(csrf),
                action = action,
            ));
        }
        rows
    };
    format!(
        r##"<section class="card" id="settings-milestones">
  <div class="card__head"><h2>Milestones</h2><span class="tab__count">{count}</span></div>
  <div class="card__body">
    <ul class="issue-list">{list}</ul>
    <form method="post" action="/r/{owner}/{name}/settings/milestones">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <div class="field">
        <label for="milestone-title">Title</label>
        <input type="text" id="milestone-title" name="title" maxlength="120" required>
      </div>
      <div class="field">
        <label for="milestone-due">Due date</label>
        <input type="text" id="milestone-due" name="due" maxlength="10" placeholder="YYYY-MM-DD" autocomplete="off" spellcheck="false">
      </div>
      <div class="actions">
        <button class="btn btn-secondary" type="submit">Create milestone</button>
      </div>
    </form>
  </div>
</section>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        csrf = esc(csrf),
        count = milestones.len(),
        list = list,
    )
}
