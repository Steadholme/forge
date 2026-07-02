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
use crate::handlers::repos::{header_with_counts, load_visible_repo, validate_branch_name};
use crate::handlers::{esc, html_with_csrf, page, redirect};
use crate::model::{
    validate_label_color, validate_label_name, validate_milestone_due, validate_milestone_title,
    Label, Milestone, Repo,
};
use crate::{now_secs, random_alnum, AppState};

const LABEL_ID_LEN: usize = 16;
const MILESTONE_ID_LEN: usize = 16;

/// Whether `who` may edit this repo's settings: the owner, or an estate/product admin.
fn can_edit(repo: &Repo, who: &Identity, headers: &HeaderMap) -> bool {
    repo.owner_sub == who.subject || auth::is_admin(headers)
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
    if !can_edit(&repo, &who, &headers) {
        return Err(AppError::Forbidden(
            "Only the repository owner or an administrator can change settings.".to_string(),
        ));
    }
    let csrf = auth::new_csrf_token();
    let body = render_settings(&state, &repo, &csrf, None).await;
    Ok(html_with_csrf(
        StatusCode::OK,
        page(
            &format!("{owner}/{name} · Settings"),
            Some(&who.email),
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
    if !can_edit(&repo, &who, &headers) {
        return Err(AppError::Forbidden(
            "Only the repository owner or an administrator can change settings.".to_string(),
        ));
    }

    let description: String = form.description.trim().chars().take(500).collect();
    let default_branch = form.default_branch.trim().to_string();

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
            &csrf,
            Some("Choose an existing branch as the default."),
        )
        .await;
        return Ok(html_with_csrf(
            StatusCode::BAD_REQUEST,
            page(
                &format!("{owner}/{name} · Settings"),
                Some(&who.email),
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
            form.require_approval == "on",
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
        require_approval = form.require_approval == "on",
        protect_default_branch = form.protect_default_branch == "on",
        "repository settings updated"
    );
    Ok(redirect(&format!("/r/{owner}/{name}/settings")))
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
    if !can_edit(&repo, &who, &headers) {
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
    if !can_edit(&repo, &who, &headers) {
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
    if !can_edit(&repo, &who, &headers) {
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

// ===========================================================================
// Rendering
// ===========================================================================

/// The settings form card (the PRG redirect re-loads the repo row, so a just-saved value renders).
/// The default branch offers the existing branches in a select — a free-text input when the repo
/// has no branches yet.
async fn render_settings(state: &AppState, repo: &Repo, csrf: &str, error: Option<&str>) -> String {
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
    let require_checked = if repo.require_approval {
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
    let labels_card = render_labels_card(repo, csrf, &labels);
    let milestones_card = render_milestones_card(state, repo, csrf, &milestones).await;

    format!(
        r##"{header}
<section class="card">
  <div class="card__head"><h2>Repository settings</h2></div>
  <div class="card__body">
    {error_block}
    <form method="post" action="/r/{owner}/{name}/settings">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <div class="field">
        <label for="description">Description</label>
        <input type="text" id="description" name="description" maxlength="500" value="{desc}" placeholder="Optional one-line summary">
        <p class="hint hint--muted">Shown on the repository list and the repository home page.</p>
      </div>
      <div class="field">
        <label for="default_branch">Default branch</label>
        {branch_field}
        <p class="hint hint--muted">What HEAD points at — new clones and the file browser use this branch.</p>
      </div>
      <div class="field field--check">
        <label class="check"><input type="checkbox" name="require_approval" value="on"{require_checked}> Require at least one approval before web merge</label>
      </div>
      <div class="field field--check">
        <label class="check"><input type="checkbox" name="protect_default_branch" value="on"{protect_checked}> Protect the default branch from direct git push</label>
      </div>
      <div class="actions">
        <button class="btn btn-primary" type="submit">Save settings</button>
      </div>
    </form>
  </div>
</section>
{labels_card}
{milestones_card}"##,
        header = header,
        error_block = error_block,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        csrf = esc(csrf),
        desc = esc(&repo.description),
        branch_field = branch_field,
        require_checked = require_checked,
        protect_checked = protect_checked,
        labels_card = labels_card,
        milestones_card = milestones_card,
    )
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
        r##"<section class="card">
  <div class="card__head"><h2>Labels</h2></div>
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
        r##"<section class="card">
  <div class="card__head"><h2>Milestones</h2></div>
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
        list = list,
    )
}
