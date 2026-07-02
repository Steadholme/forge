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
use crate::model::Repo;
use crate::AppState;

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
        page(&format!("{owner}/{name} · Settings"), Some(&who.email), &body),
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
            page(&format!("{owner}/{name} · Settings"), Some(&who.email), &body),
            &csrf,
        ));
    }

    state
        .store
        .update_repo_settings(&repo.id, &description, &default_branch)
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
        "repository settings updated"
    );
    Ok(redirect(&format!("/r/{owner}/{name}/settings")))
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
                let sel = if *b == repo.default_branch { " selected" } else { "" };
                format!("<option value=\"{v}\"{sel}>{v}</option>", v = esc(b), sel = sel)
            })
            .collect::<String>();
        format!("<select id=\"default_branch\" name=\"default_branch\">{opts}</select>")
    };

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
      <div class="actions">
        <button class="btn btn-primary" type="submit">Save settings</button>
      </div>
    </form>
  </div>
</section>"##,
        header = header,
        error_block = error_block,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        csrf = esc(csrf),
        desc = esc(&repo.description),
        branch_field = branch_field,
    )
}
