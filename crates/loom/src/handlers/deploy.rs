//! SiteFlow deployment integration for repositories.
//!
//! Mutations follow the settings handler sequence: CSRF, identity, visible repo, admin check,
//! validation, store/outbound work, audit log, PRG redirect. SiteFlow secrets are stored only for
//! server-side trigger calls and are never rendered or logged.

use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use reqwest::header::{CONTENT_TYPE, USER_AGENT};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::{self, Identity};
use crate::config::Config;
use crate::error::AppError;
use crate::gitops::CommitDetail;
use crate::handlers::repos::{can_admin_repo, load_visible_repo, validate_branch_name};
use crate::handlers::{esc, redirect};
use crate::model::{Repo, RepoDeploy};
use crate::{now_secs, random_alnum, AppState};

const DEPLOY_ID_LEN: usize = 16;
const SITEFLOW_TIMEOUT_SECS: u64 = 5;

#[derive(Debug, Deserialize)]
pub struct DeployForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub output_directory: String,
}

#[derive(Debug, Deserialize)]
pub struct DeploySettingsForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub production_branch: String,
    #[serde(default)]
    pub output_directory: String,
    #[serde(default)]
    pub framework: String,
    #[serde(default)]
    pub auto_deploy: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub confirm_name: String,
}

/// POST /r/{owner}/{name}/deploy
pub async fn deploy_now(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
    Form(form): Form<DeployForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and submit again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    require_deploy_admin(&state, &repo, &who, &headers).await?;
    ensure_public_repo(&repo)?;

    let existing = state.store.get_deploy(&repo.id).await?;
    let output_override = nonempty_trimmed(&form.output_directory);
    let deploy = deploy_from_existing(&state, &repo, existing, output_override.as_deref())?;
    let submitted = submit_deploy(&state, &repo, &who.subject, deploy).await?;
    tracing::info!(
        repo = repo.id,
        actor = who.subject,
        siteflow_slug = submitted.siteflow_slug,
        project_id = submitted.siteflow_project_id,
        build_job_id = submitted.last_build_job_id,
        "deploy submitted"
    );
    Ok(redirect(&format!("/r/{owner}/{name}/settings")))
}

/// POST /r/{owner}/{name}/settings/deploy
pub async fn update_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
    Form(form): Form<DeploySettingsForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and submit again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    require_deploy_admin(&state, &repo, &who, &headers).await?;

    if form.action == "disconnect" {
        if form.confirm_name.trim() != repo.name {
            return Err(AppError::BadRequest(
                "Repository name confirmation did not match.".to_string(),
            ));
        }
        state.store.delete_deploy(&repo.id).await?;
        tracing::info!(repo = repo.id, actor = who.subject, "deploy disconnected");
        return Ok(redirect(&format!("/r/{owner}/{name}/settings")));
    }

    ensure_public_repo(&repo)?;
    let existing = state.store.get_deploy(&repo.id).await?;
    let mut deploy = deploy_from_settings_form(&state, &repo, existing, &form).await?;
    deploy = state.store.upsert_deploy(&deploy).await?;

    if form.action == "redeploy" {
        deploy = submit_deploy(&state, &repo, &who.subject, deploy).await?;
        tracing::info!(
            repo = repo.id,
            actor = who.subject,
            siteflow_slug = deploy.siteflow_slug,
            project_id = deploy.siteflow_project_id,
            build_job_id = deploy.last_build_job_id,
            "deploy submitted from settings"
        );
    } else {
        tracing::info!(
            repo = repo.id,
            actor = who.subject,
            "deploy settings updated"
        );
    }
    Ok(redirect(&format!("/r/{owner}/{name}/settings")))
}

/// GET /r/{owner}/{name}/deploy/status
pub async fn status_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    require_deploy_admin(&state, &repo, &who, &headers).await?;
    let Some(deploy) = state.store.get_deploy(&repo.id).await? else {
        return Ok(Json(json!({ "configured": false })).into_response());
    };

    let siteflow_status = poll_siteflow_status(&state.config, &deploy).await;
    let status = siteflow_status
        .as_deref()
        .unwrap_or_else(|| deploy_status_label(&deploy));
    Ok(Json(json!({
        "configured": true,
        "status": status,
        "buildJobId": deploy.last_build_job_id,
        "previewUrl": deploy.preview_url,
        "lastDeployedSha": deploy.last_deployed_sha,
    }))
    .into_response())
}

pub fn emit_auto_deploy(state: &AppState, repo: &Repo, actor_sub: &str, push_body: &[u8]) {
    if repo.is_private {
        return;
    }
    let state = state.clone();
    let repo = repo.clone();
    let actor_sub = actor_sub.to_string();
    let push_body = push_body.to_vec();

    tokio::spawn(async move {
        let deploy = match state.store.get_deploy(&repo.id).await {
            Ok(Some(deploy)) if deploy.auto_deploy => deploy,
            Ok(_) => return,
            Err(e) => {
                tracing::warn!(error = %e, repo = repo.id, "deploy lookup failed");
                return;
            }
        };
        if !push_body_touches_branch(&push_body, &deploy.production_branch) {
            return;
        }
        match submit_deploy(&state, &repo, &actor_sub, deploy).await {
            Ok(submitted) => tracing::info!(
                repo = repo.id,
                actor = actor_sub,
                siteflow_slug = submitted.siteflow_slug,
                project_id = submitted.siteflow_project_id,
                build_job_id = submitted.last_build_job_id,
                "auto deploy submitted"
            ),
            Err(e) => tracing::warn!(error = %e, repo = repo.id, "auto deploy failed"),
        }
    });
}

pub(crate) fn render_deploy_button(repo: &Repo, csrf: &str) -> String {
    if repo.is_private {
        return r##"<button class="btn btn-ghost btn-sm deploy-trigger deploy-trigger--disabled" type="button" disabled title="Deploy supports public repositories only">Deploy</button>"##
            .to_string();
    }
    format!(
        r##"<details class="popbtn popbtn--deploy deploy-trigger">
  <summary class="btn btn-ghost btn-sm"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4.5 16.5 12 3l7.5 13.5"/><path d="M8 16.5h8"/><path d="M12 3v18"/></svg>Deploy</summary>
  <div class="popbtn__pop">
    <form method="post" action="/r/{owner}/{name}/deploy">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <div class="field">
        <label for="deploy-output-dir">Output directory</label>
        <input type="text" id="deploy-output-dir" name="output_directory" maxlength="256" value="." autocomplete="off" spellcheck="false">
      </div>
      <div class="actions">
        <button class="btn btn-primary btn-sm" type="submit">Deploy</button>
      </div>
    </form>
  </div>
</details>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        csrf = esc(csrf),
    )
}

pub(crate) fn render_deploy_card(
    state: &AppState,
    repo: &Repo,
    csrf: &str,
    deploy: Option<&RepoDeploy>,
) -> String {
    let fallback_slug = build_siteflow_slug(&repo.owner_sub, &repo.name);
    let slug = deploy
        .map(|d| d.siteflow_slug.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(fallback_slug.as_str());
    let production_branch = deploy
        .map(|d| d.production_branch.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(&repo.default_branch);
    let output_directory = deploy
        .map(|d| d.output_directory.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(".");
    let auto_checked = if deploy
        .map(|d| d.auto_deploy)
        .unwrap_or(state.config.auto_deploy_default)
    {
        " checked"
    } else {
        ""
    };
    let fallback_preview = preview_url(&state.config.siteflow_base_domain, slug);
    let preview = deploy
        .map(|d| d.preview_url.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(fallback_preview.as_str());
    let build = deploy
        .map(|d| d.last_build_job_id.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("none");
    let status = deploy.map(deploy_status_label).unwrap_or("not_configured");
    let private_note = if repo.is_private {
        "<p class=\"hint hint--muted\">Deploy supports public repositories only.</p>"
    } else {
        ""
    };
    let disabled = if repo.is_private { " disabled" } else { "" };

    format!(
        r##"<section class="card deploy-card">
  <div class="card__head">
    <h2>Deploy</h2>
    <span class="deploy-status deploy-status--{status}" data-poll="/r/{owner}/{name}/deploy/status">{status}</span>
  </div>
  <div class="card__body">
    {private_note}
    <div class="deploy-summary">
      <div class="deploy-preview-url" title="Internal placeholder; independent domain pending, not a public site.">{preview}</div>
      <div class="deploy-build-id">Build: <code>{build}</code></div>
    </div>
    <form class="deploy-form" method="post" action="/r/{owner}/{name}/settings/deploy">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <div class="field">
        <label for="deploy-production-branch">Production branch</label>
        <input type="text" id="deploy-production-branch" name="production_branch" maxlength="64" value="{branch}" autocomplete="off" spellcheck="false"{disabled}>
      </div>
      <div class="field">
        <label for="deploy-output-directory">Output directory</label>
        <input type="text" id="deploy-output-directory" name="output_directory" maxlength="256" value="{output}" autocomplete="off" spellcheck="false"{disabled}>
        <p class="hint hint--muted">Static sites serve from this directory after build; use <code>.</code> for the repository root.</p>
      </div>
      <div class="field">
        <label for="deploy-framework">Framework</label>
        <select id="deploy-framework" name="framework"{disabled}>
          <option value="static" selected>Static</option>
        </select>
      </div>
      <div class="field field--check">
        <label class="check"><input class="deploy-auto-toggle" type="checkbox" name="auto_deploy" value="on"{auto_checked}{disabled}> Auto deploy production branch pushes</label>
      </div>
      <div class="actions">
        <button class="btn btn-secondary" type="submit" name="action" value="save"{disabled}>Save</button>
        <button class="btn btn-primary" type="submit" name="action" value="redeploy"{disabled}>Redeploy</button>
      </div>
    </form>
    <form class="deploy-disconnect-form" method="post" action="/r/{owner}/{name}/settings/deploy" data-delete-confirm="{name}">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <input type="hidden" name="action" value="disconnect">
      <div class="field">
        <label for="deploy-disconnect-confirm">Type the repository name to disconnect</label>
        <input type="text" id="deploy-disconnect-confirm" name="confirm_name" maxlength="64" autocomplete="off" spellcheck="false" data-delete-confirm-input{disabled}>
      </div>
      <div class="actions">
        <button class="btn btn-ghost btn-sm" type="submit" data-delete-confirm-button disabled>Disconnect</button>
      </div>
    </form>
  </div>
</section>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        csrf = esc(csrf),
        status = esc(status),
        private_note = private_note,
        preview = esc(preview),
        build = esc(build),
        branch = esc(production_branch),
        output = esc(output_directory),
        auto_checked = auto_checked,
        disabled = disabled,
    )
}

async fn require_deploy_admin(
    state: &AppState,
    repo: &Repo,
    who: &Identity,
    headers: &HeaderMap,
) -> Result<(), AppError> {
    if can_admin_repo(state, repo, who, headers).await? {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "Only the repository owner or an administrator can manage deployments.".to_string(),
        ))
    }
}

fn ensure_public_repo(repo: &Repo) -> Result<(), AppError> {
    if repo.is_private {
        Err(AppError::BadRequest(
            "Deploy supports public repositories only.".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn deploy_from_existing(
    state: &AppState,
    repo: &Repo,
    existing: Option<RepoDeploy>,
    output_override: Option<&str>,
) -> Result<RepoDeploy, AppError> {
    let now = now_secs();
    let mut deploy = existing.unwrap_or_else(|| new_deploy(state, repo, now));
    if deploy.production_branch.trim().is_empty() {
        deploy.production_branch = repo.default_branch.clone();
    }
    if let Some(output) = output_override {
        deploy.output_directory = clean_output_directory(output)?;
    } else {
        deploy.output_directory = clean_output_directory(&deploy.output_directory)?;
    }
    deploy.framework = normalize_framework(&deploy.framework)?;
    deploy.siteflow_slug = build_siteflow_slug(&repo.owner_sub, &repo.name);
    deploy.preview_url = preview_url(&state.config.siteflow_base_domain, &deploy.siteflow_slug);
    deploy.updated_at = now;
    Ok(deploy)
}

async fn deploy_from_settings_form(
    state: &AppState,
    repo: &Repo,
    existing: Option<RepoDeploy>,
    form: &DeploySettingsForm,
) -> Result<RepoDeploy, AppError> {
    let branch = clean_branch(&form.production_branch, &repo.default_branch)?;
    let branches = state.git.branches(&repo.owner_sub, &repo.name).await;
    if !branches.is_empty() && !branches.iter().any(|b| b == &branch) {
        return Err(AppError::BadRequest(
            "Choose an existing branch as the production branch.".to_string(),
        ));
    }
    let output_directory = clean_output_directory(&form.output_directory)?;
    let framework = normalize_framework(&form.framework)?;

    let now = now_secs();
    let mut deploy = existing.unwrap_or_else(|| new_deploy(state, repo, now));
    deploy.siteflow_slug = build_siteflow_slug(&repo.owner_sub, &repo.name);
    deploy.production_branch = branch;
    deploy.output_directory = output_directory;
    deploy.framework = framework;
    deploy.auto_deploy = form.auto_deploy == "on";
    deploy.preview_url = preview_url(&state.config.siteflow_base_domain, &deploy.siteflow_slug);
    deploy.updated_at = now;
    Ok(deploy)
}

fn new_deploy(state: &AppState, repo: &Repo, now: i64) -> RepoDeploy {
    let slug = build_siteflow_slug(&repo.owner_sub, &repo.name);
    RepoDeploy {
        id: format!("rd_{}", random_alnum(DEPLOY_ID_LEN)),
        repo_id: repo.id.clone(),
        siteflow_slug: slug.clone(),
        siteflow_project_id: String::new(),
        deploy_hook_token: String::new(),
        deploy_hook_url: String::new(),
        production_branch: repo.default_branch.clone(),
        output_directory: ".".to_string(),
        framework: "static".to_string(),
        auto_deploy: state.config.auto_deploy_default,
        last_build_job_id: String::new(),
        preview_url: preview_url(&state.config.siteflow_base_domain, &slug),
        last_deployed_sha: String::new(),
        created_at: now,
        updated_at: now,
    }
}

async fn submit_deploy(
    state: &AppState,
    repo: &Repo,
    actor_sub: &str,
    mut deploy: RepoDeploy,
) -> Result<RepoDeploy, AppError> {
    let (commit_sha, detail) =
        resolve_deploy_commit(state, repo, &deploy.production_branch).await?;
    if state.config.siteflow_base_url.trim().is_empty() {
        deploy.last_build_job_id = format!("local_{}", random_alnum(12));
        deploy.last_deployed_sha = commit_sha;
        deploy.preview_url = preview_url(&state.config.siteflow_base_domain, &deploy.siteflow_slug);
        deploy.updated_at = now_secs();
        return Ok(state.store.upsert_deploy(&deploy).await?);
    }
    if state.config.siteflow_api_token.trim().is_empty() {
        return Err(AppError::BadRequest(
            "SiteFlow API token is not configured.".to_string(),
        ));
    }

    let client = siteflow_client()?;
    if deploy.siteflow_project_id.is_empty() || deploy.deploy_hook_token.is_empty() {
        let project_id = create_siteflow_project(&client, &state.config, repo, &deploy).await?;
        deploy.siteflow_project_id = project_id;
        let (hook_token, hook_url) = create_deploy_hook(&client, &state.config, &deploy).await?;
        deploy.deploy_hook_token = hook_token;
        deploy.deploy_hook_url = hook_url;
        deploy.updated_at = now_secs();
        deploy = state.store.upsert_deploy(&deploy).await?;
    }

    let build_job_id = trigger_deploy_hook(
        &client,
        &state.config,
        &deploy,
        &commit_sha,
        &detail,
        actor_sub,
    )
    .await?;
    deploy.last_build_job_id = build_job_id;
    deploy.last_deployed_sha = commit_sha;
    deploy.preview_url = preview_url(&state.config.siteflow_base_domain, &deploy.siteflow_slug);
    deploy.updated_at = now_secs();
    Ok(state.store.upsert_deploy(&deploy).await?)
}

async fn resolve_deploy_commit(
    state: &AppState,
    repo: &Repo,
    branch: &str,
) -> Result<(String, CommitDetail), AppError> {
    let branch = clean_branch(branch, &repo.default_branch)?;
    let branches = state.git.branches(&repo.owner_sub, &repo.name).await;
    if !branches.is_empty() && !branches.iter().any(|b| b == &branch) {
        return Err(AppError::BadRequest(
            "Production branch does not exist.".to_string(),
        ));
    }
    let commit_sha = state
        .git
        .branch_head_commit(&repo.owner_sub, &repo.name, &branch)
        .await
        .ok_or_else(|| {
            AppError::BadRequest("Production branch has no commits to deploy.".to_string())
        })?;
    if !valid_commit_sha(&commit_sha) {
        return Err(AppError::BadRequest(
            "Production branch did not resolve to a valid commit SHA.".to_string(),
        ));
    }
    let detail = state
        .git
        .commit_detail(&repo.owner_sub, &repo.name, &commit_sha)
        .await
        .ok_or_else(|| AppError::BadRequest("No commit metadata found.".to_string()))?;
    Ok((commit_sha, detail))
}

async fn create_siteflow_project(
    client: &reqwest::Client,
    config: &Config,
    repo: &Repo,
    deploy: &RepoDeploy,
) -> Result<String, AppError> {
    let remote_url = format!(
        "{}/{}/{}.git",
        config.siteflow_clone_base_url.trim_end_matches('/'),
        repo.owner_sub,
        repo.name
    );
    let body = json!({
        "slug": deploy.siteflow_slug,
        "name": repo.name,
        "framework": "static",
        "repository": {
            "provider": "generic",
            "owner": repo.owner_sub,
            "name": repo.name,
            "defaultBranch": deploy.production_branch,
            "providerPayload": {
                "remoteUrl": remote_url
            }
        },
        "buildSettings": {
            "framework": "static",
            "installCommand": "",
            "buildCommand": "",
            "outputDirectory": deploy.output_directory
        }
    });
    let value = siteflow_post(client, config, "/api/projects", &body, true).await?;
    json_string(&value, &["project", "id"])
        .or_else(|| json_string(&value, &["id"]))
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| {
            AppError::BadRequest("SiteFlow project response missed project.id.".to_string())
        })
}

async fn create_deploy_hook(
    client: &reqwest::Client,
    config: &Config,
    deploy: &RepoDeploy,
) -> Result<(String, String), AppError> {
    let path = format!(
        "/api/projects/{}/deploy-hooks",
        percent_encode(&deploy.siteflow_project_id)
    );
    let body = json!({
        "name": "loom-auto",
        "branch": deploy.production_branch,
        "targetEnvironment": "production"
    });
    let value = siteflow_post(client, config, &path, &body, true).await?;
    let token = json_string(&value, &["token"])
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            AppError::BadRequest("SiteFlow deploy-hook response missed token.".to_string())
        })?;
    let hook_url = json_string(&value, &["hookUrl"])
        .or_else(|| json_string(&value, &["hook_url"]))
        .unwrap_or_default();
    Ok((token, hook_url))
}

async fn trigger_deploy_hook(
    client: &reqwest::Client,
    config: &Config,
    deploy: &RepoDeploy,
    commit_sha: &str,
    detail: &CommitDetail,
    actor_sub: &str,
) -> Result<String, AppError> {
    let path = format!(
        "/api/deploy-hooks/{}/trigger",
        percent_encode(&deploy.deploy_hook_token)
    );
    let body = json!({
        "branch": deploy.production_branch,
        "commitSha": commit_sha,
        "commitMessage": detail.subject(),
        "commitAuthor": commit_author(detail),
        "idempotencyKey": format!("loom:{}:{}:{}", deploy.repo_id, deploy.production_branch, commit_sha),
        "actor": actor_sub
    });
    let value = siteflow_post(client, config, &path, &body, false).await?;
    json_string(&value, &["buildJobId"])
        .or_else(|| json_string(&value, &["build_job_id"]))
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            AppError::BadRequest("SiteFlow trigger response missed buildJobId.".to_string())
        })
}

async fn poll_siteflow_status(config: &Config, deploy: &RepoDeploy) -> Option<String> {
    if config.siteflow_base_url.trim().is_empty()
        || config.siteflow_api_token.trim().is_empty()
        || deploy.siteflow_project_id.trim().is_empty()
    {
        return None;
    }
    let client = siteflow_client().ok()?;
    let path = format!(
        "/api/deployments?projectId={}",
        percent_encode(&deploy.siteflow_project_id)
    );
    let value = siteflow_get(&client, config, &path).await.ok()?;
    latest_deployment_status(&value)
}

fn siteflow_client() -> Result<reqwest::Client, AppError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(SITEFLOW_TIMEOUT_SECS))
        .build()
        .map_err(|_| AppError::Internal("SiteFlow HTTP client could not be built.".to_string()))
}

async fn siteflow_post(
    client: &reqwest::Client,
    config: &Config,
    path: &str,
    body: &Value,
    bearer: bool,
) -> Result<Value, AppError> {
    let body = serde_json::to_vec(body).map_err(|_| {
        AppError::Internal("SiteFlow request body could not be encoded.".to_string())
    })?;
    let url = siteflow_url(config, path);
    let mut req = client
        .post(url)
        .header(USER_AGENT, "Loom-SiteFlow/0.1")
        .header(CONTENT_TYPE, "application/json")
        .body(body);
    if bearer {
        req = req.header(
            "Authorization",
            format!("Bearer {}", config.siteflow_api_token),
        );
    }
    let response = req
        .send()
        .await
        .map_err(|_| AppError::BadRequest("SiteFlow request failed.".to_string()))?;
    response_json(response).await
}

async fn siteflow_get(
    client: &reqwest::Client,
    config: &Config,
    path: &str,
) -> Result<Value, AppError> {
    let response = client
        .get(siteflow_url(config, path))
        .header(USER_AGENT, "Loom-SiteFlow/0.1")
        .header(
            "Authorization",
            format!("Bearer {}", config.siteflow_api_token),
        )
        .send()
        .await
        .map_err(|_| AppError::BadRequest("SiteFlow request failed.".to_string()))?;
    response_json(response).await
}

async fn response_json(response: reqwest::Response) -> Result<Value, AppError> {
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|_| AppError::BadRequest("SiteFlow response could not be read.".to_string()))?;
    if !status.is_success() {
        return Err(AppError::BadRequest(format!(
            "SiteFlow returned HTTP status {status}."
        )));
    }
    serde_json::from_str(&text)
        .map_err(|_| AppError::BadRequest("SiteFlow response was not valid JSON.".to_string()))
}

fn siteflow_url(config: &Config, path: &str) -> String {
    format!(
        "{}/{}",
        config.siteflow_base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

fn clean_branch(raw: &str, fallback: &str) -> Result<String, AppError> {
    let branch = nonempty_trimmed(raw).unwrap_or_else(|| fallback.to_string());
    validate_branch_name(&branch).map_err(|e| AppError::BadRequest(e.to_string()))?;
    Ok(branch)
}

fn clean_output_directory(raw: &str) -> Result<String, AppError> {
    let output = nonempty_trimmed(raw).unwrap_or_else(|| ".".to_string());
    if output.chars().count() > 256
        || output.starts_with('/')
        || output.contains('\\')
        || output.split('/').any(|seg| seg == "..")
    {
        return Err(AppError::BadRequest(
            "Output directory must be a relative path within the repository.".to_string(),
        ));
    }
    Ok(output)
}

fn normalize_framework(raw: &str) -> Result<String, AppError> {
    let framework = nonempty_trimmed(raw).unwrap_or_else(|| "static".to_string());
    if framework == "static" {
        Ok(framework)
    } else {
        Err(AppError::BadRequest(
            "Only static SiteFlow deployments are supported.".to_string(),
        ))
    }
}

fn nonempty_trimmed(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn build_siteflow_slug(owner: &str, name: &str) -> String {
    let raw = format!("{owner}-{name}");
    let mut out = String::new();
    let mut last_dash = false;
    for ch in raw.chars() {
        let next = if ch.is_ascii_alphanumeric() {
            last_dash = false;
            ch.to_ascii_lowercase()
        } else if !last_dash {
            last_dash = true;
            '-'
        } else {
            continue;
        };
        out.push(next);
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "repo".to_string()
    } else {
        trimmed
    }
}

fn preview_url(base_domain: &str, slug: &str) -> String {
    let domain = base_domain.trim().trim_end_matches('/');
    if domain.is_empty() {
        return String::new();
    }
    if let Some(rest) = domain.strip_prefix("https://") {
        format!("https://{slug}.{rest}")
    } else if let Some(rest) = domain.strip_prefix("http://") {
        format!("http://{slug}.{rest}")
    } else {
        format!("https://{slug}.{domain}")
    }
}

fn deploy_status_label(deploy: &RepoDeploy) -> &'static str {
    if deploy.last_build_job_id.is_empty() {
        "not_configured"
    } else {
        "queued"
    }
}

fn commit_author(detail: &CommitDetail) -> String {
    if detail.author_email.is_empty() {
        detail.author_name.clone()
    } else {
        format!("{} <{}>", detail.author_name, detail.author_email)
    }
}

fn valid_commit_sha(sha: &str) -> bool {
    (7..=64).contains(&sha.len())
        && sha
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

fn percent_encode(input: &str) -> String {
    let mut out = String::new();
    for b in input.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn json_string(value: &Value, path: &[&str]) -> Option<String> {
    let mut cur = value;
    for key in path {
        cur = cur.get(*key)?;
    }
    cur.as_str().map(str::to_string)
}

fn latest_deployment_status(value: &Value) -> Option<String> {
    if let Some(status) = json_string(value, &["status"]) {
        return Some(status);
    }
    if let Some(items) = value.get("deployments").and_then(Value::as_array) {
        return items
            .first()
            .and_then(|item| item.get("status"))
            .and_then(Value::as_str)
            .map(str::to_string);
    }
    value
        .as_array()
        .and_then(|items| items.first())
        .and_then(|item| item.get("status"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn push_body_touches_branch(body: &[u8], branch: &str) -> bool {
    let needle = format!("refs/heads/{branch}");
    String::from_utf8_lossy(body).contains(&needle)
}
