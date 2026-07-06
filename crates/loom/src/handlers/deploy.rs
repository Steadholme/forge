//! SiteFlow deployment integration for repositories.
//!
//! Mutations follow the settings handler sequence: CSRF, identity, visible repo, admin check,
//! validation, store/outbound work, audit log, PRG redirect. SiteFlow secrets are stored only for
//! server-side trigger calls and are never rendered or logged.

use std::time::Duration;

use async_trait::async_trait;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use reqwest::header::{CONTENT_TYPE, USER_AGENT};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::time::sleep;

use crate::auth::{self, Identity};
use crate::config::Config;
use crate::error::AppError;
use crate::gitops::CommitDetail;
use crate::handlers::repos::{can_admin_repo, load_visible_repo, validate_branch_name};
use crate::handlers::{esc, redirect, short_oid};
use crate::model::{Pull, Repo, RepoDeploy};
use crate::webhooks;
use crate::{now_secs, random_alnum, AppState};

const DEPLOY_ID_LEN: usize = 16;
const SITEFLOW_TIMEOUT_SECS: u64 = 5;
const PR_PREVIEW_POLL_ATTEMPTS: usize = 40;
const PR_PREVIEW_POLL_SECS: u64 = 5;
const AGENT_PREVIEW_BRANCH_PREFIX: &str = "agent/";

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreviewResult {
    build_job_id: String,
    commit_sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreviewCommentTarget {
    pull_id: String,
    pull_number: i64,
}

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

#[derive(Debug, Deserialize)]
pub struct DeployDomainForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub hostname: String,
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

/// POST /r/{owner}/{name}/settings/deploy/domains
pub async fn add_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
    Form(form): Form<DeployDomainForm>,
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
    let deploy = require_siteflow_deploy(&state, &repo).await?;
    let hostname =
        clean_custom_domain_hostname(&form.hostname, &state.config.siteflow_base_domain)?;

    let client = siteflow_client()?;
    let path = format!(
        "/api/projects/{}/domains",
        percent_encode(&deploy.siteflow_project_id)
    );
    let body = json!({ "hostname": hostname });
    siteflow_post(&client, &state.config, &path, &body, true).await?;
    tracing::info!(
        repo = repo.id,
        siteflow_project_id = deploy.siteflow_project_id,
        hostname = hostname,
        "deploy domain added"
    );
    Ok(redirect(&format!("/r/{owner}/{name}/settings")))
}

/// POST /r/{owner}/{name}/settings/deploy/domains/remove
pub async fn remove_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
    Form(form): Form<DeployDomainForm>,
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
    let deploy = require_siteflow_deploy(&state, &repo).await?;
    let hostname = clean_domain_hostname(&form.hostname)?;

    let client = siteflow_client()?;
    let path = format!(
        "/api/projects/{}/domains/{}",
        percent_encode(&deploy.siteflow_project_id),
        percent_encode(&hostname)
    );
    siteflow_delete(&client, &state.config, &path).await?;
    tracing::info!(
        repo = repo.id,
        siteflow_project_id = deploy.siteflow_project_id,
        hostname = hostname,
        "deploy domain removed"
    );
    Ok(redirect(&format!("/r/{owner}/{name}/settings")))
}

/// GET /r/{owner}/{name}/deploy/domains
pub async fn domains_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    require_deploy_admin(&state, &repo, &who, &headers).await?;
    ensure_public_repo(&repo)?;
    let deploy = require_siteflow_deploy(&state, &repo).await?;

    let client = siteflow_client()?;
    let path = format!(
        "/api/projects/{}",
        percent_encode(&deploy.siteflow_project_id)
    );
    let value = siteflow_get(&client, &state.config, &path).await?;
    Ok(Json(json!({ "domains": siteflow_domains(&value) })).into_response())
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
    let Some(mut deploy) = state.store.get_deploy(&repo.id).await? else {
        return Ok(Json(json!({ "configured": false })).into_response());
    };

    let (siteflow_status, siteflow_preview_url) = poll_siteflow_status(&state.config, &deploy)
        .await
        .map_or((None, None), |(status, preview_url)| {
            (Some(status), preview_url)
        });
    if let Some(preview_url) = siteflow_preview_url.filter(|url| url != &deploy.preview_url) {
        deploy.preview_url = preview_url;
        deploy = state.store.upsert_deploy(&deploy).await?;
    }
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

pub fn emit_pr_preview(state: &AppState, repo: &Repo, actor_sub: &str, pull: &Pull) {
    if repo.is_private || pull.is_draft || !siteflow_preview_configured(&state.config) {
        return;
    }
    let state = state.clone();
    let repo = repo.clone();
    let pull = pull.clone();
    let actor_sub = actor_sub.to_string();

    tokio::spawn(async move {
        let deploy = match preview_deploy_for_repo(&state, &repo).await {
            Ok(Some(deploy)) => deploy,
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(error = %e, repo = repo.id, "preview deploy lookup failed");
                return;
            }
        };
        if let Err(e) = start_pull_preview(&state, &repo, &deploy, &actor_sub, &pull).await {
            tracing::warn!(
                error = %e,
                repo = repo.id,
                pull = pull.number,
                "preview deploy failed"
            );
        }
    });
}

pub fn emit_pr_previews(state: &AppState, repo: &Repo, actor_sub: &str, push_body: &[u8]) {
    if repo.is_private || !siteflow_preview_configured(&state.config) {
        return;
    }
    let state = state.clone();
    let repo = repo.clone();
    let actor_sub = actor_sub.to_string();
    let push_body = push_body.to_vec();

    tokio::spawn(async move {
        let deploy = match preview_deploy_for_repo(&state, &repo).await {
            Ok(Some(deploy)) => deploy,
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(error = %e, repo = repo.id, "preview deploy lookup failed");
                return;
            }
        };
        for head_branch in push_body_head_branches(&push_body) {
            let pulls = match state
                .store
                .list_open_pulls_by_head(&repo.id, &head_branch)
                .await
            {
                Ok(pulls) => pulls,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        repo = repo.id,
                        branch = head_branch,
                        "open pull lookup failed for preview deploy"
                    );
                    continue;
                }
            };
            let has_open_pull = !pulls.is_empty();
            for pull in pulls {
                if pull.is_draft || !push_body_touches_branch(&push_body, &pull.head) {
                    continue;
                }
                if let Err(e) = start_pull_preview(&state, &repo, &deploy, &actor_sub, &pull).await
                {
                    tracing::warn!(
                        error = %e,
                        repo = repo.id,
                        pull = pull.number,
                        "preview deploy failed"
                    );
                }
            }
            if should_preview_pushed_agent_branch(
                &head_branch,
                &deploy.production_branch,
                has_open_pull,
            ) {
                if let Err(e) =
                    start_agent_branch_preview(&state, &repo, &deploy, &actor_sub, &head_branch)
                        .await
                {
                    tracing::warn!(
                        error = %e,
                        repo = repo.id,
                        branch = head_branch,
                        "agent branch preview deploy failed"
                    );
                }
            }
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
    let database = deploy
        .map(|d| d.cistern_slug.as_str())
        .filter(|s| !s.is_empty())
        .map(|slug| {
            let s = esc(slug);
            format!(
                "<div class=\"deploy-database\">Database <code>{s}</code> · <a class=\"deploy-db-link\" href=\"https://cistern.w33d.xyz/p/{s}\" target=\"_blank\" rel=\"noopener\">Manage database →</a></div>"
            )
        })
        .unwrap_or_default();
    let private_note = if repo.is_private {
        "<p class=\"hint hint--muted\">Deploy supports public repositories only.</p>"
    } else {
        ""
    };
    let disabled = if repo.is_private { " disabled" } else { "" };

    // TODO(opus): Domains UI section wires POST /r/{owner}/{name}/settings/deploy/domains
    // and GET /r/{owner}/{name}/deploy/domains.
    format!(
        r##"<section class="card deploy-card">
  <div class="card__head">
    <h2>Deploy</h2>
    <span class="deploy-status deploy-status--{status}" data-poll="/r/{owner}/{name}/deploy/status">{status}</span>
  </div>
  <div class="card__body">
    {private_note}
    <div class="deploy-summary">
      <div class="deploy-preview-row">
        <span class="deploy-preview-label">Preview</span>
        <a class="deploy-preview-url" data-preview-link href="{preview}" target="_blank" rel="noopener">{preview}</a>
        <button class="btn btn-ghost btn-sm" type="button" data-copy="{preview}" data-preview-copy title="Copy preview URL">Copy</button>
      </div>
      <div class="deploy-build-id">Build: <code>{build}</code></div>
      {database}
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
    <div class="deploy-domains">
      <h3 class="deploy-domains__title">Custom domains</h3>
      <p class="hint hint--muted">Add a domain you control and CNAME it to the gateway. Once verified it auto-follows production on every deploy.</p>
      <form class="deploy-domain-add" method="post" action="/r/{owner}/{name}/settings/deploy/domains">
        <input type="hidden" name="csrf_token" value="{csrf}">
        <div class="field field--inline">
          <input type="text" name="hostname" placeholder="app.example.com" maxlength="253" autocomplete="off" spellcheck="false"{disabled}>
          <button class="btn btn-secondary btn-sm" type="submit"{disabled}>Add</button>
        </div>
      </form>
      <ul class="deploy-domain-list" data-domains-poll="/r/{owner}/{name}/deploy/domains" data-domains-action="/r/{owner}/{name}/settings/deploy/domains/remove" data-domains-csrf="{csrf}"></ul>
    </div>
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
        database = database,
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

async fn require_siteflow_deploy(state: &AppState, repo: &Repo) -> Result<RepoDeploy, AppError> {
    let deploy = state
        .store
        .get_deploy(&repo.id)
        .await?
        .filter(|d| !d.siteflow_project_id.trim().is_empty())
        .ok_or_else(|| AppError::BadRequest("Deploy the site first.".to_string()))?;
    Ok(deploy)
}

fn siteflow_preview_configured(config: &Config) -> bool {
    !config.siteflow_base_url.trim().is_empty() && !config.siteflow_api_token.trim().is_empty()
}

async fn preview_deploy_for_repo(
    state: &AppState,
    repo: &Repo,
) -> Result<Option<RepoDeploy>, AppError> {
    if !siteflow_preview_configured(&state.config) {
        return Ok(None);
    }
    match require_siteflow_deploy(state, repo).await {
        Ok(deploy) => Ok(Some(deploy)),
        Err(AppError::BadRequest(_)) => Ok(None),
        Err(e) => Err(e),
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
        cistern_provisioned: false,
        cistern_slug: String::new(),
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

    // Lazily provision a cistern database on first deploy and seal its connection env vars into
    // the SiteFlow project. Fail-open: this never blocks the deploy, and the guard makes it run at
    // most once per repo. `deploy` is persisted below regardless, so a success is captured there.
    if !deploy.cistern_provisioned
        && !state.config.cistern_provision_token.trim().is_empty()
        && !deploy.siteflow_project_id.is_empty()
    {
        let provisioner = HttpProvisioner::new(&client, &state.config);
        let project_id = deploy.siteflow_project_id.clone();
        provision_cistern(
            &provisioner,
            &project_id,
            &repo.owner_sub,
            &repo.name,
            &mut deploy,
        )
        .await;
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

async fn start_pull_preview(
    state: &AppState,
    repo: &Repo,
    deploy: &RepoDeploy,
    actor_sub: &str,
    pull: &Pull,
) -> Result<(), AppError> {
    start_branch_preview(
        state,
        repo,
        deploy,
        actor_sub,
        &pull.head,
        Some(PreviewCommentTarget {
            pull_id: pull.id.clone(),
            pull_number: pull.number,
        }),
    )
    .await
}

async fn start_agent_branch_preview(
    state: &AppState,
    repo: &Repo,
    deploy: &RepoDeploy,
    actor_sub: &str,
    branch: &str,
) -> Result<(), AppError> {
    start_branch_preview(state, repo, deploy, actor_sub, branch, None).await
}

async fn start_branch_preview(
    state: &AppState,
    repo: &Repo,
    deploy: &RepoDeploy,
    actor_sub: &str,
    branch: &str,
    comment: Option<PreviewCommentTarget>,
) -> Result<(), AppError> {
    if branch == deploy.production_branch {
        return Ok(());
    }
    let Some(submitted) = submit_preview_deploy(state, repo, deploy, branch, actor_sub).await?
    else {
        return Ok(());
    };
    if let Some(target) = comment.as_ref() {
        let body = preview_comment_body("building", "", &submitted.commit_sha);
        state
            .store
            .upsert_pull_preview_comment(
                &target.pull_id,
                &submitted.build_job_id,
                "building",
                "",
                &submitted.commit_sha,
                &body,
                now_secs(),
            )
            .await?;
    }

    let state = state.clone();
    let repo = repo.clone();
    let branch = branch.to_string();
    let mut deploy = deploy.clone();
    deploy.last_build_job_id = submitted.build_job_id.clone();
    let build_job_id = submitted.build_job_id;
    let commit_sha = submitted.commit_sha;

    tokio::spawn(async move {
        let mut owned = true;
        let mut terminal_seen = false;
        for attempt in 0..PR_PREVIEW_POLL_ATTEMPTS {
            sleep(Duration::from_secs(PR_PREVIEW_POLL_SECS)).await;
            match poll_preview_status(&state.config, &deploy, &commit_sha).await {
                Some((status, preview_url)) => {
                    let preview_url = preview_url.unwrap_or_default();
                    if let Some(target) = comment.as_ref() {
                        let body = preview_comment_body(&status, &preview_url, &commit_sha);
                        match state
                            .store
                            .update_pull_preview_comment_status(
                                &target.pull_id,
                                &build_job_id,
                                &status,
                                &preview_url,
                                &commit_sha,
                                &body,
                                now_secs(),
                            )
                            .await
                        {
                            Ok(true) => {}
                            Ok(false) => {
                                owned = false;
                                break;
                            }
                            Err(e) => tracing::warn!(
                                error = %e,
                                repo = repo.id,
                                pull = target.pull_number,
                                "preview bot comment update failed"
                            ),
                        }
                    }
                    if is_terminal_preview_status(&status) {
                        if should_emit_deployment_ready(&status, &preview_url) {
                            let pull_number =
                                comment.as_ref().map_or(0, |target| target.pull_number);
                            webhooks::emit_deployment_ready(
                                &state,
                                &repo,
                                &repo.owner_sub,
                                &branch,
                                &preview_url,
                                &commit_sha,
                                pull_number,
                            );
                        }
                        terminal_seen = true;
                        break;
                    }
                }
                None => {
                    tracing::warn!(
                        repo = repo.id,
                        pull = comment.as_ref().map_or(0, |target| target.pull_number),
                        branch = branch,
                        build_job_id = build_job_id,
                        attempt = attempt + 1,
                        "preview deploy status poll returned no match"
                    );
                }
            }
        }
        if owned && !terminal_seen {
            if let Some(target) = comment.as_ref() {
                if let Err(e) =
                    mark_preview_comment_timed_out(&state, &repo, target, &build_job_id, &commit_sha)
                        .await
                {
                    tracing::warn!(
                        error = %e,
                        repo = repo.id,
                        pull = target.pull_number,
                        "preview bot timeout update failed"
                    );
                }
            } else {
                tracing::warn!(
                    repo = repo.id,
                    branch = branch,
                    build_job_id = build_job_id,
                    "preview deploy status poll timed out"
                );
            }
        }
    });
    Ok(())
}

async fn submit_preview_deploy(
    state: &AppState,
    repo: &Repo,
    deploy: &RepoDeploy,
    head_branch: &str,
    actor_sub: &str,
) -> Result<Option<PreviewResult>, AppError> {
    let deploy = if deploy.siteflow_project_id.trim().is_empty() {
        require_siteflow_deploy(state, repo).await?
    } else {
        deploy.clone()
    };
    if deploy.deploy_hook_token.trim().is_empty() {
        tracing::warn!(
            repo = repo.id,
            pull_head = head_branch,
            "preview deploy skipped: no persisted deploy hook"
        );
        return Ok(None);
    }
    let (commit_sha, detail) = resolve_deploy_commit(state, repo, head_branch).await?;
    let client = siteflow_client()?;
    let build_job_id = trigger_preview_deploy_hook(
        &client,
        &state.config,
        &deploy,
        head_branch,
        &commit_sha,
        &detail,
        actor_sub,
    )
    .await?;
    Ok(Some(PreviewResult {
        build_job_id,
        commit_sha,
    }))
}

#[cfg(test)]
async fn mark_preview_timed_out(
    state: &AppState,
    repo: &Repo,
    pull: &Pull,
    build_job_id: &str,
    commit_sha: &str,
) -> Result<bool, AppError> {
    mark_preview_comment_timed_out(
        state,
        repo,
        &PreviewCommentTarget {
            pull_id: pull.id.clone(),
            pull_number: pull.number,
        },
        build_job_id,
        commit_sha,
    )
    .await
}

async fn mark_preview_comment_timed_out(
    state: &AppState,
    repo: &Repo,
    target: &PreviewCommentTarget,
    build_job_id: &str,
    commit_sha: &str,
) -> Result<bool, AppError> {
    tracing::warn!(
        repo = repo.id,
        pull = target.pull_number,
        build_job_id = build_job_id,
        "preview deploy status poll timed out"
    );
    let body = preview_timeout_comment_body(commit_sha);
    Ok(state
        .store
        .update_pull_preview_comment_status(
            &target.pull_id,
            build_job_id,
            "failed",
            "",
            commit_sha,
            &body,
            now_secs(),
        )
        .await?)
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

async fn trigger_preview_deploy_hook(
    client: &reqwest::Client,
    config: &Config,
    deploy: &RepoDeploy,
    head_branch: &str,
    commit_sha: &str,
    detail: &CommitDetail,
    actor_sub: &str,
) -> Result<String, AppError> {
    let path = format!(
        "/api/deploy-hooks/{}/trigger",
        percent_encode(&deploy.deploy_hook_token)
    );
    let body = json!({
        "branch": head_branch,
        "commitSha": commit_sha,
        "commitMessage": detail.subject(),
        "commitAuthor": commit_author(detail),
        "idempotencyKey": format!("loom:preview:{}:{}", head_branch, commit_sha),
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

/// Connection credentials returned by cistern's provision endpoint. `anon_key`/`service_key` are
/// secrets: they are sealed straight into SiteFlow and are never persisted in loom or logged.
#[derive(Clone)]
struct CisternCredentials {
    slug: String,
    rest_url: String,
    anon_key: String,
    service_key: String,
}

/// Injectable seam over the two outbound calls first-deploy provisioning makes — opening a cistern
/// database and sealing one SiteFlow project env var. The real impl (`HttpProvisioner`) uses
/// reqwest; unit tests use an in-memory fake so the guard / fail-open / env-var scope logic runs
/// fully offline. Errors carry a short, secret-free reason for logging.
#[async_trait]
trait Provisioner: Send + Sync {
    async fn open_database(&self, owner: &str, repo: &str) -> Result<CisternCredentials, String>;
    async fn seal_env_var(
        &self,
        project_id: &str,
        key: &str,
        value: &str,
        scope: &str,
    ) -> Result<(), String>;
}

/// Real provisioner: cistern over its provision endpoint, SiteFlow over the shared control-plane.
/// Reuses the deploy request's reqwest client (bounded timeout) and config-driven tokens.
struct HttpProvisioner<'a> {
    client: &'a reqwest::Client,
    config: &'a Config,
}

impl<'a> HttpProvisioner<'a> {
    fn new(client: &'a reqwest::Client, config: &'a Config) -> Self {
        Self { client, config }
    }
}

#[async_trait]
impl Provisioner for HttpProvisioner<'_> {
    async fn open_database(&self, owner: &str, repo: &str) -> Result<CisternCredentials, String> {
        let body = serde_json::to_vec(&json!({ "owner": owner, "repo": repo }))
            .map_err(|_| "request body could not be encoded".to_string())?;
        let response = self
            .client
            .post(self.config.cistern_provision_url.trim())
            .header(USER_AGENT, "Loom-Cistern/0.1")
            .header(CONTENT_TYPE, "application/json")
            .header(
                "Authorization",
                format!("Bearer {}", self.config.cistern_provision_token),
            )
            .body(body)
            .send()
            .await
            .map_err(|_| "cistern request failed".to_string())?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|_| "cistern response could not be read".to_string())?;
        if !status.is_success() {
            return Err(format!("cistern returned HTTP status {status}"));
        }
        let value: Value = serde_json::from_str(&text)
            .map_err(|_| "cistern response was not valid JSON".to_string())?;
        let field = |key: &str| {
            json_string(&value, &[key])
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| format!("cistern response missed {key}"))
        };
        Ok(CisternCredentials {
            slug: field("slug")?,
            rest_url: field("rest_url")?,
            anon_key: field("anon_key")?,
            service_key: field("service_key")?,
        })
    }

    async fn seal_env_var(
        &self,
        project_id: &str,
        key: &str,
        value: &str,
        scope: &str,
    ) -> Result<(), String> {
        let path = format!(
            "/api/projects/{}/environment-variables",
            percent_encode(project_id)
        );
        let body = serde_json::to_vec(&json!({
            "key": key,
            "value": value,
            "targetEnvironment": "production",
            "scope": scope
        }))
        .map_err(|_| "request body could not be encoded".to_string())?;
        let response = self
            .client
            .post(siteflow_url(self.config, &path))
            .header(USER_AGENT, "Loom-SiteFlow/0.1")
            .header(CONTENT_TYPE, "application/json")
            .header(
                "Authorization",
                format!("Bearer {}", self.config.siteflow_api_token),
            )
            .body(body)
            .send()
            .await
            .map_err(|_| "SiteFlow env-var request failed".to_string())?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("SiteFlow env-var returned HTTP status {status}"));
        }
        Ok(())
    }
}

/// One-time lazy provisioning: open a cistern database for `repo` and seal its three connection
/// env vars into the SiteFlow project. Fail-open — any failure is logged (never with secret
/// values) and returns without marking `deploy` provisioned, so the next deploy retries. On
/// success `deploy.cistern_provisioned`/`cistern_slug` are set; the caller persists `deploy`.
async fn provision_cistern(
    provisioner: &dyn Provisioner,
    project_id: &str,
    owner: &str,
    repo: &str,
    deploy: &mut RepoDeploy,
) {
    if deploy.cistern_provisioned {
        return;
    }
    let creds = match provisioner.open_database(owner, repo).await {
        Ok(creds) => creds,
        Err(reason) => {
            tracing::warn!(
                repo = deploy.repo_id,
                reason = %reason,
                "cistern provisioning skipped: could not open database"
            );
            return;
        }
    };
    // `scope` gates SiteFlow-side visibility: `build` values may enter the client bundle, `runtime`
    // values are server-only secrets. Values needed by both client builds and serverless
    // functions are sealed in both scopes. The service key MUST stay `runtime` only (never
    // client-visible).
    let env_vars = [
        ("CISTERN_REST_URL", creds.rest_url.as_str(), "build"),
        ("CISTERN_REST_URL", creds.rest_url.as_str(), "runtime"),
        ("CISTERN_ANON_KEY", creds.anon_key.as_str(), "build"),
        ("CISTERN_ANON_KEY", creds.anon_key.as_str(), "runtime"),
        ("CISTERN_SERVICE_KEY", creds.service_key.as_str(), "runtime"),
    ];
    for (key, value, scope) in env_vars {
        if let Err(reason) = provisioner
            .seal_env_var(project_id, key, value, scope)
            .await
        {
            tracing::warn!(
                repo = deploy.repo_id,
                key = key,
                reason = %reason,
                "cistern provisioning skipped: could not seal env var"
            );
            return;
        }
    }
    deploy.cistern_provisioned = true;
    deploy.cistern_slug = creds.slug;
    tracing::info!(
        repo = deploy.repo_id,
        cistern_slug = deploy.cistern_slug,
        "cistern database provisioned and env vars sealed"
    );
}

async fn poll_siteflow_status(
    config: &Config,
    deploy: &RepoDeploy,
) -> Option<(String, Option<String>)> {
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
    production_status_from_deployments(&value, deploy)
}

async fn poll_preview_status(
    config: &Config,
    deploy: &RepoDeploy,
    commit_sha: &str,
) -> Option<(String, Option<String>)> {
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
    preview_status_from_deployments(&value, commit_sha, &deploy.last_build_job_id)
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

async fn siteflow_delete(
    client: &reqwest::Client,
    config: &Config,
    path: &str,
) -> Result<(), AppError> {
    let response = client
        .delete(siteflow_url(config, path))
        .header(USER_AGENT, "Loom-SiteFlow/0.1")
        .header(
            "Authorization",
            format!("Bearer {}", config.siteflow_api_token),
        )
        .send()
        .await
        .map_err(|_| AppError::BadRequest("SiteFlow request failed.".to_string()))?;
    response_empty(response).await
}

async fn response_json(response: reqwest::Response) -> Result<Value, AppError> {
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|_| AppError::BadRequest("SiteFlow response could not be read.".to_string()))?;
    if !status.is_success() {
        return Err(siteflow_response_error(status, &text));
    }
    serde_json::from_str(&text)
        .map_err(|_| AppError::BadRequest("SiteFlow response was not valid JSON.".to_string()))
}

async fn response_empty(response: reqwest::Response) -> Result<(), AppError> {
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|_| AppError::BadRequest("SiteFlow response could not be read.".to_string()))?;
    if status.is_success() {
        Ok(())
    } else {
        Err(siteflow_response_error(status, &text))
    }
}

fn siteflow_response_error(status: reqwest::StatusCode, body: &str) -> AppError {
    let detail = siteflow_error_message(body)
        .map(|message| format!("SiteFlow returned HTTP status {status}: {message}"))
        .unwrap_or_else(|| format!("SiteFlow returned HTTP status {status}."));
    AppError::BadRequest(detail)
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

fn clean_custom_domain_hostname(raw: &str, siteflow_base_domain: &str) -> Result<String, AppError> {
    let hostname = clean_domain_hostname(raw)?;
    if has_siteflow_base_suffix(&hostname, siteflow_base_domain) {
        return Err(AppError::BadRequest(
            "Use a domain outside the SiteFlow base domain.".to_string(),
        ));
    }
    Ok(hostname)
}

fn clean_domain_hostname(raw: &str) -> Result<String, AppError> {
    let hostname = raw.trim().to_ascii_lowercase();
    if hostname.is_empty() || hostname.len() > 253 {
        return Err(AppError::BadRequest(
            "Custom domain must be a DNS hostname.".to_string(),
        ));
    }
    for label in hostname.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(AppError::BadRequest(
                "Custom domain must use DNS-safe labels.".to_string(),
            ));
        }
    }
    Ok(hostname)
}

fn has_siteflow_base_suffix(hostname: &str, siteflow_base_domain: &str) -> bool {
    let Some(base) = normalized_siteflow_base_domain(siteflow_base_domain) else {
        return false;
    };
    hostname == base || hostname.ends_with(&format!(".{base}"))
}

fn normalized_siteflow_base_domain(raw: &str) -> Option<String> {
    let mut base = raw.trim().trim_end_matches('/').to_ascii_lowercase();
    if let Some(rest) = base.strip_prefix("https://") {
        base = rest.to_string();
    } else if let Some(rest) = base.strip_prefix("http://") {
        base = rest.to_string();
    }
    base = base
        .split('/')
        .next()
        .unwrap_or_default()
        .trim_matches('.')
        .to_string();
    (!base.is_empty()).then_some(base)
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

#[cfg(test)]
fn latest_deployment_preview_url(value: &Value) -> Option<String> {
    if let Some(preview_url) = value
        .get("previewUrl")
        .and_then(Value::as_str)
        .and_then(nonempty_trimmed)
    {
        return Some(preview_url);
    }
    if let Some(items) = value.get("deployments").and_then(Value::as_array) {
        return items
            .first()
            .and_then(|item| item.get("previewUrl"))
            .and_then(Value::as_str)
            .and_then(nonempty_trimmed);
    }
    value
        .as_array()
        .and_then(|items| items.first())
        .and_then(|item| item.get("previewUrl"))
        .and_then(Value::as_str)
        .and_then(nonempty_trimmed)
}

fn production_status_from_deployments(
    value: &Value,
    deploy: &RepoDeploy,
) -> Option<(String, Option<String>)> {
    let items = deployment_items(value);
    let production_branch = deploy.production_branch.trim();
    if !production_branch.is_empty() {
        if let Some(item) = items.iter().copied().find(|item| {
            deployment_branch(item)
                .as_deref()
                .is_some_and(|branch| branch == production_branch)
        }) {
            return deployment_status_with_preview(item);
        }
    }

    if let Some(item) = items
        .iter()
        .copied()
        .find(|item| deployment_matches(item, "", &deploy.last_build_job_id))
    {
        return deployment_status_with_preview(item);
    }
    if let Some(item) = items
        .iter()
        .copied()
        .find(|item| deployment_matches(item, &deploy.last_deployed_sha, ""))
    {
        return deployment_status_with_preview(item);
    }

    if items.iter().any(|item| deployment_branch(item).is_some()) {
        return None;
    }
    items
        .first()
        .and_then(|item| deployment_status_with_preview(item))
}

fn preview_status_from_deployments(
    value: &Value,
    commit_sha: &str,
    build_job_id: &str,
) -> Option<(String, Option<String>)> {
    deployment_items(value)
        .into_iter()
        .find(|item| deployment_matches(item, commit_sha, build_job_id))
        .and_then(deployment_status_with_preview)
}

fn deployment_items(value: &Value) -> Vec<&Value> {
    if let Some(items) = value.get("deployments").and_then(Value::as_array) {
        return items.iter().collect();
    }
    if let Some(items) = value.as_array() {
        return items.iter().collect();
    }
    vec![value]
}

fn deployment_matches(item: &Value, commit_sha: &str, build_job_id: &str) -> bool {
    let commit_matches = !commit_sha.trim().is_empty()
        && [
            json_string(item, &["commitSha"]),
            json_string(item, &["commit_sha"]),
            json_string(item, &["source", "commitSha"]),
            json_string(item, &["source", "commit_sha"]),
            json_string(item, &["source", "commit"]),
        ]
        .into_iter()
        .flatten()
        .any(|sha| sha == commit_sha);
    if commit_matches {
        return true;
    }
    if build_job_id.trim().is_empty() {
        return false;
    }
    [
        json_string(item, &["buildJobId"]),
        json_string(item, &["build_job_id"]),
        json_string(item, &["build", "jobId"]),
    ]
    .into_iter()
    .flatten()
    .any(|id| id == build_job_id)
}

fn deployment_status_with_preview(item: &Value) -> Option<(String, Option<String>)> {
    let status = json_string(item, &["status"])?;
    Some((status, deployment_preview_url(item)))
}

fn deployment_branch(item: &Value) -> Option<String> {
    json_string(item, &["branch"])
        .or_else(|| json_string(item, &["source", "branch"]))
        .or_else(|| json_string(item, &["git", "branch"]))
}

fn deployment_preview_url(item: &Value) -> Option<String> {
    json_string(item, &["previewUrl"])
        .or_else(|| json_string(item, &["preview_url"]))
        .and_then(|url| nonempty_trimmed(&url))
}

fn is_terminal_preview_status(status: &str) -> bool {
    matches!(
        status.trim().to_ascii_lowercase().as_str(),
        "ready" | "error" | "failed" | "canceled"
    )
}

fn should_emit_deployment_ready(status: &str, preview_url: &str) -> bool {
    status.trim().eq_ignore_ascii_case("ready") && !preview_url.is_empty()
}

fn preview_status_label(status: &str) -> &'static str {
    match status.trim().to_ascii_lowercase().as_str() {
        "ready" => "Ready",
        "error" | "failed" | "canceled" => "Failed",
        _ => "Building",
    }
}

fn preview_comment_body(status: &str, preview_url: &str, commit_sha: &str) -> String {
    let label = preview_status_label(status);
    let commit = short_oid(commit_sha);
    if preview_url.trim().is_empty() {
        format!("Preview deployment {label} for {commit}. Preview URL pending.")
    } else {
        format!(
            "Preview deployment {label} for {commit}. Preview URL: {}",
            preview_url.trim()
        )
    }
}

fn preview_timeout_comment_body(commit_sha: &str) -> String {
    format!(
        "Preview deployment Failed for {}. Preview timed out before SiteFlow returned a terminal status.",
        short_oid(commit_sha)
    )
}

fn siteflow_domains(value: &Value) -> Vec<Value> {
    // SiteFlow GET /api/projects/{id} nests the project under `.project`, so domains live at
    // `.project.domains`; fall back to a top-level `.domains` for robustness (mirrors how
    // create_siteflow_project resolves `.project.id` or `.id`).
    value
        .get("project")
        .and_then(|project| project.get("domains"))
        .or_else(|| value.get("domains"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let hostname = item.get("hostname")?.as_str()?.trim();
                    if hostname.is_empty() {
                        return None;
                    }
                    Some(json!({
                        "hostname": hostname,
                        "verified": item.get("verified").and_then(Value::as_bool).unwrap_or(false),
                    }))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn siteflow_error_message(body: &str) -> Option<String> {
    let body = body.trim();
    if body.is_empty() {
        return None;
    }
    if let Ok(value) = serde_json::from_str::<Value>(body) {
        return json_string(&value, &["message"])
            .or_else(|| json_string(&value, &["error", "message"]))
            .or_else(|| json_string(&value, &["error"]))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
    }
    Some(body.chars().take(512).collect())
}

fn push_body_touches_branch(body: &[u8], branch: &str) -> bool {
    let needle = format!("refs/heads/{branch}");
    String::from_utf8_lossy(body).contains(&needle)
}

fn should_preview_pushed_agent_branch(
    branch: &str,
    production_branch: &str,
    has_open_pull: bool,
) -> bool {
    branch.starts_with(AGENT_PREVIEW_BRANCH_PREFIX)
        && branch != production_branch
        && !has_open_pull
}

fn push_body_head_branches(body: &[u8]) -> Vec<String> {
    let mut branches = Vec::new();
    for segment in String::from_utf8_lossy(body).split("refs/heads/").skip(1) {
        let branch = segment
            .split(|c: char| c == '\0' || c.is_whitespace())
            .next()
            .unwrap_or_default()
            .trim();
        if !branch.is_empty() && !branches.iter().any(|b| b == branch) {
            branches.push(branch.to_string());
        }
    }
    branches
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::gitops::GitOps;
    use crate::store::InMemoryStore;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// In-memory provisioner double: records sealed env vars and can be told to fail either the
    /// database open or one specific env-var seal, so the guard / fail-open / scope logic runs
    /// entirely offline (no reqwest, no cistern, no SiteFlow).
    struct FakeProvisioner {
        open_result: Result<CisternCredentials, String>,
        open_calls: AtomicUsize,
        sealed: Mutex<Vec<(String, String, String)>>,
        fail_seal_for: Option<&'static str>,
    }

    impl FakeProvisioner {
        fn new(open_result: Result<CisternCredentials, String>) -> Self {
            Self {
                open_result,
                open_calls: AtomicUsize::new(0),
                sealed: Mutex::new(Vec::new()),
                fail_seal_for: None,
            }
        }

        fn fail_seal(mut self, key: &'static str) -> Self {
            self.fail_seal_for = Some(key);
            self
        }

        fn sealed(&self) -> Vec<(String, String, String)> {
            self.sealed.lock().expect("sealed lock").clone()
        }
    }

    #[async_trait]
    impl Provisioner for FakeProvisioner {
        async fn open_database(
            &self,
            _owner: &str,
            _repo: &str,
        ) -> Result<CisternCredentials, String> {
            self.open_calls.fetch_add(1, Ordering::SeqCst);
            self.open_result.clone()
        }

        async fn seal_env_var(
            &self,
            _project_id: &str,
            key: &str,
            value: &str,
            scope: &str,
        ) -> Result<(), String> {
            if self.fail_seal_for == Some(key) {
                return Err(format!("seal failed for {key}"));
            }
            self.sealed.lock().expect("sealed lock").push((
                key.to_string(),
                value.to_string(),
                scope.to_string(),
            ));
            Ok(())
        }
    }

    fn sample_creds() -> CisternCredentials {
        CisternCredentials {
            slug: "sf_abc123".to_string(),
            rest_url: "https://cistern.internal/rest/v1".to_string(),
            anon_key: "anon-key-secret".to_string(),
            service_key: "service-key-secret".to_string(),
        }
    }

    fn sample_deploy(provisioned: bool) -> RepoDeploy {
        RepoDeploy {
            id: "rd_test".to_string(),
            repo_id: "rp_test".to_string(),
            siteflow_slug: "alice-site".to_string(),
            siteflow_project_id: "proj_1".to_string(),
            deploy_hook_token: "hook-token".to_string(),
            deploy_hook_url: "https://siteflow.test/hook".to_string(),
            production_branch: "main".to_string(),
            output_directory: ".".to_string(),
            framework: "static".to_string(),
            auto_deploy: false,
            last_build_job_id: String::new(),
            preview_url: String::new(),
            last_deployed_sha: String::new(),
            created_at: 0,
            updated_at: 0,
            cistern_provisioned: provisioned,
            cistern_slug: String::new(),
        }
    }

    fn sample_repo() -> Repo {
        Repo {
            id: "rp_test".to_string(),
            owner_sub: "alice".to_string(),
            name: "site".to_string(),
            description: String::new(),
            is_private: false,
            default_branch: "main".to_string(),
            require_approval: false,
            required_approvals: 0,
            require_code_owner_reviews: false,
            protect_default_branch: false,
            forked_from_id: String::new(),
            created_at: 0,
        }
    }

    fn sample_pull(head: &str) -> Pull {
        Pull {
            id: "pl_test".to_string(),
            repo_id: "rp_test".to_string(),
            number: 1,
            title: "Preview".to_string(),
            body: String::new(),
            base: "main".to_string(),
            head: head.to_string(),
            author_sub: "alice".to_string(),
            assignee_sub: String::new(),
            reviewer_sub: String::new(),
            milestone_id: String::new(),
            is_draft: false,
            state: "open".to_string(),
            created_at: 0,
            merged_at: 0,
        }
    }

    fn sample_state() -> AppState {
        let config = Arc::new(Config::dev());
        AppState {
            config: config.clone(),
            store: Arc::new(InMemoryStore::new()),
            git: GitOps::new(config.as_ref()),
            klaxon: None,
        }
    }

    #[tokio::test]
    async fn start_pull_preview_skips_when_head_is_production_branch() {
        let state = sample_state();
        let repo = sample_repo();
        let deploy = sample_deploy(false);
        let pull = sample_pull("main");

        start_pull_preview(&state, &repo, &deploy, "alice", &pull)
            .await
            .unwrap();

        assert!(state
            .store
            .get_pull_preview_comment(&pull.id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn submit_preview_deploy_skips_when_deploy_hook_token_is_empty() {
        let state = sample_state();
        let repo = sample_repo();
        let mut deploy = sample_deploy(false);
        deploy.deploy_hook_token.clear();
        deploy.deploy_hook_url.clear();

        let result = submit_preview_deploy(&state, &repo, &deploy, "feature", "alice")
            .await
            .unwrap();

        assert_eq!(result, None);
        assert!(state.store.get_deploy(&repo.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn mark_preview_timed_out_sets_failed_when_build_still_owns_row() {
        let state = sample_state();
        let repo = sample_repo();
        let pull = sample_pull("feature");
        state
            .store
            .upsert_pull_preview_comment(
                &pull.id,
                "build_1",
                "building",
                "",
                "deadbeefcafebabe",
                "building",
                10,
            )
            .await
            .unwrap();

        assert!(
            mark_preview_timed_out(&state, &repo, &pull, "build_1", "deadbeefcafebabe")
                .await
                .unwrap()
        );
        let comment = state
            .store
            .get_pull_preview_comment(&pull.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(comment.deployment_status, "failed");
        assert!(comment.body.contains("Preview timed out"));
    }

    #[tokio::test]
    async fn provision_guard_skips_already_provisioned_repo() {
        let fake = FakeProvisioner::new(Ok(sample_creds()));
        let mut deploy = sample_deploy(true);
        provision_cistern(&fake, "proj_1", "alice", "site", &mut deploy).await;
        assert_eq!(
            fake.open_calls.load(Ordering::SeqCst),
            0,
            "guard must short-circuit before opening a database"
        );
        assert!(fake.sealed().is_empty(), "no env vars sealed on re-deploy");
        assert!(deploy.cistern_provisioned);
        assert!(deploy.cistern_slug.is_empty());
    }

    #[tokio::test]
    async fn provision_fail_open_when_database_open_fails() {
        let fake = FakeProvisioner::new(Err("cistern unreachable".to_string()));
        let mut deploy = sample_deploy(false);
        provision_cistern(&fake, "proj_1", "alice", "site", &mut deploy).await;
        assert_eq!(fake.open_calls.load(Ordering::SeqCst), 1);
        assert!(fake.sealed().is_empty());
        assert!(
            !deploy.cistern_provisioned,
            "fail-open: unprovisioned so the next deploy retries"
        );
        assert!(deploy.cistern_slug.is_empty());
    }

    #[tokio::test]
    async fn provision_seals_runtime_and_build_env_vars_with_correct_scopes() {
        let fake = FakeProvisioner::new(Ok(sample_creds()));
        let mut deploy = sample_deploy(false);
        provision_cistern(&fake, "proj_1", "alice", "site", &mut deploy).await;
        assert_eq!(
            fake.sealed(),
            vec![
                (
                    "CISTERN_REST_URL".to_string(),
                    "https://cistern.internal/rest/v1".to_string(),
                    "build".to_string()
                ),
                (
                    "CISTERN_REST_URL".to_string(),
                    "https://cistern.internal/rest/v1".to_string(),
                    "runtime".to_string()
                ),
                (
                    "CISTERN_ANON_KEY".to_string(),
                    "anon-key-secret".to_string(),
                    "build".to_string()
                ),
                (
                    "CISTERN_ANON_KEY".to_string(),
                    "anon-key-secret".to_string(),
                    "runtime".to_string()
                ),
                (
                    "CISTERN_SERVICE_KEY".to_string(),
                    "service-key-secret".to_string(),
                    "runtime".to_string()
                ),
            ],
            "service key must be runtime-scoped only; rest_url + anon_key must be build and runtime scoped"
        );
        assert!(deploy.cistern_provisioned);
        assert_eq!(deploy.cistern_slug, "sf_abc123");
    }

    #[tokio::test]
    async fn provision_fail_open_when_env_var_seal_fails() {
        let fake = FakeProvisioner::new(Ok(sample_creds())).fail_seal("CISTERN_SERVICE_KEY");
        let mut deploy = sample_deploy(false);
        provision_cistern(&fake, "proj_1", "alice", "site", &mut deploy).await;
        assert!(
            !deploy.cistern_provisioned,
            "any seal failure leaves the repo unprovisioned for a later retry"
        );
        assert!(deploy.cistern_slug.is_empty());
        assert_eq!(
            fake.sealed().len(),
            4,
            "rest_url and anon_key seal in both scopes before the service-key runtime seal failed"
        );
    }

    #[test]
    fn custom_domain_hostname_validation_normalizes_dns_labels() {
        assert_eq!(
            clean_domain_hostname("  WWW.Example.COM  ").unwrap(),
            "www.example.com"
        );
        assert!(clean_domain_hostname("").is_err());
        assert!(clean_domain_hostname("-bad.example.com").is_err());
        assert!(clean_domain_hostname("bad-.example.com").is_err());
        assert!(clean_domain_hostname("bad..example.com").is_err());
        assert!(clean_domain_hostname("bad_example.com").is_err());
        assert!(clean_domain_hostname("example.com.").is_err());
    }

    #[test]
    fn custom_domain_rejects_siteflow_base_domain_suffix() {
        assert!(
            clean_custom_domain_hostname("app.siteflow.w33d.xyz", "siteflow.w33d.xyz").is_err()
        );
        assert!(clean_custom_domain_hostname("siteflow.w33d.xyz", "siteflow.w33d.xyz").is_err());
        assert!(
            clean_custom_domain_hostname("app.example.com", "https://siteflow.w33d.xyz/").is_ok()
        );
        assert!(clean_custom_domain_hostname(
            "siteflow.w33d.xyz.evil.example",
            "siteflow.w33d.xyz"
        )
        .is_ok());
    }

    #[test]
    fn latest_deployment_preview_url_extracts_real_preview_url() {
        let deployments = json!({
            "deployments": [
                { "status": "ready", "previewUrl": " https://preview-1.siteflow.test " },
                { "status": "ready", "previewUrl": "https://preview-2.siteflow.test" }
            ]
        });
        assert_eq!(
            latest_deployment_preview_url(&deployments).as_deref(),
            Some("https://preview-1.siteflow.test")
        );

        let top_level = json!({ "status": "ready", "previewUrl": "https://top.siteflow.test" });
        assert_eq!(
            latest_deployment_preview_url(&top_level).as_deref(),
            Some("https://top.siteflow.test")
        );

        let array = json!([{ "status": "ready", "previewUrl": "https://array.siteflow.test" }]);
        assert_eq!(
            latest_deployment_preview_url(&array).as_deref(),
            Some("https://array.siteflow.test")
        );

        let missing = json!({ "deployments": [{ "status": "ready" }] });
        assert_eq!(latest_deployment_preview_url(&missing), None);

        let empty = json!({ "deployments": [{ "status": "ready", "previewUrl": "  " }] });
        assert_eq!(latest_deployment_preview_url(&empty), None);
    }

    #[test]
    fn preview_status_terminal_classification_matches_siteflow_states() {
        for status in ["ready", "error", "failed", "canceled", "READY"] {
            assert!(
                is_terminal_preview_status(status),
                "{status} should be terminal"
            );
        }
        for status in ["building", "queued", "pending", "unknown"] {
            assert!(
                !is_terminal_preview_status(status),
                "{status} should not be terminal"
            );
        }
    }

    #[test]
    fn deployment_ready_emit_guard_requires_ready_status_and_url() {
        assert!(should_emit_deployment_ready(
            " ready ",
            "https://preview.siteflow.test"
        ));
        for status in ["error", "failed", "canceled", "building", "queued"] {
            assert!(
                !should_emit_deployment_ready(status, "https://preview.siteflow.test"),
                "{status} must not emit deployment_ready"
            );
        }
        assert!(!should_emit_deployment_ready("ready", ""));
    }

    #[test]
    fn pushed_agent_branch_preview_selection_matches_rules() {
        let push_body = b"old new refs/heads/agent/multica/issue-123\0old new refs/heads/feature/no-pr\0";
        let selected: Vec<String> = push_body_head_branches(push_body)
            .into_iter()
            .filter(|branch| should_preview_pushed_agent_branch(branch, "main", false))
            .collect();

        assert_eq!(selected, vec!["agent/multica/issue-123".to_string()]);
        assert!(!should_preview_pushed_agent_branch(
            "feature/no-pr",
            "main",
            false
        ));
        assert!(!should_preview_pushed_agent_branch(
            "agent/multica/issue-123",
            "agent/multica/issue-123",
            false
        ));
        assert!(!should_preview_pushed_agent_branch(
            "agent/multica/issue-123",
            "main",
            true
        ));
    }

    #[test]
    fn preview_status_from_deployments_matches_commit_sha_before_latest() {
        let deployments = json!({
            "deployments": [
                {
                    "status": "ready",
                    "source": { "commitSha": "ffffffff" },
                    "previewUrl": "https://wrong.siteflow.test",
                    "buildJobId": "build_wrong"
                },
                {
                    "status": "building",
                    "source": { "commitSha": "deadbeefcafebabe" },
                    "previewUrl": "https://right.siteflow.test",
                    "buildJobId": "build_right"
                }
            ]
        });
        assert_eq!(
            preview_status_from_deployments(&deployments, "deadbeefcafebabe", "")
                .map(|(status, url)| (status, url.unwrap())),
            Some((
                "building".to_string(),
                "https://right.siteflow.test".to_string()
            ))
        );
    }

    #[test]
    fn preview_status_from_deployments_falls_back_to_build_job_id() {
        let deployments = json!({
            "deployments": [
                { "status": "ready", "previewUrl": "https://wrong.siteflow.test", "buildJobId": "build_wrong" },
                { "status": "failed", "previewUrl": "https://right.siteflow.test", "buildJobId": "build_right" }
            ]
        });
        assert_eq!(
            preview_status_from_deployments(&deployments, "deadbeefcafebabe", "build_right")
                .map(|(status, url)| (status, url.unwrap())),
            Some((
                "failed".to_string(),
                "https://right.siteflow.test".to_string()
            ))
        );
    }

    #[test]
    fn production_status_from_deployments_prefers_production_branch_over_latest_preview() {
        let mut deploy = sample_deploy(false);
        deploy.production_branch = "main".to_string();
        deploy.last_build_job_id = "prod_build".to_string();
        deploy.last_deployed_sha = "prod_sha".to_string();
        let deployments = json!({
            "deployments": [
                {
                    "branch": "feature",
                    "status": "ready",
                    "previewUrl": "https://preview.siteflow.test",
                    "buildJobId": "preview_build",
                    "commitSha": "preview_sha"
                },
                {
                    "branch": "main",
                    "status": "building",
                    "previewUrl": "https://prod.siteflow.test",
                    "buildJobId": "prod_build",
                    "commitSha": "prod_sha"
                }
            ]
        });

        assert_eq!(
            production_status_from_deployments(&deployments, &deploy)
                .map(|(status, url)| (status, url.unwrap())),
            Some((
                "building".to_string(),
                "https://prod.siteflow.test".to_string()
            ))
        );
    }

    #[test]
    fn siteflow_domains_extracts_hostname_and_verified_flag() {
        // SiteFlow nests domains under `.project.domains` (the real GET /api/projects/{id} shape).
        let value = json!({
            "project": {
                "domains": [
                    { "hostname": "www.example.com", "verified": true },
                    { "hostname": "api.example.com" },
                    { "verified": true },
                    { "hostname": "" }
                ]
            }
        });
        assert_eq!(
            siteflow_domains(&value),
            vec![
                json!({ "hostname": "www.example.com", "verified": true }),
                json!({ "hostname": "api.example.com", "verified": false }),
            ]
        );
    }

    #[test]
    fn siteflow_error_message_prefers_json_message_fields() {
        assert_eq!(
            siteflow_error_message(r#"{"message":"domain already exists"}"#).as_deref(),
            Some("domain already exists")
        );
        assert_eq!(
            siteflow_error_message(r#"{"error":{"message":"invalid hostname"}}"#).as_deref(),
            Some("invalid hostname")
        );
        assert_eq!(
            siteflow_error_message("plain failure").as_deref(),
            Some("plain failure")
        );
    }
}
