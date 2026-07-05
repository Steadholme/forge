//! The `/admin/robots` panel: mint / list / disable / delete robot accounts.
//!
//! A robot account is an ADDITIONAL `/v2/` credential (alongside the human `CELLAR_USER`), scoped to
//! `pull` or `pushpull` on repos matching a `repo_pattern`. It authenticates on the `/v2/` protocol
//! as `robot$<name>` (Basic) or as a `Bearer` token (see [`crate::handlers::registry`]); minting it
//! never weakens the human path. The token is generated here, shown ONCE, and only its sha256 hash
//! is persisted.
//!
//! Gated by [`auth::require_admin`]; every state-changing POST is double-submit CSRF checked. All
//! producer-supplied text (names, patterns) is HTML-escaped on render.

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::auth::{self, Identity};
use crate::error::WebError;
use crate::handlers::{admin_tabs, esc, fmt_ts, time_ago, userbox, app_css};
use crate::model::{is_valid_robot_scope, RobotAccount, ROBOT_SCOPE_PUSHPULL};
use crate::names::{is_valid_repo_pattern, is_valid_robot_name};
use crate::{now_secs, random_alnum, AppState};

const ROBOTS_HTML: &str = include_str!("../../templates/robots.html");

// ---------------------------------------------------------------------------
// GET /admin/robots
// ---------------------------------------------------------------------------

/// `GET /admin/robots` — list robot accounts with a mint form.
pub async fn index(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, WebError> {
    auth::require_admin(&headers)?;
    let who = auth::identity(&headers);
    let robots = state.store.list_robots().await?;
    let csrf = auth::new_csrf_token();
    Ok(page(render(&who, &robots, &csrf, "", ""), &csrf))
}

// ---------------------------------------------------------------------------
// POST /admin/robots/create — mint (token shown ONCE)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateForm {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub repo_pattern: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /admin/robots/create` — mint a robot (CSRF-checked). Validates the name/scope/pattern,
/// generates the token, stores only its hash, and renders the token ONCE.
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateForm>,
) -> Result<Response, WebError> {
    auth::require_admin(&headers)?;
    csrf_guard(&headers, &form.csrf_token)?;
    let who = auth::identity(&headers);

    let name = form.name.trim();
    if !is_valid_robot_name(name) {
        return Err(WebError::BadRequest(
            "Enter a valid robot name (lowercase alphanumerics with . _ - separators).".to_string(),
        ));
    }
    let scope = form.scope.trim();
    if !is_valid_robot_scope(scope) {
        return Err(WebError::BadRequest(
            "Scope must be either pull or pushpull.".to_string(),
        ));
    }
    let pattern = form.repo_pattern.trim();
    if !is_valid_repo_pattern(pattern) {
        return Err(WebError::BadRequest(
            "Enter a valid repository pattern (lowercase name, or a prefix ending in *).".to_string(),
        ));
    }
    if state.store.get_robot_by_name(name).await?.is_some() {
        return Err(WebError::BadRequest(format!(
            "A robot named \"{name}\" already exists."
        )));
    }

    let token = auth::new_robot_token();
    let robot = RobotAccount {
        id: format!("rob-{}", random_alnum(16)),
        name: name.to_string(),
        token_hash: auth::hash_token(&token),
        scope: scope.to_string(),
        repo_pattern: pattern.to_string(),
        enabled: true,
        created_at: now_secs(),
        last_used_at: 0,
    };
    // The store also enforces name-uniqueness; surface a duplicate as a friendly 400 (not a 500).
    state
        .store
        .create_robot(&robot)
        .await
        .map_err(|e| WebError::BadRequest(e.to_string()))?;
    tracing::warn!(
        actor = who.subject,
        robot = robot.name,
        scope = robot.scope,
        pattern = robot.repo_pattern,
        "robot account created"
    );

    let robots = state.store.list_robots().await?;
    let csrf = auth::new_csrf_token();
    let token_block = render_token(&state, &robot, &token);
    Ok(page(render(&who, &robots, &csrf, "", &token_block), &csrf))
}

// ---------------------------------------------------------------------------
// POST /admin/robots/toggle + /delete
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ToggleForm {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub enabled: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /admin/robots/toggle` — enable/disable a robot (CSRF-checked). A disabled robot's token is
/// rejected at the `/v2/` auth path.
pub async fn toggle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ToggleForm>,
) -> Result<Response, WebError> {
    auth::require_admin(&headers)?;
    csrf_guard(&headers, &form.csrf_token)?;
    let who = auth::identity(&headers);
    let enabled = form.enabled == "true";
    state.store.set_robot_enabled(&form.id, enabled).await?;
    tracing::warn!(actor = who.subject, id = form.id, enabled, "robot account toggled");

    let robots = state.store.list_robots().await?;
    let csrf = auth::new_csrf_token();
    let notice = notice_ok(if enabled { "Robot enabled." } else { "Robot disabled." });
    Ok(page(render(&who, &robots, &csrf, &notice, ""), &csrf))
}

#[derive(Debug, Deserialize)]
pub struct IdForm {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /admin/robots/delete` — permanently remove a robot (CSRF-checked). Its token stops working.
pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<IdForm>,
) -> Result<Response, WebError> {
    auth::require_admin(&headers)?;
    csrf_guard(&headers, &form.csrf_token)?;
    let who = auth::identity(&headers);
    let removed = state.store.delete_robot(&form.id).await?;
    tracing::warn!(actor = who.subject, id = form.id, removed, "robot account deleted");

    let robots = state.store.list_robots().await?;
    let csrf = auth::new_csrf_token();
    Ok(page(render(&who, &robots, &csrf, &notice_ok("Robot deleted."), ""), &csrf))
}

// ---------------------------------------------------------------------------
// Helpers + rendering
// ---------------------------------------------------------------------------

fn csrf_guard(headers: &HeaderMap, submitted: &str) -> Result<(), WebError> {
    if auth::verify_csrf(headers, submitted) {
        Ok(())
    } else {
        Err(WebError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ))
    }
}

fn notice_ok(msg: &str) -> String {
    format!("<div class=\"notice notice-ok\">{}</div>", esc(msg))
}

/// The registry host (scheme stripped) used in the `docker login` example.
fn registry_host(public_base: &str) -> String {
    public_base
        .trim_end_matches('/')
        .splitn(2, "://")
        .last()
        .unwrap_or(public_base)
        .to_string()
}

fn page(html: String, csrf: &str) -> Response {
    (
        StatusCode::OK,
        [(header::SET_COOKIE, auth::csrf_cookie(csrf))],
        Html(html),
    )
        .into_response()
}

fn render(
    who: &Identity,
    robots: &[RobotAccount],
    csrf: &str,
    notice: &str,
    token_block: &str,
) -> String {
    let count = match robots.len() {
        0 => "No robots".to_string(),
        1 => "1 robot".to_string(),
        n => format!("{n} robots"),
    };
    ROBOTS_HTML
        .replace("{{CSS}}", app_css())
        .replace("{{USERBOX}}", &userbox("Registry admin", Some(&who.email)))
        .replace("{{TABS}}", &admin_tabs("robots"))
        .replace("{{NOTICE}}", notice)
        .replace("{{TOKEN}}", token_block)
        .replace("{{COUNT}}", &esc(&count))
        .replace("{{ROBOT_ROWS}}", &render_robot_rows(robots, csrf))
        .replace("{{CSRF}}", &esc(csrf))
}

/// The one-time token card. The token is rendered in a `data-token` attribute (and inline) so an
/// operator can copy it; it is never stored in plaintext and never shown again.
fn render_token(state: &AppState, robot: &RobotAccount, token: &str) -> String {
    let host = registry_host(&state.config.public_base);
    let scope_label = if robot.scope == ROBOT_SCOPE_PUSHPULL {
        "push + pull"
    } else {
        "pull"
    };
    format!(
        "<div class=\"card\"><div class=\"card__head\"><h2>Robot “{name}” created</h2></div>\
         <div class=\"card__body\">\
           <p class=\"sub\">Copy this token now — it is shown <b>once</b> and cannot be retrieved again. \
             It grants <b>{scope}</b> on <code>{pattern}</code>.</p>\
           <div class=\"cmd-strip\"><span class=\"cmd-label\">Token</span><code data-token=\"{token_attr}\">{token}</code></div>\
           <div class=\"cmd-strip\"><span class=\"cmd-label\">docker login</span><code>docker login -u robot${name} -p {token} {host}</code></div>\
         </div></div>",
        name = esc(&robot.name),
        scope = esc(scope_label),
        pattern = esc(&robot.repo_pattern),
        token_attr = esc(token),
        token = esc(token),
        host = esc(&host),
    )
}

fn render_robot_rows(robots: &[RobotAccount], csrf: &str) -> String {
    if robots.is_empty() {
        return "<tr class=\"empty-row\"><td colspan=\"7\">No robot accounts yet.</td></tr>".to_string();
    }
    let now = now_secs();
    robots
        .iter()
        .map(|r| {
            let scope = if r.scope == ROBOT_SCOPE_PUSHPULL {
                "<span class=\"pill pill-accent\">push + pull</span>"
            } else {
                "<span class=\"pill\">pull</span>"
            };
            let (status, toggle_label, toggle_to) = if r.enabled {
                ("<span class=\"pill pill-ok\">Enabled</span>", "Disable", "false")
            } else {
                ("<span class=\"pill\">Disabled</span>", "Enable", "true")
            };
            let last_used = if r.last_used_at == 0 {
                "Never".to_string()
            } else {
                time_ago(r.last_used_at, now)
            };
            format!(
                "<tr>\
                   <td class=\"mono\">robot${name}</td>\
                   <td>{scope}</td>\
                   <td class=\"mono\">{pattern}</td>\
                   <td>{status}</td>\
                   <td class=\"muted\">{created}</td>\
                   <td class=\"muted\">{last_used}</td>\
                   <td class=\"row-action\"><div class=\"rowactions\">\
                     <form method=\"post\" action=\"/admin/robots/toggle\">\
                       <input type=\"hidden\" name=\"id\" value=\"{id}\">\
                       <input type=\"hidden\" name=\"enabled\" value=\"{toggle_to}\">\
                       <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                       <button class=\"btn btn-ghost btn-sm\" type=\"submit\">{toggle_label}</button>\
                     </form>\
                     <form method=\"post\" action=\"/admin/robots/delete\" onsubmit=\"return confirm('Delete robot {name_js}? Its token stops working immediately.');\">\
                       <input type=\"hidden\" name=\"id\" value=\"{id}\">\
                       <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                       <button class=\"btn btn-danger btn-sm\" type=\"submit\">Delete</button>\
                     </form>\
                   </div></td>\
                 </tr>",
                name = esc(&r.name),
                scope = scope,
                pattern = esc(&r.repo_pattern),
                status = status,
                created = esc(&fmt_ts(r.created_at)),
                last_used = esc(&last_used),
                id = esc(&r.id),
                toggle_to = toggle_to,
                toggle_label = toggle_label,
                name_js = esc(&r.name),
                csrf = esc(csrf),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}
