//! The `/admin/retention` panel: tag-retention keep-rules, a dry-run **Preview**, and an
//! **Apply now** action.
//!
//! Gated by [`auth::require_admin`] like the rest of the `/admin` subtree, and every state-changing
//! POST is double-submit CSRF checked. A keep-rule KEEPS the newest `keep_last` tags and/or tags
//! pushed within `keep_days` days (0 = ignore that dimension) in repos matching its `repo_pattern`;
//! any other tag is a deletion candidate. Two protections are absolute: a tag named `latest` is
//! never deleted, and a tag kept by ANY enabled applicable rule is never deleted.
//!
//! **Preview** lists the candidate `(repo, tag)` pairs WITHOUT mutating anything. **Apply** deletes
//! those tags via the existing tag-delete path and then reclaims the now-orphaned manifests + blobs
//! through the shared GC sweep ([`crate::handlers::admin::run_gc`]), auditing the result. All
//! producer-supplied text (patterns, repos, tags) is HTML-escaped on render.

use std::collections::HashSet;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::auth::{self, Identity};
use crate::error::WebError;
use crate::handlers::{admin_tabs, esc, human_size, userbox, APP_JS};
use crate::model::{repo_pattern_matches, RetentionRule};
use crate::names::is_valid_repo_pattern;
use crate::{now_secs, random_alnum, AppState};

const RETENTION_HTML: &str = include_str!("../../templates/retention.html");

// ---------------------------------------------------------------------------
// GET /admin/retention
// ---------------------------------------------------------------------------

/// `GET /admin/retention` — list keep-rules with a create form and Preview / Apply controls.
pub async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, WebError> {
    auth::require_admin(&headers)?;
    let who = auth::identity(&headers);
    let rules = state.store.list_retention_rules().await?;
    let csrf = auth::new_csrf_token();
    Ok(page(render(&who, &rules, &csrf, "", ""), &csrf))
}

// ---------------------------------------------------------------------------
// POST /admin/retention/create
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateForm {
    #[serde(default)]
    pub repo_pattern: String,
    #[serde(default)]
    pub keep_last: String,
    #[serde(default)]
    pub keep_days: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /admin/retention/create` — add a keep-rule (CSRF-checked). Requires a valid pattern and at
/// least one keep condition (a rule that kept nothing would delete every non-`latest` tag).
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateForm>,
) -> Result<Response, WebError> {
    auth::require_admin(&headers)?;
    csrf_guard(&headers, &form.csrf_token)?;
    let who = auth::identity(&headers);

    let pattern = form.repo_pattern.trim();
    if !is_valid_repo_pattern(pattern) {
        return Err(WebError::BadRequest(
            "Enter a valid repository pattern (lowercase name, or a prefix ending in *)."
                .to_string(),
        ));
    }
    let keep_last = parse_nonneg(&form.keep_last)?;
    let keep_days = parse_nonneg(&form.keep_days)?;
    if keep_last == 0 && keep_days == 0 {
        return Err(WebError::BadRequest(
            "A rule must keep at least one condition: keep newest ≥ 1, or keep days ≥ 1."
                .to_string(),
        ));
    }

    let rule = RetentionRule {
        id: format!("ret-{}", random_alnum(16)),
        repo_pattern: pattern.to_string(),
        keep_last,
        keep_days,
        enabled: true,
    };
    state.store.create_retention_rule(&rule).await?;
    tracing::info!(
        actor = who.subject,
        pattern = rule.repo_pattern,
        keep_last,
        keep_days,
        "retention rule created"
    );

    let rules = state.store.list_retention_rules().await?;
    let csrf = auth::new_csrf_token();
    let notice = notice_ok(&format!(
        "Added a keep-rule for {}.",
        esc(&rule.repo_pattern)
    ));
    Ok(page(render(&who, &rules, &csrf, &notice, ""), &csrf))
}

// ---------------------------------------------------------------------------
// POST /admin/retention/toggle + /delete
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

/// `POST /admin/retention/toggle` — enable/disable a rule (CSRF-checked).
pub async fn toggle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ToggleForm>,
) -> Result<Response, WebError> {
    auth::require_admin(&headers)?;
    csrf_guard(&headers, &form.csrf_token)?;
    let who = auth::identity(&headers);
    let enabled = form.enabled == "true";
    state.store.set_retention_enabled(&form.id, enabled).await?;
    tracing::info!(
        actor = who.subject,
        id = form.id,
        enabled,
        "retention rule toggled"
    );

    let rules = state.store.list_retention_rules().await?;
    let csrf = auth::new_csrf_token();
    let notice = notice_ok(if enabled {
        "Rule enabled."
    } else {
        "Rule disabled."
    });
    Ok(page(render(&who, &rules, &csrf, &notice, ""), &csrf))
}

#[derive(Debug, Deserialize)]
pub struct IdForm {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /admin/retention/delete` — remove a rule (CSRF-checked).
pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<IdForm>,
) -> Result<Response, WebError> {
    auth::require_admin(&headers)?;
    csrf_guard(&headers, &form.csrf_token)?;
    let who = auth::identity(&headers);
    let removed = state.store.delete_retention_rule(&form.id).await?;
    tracing::info!(
        actor = who.subject,
        id = form.id,
        removed,
        "retention rule deleted"
    );

    let rules = state.store.list_retention_rules().await?;
    let csrf = auth::new_csrf_token();
    Ok(page(
        render(&who, &rules, &csrf, &notice_ok("Rule deleted."), ""),
        &csrf,
    ))
}

// ---------------------------------------------------------------------------
// POST /admin/retention/preview (dry run) + /apply (mutating)
// ---------------------------------------------------------------------------

/// `POST /admin/retention/preview` — a DRY RUN: compute and list the tags every enabled rule would
/// delete, WITHOUT mutating anything. CSRF-checked (it reveals repo/tag inventory).
pub async fn preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<IdForm>,
) -> Result<Response, WebError> {
    auth::require_admin(&headers)?;
    csrf_guard(&headers, &form.csrf_token)?;
    let who = auth::identity(&headers);
    let deletions = plan_retention(&state, now_secs()).await?;
    let rules = state.store.list_retention_rules().await?;
    let csrf = auth::new_csrf_token();
    Ok(page(
        render(&who, &rules, &csrf, "", &render_preview(&deletions)),
        &csrf,
    ))
}

/// `POST /admin/retention/preview.json` — JSON sibling of [`preview`] backing the inline (no-reload)
/// dry-run on the retention panel. Same admin gate + double-submit CSRF; returns the candidate
/// `(repo, tag)` pairs. The form route above is unchanged for no-JS clients (progressive enhancement).
pub async fn preview_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<IdForm>,
) -> Result<Response, WebError> {
    auth::require_admin(&headers)?;
    csrf_guard(&headers, &form.csrf_token)?;
    let deletions = plan_retention(&state, now_secs()).await?;
    let items: Vec<serde_json::Value> = deletions
        .iter()
        .map(|(repo, tag)| serde_json::json!({ "repo": repo, "tag": tag }))
        .collect();
    Ok(axum::Json(serde_json::json!({
        "ok": true,
        "count": deletions.len(),
        "deletions": items,
    }))
    .into_response())
}

/// `POST /admin/retention/apply` — delete every non-kept tag (via the existing tag-delete path),
/// then reclaim the now-orphaned manifests + blobs through the shared GC sweep. CSRF-checked;
/// audited. Never deletes a `latest` tag or a tag kept by a rule.
pub async fn apply(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<IdForm>,
) -> Result<Response, WebError> {
    auth::require_admin(&headers)?;
    csrf_guard(&headers, &form.csrf_token)?;
    let who = auth::identity(&headers);

    let deletions = plan_retention(&state, now_secs()).await?;
    let mut tags_deleted = 0i64;
    for (repo, tag) in &deletions {
        if state.store.delete_tag(repo, tag).await? {
            tags_deleted += 1;
        }
    }
    // Reclaim the storage the now-untagged manifests kept alive — the SAME GC path the admin panel
    // uses, so retention and GC stay consistent.
    let gc = crate::handlers::admin::run_gc(&state).await?;
    tracing::warn!(
        actor = who.subject,
        tags_deleted,
        manifests = gc.manifests_deleted,
        blobs = gc.blobs_deleted,
        bytes_freed = gc.bytes_freed,
        "admin retention apply"
    );

    let notice = if tags_deleted == 0 {
        notice_ok("Retention applied. Nothing to delete — every tag is kept.")
    } else {
        notice_ok(&format!(
            "Retention applied — deleted {tags_deleted} tag(s) and reclaimed {} across {} manifest(s) and {} blob(s).",
            human_size(gc.bytes_freed),
            gc.manifests_deleted,
            gc.blobs_deleted,
        ))
    };
    let rules = state.store.list_retention_rules().await?;
    let csrf = auth::new_csrf_token();
    Ok(page(render(&who, &rules, &csrf, &notice, ""), &csrf))
}

// ---------------------------------------------------------------------------
// Retention planning (shared by preview + apply)
// ---------------------------------------------------------------------------

/// Compute the `(repo, tag)` deletion candidates across every repository under the ENABLED rules.
/// A tag is KEPT when it is named `latest`, is among the newest `keep_last` tags of an applicable
/// rule, or was pushed within an applicable rule's `keep_days` window; anything else is a candidate.
/// Repos with no applicable rule are left completely untouched. No mutation — used by both preview
/// (rendered) and apply (executed).
async fn plan_retention(state: &AppState, now: i64) -> Result<Vec<(String, String)>, WebError> {
    let rules: Vec<RetentionRule> = state
        .store
        .list_retention_rules()
        .await?
        .into_iter()
        .filter(|r| r.enabled)
        .collect();
    let mut deletions: Vec<(String, String)> = Vec::new();
    if rules.is_empty() {
        return Ok(deletions);
    }

    for repo in state.store.list_repositories().await? {
        let applicable: Vec<&RetentionRule> = rules
            .iter()
            .filter(|r| repo_pattern_matches(&r.repo_pattern, &repo.name))
            .collect();
        if applicable.is_empty() {
            continue; // no rule governs this repo — never delete anything here
        }

        let mut tags = state.store.tags_for(&repo.name).await?;
        // Newest first (ties broken by name for determinism).
        tags.sort_by(|a, b| {
            b.updated_at
                .cmp(&a.updated_at)
                .then_with(|| a.tag.cmp(&b.tag))
        });

        let mut keep: HashSet<String> = HashSet::new();
        keep.insert("latest".to_string()); // `latest` is never deleted
        for rule in &applicable {
            if rule.keep_last > 0 {
                for t in tags.iter().take(rule.keep_last as usize) {
                    keep.insert(t.tag.clone());
                }
            }
            if rule.keep_days > 0 {
                let cutoff = now - rule.keep_days.saturating_mul(86_400);
                for t in &tags {
                    if t.updated_at >= cutoff {
                        keep.insert(t.tag.clone());
                    }
                }
            }
        }

        for t in &tags {
            if !keep.contains(&t.tag) {
                deletions.push((repo.name.clone(), t.tag.clone()));
            }
        }
    }
    Ok(deletions)
}

// ---------------------------------------------------------------------------
// Helpers + rendering
// ---------------------------------------------------------------------------

/// Parse a non-negative integer from a form field (empty = 0). Rejects negatives / non-numbers.
fn parse_nonneg(s: &str) -> Result<i64, WebError> {
    let t = s.trim();
    if t.is_empty() {
        return Ok(0);
    }
    match t.parse::<i64>() {
        Ok(n) if n >= 0 => Ok(n),
        _ => Err(WebError::BadRequest(
            "Keep values must be non-negative whole numbers.".to_string(),
        )),
    }
}

/// Double-submit CSRF guard shared by every state-changing route here.
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

/// Render the panel with a page shell + a fresh CSRF cookie.
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
    rules: &[RetentionRule],
    csrf: &str,
    notice: &str,
    preview: &str,
) -> String {
    let count = match rules.len() {
        0 => "No rules".to_string(),
        1 => "1 rule".to_string(),
        n => format!("{n} rules"),
    };
    RETENTION_HTML
        .replace("{{THEME}}", odyssey::html_theme_attr(who.theme))
        .replace("{{COLOR_SCHEME}}", odyssey::color_scheme_meta(who.theme))
        .replace("{{JS}}", &format!("{}\n{}", odyssey::MOTION_JS, APP_JS))
        .replace(
            "{{USERBOX}}",
            &userbox("Registry admin", Some(&who.email), who.theme),
        )
        .replace("{{TABS}}", &admin_tabs("retention"))
        .replace("{{NOTICE}}", notice)
        .replace("{{PREVIEW}}", preview)
        .replace("{{COUNT}}", &esc(&count))
        .replace("{{RULE_ROWS}}", &render_rule_rows(rules, csrf))
        .replace("{{CSRF}}", &esc(csrf))
}

fn render_rule_rows(rules: &[RetentionRule], csrf: &str) -> String {
    if rules.is_empty() {
        return "<tr class=\"empty-row\"><td colspan=\"5\">No retention rules yet — every tag is kept.</td></tr>"
            .to_string();
    }
    rules
        .iter()
        .map(|r| {
            let (status, toggle_label, toggle_to) = if r.enabled {
                ("<span class=\"pill pill-ok\">Enabled</span>", "Disable", "false")
            } else {
                ("<span class=\"pill\">Disabled</span>", "Enable", "true")
            };
            let keep_last = if r.keep_last == 0 {
                "<span class=\"muted\">—</span>".to_string()
            } else {
                format!("<span class=\"chip\">newest {}</span>", r.keep_last)
            };
            let keep_days = if r.keep_days == 0 {
                "—".to_string()
            } else {
                format!("<span class=\"chip chip--outline\">within {}d</span>", r.keep_days)
            };
            format!(
                "<tr>\
                   <td class=\"mono\">{pattern}</td>\
                   <td><span class=\"cl-keep\">{keep_last}</span></td>\
                   <td><span class=\"cl-keep\">{keep_days}</span></td>\
                   <td>{status}</td>\
                   <td class=\"row-action\"><div class=\"rowactions\">\
                     <form method=\"post\" action=\"/admin/retention/toggle\">\
                       <input type=\"hidden\" name=\"id\" value=\"{id}\">\
                       <input type=\"hidden\" name=\"enabled\" value=\"{toggle_to}\">\
                       <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                       <button class=\"btn btn-ghost btn-sm\" type=\"submit\">{toggle_label}</button>\
                     </form>\
                     <form method=\"post\" action=\"/admin/retention/delete\" onsubmit=\"return confirm('Delete this rule?');\">\
                       <input type=\"hidden\" name=\"id\" value=\"{id}\">\
                       <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                       <button class=\"btn btn-danger btn-sm\" type=\"submit\">Delete</button>\
                     </form>\
                   </div></td>\
                </tr>",
                pattern = esc(&r.repo_pattern),
                keep_last = keep_last,
                keep_days = keep_days,
                status = status,
                id = esc(&r.id),
                toggle_to = toggle_to,
                toggle_label = toggle_label,
                csrf = esc(csrf),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

/// The dry-run preview block: which tags WOULD be deleted (no mutation).
fn render_preview(deletions: &[(String, String)]) -> String {
    let rows = if deletions.is_empty() {
        "<tr class=\"empty-row\"><td colspan=\"2\">Nothing would be deleted — every tag is kept by a rule (or is <code>latest</code>).</td></tr>"
            .to_string()
    } else {
        deletions
            .iter()
            .map(|(repo, tag)| {
                format!(
                    "<tr><td class=\"repo-cell\"><span class=\"repo-name\">{repo}</span></td><td><span class=\"tag-pill\">{tag}</span></td></tr>",
                    repo = esc(repo),
                    tag = esc(tag),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let count = match deletions.len() {
        1 => "1 tag".to_string(),
        n => format!("{n} tags"),
    };
    format!(
        "<div class=\"section-head\"><h2>Dry run — tags that would be deleted</h2><span class=\"count-badge\">{count}</span></div>\
         <div class=\"table-wrap\"><table class=\"data\">\
           <thead><tr><th>Repository</th><th>Tag</th></tr></thead>\
           <tbody>{rows}</tbody>\
         </table></div>",
        count = esc(&count),
        rows = rows,
    )
}
