//! HTTP handlers + shared server-render helpers.
//!
//! - [`health`] — unauthenticated liveness probe (`/healthz`).
//! - [`repos`] — the SSO web surface: repo list/create, browse (tree/blob), the repo home.
//! - [`commits`] — commit history (keyset-paginated) + the single-commit page (metadata + diff).
//! - [`branches`] — the branches + tags listing.
//! - [`issues`] — the per-repo issue tracker (list/filter, detail + comments, create/comment/toggle).
//! - [`pulls`] — pull requests (compare, create, detail, gated merge).
//! - [`releases`] — repo releases attached to git tags, with Markdown notes.
//! - [`settings`] — repo settings (description + default branch; owner/admin only).
//! - [`pats`] — personal-access-token management (mint once / revoke).
//! - [`smart_http`] — the git smart-HTTP protocol (`/git/...`) with PAT Basic auth.
//!
//! The shared design tokens / CSS are embedded (via `include_str!`) and inlined into every page,
//! matching the Steadholme enterprise brand. All producer-supplied text (repo names, descriptions,
//! file contents, commit subjects) is HTML-escaped on render. Markdown surfaces (README files,
//! `.md` blobs, issue bodies) are rendered through the sanitising [`crate::markdown`] pipeline
//! (raw HTML downgraded to text, unsafe link schemes defused) — Loom serves no executable file
//! content from the browser-facing surface.

pub mod branches;
pub mod commits;
pub mod deploy;
pub mod health;
pub mod issues;
pub mod pats;
pub mod pulls;
pub mod releases;
pub mod repos;
pub mod settings;
pub mod smart_http;

use axum::extract::Query;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use serde::de::{SeqAccess, Visitor};
use serde::Deserialize;
use serde::Deserializer;
use std::fmt;

use crate::model::ReactionSummary;

/// Loom-only CSS layered after Odyssey's canonical font, tokens, and components.
pub const SERVICE_CSS: &str = include_str!("../../static/service.css");

static APP_CSS: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Embedded design system (Odyssey canonical + Loom service CSS), inlined into each page's `<style>`.
pub fn app_css() -> &'static str {
    APP_CSS
        .get_or_init(|| {
            let mut css = String::with_capacity(odyssey::APP_CSS.len() + SERVICE_CSS.len());
            css.push_str(odyssey::APP_CSS);
            css.push_str(SERVICE_CSS);
            css
        })
        .as_str()
}

/// Embedded progressive-enhancement script, inlined into each rendered page's `<script>`. Purely
/// additive: every form route + server-rendered markup still works with JavaScript disabled.
pub const APP_JS: &str = include_str!("../../static/app.js");

/// The Steadholme shield glyph (small, for the app-bar brand lockup).
pub const SHIELD_SVG: &str = r##"<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="hf-shield-sm" x1="8" y1="4" x2="40" y2="44" gradientUnits="userSpaceOnUse"><stop stop-color="#818CF8"/><stop offset="1" stop-color="#4F46E5"/></linearGradient></defs><path d="M24 4 8 9.5V22c0 11 7 17.4 16 21.5C33 39.4 40 33 40 22V9.5L24 4Z" fill="url(#hf-shield-sm)"/><rect x="20" y="19" width="8" height="13" rx="1" fill="#fff" fill-opacity="0.92"/><path d="M20 19v-2.5a4 4 0 0 1 8 0V19" stroke="#fff" stroke-width="2" stroke-opacity="0.92" fill="none"/></svg>"##;

/// Reserved subject for the PR preview bot. `:` is intentionally invalid for real owner subjects.
pub const PREVIEW_BOT_SUB: &str = "loom:preview-bot";

/// Cross-subdomain SSO logout (terminated at the Keystone IdP behind the gateway).
pub const LOGOUT_URL: &str = "https://sso.w33d.xyz/_gw/auth/logout";

/// Branded error page shell.
const ERROR_HTML: &str = include_str!("../../templates/error.html");

/// Format epoch seconds as a compact UTC timestamp `YYYY-MM-DD HH:MM:SSZ`.
pub fn fmt_ts(secs: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}Z",
            dt.year(),
            dt.month() as u8,
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        ),
        Err(_) => secs.to_string(),
    }
}

/// Format epoch seconds as a UTC day heading like `Jul 3, 2026`.
pub fn fmt_day(secs: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => {
            let month = match dt.month() {
                time::Month::January => "Jan",
                time::Month::February => "Feb",
                time::Month::March => "Mar",
                time::Month::April => "Apr",
                time::Month::May => "May",
                time::Month::June => "Jun",
                time::Month::July => "Jul",
                time::Month::August => "Aug",
                time::Month::September => "Sep",
                time::Month::October => "Oct",
                time::Month::November => "Nov",
                time::Month::December => "Dec",
            };
            format!("{month} {}, {}", dt.day(), dt.year())
        }
        Err(_) => secs.to_string(),
    }
}

/// First 8 hex characters of a commit OID, for compact display.
pub fn short_oid(oid: &str) -> String {
    oid.chars().take(8).collect()
}

/// Compact relative age of an epoch-seconds timestamp against `now` ("3 days ago"). Future or
/// zero timestamps fall back to the absolute [`fmt_ts`] form.
pub fn fmt_rel(now: i64, then: i64) -> String {
    let d = now - then;
    if then <= 0 || d < 0 {
        return fmt_ts(then);
    }
    let (n, unit) = if d < 60 {
        return "just now".to_string();
    } else if d < 3600 {
        (d / 60, "minute")
    } else if d < 86_400 {
        (d / 3600, "hour")
    } else if d < 30 * 86_400 {
        (d / 86_400, "day")
    } else if d < 365 * 86_400 {
        (d / (30 * 86_400), "month")
    } else {
        (d / (365 * 86_400), "year")
    };
    let s = if n == 1 { "" } else { "s" };
    format!("{n} {unit}{s} ago")
}

/// Render the shared HTML page shell with the app-bar. `title` is the app-bar page label, `email`
/// the signed-in identity (shown when known), `body` the already-escaped main content HTML.
pub fn page(title: &str, email: Option<&str>, theme: &str, body: &str) -> String {
    PAGE_HTML
        .replace("{{CSS}}", app_css())
        .replace(
            "{{JS}}",
            &format!("{}\n{}\n{}", odyssey::MOTION_JS, odyssey::WIRE_JS, APP_JS),
        )
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{THEME}}", odyssey::html_theme_attr(theme))
        .replace("{{COLOR_SCHEME}}", odyssey::color_scheme_meta(theme))
        .replace("{{TITLE}}", &esc(title))
        .replace("{{USERBOX}}", &userbox(title, email, theme))
        .replace("{{BODY}}", body)
}

const PAGE_HTML: &str = include_str!("../../templates/page.html");

/// Wrap a rendered page in a `200 OK` HTML response.
pub fn html_ok(body: String) -> Response {
    (StatusCode::OK, Html(body)).into_response()
}

/// Wrap a rendered page in an HTML response that also (re)sets the CSRF cookie.
pub fn html_with_csrf(status: StatusCode, body: String, csrf: &str) -> Response {
    (
        status,
        [(header::SET_COOKIE, crate::auth::csrf_cookie(csrf))],
        Html(body),
    )
        .into_response()
}

/// A `302 Found` redirect to `location`.
pub fn redirect(location: &str) -> Response {
    (
        StatusCode::FOUND,
        [(header::LOCATION, location.to_string())],
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct SigninQuery {
    #[serde(rename = "return")]
    pub return_to: Option<String>,
}

/// SSO bounce target. The gateway authenticates `/signin` before Loom sees it; Loom only redirects
/// back to a same-origin relative path and rejects absolute/protocol-relative targets.
pub async fn signin(Query(q): Query<SigninQuery>) -> Response {
    redirect(safe_signin_return(q.return_to.as_deref()))
}

fn safe_signin_return(return_to: Option<&str>) -> &str {
    match return_to {
        Some(path) if path.starts_with('/') && !path.starts_with("//") => path,
        _ => "/",
    }
}

/// GitHub-compatible reaction glyphs accepted by Loom. Escapes keep this source ASCII-only.
pub const REACTION_EMOJIS: [&str; 8] = [
    "\u{1f44d}",
    "\u{1f44e}",
    "\u{1f604}",
    "\u{1f389}",
    "\u{1f615}",
    "\u{2764}\u{fe0f}",
    "\u{1f680}",
    "\u{1f440}",
];

pub const REACTION_TARGET_ISSUE: &str = "issue";
pub const REACTION_TARGET_PULL: &str = "pull";
pub const REACTION_TARGET_COMMENT: &str = "comment";

/// True when the request explicitly prefers a JSON response.
pub fn accepts_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|part| part.trim().starts_with("application/json"))
        })
        .unwrap_or(false)
}

/// Reject arbitrary client-supplied emoji; only the fixed reaction palette is accepted.
pub fn is_valid_reaction_emoji(emoji: &str) -> bool {
    REACTION_EMOJIS.contains(&emoji)
}

fn ordered_reaction_summaries(summaries: &[ReactionSummary]) -> Vec<&ReactionSummary> {
    REACTION_EMOJIS
        .iter()
        .filter_map(|emoji| {
            summaries
                .iter()
                .find(|summary| summary.emoji == *emoji && summary.count > 0)
        })
        .collect()
}

/// JSON aggregate for progressive enhancement callers.
pub fn reaction_summaries_json(summaries: &[ReactionSummary]) -> serde_json::Value {
    serde_json::Value::Array(
        ordered_reaction_summaries(summaries)
            .into_iter()
            .map(|summary| {
                serde_json::json!({
                    "emoji": summary.emoji,
                    "count": summary.count,
                    "viewer_selected": summary.viewer_selected,
                })
            })
            .collect(),
    )
}

/// Render the reaction bar and add-reaction picker. When there are no reactions yet, only the
/// picker is visible, keeping the empty state backward-compatible.
pub fn render_reactions(
    action: &str,
    target_type: &str,
    target_id: &str,
    summaries: &[ReactionSummary],
    csrf: &str,
) -> String {
    let reaction_buttons = ordered_reaction_summaries(summaries)
        .into_iter()
        .map(|summary| {
            let active_class = if summary.viewer_selected {
                " reaction--active"
            } else {
                ""
            };
            let pressed = if summary.viewer_selected { "true" } else { "false" };
            format!(
                r##"<form class="reaction-form" method="post" action="{action}">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <input type="hidden" name="emoji" value="{emoji}">
  <button class="reaction{active_class}" type="submit" aria-pressed="{pressed}"><span class="reaction__emoji">{emoji}</span> <span class="reaction__count">{count}</span></button>
</form>"##,
                action = esc(action),
                csrf = esc(csrf),
                emoji = esc(&summary.emoji),
                active_class = active_class,
                pressed = pressed,
                count = summary.count,
            )
        })
        .collect::<String>();
    let reaction_list = if reaction_buttons.is_empty() {
        String::new()
    } else {
        format!("<div class=\"reactions__list\">{reaction_buttons}</div>")
    };

    let picker_buttons = REACTION_EMOJIS
        .iter()
        .map(|emoji| {
            let selected = summaries
                .iter()
                .any(|summary| summary.emoji == *emoji && summary.viewer_selected);
            let active_class = if selected { " reaction--active" } else { "" };
            let pressed = if selected { "true" } else { "false" };
            format!(
                r##"<form class="reaction-picker__form" method="post" action="{action}">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <input type="hidden" name="emoji" value="{emoji}">
  <button class="reaction reaction-picker__emoji{active_class}" type="submit" aria-pressed="{pressed}">{emoji}</button>
</form>"##,
                action = esc(action),
                csrf = esc(csrf),
                emoji = esc(emoji),
                active_class = active_class,
                pressed = pressed,
            )
        })
        .collect::<String>();

    format!(
        r##"<div class="reactions" data-target-type="{target_type}" data-target-id="{target_id}">
  {reaction_list}
  <details class="reaction-picker">
    <summary class="reaction-picker__button" aria-label="Add reaction">+</summary>
    <div class="reaction-picker__menu">{picker_buttons}</div>
  </details>
</div>"##,
        target_type = esc(target_type),
        target_id = esc(target_id),
        reaction_list = reaction_list,
        picker_buttons = picker_buttons,
    )
}

/// Two-letter avatar initials from an email-ish identity (falls back to a neutral glyph).
pub fn initials(email: &str) -> String {
    let local = email.split('@').next().unwrap_or(email);
    let mut parts = local
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty());
    let a = parts.next().and_then(|s| s.chars().next());
    let b = parts.next().and_then(|s| s.chars().next());
    match (a, b) {
        (Some(a), Some(b)) => format!("{}{}", a.to_uppercase(), b.to_uppercase()),
        (Some(a), None) => a.to_uppercase().to_string(),
        _ => "·".to_string(),
    }
}

const ISSUE_OPEN_SVG: &str = r##"<svg viewBox="0 0 16 16" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M8 1.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13ZM0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8Zm8-2.25a2.25 2.25 0 1 1 0 4.5 2.25 2.25 0 0 1 0-4.5Z"/></svg>"##;
const ISSUE_CLOSED_SVG: &str = r##"<svg viewBox="0 0 16 16" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M8 1.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13ZM0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8Zm11.28-1.78a.75.75 0 0 1 0 1.06l-3.5 3.5a.75.75 0 0 1-1.06 0l-1.75-1.75a.75.75 0 0 1 1.06-1.06l1.22 1.22 2.97-2.97a.75.75 0 0 1 1.06 0Z"/></svg>"##;
const PULL_REQUEST_SVG: &str = r##"<svg viewBox="0 0 16 16" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M5 3.25a2.25 2.25 0 1 0-3 2.122v5.256a2.251 2.251 0 1 0 1.5 0V5.372A2.25 2.25 0 0 0 5 3.25Zm7.5 7.378V5.372a2.25 2.25 0 1 0-1.5 0v5.256a2.251 2.251 0 1 0 1.5 0ZM3.75 3.25a.75.75 0 1 1-1.5 0 .75.75 0 0 1 1.5 0Zm0 9.5a.75.75 0 1 1-1.5 0 .75.75 0 0 1 1.5 0Zm8.25.75a.75.75 0 1 1 0-1.5.75.75 0 0 1 0 1.5Zm.75-10.25a.75.75 0 1 1-1.5 0 .75.75 0 0 1 1.5 0Z"/></svg>"##;
const MERGE_SVG: &str = r##"<svg viewBox="0 0 16 16" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M5 3.25a2.25 2.25 0 1 0-3 2.122v5.256a2.251 2.251 0 1 0 1.5 0V5.372A2.25 2.25 0 0 0 5 3.25Zm-1.25 0a.75.75 0 1 1-1.5 0 .75.75 0 0 1 1.5 0Zm0 9.5a.75.75 0 1 1-1.5 0 .75.75 0 0 1 1.5 0ZM13.5 5.372A2.25 2.25 0 1 0 12 5.372V6c0 1.657-1.343 3-3 3H7.75V7.75L5.5 10l2.25 2.25V10.5H9A4.5 4.5 0 0 0 13.5 6v-.628Zm-.75-2.122a.75.75 0 1 1-1.5 0 .75.75 0 0 1 1.5 0Z"/></svg>"##;

/// Inline state icon SVG for issue and pull-request list rows.
pub fn state_icon(kind: &str) -> &'static str {
    match kind {
        "issue-open" => ISSUE_OPEN_SVG,
        "issue-closed" => ISSUE_CLOSED_SVG,
        "merged" => MERGE_SVG,
        _ => PULL_REQUEST_SVG,
    }
}

/// The Odyssey v2 avatar menu (CSS focus-within dropdown): an avatar + name button, and a popover
/// listing Account, All apps, and the cross-subdomain sign-out link (a GET link, method preserved).
fn user_menu(email: Option<&str>) -> String {
    let (glyph, name_html, head_html) = match email {
        Some(e) if !e.is_empty() => {
            let local = e.split('@').next().unwrap_or(e);
            (
                esc(&initials(e)),
                format!("<span class=\"usermenu__name\">{}</span>", esc(e)),
                format!("<b>{}</b><span>{}</span>", esc(local), esc(e)),
            )
        }
        _ => (
            "·".to_string(),
            String::new(),
            "<b>Signed in</b><span>Steadholme estate</span>".to_string(),
        ),
    };
    format!(
        r##"<div class="usermenu">
  <button class="usermenu__btn" type="button" aria-haspopup="menu">
    <span class="avatar" aria-hidden="true">{glyph}</span>{name}
    <svg class="usermenu__caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>
  </button>
  <div class="usermenu__pop" role="menu">
    <div class="usermenu__head"><span class="avatar avatar--lg" aria-hidden="true">{glyph}</span><div>{head}</div></div>
    <a class="menuitem" role="menuitem" href="https://account.w33d.xyz"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>Account</a>
    <a class="menuitem" role="menuitem" href="https://w33d.xyz"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>All apps</a>
    <a class="menuitem menuitem--danger" role="menuitem" href="{LOGOUT_URL}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>Sign out</a>
  </div>
</div>"##,
        glyph = glyph,
        name = name_html,
        head = head_html,
        LOGOUT_URL = LOGOUT_URL,
    )
}

/// The Odyssey v2 app-bar: a brand lockup (Loom's git-branch tile + wordmark), the service nav
/// (Repositories / Tokens, current marked `.is-active`), an "All apps" waffle to the apex portal,
/// and the avatar menu. Shared by every page so the chrome stays identical across the estate.
pub fn userbox(title: &str, email: Option<&str>, theme: &str) -> String {
    if email.map_or(true, |e| e.is_empty()) {
        return format!(
            r##"<a class="appbar__brand" href="/" aria-label="Steadholme Loom">
  <span class="app-tile" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="6" y1="3" x2="6" y2="15"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 9a9 9 0 0 1-9 9"/></svg></span>
  <span class="appbar__name"><b>Loom</b></span>
</a>
<form class="appbar__search" method="get" action="/" role="search">
  <svg class="appbar__search-ico" viewBox="0 0 16 16" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M10.68 11.74a6 6 0 0 1-7.922-8.982 6 6 0 0 1 8.982 7.922l3.04 3.04a.749.749 0 0 1-.326 1.275.749.749 0 0 1-.734-.215ZM11.5 7a4.499 4.499 0 1 0-8.997 0A4.499 4.499 0 0 0 11.5 7Z"/></svg>
  <input class="appbar__search-q" type="search" name="q" placeholder="Find a repository&hellip;" aria-label="Find a repository">
</form>
<nav class="appbar__nav" aria-label="Loom sections">
  <a class="appnav is-active" href="/" data-wire-off>Repositories</a>
</nav>
<div class="appbar__spacer"></div>
<div class="appbar__right">
  <a class="iconbtn" href="https://w33d.xyz" title="All apps" aria-label="All apps"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg></a>
  {switcher}
  <a class="btn" href="/signin">Sign in</a>
</div>"##,
            switcher = theme_switcher(theme),
        );
    }

    let tokens_active = title == "Access tokens";
    let repos_cls = if tokens_active {
        "appnav"
    } else {
        "appnav is-active"
    };
    let tokens_cls = if tokens_active {
        "appnav is-active"
    } else {
        "appnav"
    };
    format!(
        r##"<a class="appbar__brand" href="/" aria-label="Steadholme Loom">
  <span class="app-tile" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="6" y1="3" x2="6" y2="15"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 9a9 9 0 0 1-9 9"/></svg></span>
  <span class="appbar__name"><b>Loom</b></span>
</a>
<form class="appbar__search" method="get" action="/" role="search">
  <svg class="appbar__search-ico" viewBox="0 0 16 16" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M10.68 11.74a6 6 0 0 1-7.922-8.982 6 6 0 0 1 8.982 7.922l3.04 3.04a.749.749 0 0 1-.326 1.275.749.749 0 0 1-.734-.215ZM11.5 7a4.499 4.499 0 1 0-8.997 0A4.499 4.499 0 0 0 11.5 7Z"/></svg>
  <input class="appbar__search-q" type="search" name="q" placeholder="Find a repository&hellip;" aria-label="Find a repository">
</form>
<nav class="appbar__nav" aria-label="Loom sections">
  <a class="{repos_cls}" href="/" data-wire-off>Repositories</a>
  <a class="{tokens_cls}" href="/pats" data-wire-off>Tokens</a>
</nav>
<div class="appbar__spacer"></div>
<div class="appbar__right">
  <details class="create-menu">
    <summary class="iconbtn" aria-label="Create new" title="Create new&hellip;"><svg viewBox="0 0 16 16" width="16" height="16" fill="currentColor"><path d="M7.75 2a.75.75 0 0 1 .75.75V7h4.25a.75.75 0 0 1 0 1.5H8.5v4.25a.75.75 0 0 1-1.5 0V8.5H2.75a.75.75 0 0 1 0-1.5H7V2.75A.75.75 0 0 1 7.75 2Z"/></svg><svg class="create-menu__caret" viewBox="0 0 16 16" width="12" height="12" fill="currentColor"><path d="m4.427 7.427 3.396 3.396a.25.25 0 0 0 .354 0l3.396-3.396A.25.25 0 0 0 11.396 7H4.604a.25.25 0 0 0-.177.427Z"/></svg></summary>
    <div class="create-menu__pop">
      <a class="menuitem" href="/new" data-wire-off>New repository</a>
      <a class="menuitem" href="/pats" data-wire-off>New access token</a>
    </div>
  </details>
  <a class="iconbtn" href="https://w33d.xyz" title="All apps" aria-label="All apps"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg></a>
  {switcher}
  {user}
</div>"##,
        repos_cls = repos_cls,
        tokens_cls = tokens_cls,
        switcher = theme_switcher(theme),
        user = user_menu(email),
    )
}

fn theme_switcher(current: &str) -> String {
    let light_active = if current == "light" { " is-active" } else { "" };
    let dark_active = if current == "dark" { " is-active" } else { "" };
    let auto_active = if current == "auto" { " is-active" } else { "" };
    let light_cur = if current == "light" {
        r#" aria-current="true""#
    } else {
        ""
    };
    let dark_cur = if current == "dark" {
        r#" aria-current="true""#
    } else {
        ""
    };
    let auto_cur = if current == "auto" {
        r#" aria-current="true""#
    } else {
        ""
    };
    format!(
        r##"<div class="themeswitch" role="group" aria-label="Theme">
  <a class="themeswitch__opt{light_active}" href="/_gw/theme?to=light" title="Light" aria-label="Light"{light_cur}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg></a>
  <a class="themeswitch__opt{dark_active}" href="/_gw/theme?to=dark" title="Dark" aria-label="Dark"{dark_cur}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3a6.5 6.5 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg></a>
  <a class="themeswitch__opt{auto_active}" href="/_gw/theme?to=auto" title="System" aria-label="System"{auto_cur}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg></a>
</div>"##
    )
}

/// Render the branded error page (used by [`crate::error::AppError`]).
pub fn render_error(
    status: StatusCode,
    heading: &str,
    message: &str,
    email: Option<&str>,
) -> (StatusCode, Html<String>) {
    let body = ERROR_HTML
        .replace("{{CSS}}", app_css())
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Loom", email, "light"))
        .replace("{{STATUS}}", &status.as_u16().to_string())
        .replace("{{HEADING}}", &esc(heading))
        .replace("{{MESSAGE}}", &esc(message));
    (status, Html(body))
}

/// Minimal HTML escaping for text/attribute interpolation.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// Link issue references like `#12` in already-rendered, already-sanitised HTML. Replacement only
/// happens outside tags, so generated attributes are never rewritten.
pub fn link_issue_refs(html: &str, repo_owner: &str, repo_name: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut text = String::new();
    let mut in_tag = false;
    for ch in html.chars() {
        if ch == '<' {
            if !text.is_empty() {
                out.push_str(&link_issue_refs_text(&text, repo_owner, repo_name));
                text.clear();
            }
            in_tag = true;
            out.push(ch);
        } else if ch == '>' {
            in_tag = false;
            out.push(ch);
        } else if in_tag {
            out.push(ch);
        } else {
            text.push(ch);
        }
    }
    if !text.is_empty() {
        out.push_str(&link_issue_refs_text(&text, repo_owner, repo_name));
    }
    out
}

fn link_issue_refs_text(text: &str, repo_owner: &str, repo_name: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.char_indices().peekable();
    let mut last = 0;
    while let Some((idx, ch)) = chars.next() {
        if ch != '#' {
            continue;
        }
        let prev_ok = idx == 0
            || text[..idx]
                .chars()
                .next_back()
                .is_some_and(|c| !c.is_ascii_alphanumeric() && c != '_');
        if !prev_ok {
            continue;
        }
        let start_digits = idx + ch.len_utf8();
        let mut end = start_digits;
        while let Some((next_idx, next_ch)) = chars.peek().copied() {
            if next_ch.is_ascii_digit() {
                end = next_idx + next_ch.len_utf8();
                chars.next();
            } else {
                break;
            }
        }
        if end == start_digits {
            continue;
        }
        out.push_str(&text[last..idx]);
        let n = &text[start_digits..end];
        out.push_str(&format!(
            "<a href=\"/r/{}/{}/issues/{}\">#{}</a>",
            esc(repo_owner),
            esc(repo_name),
            n,
            n
        ));
        last = end;
    }
    out.push_str(&text[last..]);
    out
}

/// Form helper for checkbox groups. `serde_urlencoded` may present one checked box as a scalar
/// and several checked boxes as a sequence; accept both shapes.
pub fn form_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct FormVecVisitor;

    impl<'de> Visitor<'de> for FormVecVisitor {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a string or list of strings")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(vec![value.to_string()])
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(vec![value])
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut out = Vec::new();
            while let Some(value) = seq.next_element::<String>()? {
                out.push(value);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_any(FormVecVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html_metacharacters() {
        assert_eq!(esc("<script>&\"'"), "&lt;script&gt;&amp;&quot;&#x27;");
    }

    #[test]
    fn issue_refs_link_outside_tags_only() {
        let html = "<p>fixes #12</p><a href=\"#x\">#notnum</a>";
        let linked = link_issue_refs(html, "alice", "proj");
        assert!(linked.contains("/r/alice/proj/issues/12"));
        assert!(linked.contains("href=\"#x\""));
    }

    #[test]
    fn short_oid_truncates() {
        assert_eq!(short_oid("deadbeefcafebabe"), "deadbeef");
        assert_eq!(short_oid("abc"), "abc");
    }

    #[test]
    fn day_heading_formats_utc_date() {
        assert_eq!(fmt_day(1_720_022_400), "Jul 3, 2024");
    }

    #[test]
    fn relative_age_buckets() {
        let now = 1_700_000_000;
        assert_eq!(fmt_rel(now, now - 5), "just now");
        assert_eq!(fmt_rel(now, now - 60), "1 minute ago");
        assert_eq!(fmt_rel(now, now - 5 * 3600), "5 hours ago");
        assert_eq!(fmt_rel(now, now - 3 * 86_400), "3 days ago");
        assert_eq!(fmt_rel(now, now - 70 * 86_400), "2 months ago");
        assert_eq!(fmt_rel(now, now - 800 * 86_400), "2 years ago");
        // Future / zero timestamps fall back to the absolute form.
        assert_eq!(fmt_rel(now, now + 10), fmt_ts(now + 10));
        assert_eq!(fmt_rel(now, 0), fmt_ts(0));
    }

    #[test]
    fn signin_return_is_same_origin_relative() {
        assert_eq!(safe_signin_return(Some("/r/w33d/x")), "/r/w33d/x");
        assert_eq!(safe_signin_return(Some("/")), "/");
        assert_eq!(safe_signin_return(Some("https://evil")), "/");
        assert_eq!(safe_signin_return(Some("//evil")), "/");
        assert_eq!(safe_signin_return(None), "/");
    }
}
