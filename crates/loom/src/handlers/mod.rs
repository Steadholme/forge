//! HTTP handlers + shared server-render helpers.
//!
//! - [`health`] — unauthenticated liveness probe (`/healthz`).
//! - [`repos`] — the SSO web surface: repo list/create, browse (tree/blob), the repo home.
//! - [`commits`] — commit history (keyset-paginated) + the single-commit page (metadata + diff).
//! - [`branches`] — the branches + tags listing.
//! - [`issues`] — the per-repo issue tracker (list/filter, detail + comments, create/comment/toggle).
//! - [`pulls`] — pull requests (compare, create, detail, gated merge).
//! - [`settings`] — repo settings (description + default branch; owner/admin only).
//! - [`pats`] — personal-access-token management (mint once / revoke).
//! - [`smart_http`] — the git smart-HTTP protocol (`/git/...`) with PAT Basic auth.
//!
//! The shared design tokens / CSS are embedded (via `include_str!`) and inlined into every page,
//! matching the HOLDFAST enterprise brand. All producer-supplied text (repo names, descriptions,
//! file contents, commit subjects) is HTML-escaped on render. Markdown surfaces (README files,
//! `.md` blobs, issue bodies) are rendered through the sanitising [`crate::markdown`] pipeline
//! (raw HTML downgraded to text, unsafe link schemes defused) — Loom serves no executable file
//! content from the browser-facing surface.

pub mod branches;
pub mod commits;
pub mod health;
pub mod issues;
pub mod pats;
pub mod pulls;
pub mod repos;
pub mod settings;
pub mod smart_http;

use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};

/// Embedded design system, inlined into each rendered page's `<style>`.
pub const APP_CSS: &str = include_str!("../../static/app.css");

/// The HOLDFAST shield glyph (small, for the app-bar brand lockup).
pub const SHIELD_SVG: &str = r##"<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="hf-shield-sm" x1="8" y1="4" x2="40" y2="44" gradientUnits="userSpaceOnUse"><stop stop-color="#818CF8"/><stop offset="1" stop-color="#4F46E5"/></linearGradient></defs><path d="M24 4 8 9.5V22c0 11 7 17.4 16 21.5C33 39.4 40 33 40 22V9.5L24 4Z" fill="url(#hf-shield-sm)"/><rect x="20" y="19" width="8" height="13" rx="1" fill="#fff" fill-opacity="0.92"/><path d="M20 19v-2.5a4 4 0 0 1 8 0V19" stroke="#fff" stroke-width="2" stroke-opacity="0.92" fill="none"/></svg>"##;

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
pub fn page(title: &str, email: Option<&str>, body: &str) -> String {
    PAGE_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{TITLE}}", &esc(title))
        .replace("{{USERBOX}}", &userbox(title, email))
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
    (StatusCode::FOUND, [(header::LOCATION, location.to_string())]).into_response()
}

/// Two-letter avatar initials from the signed-in email (falls back to a neutral glyph).
fn initials(email: &str) -> String {
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
            "<b>Signed in</b><span>HOLDFAST estate</span>".to_string(),
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
pub fn userbox(title: &str, email: Option<&str>) -> String {
    let tokens_active = title == "Access tokens";
    let repos_cls = if tokens_active { "appnav" } else { "appnav is-active" };
    let tokens_cls = if tokens_active { "appnav is-active" } else { "appnav" };
    format!(
        r##"<a class="appbar__brand" href="/" aria-label="HOLDFAST Loom">
  <span class="app-tile" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="6" y1="3" x2="6" y2="15"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 9a9 9 0 0 1-9 9"/></svg></span>
  <span class="appbar__name"><b>Loom</b><span>git.w33d.xyz</span></span>
</a>
<nav class="appbar__nav" aria-label="Loom sections">
  <a class="{repos_cls}" href="/"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>Repositories</a>
  <a class="{tokens_cls}" href="/pats"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg>Tokens</a>
</nav>
<div class="appbar__spacer"></div>
<div class="appbar__right">
  <a class="iconbtn" href="https://w33d.xyz" title="All apps" aria-label="All apps"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg></a>
  {user}
</div>"##,
        repos_cls = repos_cls,
        tokens_cls = tokens_cls,
        user = user_menu(email),
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
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Loom", email))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html_metacharacters() {
        assert_eq!(esc("<script>&\"'"), "&lt;script&gt;&amp;&quot;&#x27;");
    }

    #[test]
    fn short_oid_truncates() {
        assert_eq!(short_oid("deadbeefcafebabe"), "deadbeef");
        assert_eq!(short_oid("abc"), "abc");
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
}
