//! HTTP handlers + shared server-render helpers.
//!
//! - [`health`] — unauthenticated liveness probe (`/healthz`).
//! - [`repos`] — the SSO web surface: repo list/create, browse (tree/blob), commit history.
//! - [`issues`] — the per-repo issue tracker (list/create/toggle).
//! - [`pats`] — personal-access-token management (mint once / revoke).
//! - [`smart_http`] — the git smart-HTTP protocol (`/git/...`) with PAT Basic auth.
//!
//! The shared design tokens / CSS are embedded (via `include_str!`) and inlined into every page,
//! matching the HOLDFAST enterprise brand. All producer-supplied text (repo names, descriptions,
//! file contents, commit subjects) is HTML-escaped on render. Markdown surfaces (README files,
//! `.md` blobs, issue bodies) are rendered through the sanitising [`crate::markdown`] pipeline
//! (raw HTML downgraded to text, unsafe link schemes defused) — Loom serves no executable file
//! content from the browser-facing surface.

pub mod health;
pub mod issues;
pub mod pats;
pub mod pulls;
pub mod repos;
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

/// The right side of the app-bar: a page title, the service nav (repos / tokens), an "All apps"
/// pill back to the apex portal, a user chip (avatar initial + signed-in email when known), and
/// the cross-subdomain logout link. Shared by every page so the chrome stays identical.
pub fn userbox(title: &str, email: Option<&str>) -> String {
    // A user chip (avatar initial + email) is shown only when a gateway identity is known.
    let chip = match email {
        Some(e) if !e.is_empty() => {
            let initial = e
                .chars()
                .next()
                .map(|c| c.to_uppercase().to_string())
                .unwrap_or_else(|| "H".to_string());
            format!(
                "<span class=\"userchip\"><span class=\"userchip__avatar\" aria-hidden=\"true\">{}</span><span class=\"user-email\">{}</span></span>",
                esc(&initial),
                esc(e),
            )
        }
        _ => String::new(),
    };
    format!(
        concat!(
            "<span class=\"topbar__title\">{title}</span>",
            "<a class=\"btn btn-ghost btn-sm\" href=\"/\">Repositories</a>",
            "<a class=\"btn btn-ghost btn-sm\" href=\"/pats\">Tokens</a>",
            "<a class=\"allapps\" href=\"https://w33d.xyz\" title=\"All apps\">",
            "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\">",
            "<rect x=\"3\" y=\"3\" width=\"7\" height=\"7\" rx=\"1.5\"/><rect x=\"14\" y=\"3\" width=\"7\" height=\"7\" rx=\"1.5\"/>",
            "<rect x=\"3\" y=\"14\" width=\"7\" height=\"7\" rx=\"1.5\"/><rect x=\"14\" y=\"14\" width=\"7\" height=\"7\" rx=\"1.5\"/></svg>All apps</a>",
            "{chip}",
            "<a class=\"btn btn-ghost btn-sm\" href=\"{LOGOUT_URL}\">Log out</a>",
        ),
        title = esc(title),
        chip = chip,
        LOGOUT_URL = LOGOUT_URL,
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
}
