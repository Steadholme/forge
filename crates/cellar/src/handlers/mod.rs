//! HTTP handlers + shared server-render helpers.
//!
//! - [`health`] — unauthenticated liveness probe (`/healthz`).
//! - [`registry`] — the `/v2/` OCI Distribution API (Basic-auth; the CLI protocol surface).
//! - [`web`] — the SSO web console (repository list + detail; the browser surface).
//!
//! The shared design tokens / CSS are embedded (via `include_str!`) and inlined into every page,
//! matching the Steadholme enterprise brand (brand gradient, indigo accent, cards, app-bar with the
//! shield + the signed-in email + the gateway logout). All producer-supplied text (repo names,
//! tags, media types, digests) is HTML-escaped on render.

pub mod admin;
pub mod health;
pub mod registry;
pub mod retention;
pub mod robots;
pub mod web;

use axum::http::StatusCode;
use axum::response::Html;

/// Cellar-only CSS layered after Odyssey's canonical font, tokens, and components.
pub const SERVICE_CSS: &str = include_str!("../../static/service.css");

static APP_CSS: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Embedded design system (Odyssey canonical + Cellar service CSS), inlined into each page's `<style>`.
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
pub const SHIELD_SVG: &str = r##"<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M24 4 8 9.5V22c0 11 7 17.4 16 21.5C33 39.4 40 33 40 22V9.5L24 4Z" fill="currentColor" fill-opacity=".18" stroke="currentColor" stroke-opacity=".72" stroke-width="2" stroke-linejoin="round"/><rect x="20" y="19" width="8" height="13" rx="1" fill="currentColor" fill-opacity=".62"/><path d="M20 19v-2.5a4 4 0 0 1 8 0V19" stroke="currentColor" stroke-width="2" stroke-opacity=".9" fill="none"/></svg>"##;

/// A stacked-layers glyph used on repository cards / the detail header.
pub const LAYERS_SVG: &str = r##"<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M24 6 6 15l18 9 18-9-18-9Z" fill="currentColor" fill-opacity=".14" stroke="currentColor" stroke-opacity=".46" stroke-width="2" stroke-linejoin="round"/><path d="M6 24l18 9 18-9" stroke="currentColor" stroke-opacity=".64" stroke-width="2" stroke-linejoin="round" fill="none"/><path d="M6 33l18 9 18-9" stroke="currentColor" stroke-opacity=".82" stroke-width="2" stroke-linejoin="round" fill="none"/></svg>"##;

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

/// Human-readable byte size (`1.0 KB`, `2.3 MB`, ...). Decimal-ish (1024) units.
pub fn human_size(bytes: i64) -> String {
    const KB: f64 = 1024.0;
    let b = bytes.max(0) as f64;
    if b < KB {
        return format!("{bytes} B");
    }
    let units = ["KB", "MB", "GB", "TB"];
    let mut size = b / KB;
    let mut unit = 0;
    while size >= KB && unit < units.len() - 1 {
        size /= KB;
        unit += 1;
    }
    format!("{size:.1} {}", units[unit])
}

/// Compact relative time from `then` to `now` (both epoch seconds): `just now`, `3 minutes ago`,
/// `2 days ago`, ... Used for the "last pulled X ago" / robot "last used" lines.
pub fn time_ago(then: i64, now: i64) -> String {
    let d = (now - then).max(0);
    if d < 60 {
        return "just now".to_string();
    }
    let (n, unit) = if d < 3_600 {
        (d / 60, "minute")
    } else if d < 86_400 {
        (d / 3_600, "hour")
    } else if d < 2_592_000 {
        (d / 86_400, "day")
    } else if d < 31_536_000 {
        (d / 2_592_000, "month")
    } else {
        (d / 31_536_000, "year")
    };
    format!("{n} {unit}{} ago", if n == 1 { "" } else { "s" })
}

/// The Odyssey v2 tab-strip shared by the `/admin` subtree. `active` is `"overview"`, `"retention"`
/// or `"robots"`; the matching tab gets `is-active`.
pub fn admin_tabs(active: &str) -> String {
    let tab = |href: &str, key: &str, label: &str| {
        let cls = if key == active {
            "tab is-active"
        } else {
            "tab"
        };
        format!("<a class=\"{cls}\" href=\"{href}\">{label}</a>")
    };
    format!(
        "<nav class=\"tabs\" aria-label=\"Admin sections\">{}{}{}</nav>",
        tab("/admin", "overview", "Storage &amp; GC"),
        tab("/admin/retention", "retention", "Retention"),
        tab("/admin/robots", "robots", "Robot accounts"),
    )
}

/// A short `sha256:abcd…wxyz` digest for compact display (full value kept in `title`).
pub fn short_digest(digest: &str) -> String {
    match digest.split_once(':') {
        Some((algo, hex)) if hex.len() > 16 => {
            format!("{algo}:{}…{}", &hex[..8], &hex[hex.len() - 6..])
        }
        _ => digest.to_string(),
    }
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

/// The Odyssey v2 app-bar: a brand lockup (Cellar's package tile + wordmark), the Repositories nav,
/// an "All apps" waffle to the apex portal, and the avatar menu. Shared by every page so the chrome
/// stays identical across the estate. (`_title` is retained for a uniform signature.)
pub fn userbox(_title: &str, email: Option<&str>, theme: &str) -> String {
    format!(
        r##"<a class="appbar__brand" href="/" aria-label="Steadholme Registry">
  <span class="app-tile" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16.5 9.4 7.5 4.21"/><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><path d="M3.27 6.96 12 12.01l8.73-5.05"/><path d="M12 22.08V12"/></svg></span>
  <span class="appbar__name"><b>Cellar</b><span>registry.w33d.xyz</span></span>
</a>
<nav class="appbar__nav" aria-label="Cellar sections">
  <a class="appnav is-active" href="/" data-wire-off><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12.83 2.18 8 4A2 2 0 0 1 22 8v8a2 2 0 0 1-1.17 1.82l-8 4a2 2 0 0 1-1.66 0l-8-4A2 2 0 0 1 2 16V8a2 2 0 0 1 1.17-1.82l8-4a2 2 0 0 1 1.66 0Z"/><path d="m7 5 10 5"/></svg>Repositories</a>
</nav>
<div class="appbar__spacer"></div>
<div class="appbar__right">
  <a class="iconbtn" href="https://w33d.xyz" title="All apps" aria-label="All apps"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg></a>
  {switcher}
  {user}
</div>"##,
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
  <a class="themeswitch__opt{light_active}" href="/_gw/theme?to=light" data-wire-off title="Light" aria-label="Light"{light_cur}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg></a>
  <a class="themeswitch__opt{dark_active}" href="/_gw/theme?to=dark" data-wire-off title="Dark" aria-label="Dark"{dark_cur}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3a6.5 6.5 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg></a>
  <a class="themeswitch__opt{auto_active}" href="/_gw/theme?to=auto" data-wire-off title="System" aria-label="System"{auto_cur}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg></a>
</div>"##
    )
}

/// Render the branded error page (used by [`crate::error::WebError`]).
pub fn render_error(
    status: StatusCode,
    heading: &str,
    message: &str,
    email: Option<&str>,
) -> (StatusCode, Html<String>) {
    let body = ERROR_HTML
        .replace("{{CSS}}", app_css())
        .replace("{{THEME}}", odyssey::html_theme_attr("light"))
        .replace("{{COLOR_SCHEME}}", odyssey::color_scheme_meta("light"))
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Registry", email, "light"))
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
    fn human_size_scales_units() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1024), "1.0 KB");
        assert_eq!(human_size(5 * 1024 * 1024), "5.0 MB");
    }

    #[test]
    fn time_ago_scales() {
        assert_eq!(time_ago(100, 100), "just now");
        assert_eq!(time_ago(100, 130), "just now"); // < 60s
        assert_eq!(time_ago(0, 60), "1 minute ago");
        assert_eq!(time_ago(0, 7200), "2 hours ago");
        assert_eq!(time_ago(0, 86_400), "1 day ago");
        assert_eq!(time_ago(0, 3 * 86_400), "3 days ago");
        // A future timestamp clamps to "just now" (never negative).
        assert_eq!(time_ago(200, 100), "just now");
    }

    #[test]
    fn admin_tabs_marks_active() {
        let html = admin_tabs("retention");
        assert!(html.contains("href=\"/admin/retention\""));
        assert!(html.contains("tab is-active"));
        // Only one tab is active.
        assert_eq!(html.matches("is-active").count(), 1);
    }

    #[test]
    fn short_digest_truncates() {
        let d = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(short_digest(d), "sha256:ba7816bf…0015ad");
        assert_eq!(short_digest("latest"), "latest");
    }
}
