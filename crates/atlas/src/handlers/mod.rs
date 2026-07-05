//! HTTP handlers + shared server-render helpers.
//!
//! `health` is the unauthenticated liveness probe; `catalog` carries the catalog, the per-service
//! detail + annotation editor, the topology graph, and the JSON inventory.
//!
//! The shared design tokens / CSS are embedded (via `include_str!`) and inlined into every page,
//! matching the estate's Odyssey design language (light neutral canvas, white hairline-bordered
//! cards, indigo accent): shield lockup, status pills, flat soft-color chips.

pub mod catalog;
pub mod health;

use axum::http::StatusCode;

use crate::inventory::auth_color;

/// Atlas-only CSS layered after Odyssey's canonical font, tokens, and components.
pub const SERVICE_CSS: &str = include_str!("../../static/service.css");

static APP_CSS: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Embedded design system (Odyssey canonical + Atlas service CSS), inlined into each page's `<style>`.
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

/// Cross-subdomain gateway logout (Atlas lives at atlas.w33d.xyz; the IdP is at id.w33d.xyz).
pub const LOGOUT_URL: &str = "https://sso.w33d.xyz/_gw/auth/logout";

/// The HOLDFAST shield glyph (small, for the app-bar brand lockup).
pub const SHIELD_SVG: &str = r##"<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="hf-shield-sm" x1="8" y1="4" x2="40" y2="44" gradientUnits="userSpaceOnUse"><stop stop-color="#818CF8"/><stop offset="1" stop-color="#4F46E5"/></linearGradient></defs><path d="M24 4 8 9.5V22c0 11 7 17.4 16 21.5C33 39.4 40 33 40 22V9.5L24 4Z" fill="url(#hf-shield-sm)"/><rect x="20" y="19" width="8" height="13" rx="1" fill="#fff" fill-opacity="0.92"/><path d="M20 19v-2.5a4 4 0 0 1 8 0V19" stroke="#fff" stroke-width="2" stroke-opacity="0.92" fill="none"/></svg>"##;

/// Minimal HTML escaping for text/attribute interpolation (defense-in-depth on every field).
pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
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
/// A placeholder (`—`) or empty email renders a minimal avatar glyph so the shell never breaks.
fn user_menu(email: &str) -> String {
    let known = !(email.is_empty() || email == "—");
    let (glyph, name_html, head_html) = if known {
        let local = email.split('@').next().unwrap_or(email);
        (
            esc(&initials(email)),
            format!("<span class=\"usermenu__name\">{}</span>", esc(email)),
            format!("<b>{}</b><span>{}</span>", esc(local), esc(email)),
        )
    } else {
        (
            "·".to_string(),
            String::new(),
            "<b>Signed in</b><span>HOLDFAST estate</span>".to_string(),
        )
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
    <a class="menuitem menuitem--danger" role="menuitem" href="{logout}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>Sign out</a>
  </div>
</div>"##,
        glyph = glyph,
        name = name_html,
        head = head_html,
        logout = LOGOUT_URL,
    )
}

/// Render the shared Odyssey v2 app-bar: a brand lockup (Atlas's network tile + wordmark), the
/// estate nav (Catalog / Topology, current marked `.is-active`), an "All apps" waffle to the apex
/// portal, and the avatar menu. `page_title` selects the active nav item.
pub fn topbar(page_title: &str, email: &str) -> String {
    let topology_active = page_title == "Topology";
    let catalog_cls = if topology_active { "appnav" } else { "appnav is-active" };
    let topology_cls = if topology_active { "appnav is-active" } else { "appnav" };
    format!(
        r##"<header class="appbar">
  <a class="appbar__brand" href="/" aria-label="HOLDFAST Atlas">
    <span class="app-tile" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg></span>
    <span class="appbar__name"><b>Atlas</b><span>atlas.w33d.xyz</span></span>
  </a>
  <nav class="appbar__nav" aria-label="Atlas sections">
    <a class="{catalog_cls}" href="/"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>Catalog</a>
    <a class="{topology_cls}" href="/graph"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>Topology</a>
  </nav>
  <div class="appbar__spacer"></div>
  <div class="appbar__right">
    <a class="iconbtn" href="https://w33d.xyz" title="All apps" aria-label="All apps"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg></a>
    {user}
  </div>
</header>"##,
        catalog_cls = catalog_cls,
        topology_cls = topology_cls,
        user = user_menu(email),
    )
}

/// Format epoch seconds as a compact UTC date `Mon D, YYYY` (e.g. `Jun 30, 2026`). std `time` only.
/// `0` (never annotated) renders an em dash.
pub fn fmt_date(secs: i64) -> String {
    if secs <= 0 {
        return "—".to_string();
    }
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!("{} {}, {}", month_abbr(dt.month()), dt.day(), dt.year()),
        Err(_) => secs.to_string(),
    }
}

fn month_abbr(m: time::Month) -> &'static str {
    use time::Month::*;
    match m {
        January => "Jan",
        February => "Feb",
        March => "Mar",
        April => "Apr",
        May => "May",
        June => "Jun",
        July => "Jul",
        August => "Aug",
        September => "Sep",
        October => "Oct",
        November => "Nov",
        December => "Dec",
    }
}

/// A live-status pill (one of `operational` | `degraded` | `down` | `unknown` | `unavailable`).
pub fn status_pill(status: &str) -> String {
    let (cls, label) = match status {
        "operational" => ("pill--ok", "Operational"),
        "degraded" => ("pill--warn", "Degraded"),
        "down" => ("pill--down", "Down"),
        "unavailable" => ("pill--muted", "Unavailable"),
        _ => ("pill--muted", "Unknown"),
    };
    format!(r#"<span class="pill {cls}">{label}</span>"#)
}

/// An auth-mode badge (`sso` | `public` | `bearer` | other), colored by the design token.
pub fn auth_badge(auth: &str) -> String {
    let color = auth_color(auth);
    let label = match auth {
        "sso" => "SSO",
        "public" => "Public",
        "bearer" => "Bearer",
        other if other.is_empty() => "—",
        other => other,
    };
    format!(
        r#"<span class="abadge" style="--abadge:{color}">{label}</span>"#,
        label = esc(label)
    )
}

/// A small, branded HTML error page (used by [`crate::error::AppError`]).
pub fn error_page(status: StatusCode, message: &str) -> String {
    let code = status.as_u16();
    let reason = status.canonical_reason().unwrap_or("Error");
    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>{code} {reason} · Atlas</title><style>{css}</style></head>
<body class="page-reading">
{topbar}
<main class="reader">
  <div class="error-card">
    <div class="error-card__code">{code}</div>
    <h1 class="error-card__title">{reason}</h1>
    <p class="error-card__msg">{msg}</p>
    <a class="btn btn-primary" href="/">Back to the catalog</a>
  </div>
</main>
<footer class="site-foot">
  <span>HOLDFAST · Atlas</span>
  <span>Estate ops atlas · part of the HOLDFAST estate</span>
</footer>
</body></html>"#,
        css = app_css(),
        topbar = topbar("Atlas", "—"),
        code = code,
        reason = esc(reason),
        msg = esc(message),
    )
}
