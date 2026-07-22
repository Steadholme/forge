//! The catalog, per-service detail + annotation editor, topology graph, and JSON inventory.
//!
//! Every endpoint here (except the health probe) requires a gateway-injected SSO identity — the
//! catalog is sensitive infrastructure inventory, so an unauthenticated request 401s as defense in
//! depth behind the gateway. The annotate POST is additionally double-submit CSRF protected and
//! emits a non-blocking `atlas.annotate` audit event.
//!
//! RESILIENCE: the route table and Beacon are fetched independently; a failure of either degrades
//! (a banner / "unavailable" pills) but NEVER errors the page.

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::{Form, Json};
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::beacon;
use crate::error::AppError;
use crate::handlers::{
    app_css, auth_cat, auth_word, esc, fmt_date, status_label, status_pill, status_slug, topbar,
};
use crate::inventory::{self, auth_slug, Inventory, ServiceEntry};
use crate::store::Service;
use crate::{now_secs, AppState};

const CATALOG_HTML: &str = include_str!("../../templates/catalog.html");
const DETAIL_HTML: &str = include_str!("../../templates/detail.html");
const GRAPH_HTML: &str = include_str!("../../templates/graph.html");

/// Hard caps on operator metadata (defense against unbounded form input).
const MAX_KEY: usize = 128;
const MAX_FIELD: usize = 256;
const MAX_NOTES: usize = 4096;

/// The annotate form body. Identity is NEVER taken from the form — only from the gateway headers.
#[derive(Debug, Deserialize)]
pub struct AnnotateForm {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub tier: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// Fetch the three inputs (routes read-only, Beacon status, operator annotations) and assemble the
/// inventory. A route-table read failure degrades to an empty, `routes_available == false`
/// inventory; a Beacon failure degrades every status to "unavailable".
async fn load_inventory(state: &AppState) -> Inventory {
    let (routes, routes_ok) = match state.routes.list_routes().await {
        Ok(rs) => (rs, true),
        Err(e) => {
            tracing::warn!(error = %e, "route table unavailable — degrading catalog");
            (Vec::new(), false)
        }
    };
    let statuses = beacon::fetch(&state.config.beacon_url).await;
    let annotations = state.store.list_services().await;
    inventory::build(routes, routes_ok, &annotations, &statuses)
}

// ---------------------------------------------------------------------------
// GET / — the catalog
// ---------------------------------------------------------------------------

/// `GET /` — every host grouped by upstream service, with auth mode, WAF flag, live status pill,
/// and any operator annotation, plus a headline summary.
pub async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_sub, email) = auth::require_viewer(&headers)?;
    let theme = odyssey::resolve_theme(headers.get(header::COOKIE).and_then(|v| v.to_str().ok()));
    let inv = load_inventory(&state).await;

    let banner = if inv.routes_available {
        String::new()
    } else {
        r#"<div class="banner banner--warn">The gateway route table is unavailable — the catalog is degraded. Live status and inventory will return once the route DB is reachable.</div>"#.to_string()
    };

    let summary = render_cartouche(&inv);

    let mut rows = String::new();
    if inv.services.is_empty() {
        rows.push_str(
            r#"<tr class="ledger__row ledger__row--empty"><td class="ledger__empty" colspan="9">No services discovered — the gateway route table is empty or unavailable.</td></tr>"#,
        );
    } else {
        for s in &inv.services {
            rows.push_str(&ledger_row(s));
        }
    }

    let page = CATALOG_HTML
        .replace("{{CSS}}", app_css())
        .replace("{{THEME}}", odyssey::html_theme_attr(theme))
        .replace("{{COLOR_SCHEME}}", odyssey::color_scheme_meta(theme))
        .replace("{{TOPBAR}}", &topbar("Catalog", &email, theme))
        .replace("{{BANNER}}", &banner)
        .replace("{{SUMMARY}}", &summary)
        .replace("{{SERVICES}}", &rows);
    Ok(Html(page).into_response())
}

// ---------------------------------------------------------------------------
// GET /service/{key} — detail + annotation editor
// ---------------------------------------------------------------------------

/// `GET /service/{key}` — one service's routes + the operator annotation edit form.
pub async fn detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<Response, AppError> {
    let (_sub, email) = auth::require_viewer(&headers)?;
    let theme = odyssey::resolve_theme(headers.get(header::COOKIE).and_then(|v| v.to_str().ok()));
    let inv = load_inventory(&state).await;

    // The discovered entry (from routes), if any.
    let discovered = inv.services.iter().find(|s| s.key == key).cloned();
    // The stored annotation, if any (so an annotation-only key still has a detail page).
    let annotation = state.store.get_service(&key).await;

    let entry = match (discovered, annotation) {
        (Some(e), _) => e,
        (None, Some(a)) => annotation_only_entry(a),
        (None, None) => return Err(AppError::NotFound(format!("no service '{key}'"))),
    };

    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let routes_html = if entry.routes.is_empty() {
        r#"<tr><td colspan="3" class="muted">No public routes front this service.</td></tr>"#
            .to_string()
    } else {
        entry
            .routes
            .iter()
            .map(|r| {
                format!(
                    r#"<tr>
  <td><a href="{url}" rel="noopener noreferrer">{url_txt}</a></td>
  <td>{auth}</td>
  <td>{waf}</td>
</tr>"#,
                    url = esc(&safe_link(&r.public_url)),
                    url_txt = esc(&r.public_url),
                    auth = auth_cat(&r.auth),
                    waf = if r.waf {
                        r#"<span class="wafflag">WAF</span>"#
                    } else {
                        r#"<span class="muted">—</span>"#
                    },
                )
            })
            .collect::<String>()
    };

    let page = DETAIL_HTML
        .replace("{{CSS}}", app_css())
        .replace("{{THEME}}", odyssey::html_theme_attr(theme))
        .replace("{{COLOR_SCHEME}}", odyssey::color_scheme_meta(theme))
        .replace("{{TOPBAR}}", &topbar("Service", &email, theme))
        .replace("{{KEY}}", &esc(&entry.key))
        .replace("{{DISPLAY_NAME}}", &esc(&entry.display_name))
        .replace("{{STATUS_PILL}}", &status_pill(&entry.status))
        .replace("{{UPDATED}}", &esc(&fmt_date(entry.updated_at)))
        .replace("{{ROUTES}}", &routes_html)
        .replace("{{CSRF}}", &esc(&csrf))
        .replace("{{F_DISPLAY}}", &esc(&entry.display_name))
        .replace("{{F_OWNER}}", &esc(&entry.owner))
        .replace("{{F_TIER}}", &esc(&entry.tier))
        .replace("{{F_NOTES}}", &esc(&entry.notes));

    Ok(html_with_cookie(page, set_cookie))
}

// ---------------------------------------------------------------------------
// POST /api/annotate — save operator metadata
// ---------------------------------------------------------------------------

/// `POST /api/annotate` — upsert operator metadata for a service key (CSRF-protected, audited).
pub async fn annotate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AnnotateForm>,
) -> Result<Response, AppError> {
    let (sub, email) = auth::require_viewer(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let key = form.key.trim();
    if key.is_empty() {
        return Err(AppError::InvalidRequest(
            "service key is required".to_string(),
        ));
    }
    if key.chars().count() > MAX_KEY {
        return Err(AppError::InvalidRequest(
            "service key is too long".to_string(),
        ));
    }

    let service = Service {
        key: key.to_string(),
        display_name: cap(form.display_name.trim(), MAX_FIELD),
        owner: cap(form.owner.trim(), MAX_FIELD),
        tier: cap(form.tier.trim(), MAX_FIELD),
        notes: cap(form.notes.trim(), MAX_NOTES),
        updated_at: now_secs(),
    };
    state.store.upsert_service(&service).await?;

    // Non-blocking audit: WHO annotated WHICH service. The actor is the gateway-verified identity.
    let actor = if email.is_empty() { sub } else { email };
    state.audit.emit(AuditEvent::notice(
        "atlas.annotate",
        &actor,
        key,
        "service metadata updated",
    ));
    tracing::info!(key = %key, "service annotation updated");

    Ok(redirect(&format!("/service/{}", urlpath(key))))
}

// ---------------------------------------------------------------------------
// GET /graph — inline-SVG topology
// ---------------------------------------------------------------------------

/// `GET /graph` — an inline-SVG topology: the gateway in the center with one edge to each upstream
/// service, classified by the service's primary auth mode.
pub async fn graph(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_sub, email) = auth::require_viewer(&headers)?;
    let theme = odyssey::resolve_theme(headers.get(header::COOKIE).and_then(|v| v.to_str().ok()));
    let inv = load_inventory(&state).await;

    let svg = render_graph_svg(&inv);
    let page = GRAPH_HTML
        .replace("{{CSS}}", app_css())
        .replace("{{THEME}}", odyssey::html_theme_attr(theme))
        .replace("{{COLOR_SCHEME}}", odyssey::color_scheme_meta(theme))
        .replace("{{TOPBAR}}", &topbar("Topology", &email, theme))
        .replace("{{COUNT}}", &inv.services_total.to_string())
        .replace("{{SVG}}", &svg);
    Ok(Html(page).into_response())
}

// ---------------------------------------------------------------------------
// GET /api/inventory — JSON
// ---------------------------------------------------------------------------

/// `GET /api/inventory` — the full assembled inventory as JSON (SSO-gated).
pub async fn api_inventory(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    auth::require_viewer(&headers)?;
    let inv = load_inventory(&state).await;
    Ok(Json(inv).into_response())
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

/// Compact survey provenance derived only from the assembled inventory.
fn render_cartouche(inv: &Inventory) -> String {
    let online = if inv.beacon_reached {
        format!("Beacon {} / {} online", inv.beacon_up, inv.beacon_total)
    } else {
        "Beacon status unavailable".to_string()
    };
    format!(
        r#"<p class="survey__cartouche">Survey of {services} services · {routes} routes — {sso} SSO · {public} public · {bearer} bearer · {online}</p>"#,
        services = inv.services_total,
        routes = inv.routes_total,
        sso = inv.sso_count,
        public = inv.public_count,
        bearer = inv.bearer_count,
        online = esc(&online),
    )
}

/// One semantic ledger row. The K3-owned template supplies the table, caption, and column heads.
pub fn ledger_row(s: &ServiceEntry) -> String {
    let exposure = if let Some(route) = s.routes.first() {
        format!(
            r#"<a class="ledger__url" href="{url}" rel="noopener noreferrer">{label}</a>"#,
            url = esc(&safe_link(&route.public_url)),
            label = esc(&route.public_url),
        )
    } else {
        "—".to_string()
    };
    let waf = if s.waf_any {
        r#"<span class="wafflag">WAF</span>"#
    } else {
        ""
    };
    let auth = if s.auth_modes.is_empty() {
        "—".to_string()
    } else {
        s.auth_modes.iter().map(|mode| auth_cat(mode)).collect()
    };
    let owner = if s.owner.trim().is_empty() {
        "—".to_string()
    } else {
        format!("Owner: {}", esc(&s.owner))
    };
    let tier = if s.tier.trim().is_empty() {
        "—".to_string()
    } else {
        format!("Tier: {}", esc(&s.tier))
    };
    let notes = if s.notes.trim().is_empty() {
        "—".to_string()
    } else {
        esc(&s.notes)
    };
    let waf_attr = if s.waf_any { r#" data-waf="true""# } else { "" };

    format!(
        r#"<tr class="ledger__row" data-status="{status_slug}" data-annotated="{annotated}"{waf_attr}>
  <td class="ledger__status">{status}</td>
  <td class="ledger__svc"><a class="ledger__svclink" href="/service/{key_url}">{name}</a><span class="ledger__key">{key}</span></td>
  <td class="ledger__exposure">{exposure}{waf}</td>
  <td class="ledger__auth">{auth}</td>
  <td class="ledger__routes">{routes}</td>
  <td class="ledger__owner">{owner}</td>
  <td class="ledger__tier">{tier}</td>
  <td class="ledger__notes">{notes}</td>
  <td class="ledger__act"><a class="ledger__actlink" href="/service/{key_url}">Annotate</a></td>
</tr>"#,
        key_url = esc(&urlpath(&s.key)),
        name = esc(&s.display_name),
        key = esc(&s.key),
        status = status_pill(&s.status),
        status_slug = status_slug(&s.status),
        annotated = s.annotated,
        waf_attr = waf_attr,
        exposure = exposure,
        waf = waf,
        auth = auth,
        routes = s.routes.len(),
        owner = owner,
        tier = tier,
        notes = notes,
    )
}

/// Build the topology SVG: the gateway hub center, one spoke + node per service around a circle,
/// with auth encoded by bounded semantic hooks and redundant node shapes.
fn render_graph_svg(inv: &Inventory) -> String {
    let w = 820.0_f64;
    let h = 560.0_f64;
    let cx = w / 2.0;
    let cy = h / 2.0;
    let n = inv.services.len().max(1);
    let radius = if n > 16 { 210.0 } else { 180.0 };

    let mut edges = String::new();
    let mut nodes = String::new();
    for (i, s) in inv.services.iter().enumerate() {
        let angle = (i as f64) / (n as f64) * std::f64::consts::TAU - std::f64::consts::FRAC_PI_2;
        let x = cx + radius * angle.cos();
        let y = cy + radius * angle.sin();
        let auth = auth_slug(&s.primary_auth);

        edges.push_str(&format!(
            r#"<line class="gedge" data-auth="{auth}" x1="{cx:.1}" y1="{cy:.1}" x2="{x:.1}" y2="{y:.1}"/>"#
        ));

        // Place the label just outside the node, anchored away from the hub.
        let on_left = x < cx;
        let lx = if on_left { x - 11.0 } else { x + 11.0 };
        let anchor = if on_left { "end" } else { "start" };
        let shape = match auth {
            "sso" => format!(r#"<circle class="gnode__mark" cx="{x:.1}" cy="{y:.1}" r="7"/>"#),
            "public" => format!(
                r#"<rect class="gnode__mark" x="{sx:.1}" y="{sy:.1}" width="14" height="14" rx="1"/>"#,
                sx = x - 7.0,
                sy = y - 7.0,
            ),
            "bearer" => format!(
                r#"<rect class="gnode__mark gnode__mark--diamond" x="{sx:.1}" y="{sy:.1}" width="14" height="14" transform="rotate(45 {x:.1} {y:.1})"/>"#,
                sx = x - 7.0,
                sy = y - 7.0,
            ),
            _ => format!(
                r#"<polygon class="gnode__mark" points="{x:.1},{top:.1} {right:.1},{bottom:.1} {left:.1},{bottom:.1}"/>"#,
                top = y - 8.0,
                right = x + 8.0,
                bottom = y + 7.0,
                left = x - 8.0,
            ),
        };
        let waf = if s.waf_any { " · WAF" } else { "" };
        let title = format!(
            "{} — {}{} · {}",
            s.display_name,
            auth_word(&s.primary_auth),
            waf,
            status_label(&s.status)
        );
        nodes.push_str(&format!(
            r#"<g class="gnode" data-auth="{auth}"><title>{title}</title>{shape}<text x="{lx:.1}" y="{ly:.1}" text-anchor="{anchor}" class="glabel">{label}</text></g>"#,
            ly = y + 4.0,
            title = esc(&title),
            label = esc(&s.display_name),
        ));
    }

    format!(
        r##"<svg class="topology" viewBox="0 0 {w:.0} {h:.0}" role="img" aria-labelledby="topo-title topo-desc">
  <title id="topo-title">Estate topology</title>
  <desc id="topo-desc">Sluice gateway connects to {count} discovered services. Node shape and line style encode the auth category; status is stated in each node title.</desc>
  <g class="gedges">{edges}</g>
  <g class="gnodes">{nodes}</g>
  <g class="ghub">
    <circle class="ghub__disc" cx="{cx:.1}" cy="{cy:.1}" r="34"/>
    <circle class="ghub__ring" cx="{cx:.1}" cy="{cy:.1}" r="34" fill="none"/>
    <text x="{cx:.1}" y="{ty:.1}" text-anchor="middle" class="ghub__label">Sluice</text>
    <text x="{cx:.1}" y="{ty2:.1}" text-anchor="middle" class="ghub__sub">gateway</text>
  </g>
</svg>"##,
        count = inv.services.len(),
        ty = cy - 2.0,
        ty2 = cy + 12.0,
    )
}

/// An annotation-only entry (a key that exists in `services` but not in the current route table).
fn annotation_only_entry(a: Service) -> ServiceEntry {
    let display_name = if a.display_name.trim().is_empty() {
        a.key.clone()
    } else {
        a.display_name.clone()
    };
    ServiceEntry {
        key: a.key,
        display_name,
        owner: a.owner,
        tier: a.tier,
        notes: a.notes,
        routes: Vec::new(),
        auth_modes: Vec::new(),
        primary_auth: String::new(),
        waf_any: false,
        status: "unknown".to_string(),
        annotated: true,
        updated_at: a.updated_at,
    }
}

/// Truncate a string to at most `max` characters (by char boundary), trimming the rest.
fn cap(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}

/// Scheme-allowlist a link target: only `https://` / `http://` survive; anything else (a stray
/// `javascript:`/`data:` from a malformed upstream) collapses to `#`. The catalog's URLs are
/// operator-controlled, but this keeps the render safe by construction.
fn safe_link(url: &str) -> String {
    let low = url.trim().to_ascii_lowercase();
    if low.starts_with("https://") || low.starts_with("http://") || url.starts_with('/') {
        url.to_string()
    } else {
        "#".to_string()
    }
}

/// Percent-encode a service key for safe inclusion in a URL path segment (keys are container-name
/// shaped, but be defensive).
fn urlpath(key: &str) -> String {
    let mut o = String::with_capacity(key.len());
    for b in key.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                o.push(b as char)
            }
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

/// A 303 redirect (post/redirect/get).
fn redirect(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(
            header::LOCATION,
            HeaderValue::from_str(location).expect("valid location"),
        )],
    )
        .into_response()
}

/// An HTML response, optionally attaching a freshly-minted CSRF `Set-Cookie`.
fn html_with_cookie(body: String, set_cookie: Option<String>) -> Response {
    let mut resp = Html(body).into_response();
    if let Some(c) = set_cookie {
        if let Ok(value) = HeaderValue::from_str(&c) {
            resp.headers_mut().insert(header::SET_COOKIE, value);
        }
    }
    resp
}
