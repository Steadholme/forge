//! End-to-end HTTP flow over the in-memory store + demo route seed (NO database, NO Beacon).
//!
//! Drives the real `app` router via `tower::oneshot`, exactly like the rest of the estate. Covers:
//! health, the SSO guard on every catalog endpoint, the catalog render, service detail, the
//! CSRF-protected annotate flow, the topology graph, and the JSON inventory. Beacon is unreachable
//! in tests, so every live status degrades to "Unavailable" (the resilience contract).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use atlas::handlers::{auth_cat, status_pill};
use atlas::inventory::{RouteView, ServiceEntry};
use atlas::routes_src::{InMemoryRoutes, Route};
use atlas::{app, build_dev_state};

const CSRF: &str = "tok_csrf_for_tests";

#[tokio::test]
async fn full_catalog_flow_in_memory() {
    let state = build_dev_state();

    // --- health (no auth) --------------------------------------------------
    let (status, body) = call(&state, get("/healthz")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");

    // --- SSO guard: no identity -> 401 -------------------------------------
    let (status, _) = call(&state, get("/")).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "catalog requires SSO identity"
    );
    let (status, _) = call(&state, get("/api/inventory")).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "inventory requires SSO identity"
    );

    // --- catalog renders the discovered estate -----------------------------
    let (status, body) = call(&state, get_auth("/", "u_op", "op@hf")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Estate Catalog"));
    // Demo seed groups by upstream service: inkwell, cellar, aperture, etc. are present.
    assert!(body.contains("inkwell"), "inkwell service discovered");
    assert!(body.contains("cellar"), "cellar service discovered");
    assert!(
        body.contains("https://blog.w33d.xyz/"),
        "public URL derived from host"
    );
    // Beacon unreachable in tests -> every status degrades to Unavailable.
    assert!(
        body.contains("Unavailable"),
        "down Beacon degrades status, never errors"
    );
    assert!(body.contains("<tr class=\"ledger__row\""));
    assert!(body.contains("data-status=\"unavailable\""));
    assert!(body.contains("class=\"survey__cartouche\""));
    assert!(!body.contains("class=\"metrics\""));
    assert!(!body.contains("class=\"svc-card"));
    assert!(!body.contains("style=\"--abadge:"));

    // --- service detail -----------------------------------------------------
    let (status, body) = call(&state, get_auth("/service/inkwell", "u_op", "op@hf")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Operator annotation"), "edit form present");
    assert!(
        body.contains("name=\"key\" value=\"inkwell\""),
        "key prefilled"
    );

    // unknown service -> 404
    let (status, _) = call(&state, get_auth("/service/nope", "u_op", "op@hf")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // --- annotate: no identity -> 401 --------------------------------------
    let f = form(&[
        ("key", "inkwell"),
        ("display_name", "Blog"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(&state, post_csrf("/api/annotate", &f, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // --- annotate: bad CSRF -> 401 -----------------------------------------
    let f = form(&[
        ("key", "inkwell"),
        ("display_name", "Blog"),
        ("csrf_token", "WRONG"),
    ]);
    let (status, _) = call(
        &state,
        post_csrf("/api/annotate", &f, Some(("u_op", "op@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // --- annotate: empty key -> 400 ----------------------------------------
    let f = form(&[("key", ""), ("display_name", "x"), ("csrf_token", CSRF)]);
    let (status, _) = call(
        &state,
        post_csrf("/api/annotate", &f, Some(("u_op", "op@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // --- annotate: success -> 303 ------------------------------------------
    let f = form(&[
        ("key", "inkwell"),
        ("display_name", "Inkwell Blog"),
        ("owner", "platform"),
        ("tier", "content"),
        ("notes", "personal CMS <b>noted</b>"),
        ("csrf_token", CSRF),
    ]);
    let resp = app(state.clone())
        .oneshot(post_csrf("/api/annotate", &f, Some(("u_op", "op@hf"))))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap();
    assert_eq!(loc, "/service/inkwell");

    // --- the annotation now shows on the catalog (sanitized) ----------------
    let (_, body) = call(&state, get_auth("/", "u_op", "op@hf")).await;
    assert!(body.contains("Inkwell Blog"), "display name applied");
    assert!(body.contains("Owner: platform"));
    assert!(body.contains("<td class=\"ledger__owner\">Owner: platform</td>"));
    assert!(body.contains("data-annotated=\"true\""));
    assert!(!body.contains("<b>noted</b>"), "notes are HTML-escaped");
    assert!(
        body.contains("&lt;b&gt;noted&lt;/b&gt;"),
        "notes shown as escaped text"
    );

    // --- topology graph -----------------------------------------------------
    let (status, body) = call(&state, get_auth("/graph", "u_op", "op@hf")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<svg"), "inline SVG topology rendered");
    assert!(body.contains("Sluice"), "gateway hub labeled");

    // --- JSON inventory -----------------------------------------------------
    let (status, body) = call(&state, get_auth("/api/inventory", "u_op", "op@hf")).await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(v["services_total"].as_u64().unwrap() > 0);
    assert!(v["routes_total"].as_u64().unwrap() >= 20);
    assert_eq!(v["routes_available"], true);
    assert_eq!(v["beacon_reached"], false);
}

#[tokio::test]
async fn route_table_outage_degrades_not_errors() {
    // Swap in a routes source that always errors.
    let mut state = build_dev_state();
    state.routes = Arc::new(InMemoryRoutes::down());

    let (status, body) = call(&state, get_auth("/", "u_op", "op@hf")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a down route table degrades, never errors"
    );
    assert!(
        body.contains("route table is unavailable"),
        "degrade banner shown"
    );
    assert!(body.contains("class=\"ledger__row ledger__row--empty\""));
    assert!(body.contains("colspan=\"9\""));
}

#[test]
fn ledger_row_is_rows_only_and_nine_columns() {
    let row = atlas::handlers::catalog::ledger_row(&sample_entry());
    assert!(row.starts_with("<tr class=\"ledger__row\""));
    assert_eq!(row.matches("<td ").count(), 9);
    for forbidden in [
        "<table", "<thead", "<tbody", "<caption", "<section", "svc-card", "svc-grid",
    ] {
        assert!(
            !row.contains(forbidden),
            "row emitted forbidden shell: {forbidden}"
        );
    }
}

#[test]
fn ledger_row_status_annotation_waf_hooks() {
    let row = atlas::handlers::catalog::ledger_row(&sample_entry());
    assert!(row.contains("data-status=\"operational\""));
    assert!(row.contains("data-annotated=\"true\""));
    assert!(row.contains("data-waf=\"true\""));
    assert!(row.contains("<td class=\"ledger__owner\">Owner: platform</td>"));
    assert!(row.contains("class=\"wafflag\""));
}

#[test]
fn status_slug_never_leaks_raw_value() {
    let maintenance = status_pill("maintenance");
    assert!(maintenance.contains("data-status=\"unknown\""));
    assert!(!maintenance.contains("maintenance"));

    let hostile = status_pill("<b>x");
    assert!(hostile.contains("data-status=\"unknown\""));
    assert!(!hostile.contains("<b>x"));

    assert!(status_pill("degraded").contains("data-status=\"degraded\""));
}

#[test]
fn auth_cat_known_words_and_glyphs_are_redundant() {
    let cases = [
        ("sso", "sso", "●", "SSO"),
        ("public", "public", "■", "Public"),
        ("bearer", "bearer", "◆", "Bearer"),
    ];
    for (raw, slug, glyph, word) in cases {
        let html = auth_cat(raw);
        assert!(html.contains(&format!("data-auth=\"{slug}\"")));
        assert!(html.contains(glyph));
        assert!(html.contains(word));
    }
}

#[test]
fn auth_cat_other_hostile_is_escaped() {
    let mtls = auth_cat("mtls");
    assert!(mtls.contains("data-auth=\"other\""));
    assert!(mtls.contains("▲"));
    assert!(mtls.contains("mtls"));

    let hostile = auth_cat("<script>");
    assert!(hostile.contains("data-auth=\"other\""));
    assert!(hostile.contains("&lt;script&gt;"));
    assert!(!hostile.contains("<script>"));
}

#[test]
fn auth_cat_empty_other_is_unclassified() {
    for raw in ["", "   "] {
        let html = auth_cat(raw);
        assert!(html.contains("data-auth=\"other\""));
        assert!(html.contains("Unclassified"));
    }
}

#[test]
fn four_rust_files_contain_no_presentation_hex() {
    let sources = [
        include_str!("../src/handlers/catalog.rs"),
        include_str!("../src/handlers/mod.rs"),
        include_str!("../src/inventory.rs"),
        include_str!("catalog_flow.rs"),
    ];
    for source in sources {
        assert!(
            !has_presentation_hex(source),
            "presentation hex remained in a modified Rust file"
        );
    }

    for digits in [
        "818CF8", "4F46E5", "16A34A", "D97706", "0F172A", "64748B", "fff",
    ] {
        let needle = format!("#{digits}");
        for source in sources {
            assert!(!source.contains(&needle), "legacy presenter color remained");
        }
    }
}

#[tokio::test]
async fn topology_svg_emits_semantic_shapes_without_hex() {
    let state = build_dev_state();
    let (status, body) = call(&state, get_auth("/graph", "u_op", "op@hf")).await;
    assert_eq!(status, StatusCode::OK);
    let start = body
        .find("<svg class=\"topology\"")
        .expect("topology svg start");
    let end = body[start..].find("</svg>").expect("topology svg end") + start + "</svg>".len();
    let svg = &body[start..end];

    assert!(svg.contains("role=\"img\""));
    assert!(svg.contains("aria-labelledby=\"topo-title topo-desc\""));
    assert!(svg.contains("<title id=\"topo-title\""));
    assert!(svg.contains("<desc id=\"topo-desc\""));
    assert!(svg.contains("data-auth=\""));
    assert!(svg.contains("class=\"gedge\""));
    assert!(svg.contains("class=\"gnode__mark"));
    assert!(!svg.contains("fill=\"#"));
    assert!(!svg.contains("stroke=\"#"));
    assert!(!has_presentation_hex(svg));
}

#[tokio::test]
async fn catalog_table_slot_matches_inventory_service_count() {
    let state = build_dev_state();
    let (status, catalog) = call(&state, get_auth("/", "u_op", "op@hf")).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = call(&state, get_auth("/api/inventory", "u_op", "op@hf")).await;
    assert_eq!(status, StatusCode::OK);
    let inventory: serde_json::Value = serde_json::from_str(&body).unwrap();
    let expected = inventory["services_total"].as_u64().unwrap() as usize;
    assert_eq!(
        catalog.matches("<tr class=\"ledger__row\"").count(),
        expected
    );
}

#[tokio::test]
async fn detail_and_ledger_use_wafflag_for_seeded_other_auth() {
    let mut state = build_dev_state();
    state.routes = Arc::new(InMemoryRoutes::new(vec![Route {
        name: "odd-root".into(),
        host: "odd.w33d.xyz".into(),
        path_prefix: "/".into(),
        upstream: "http://odd-auth:9191".into(),
        protected: true,
        auth: "<script>".into(),
        waf: true,
    }]));

    let (status, catalog) = call(&state, get_auth("/", "u_op", "op@hf")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(catalog.contains("data-waf=\"true\""));
    assert!(catalog.contains("class=\"wafflag\""));
    assert!(catalog.contains("data-auth=\"other\""));
    assert!(catalog.contains("&lt;script&gt;"));
    assert!(!catalog.contains("style=\"--abadge:"));

    let (status, detail) = call(&state, get_auth("/service/odd-auth", "u_op", "op@hf")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(detail.contains("class=\"wafflag\""));
    assert!(detail.contains("class=\"authcat\""));
    assert!(detail.contains("data-auth=\"other\""));
    assert!(detail.contains("&lt;script&gt;"));
    assert!(!detail.contains("style=\"--abadge:"));
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async fn call(state: &atlas::AppState, req: Request<Body>) -> (StatusCode, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn get_auth(uri: &str, sub: &str, email: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-auth-subject", sub)
        .header("x-auth-email", email)
        .body(Body::empty())
        .unwrap()
}

fn post_csrf(uri: &str, body: &str, ident: Option<(&str, &str)>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"));
    if let Some((sub, email)) = ident {
        b = b
            .header("x-auth-subject", sub)
            .header("x-auth-email", email);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", k, enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn enc(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                o.push(b as char)
            }
            b' ' => o.push('+'),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

fn sample_entry() -> ServiceEntry {
    ServiceEntry {
        key: "atlas".into(),
        display_name: "Atlas Survey".into(),
        owner: "platform".into(),
        tier: "control".into(),
        notes: "Estate catalog".into(),
        routes: vec![RouteView {
            name: "atlas-root".into(),
            host: "atlas.w33d.xyz".into(),
            path_prefix: "/".into(),
            public_url: "https://atlas.w33d.xyz/".into(),
            auth: "sso".into(),
            waf: true,
        }],
        auth_modes: vec!["sso".into()],
        primary_auth: "sso".into(),
        waf_any: true,
        status: "operational".into(),
        annotated: true,
        updated_at: 42,
    }
}

fn has_presentation_hex(source: &str) -> bool {
    let bytes = source.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'#' {
            continue;
        }
        let mut count = 0;
        while bytes
            .get(index + 1 + count)
            .is_some_and(u8::is_ascii_hexdigit)
        {
            count += 1;
        }
        if matches!(count, 3 | 4 | 6 | 8)
            && bytes
                .get(index + 1 + count)
                .is_none_or(|next| !next.is_ascii_alphanumeric())
        {
            return true;
        }
    }
    false
}
