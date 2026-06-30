//! End-to-end HTTP flow over the in-memory store + demo route seed (NO database, NO Beacon).
//!
//! Drives the real `app` router via `tower::oneshot`, exactly like the rest of the estate. Covers:
//! health, the SSO guard on every catalog endpoint, the catalog render, service detail, the
//! CSRF-protected annotate flow, the topology graph, and the JSON inventory. Beacon is unreachable
//! in tests, so every live status degrades to "Unavailable" (the resilience contract).

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

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
    assert_eq!(status, StatusCode::UNAUTHORIZED, "catalog requires SSO identity");
    let (status, _) = call(&state, get("/api/inventory")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "inventory requires SSO identity");

    // --- catalog renders the discovered estate -----------------------------
    let (status, body) = call(&state, get_auth("/", "u_op", "op@hf")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Estate Catalog"));
    // Demo seed groups by upstream service: inkwell, cellar, aperture, etc. are present.
    assert!(body.contains("inkwell"), "inkwell service discovered");
    assert!(body.contains("cellar"), "cellar service discovered");
    assert!(body.contains("https://blog.w33d.xyz/"), "public URL derived from host");
    // Beacon unreachable in tests -> every status degrades to Unavailable.
    assert!(body.contains("Unavailable"), "down Beacon degrades status, never errors");

    // --- service detail -----------------------------------------------------
    let (status, body) = call(&state, get_auth("/service/inkwell", "u_op", "op@hf")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Operator annotation"), "edit form present");
    assert!(body.contains("name=\"key\" value=\"inkwell\""), "key prefilled");

    // unknown service -> 404
    let (status, _) = call(&state, get_auth("/service/nope", "u_op", "op@hf")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // --- annotate: no identity -> 401 --------------------------------------
    let f = form(&[("key", "inkwell"), ("display_name", "Blog"), ("csrf_token", CSRF)]);
    let (status, _) = call(&state, post_csrf("/api/annotate", &f, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // --- annotate: bad CSRF -> 401 -----------------------------------------
    let f = form(&[("key", "inkwell"), ("display_name", "Blog"), ("csrf_token", "WRONG")]);
    let (status, _) = call(&state, post_csrf("/api/annotate", &f, Some(("u_op", "op@hf")))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // --- annotate: empty key -> 400 ----------------------------------------
    let f = form(&[("key", ""), ("display_name", "x"), ("csrf_token", CSRF)]);
    let (status, _) = call(&state, post_csrf("/api/annotate", &f, Some(("u_op", "op@hf")))).await;
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
    assert!(!body.contains("<b>noted</b>"), "notes are HTML-escaped");
    assert!(body.contains("&lt;b&gt;noted&lt;/b&gt;"), "notes shown as escaped text");

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
    use std::sync::Arc;
    // Swap in a routes source that always errors.
    let mut state = build_dev_state();
    state.routes = Arc::new(atlas::routes_src::InMemoryRoutes::down());

    let (status, body) = call(&state, get_auth("/", "u_op", "op@hf")).await;
    assert_eq!(status, StatusCode::OK, "a down route table degrades, never errors");
    assert!(body.contains("route table is unavailable"), "degrade banner shown");
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async fn call(state: &atlas::AppState, req: Request<Body>) -> (StatusCode, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
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
        b = b.header("x-auth-subject", sub).header("x-auth-email", email);
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
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => o.push(b as char),
            b' ' => o.push('+'),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}
