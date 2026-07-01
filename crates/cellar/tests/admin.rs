//! End-to-end tests for the admin panel: gating (403 for non-admins, allowed for admins), storage
//! accounting, and the garbage-collection mutation — all against the in-memory store + blobs (NO
//! database, NO volume required).

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use cellar::digest::sha256_digest;
use cellar::{app, build_dev_state};
use tower::ServiceExt;

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Resp {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
    fn header(&self, name: &str) -> String {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }
}

async fn send(app: &axum::Router, req: Request<Body>) -> Resp {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap().to_vec();
    Resp { status, headers, body }
}

/// Percent-encode the `:` in a digest for the query string.
fn encode(digest: &str) -> String {
    digest.replace(':', "%3A")
}

/// Push a blob through the chunked upload flow; returns its digest.
async fn push_blob(app: &axum::Router, name: &str, payload: &[u8]) -> String {
    let digest = sha256_digest(payload);
    let init = send(app, Request::builder().method("POST").uri(format!("/v2/{name}/blobs/uploads/")).body(Body::empty()).unwrap()).await;
    assert_eq!(init.status, StatusCode::ACCEPTED, "init: {}", init.text());
    let location = init.header("location");
    let patch = send(app, Request::builder().method("PATCH").uri(&location).body(Body::from(payload.to_vec())).unwrap()).await;
    assert_eq!(patch.status, StatusCode::ACCEPTED, "patch: {}", patch.text());
    let put = send(app, Request::builder().method("PUT").uri(format!("{location}?digest={}", encode(&digest))).body(Body::empty()).unwrap()).await;
    assert_eq!(put.status, StatusCode::CREATED, "put: {}", put.text());
    digest
}

/// PUT an image manifest referencing a config + layer blob, at `reference`. Returns its digest.
async fn put_image_manifest(app: &axum::Router, name: &str, reference: &str, config: &str, layer: &str) -> String {
    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config}","size":10}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{layer}","size":20}}]}}"#,
    );
    let digest = sha256_digest(manifest.as_bytes());
    let r = send(
        app,
        Request::builder()
            .method("PUT")
            .uri(format!("/v2/{name}/manifests/{reference}"))
            .header(header::CONTENT_TYPE, "application/vnd.oci.image.manifest.v1+json")
            .body(Body::from(manifest))
            .unwrap(),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "put manifest: {}", r.text());
    digest
}

/// GET /admin with the given comma-separated groups header (None = no header at all).
async fn get_admin(app: &axum::Router, groups: Option<&str>) -> Resp {
    let mut b = Request::builder().method("GET").uri("/admin");
    if let Some(g) = groups {
        b = b.header("x-auth-groups", g);
    }
    send(app, b.body(Body::empty()).unwrap()).await
}

#[tokio::test]
async fn admin_gate_forbids_non_admins_and_allows_admins() {
    let app = app(build_dev_state());

    // 1. No groups at all -> 403.
    let anon = get_admin(&app, None).await;
    assert_eq!(anon.status, StatusCode::FORBIDDEN, "{}", anon.text());

    // 2. An ordinary signed-in user (non-admin group) -> 403.
    let user = get_admin(&app, Some("readers,writers")).await;
    assert_eq!(user.status, StatusCode::FORBIDDEN, "{}", user.text());

    // 3. `admins` -> 200, and the panel renders.
    let admin = get_admin(&app, Some("admins")).await;
    assert_eq!(admin.status, StatusCode::OK, "{}", admin.text());
    assert!(admin.text().contains("Registry administration"));
    // Mints a CSRF cookie for the GC form.
    assert!(admin.header("set-cookie").contains("__Host-csrf="));

    // 4. `infra-admins` is also allowed.
    let infra = get_admin(&app, Some("infra-admins")).await;
    assert_eq!(infra.status, StatusCode::OK);

    // 5. Delegated admin: the product-scoped operator group (default "registry-admins") reaches the
    //    panel too, without belonging to either global admin group.
    let registry = get_admin(&app, Some("registry-admins")).await;
    assert_eq!(registry.status, StatusCode::OK, "{}", registry.text());
    assert!(registry.text().contains("Registry administration"));

    // 6. A random unrelated group is still forbidden.
    let random = get_admin(&app, Some("random-group")).await;
    assert_eq!(random.status, StatusCode::FORBIDDEN, "{}", random.text());
}

#[tokio::test]
async fn admin_gc_is_also_gated() {
    let app = app(build_dev_state());
    // POST /admin/gc without an admin group is forbidden BEFORE any CSRF check.
    let r = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/admin/gc")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("csrf_token=whatever"))
            .unwrap(),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.text());
}

#[tokio::test]
async fn admin_gc_reclaims_orphans_and_keeps_live() {
    let app = app(build_dev_state());
    let name = "library/app";

    // Two distinct config + layer blob pairs -> two distinct image manifests.
    let cfg_live = push_blob(&app, name, b"live config blob").await;
    let lay_live = push_blob(&app, name, b"live layer blob").await;
    let cfg_orphan = push_blob(&app, name, b"orphan config blob").await;
    let lay_orphan = push_blob(&app, name, b"orphan layer blob").await;

    // Push the orphan image at tag `keep`, then RE-PUSH `keep` to the live image (last-writer-wins).
    // That leaves the first manifest + its blobs untagged/orphaned — the classic reclaim scenario.
    let orphan_digest = put_image_manifest(&app, name, "keep", &cfg_orphan, &lay_orphan).await;
    put_image_manifest(&app, name, "keep", &cfg_live, &lay_live).await;

    // The admin panel shows reclaimable bytes (the orphan manifest + its 2 orphan blobs).
    let before = get_admin(&app, Some("admins")).await;
    assert_eq!(before.status, StatusCode::OK);
    assert!(before.text().contains("reclaimable"), "expected a reclaim line: {}", before.text());

    // The orphan blobs exist before GC.
    for d in [&cfg_orphan, &lay_orphan] {
        let h = send(&app, Request::builder().method("HEAD").uri(format!("/v2/{name}/blobs/{d}")).body(Body::empty()).unwrap()).await;
        assert_eq!(h.status, StatusCode::OK, "orphan blob {d} should exist pre-GC");
    }

    // Run GC (double-submit CSRF: cookie + form token must match).
    let token = "test-csrf-token-value";
    let gc = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/admin/gc")
            .header("x-auth-groups", "infra-admins")
            .header(header::COOKIE, format!("__Host-csrf={token}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!("csrf_token={token}")))
            .unwrap(),
    )
    .await;
    assert_eq!(gc.status, StatusCode::OK, "{}", gc.text());
    assert!(gc.text().contains("reclaimed"), "expected a reclaimed notice: {}", gc.text());

    // The orphan blobs are gone; the live blobs remain.
    for d in [&cfg_orphan, &lay_orphan] {
        let h = send(&app, Request::builder().method("HEAD").uri(format!("/v2/{name}/blobs/{d}")).body(Body::empty()).unwrap()).await;
        assert_eq!(h.status, StatusCode::NOT_FOUND, "orphan blob {d} should be reclaimed");
    }
    for d in [&cfg_live, &lay_live] {
        let h = send(&app, Request::builder().method("HEAD").uri(format!("/v2/{name}/blobs/{d}")).body(Body::empty()).unwrap()).await;
        assert_eq!(h.status, StatusCode::OK, "live blob {d} must survive GC");
    }

    // The live tag still pulls.
    let m = send(&app, Request::builder().method("GET").uri(format!("/v2/{name}/manifests/keep")).body(Body::empty()).unwrap()).await;
    assert_eq!(m.status, StatusCode::OK, "live tag must still resolve");

    // The orphan manifest is gone (its digest no longer resolves).
    let om = send(&app, Request::builder().method("GET").uri(format!("/v2/{name}/manifests/{orphan_digest}")).body(Body::empty()).unwrap()).await;
    assert_eq!(om.status, StatusCode::NOT_FOUND, "orphan manifest must be reclaimed");

    // A second GC is a no-op (idempotent) -> "Nothing to reclaim".
    let gc2 = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/admin/gc")
            .header("x-auth-groups", "admins")
            .header(header::COOKIE, format!("__Host-csrf={token}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!("csrf_token={token}")))
            .unwrap(),
    )
    .await;
    assert_eq!(gc2.status, StatusCode::OK);
    assert!(gc2.text().contains("Nothing to reclaim"), "second GC should reclaim nothing: {}", gc2.text());
}

#[tokio::test]
async fn admin_gc_rejects_bad_csrf() {
    let app = app(build_dev_state());
    // Admin group present, but cookie and form token do not match -> 400.
    let r = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/admin/gc")
            .header("x-auth-groups", "admins")
            .header(header::COOKIE, "__Host-csrf=cookie-token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("csrf_token=form-token"))
            .unwrap(),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.text());
}
