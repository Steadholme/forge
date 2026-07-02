//! End-to-end tests for the additive JSON endpoints backing the optimistic (no-reload) web
//! actions: `/delete-tag.json` and `/admin/retention/preview.json`. Each shares the CSRF (and, for
//! retention, admin) gate + audit of its form sibling and reuses the exact same store path — the
//! form routes are unchanged (progressive enhancement). Tags are seeded through a held
//! `InMemoryStore` handle and the endpoints are driven over HTTP.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use cellar::blobs::MemoryBlobStore;
use cellar::config::Config;
use cellar::model::{ManifestRec, RetentionRule};
use cellar::store::{InMemoryStore, Store};
use cellar::{app, AppState};
use tower::ServiceExt;

const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const CSRF: &str = "test-csrf-token";

struct Resp {
    status: StatusCode,
    body: Vec<u8>,
}
impl Resp {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
}

async fn send(app: &axum::Router, req: Request<Body>) -> Resp {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    Resp { status, body }
}

/// POST a signed-in web form (SSO identity + double-submit CSRF cookie/token).
async fn sso_post(app: &axum::Router, uri: &str, body: String, cookie: &str) -> Resp {
    send(
        app,
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("x-auth-subject", "u_op")
            .header("x-auth-email", "op@w33d.xyz")
            .header(header::COOKIE, format!("__Host-csrf={cookie}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap(),
    )
    .await
}

/// POST an admin form (admin group + CSRF).
async fn admin_post(app: &axum::Router, uri: &str, body: String) -> Resp {
    send(
        app,
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("x-auth-groups", "admins")
            .header(header::COOKIE, format!("__Host-csrf={CSRF}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap(),
    )
    .await
}

fn manifest(repo: &str, digest: &str) -> ManifestRec {
    ManifestRec {
        id: ManifestRec::make_id(repo, digest),
        repo: repo.to_string(),
        digest: digest.to_string(),
        media_type: OCI_MANIFEST.to_string(),
        raw: "{}".to_string(),
        size: 10,
        created_at: 100,
    }
}

async fn seed(store: &InMemoryStore) {
    store.ensure_repository("app", 100).await.unwrap();
    for (tag, digest, t) in [
        ("old", "sha256:aa", 100),
        ("latest", "sha256:bb", 150),
        ("mid", "sha256:cc", 200),
        ("new", "sha256:dd", 300),
    ] {
        store.put_manifest(&manifest("app", digest)).await.unwrap();
        store.put_tag("app", tag, digest, t).await.unwrap();
    }
}

fn state_with(store: Arc<InMemoryStore>) -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store,
        blobs: Arc::new(MemoryBlobStore::new()),
    }
}

#[tokio::test]
async fn delete_tag_json_removes_tag_and_mirrors_form_gate() {
    let store = Arc::new(InMemoryStore::new());
    seed(&store).await;
    let app = app(state_with(store.clone()));

    // Happy path: 200 + JSON, and the tag really goes away via the same store path as the form.
    let res = sso_post(
        &app,
        "/delete-tag.json",
        format!("repo=app&tag=old&csrf_token={CSRF}"),
        CSRF,
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert!(res.text().contains("\"removed\":true"), "{}", res.text());
    let tags: Vec<String> = store
        .tags_for("app")
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.tag)
        .collect();
    assert!(!tags.contains(&"old".to_string()), "tag was deleted");
    assert_eq!(tags.len(), 3);

    // A mismatched CSRF token is rejected exactly like the form route (no mutation).
    let bad = sso_post(
        &app,
        "/delete-tag.json",
        "repo=app&tag=mid&csrf_token=wrong".to_string(),
        CSRF,
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert_eq!(store.tags_for("app").await.unwrap().len(), 3, "CSRF-rejected delete must not mutate");
}

#[tokio::test]
async fn retention_preview_json_lists_candidates_without_mutating() {
    let store = Arc::new(InMemoryStore::new());
    seed(&store).await;
    store
        .create_retention_rule(&RetentionRule {
            id: "ret-1".into(),
            repo_pattern: "app".into(),
            keep_last: 1,
            keep_days: 0,
            enabled: true,
        })
        .await
        .unwrap();
    let app = app(state_with(store.clone()));

    let res = admin_post(
        &app,
        "/admin/retention/preview.json",
        format!("csrf_token={CSRF}"),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let body = res.text();
    // Candidates are `old` + `mid`; the newest (`new`) and `latest` are kept.
    assert!(body.contains("\"tag\":\"old\""), "{body}");
    assert!(body.contains("\"tag\":\"mid\""), "{body}");
    assert!(!body.contains("\"tag\":\"new\""), "newest tag must be kept: {body}");
    // A dry run must not mutate: all four tags remain.
    assert_eq!(store.tags_for("app").await.unwrap().len(), 4, "preview mutated the store");

    // The JSON endpoint enforces the same admin gate as the form: no admin group -> not OK.
    let unauth = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/admin/retention/preview.json")
            .header(header::COOKIE, format!("__Host-csrf={CSRF}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!("csrf_token={CSRF}")))
            .unwrap(),
    )
    .await;
    assert_ne!(unauth.status, StatusCode::OK, "non-admin must be refused");
}
