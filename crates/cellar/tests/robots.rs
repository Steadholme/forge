//! End-to-end tests for ROBOT ACCOUNTS: minting (token shown once), `/v2/` verification via Basic
//! (`robot$<name>`) and Bearer, scope enforcement (a pull token is rejected on push; a pushpull
//! token is bounded by its repo pattern), disable/delete revocation, and — critically — that adding
//! robots does NOT weaken the existing human Basic auth path.
//!
//! Auth is ENABLED (a `CELLAR_USER` is configured), because robot verification only runs on the
//! authenticated path. A held `InMemoryStore` handle lets the test read `last_used_at` back.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use cellar::config::Config;
use cellar::blobs::MemoryBlobStore;
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
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap().to_vec();
    Resp { status, body }
}

/// Standard base64 (with padding) — enough to build `Authorization: Basic` headers in-test.
fn b64(input: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        out.push(A[(b0 >> 2) as usize] as char);
        out.push(A[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            A[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn basic(user: &str, pass: &str) -> String {
    format!("Basic {}", b64(format!("{user}:{pass}").as_bytes()))
}

fn manifest_body() -> String {
    format!(
        r#"{{"schemaVersion":2,"mediaType":"{OCI_MANIFEST}","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{c:064x}","size":10}},"layers":[]}}"#,
        c = 1u32,
    )
}

/// PUT a manifest at `name:latest` with the given `Authorization` (a write => scope-checked).
async fn put_manifest(app: &axum::Router, name: &str, authz: Option<&str>) -> Resp {
    let mut b = Request::builder()
        .method("PUT")
        .uri(format!("/v2/{name}/manifests/latest"))
        .header(header::CONTENT_TYPE, OCI_MANIFEST);
    if let Some(a) = authz {
        b = b.header(header::AUTHORIZATION, a);
    }
    send(app, b.body(Body::from(manifest_body())).unwrap()).await
}

async fn get_manifest(app: &axum::Router, name: &str, authz: Option<&str>) -> Resp {
    let mut b = Request::builder()
        .method("GET")
        .uri(format!("/v2/{name}/manifests/latest"));
    if let Some(a) = authz {
        b = b.header(header::AUTHORIZATION, a);
    }
    send(app, b.body(Body::empty()).unwrap()).await
}

async fn v2_probe(app: &axum::Router, authz: Option<&str>) -> Resp {
    let mut b = Request::builder().method("GET").uri("/v2/");
    if let Some(a) = authz {
        b = b.header(header::AUTHORIZATION, a);
    }
    send(app, b.body(Body::empty()).unwrap()).await
}

/// Mint a robot via the admin panel; return the token shown once.
async fn mint(app: &axum::Router, body: &str) -> Resp {
    send(
        app,
        Request::builder()
            .method("POST")
            .uri("/admin/robots/create")
            .header("x-auth-groups", "admins")
            .header(header::COOKIE, format!("__Host-csrf={CSRF}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!("{body}&csrf_token={CSRF}")))
            .unwrap(),
    )
    .await
}

fn extract_token(html: &str) -> String {
    let marker = "data-token=\"";
    let start = html.find(marker).expect("token present in mint response") + marker.len();
    let rest = &html[start..];
    let end = rest.find('"').unwrap();
    rest[..end].to_string()
}

fn auth_app(store: Arc<InMemoryStore>) -> axum::Router {
    let mut cfg = Config::dev();
    cfg.user = "ci".to_string();
    cfg.password = "s3cret".to_string();
    app(AppState {
        config: Arc::new(cfg),
        store,
        blobs: Arc::new(MemoryBlobStore::new()),
    })
}

#[tokio::test]
async fn pull_token_can_pull_but_is_rejected_on_push() {
    let store = Arc::new(InMemoryStore::new());
    let app = auth_app(store.clone());
    let human = basic("ci", "s3cret");

    // Human seeds a manifest to pull.
    assert_eq!(put_manifest(&app, "app", Some(&human)).await.status, StatusCode::CREATED);

    // Mint a PULL-only robot.
    let resp = mint(&app, "name=puller&scope=pull&repo_pattern=app").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text());
    let token = extract_token(&resp.text());
    let robot = basic("robot$puller", &token);

    // The robot can log in (GET /v2/) ...
    assert_eq!(v2_probe(&app, Some(&robot)).await.status, StatusCode::OK);
    // ... and pull ...
    assert_eq!(get_manifest(&app, "app", Some(&robot)).await.status, StatusCode::OK);
    // ... but a push is DENIED (403), because the token is pull-scoped.
    let push = put_manifest(&app, "app", Some(&robot)).await;
    assert_eq!(push.status, StatusCode::FORBIDDEN, "pull token must not push: {}", push.text());

    // The token also works as a Bearer credential (docker token-auth style).
    let bearer = format!("Bearer {token}");
    assert_eq!(v2_probe(&app, Some(&bearer)).await.status, StatusCode::OK);

    // last_used_at was stamped on use.
    let rec = store.get_robot_by_name("puller").await.unwrap().unwrap();
    assert!(rec.last_used_at > 0, "last_used_at must update on use");
}

#[tokio::test]
async fn pushpull_token_is_bounded_by_repo_pattern() {
    let store = Arc::new(InMemoryStore::new());
    let app = auth_app(store.clone());

    // A pushpull robot scoped to team/* (%2A encodes the trailing '*').
    let resp = mint(&app, "name=teambot&scope=pushpull&repo_pattern=team/%2A").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text());
    let robot = basic("robot$teambot", &extract_token(&resp.text()));

    // Push to a matching repo succeeds.
    assert_eq!(put_manifest(&app, "team/app", Some(&robot)).await.status, StatusCode::CREATED);
    // Push to a NON-matching repo is denied.
    let off = put_manifest(&app, "other/app", Some(&robot)).await;
    assert_eq!(off.status, StatusCode::FORBIDDEN, "pattern miss must deny: {}", off.text());
}

#[tokio::test]
async fn disable_and_delete_revoke_the_token() {
    let store = Arc::new(InMemoryStore::new());
    let app = auth_app(store.clone());
    let resp = mint(&app, "name=tmp&scope=pushpull&repo_pattern=%2A").await;
    let token = extract_token(&resp.text());
    let robot = basic("robot$tmp", &token);
    assert_eq!(v2_probe(&app, Some(&robot)).await.status, StatusCode::OK);

    let id = store.get_robot_by_name("tmp").await.unwrap().unwrap().id;

    // Disable -> the token is rejected (401).
    let toggle = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/admin/robots/toggle")
            .header("x-auth-groups", "admins")
            .header(header::COOKIE, format!("__Host-csrf={CSRF}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!("id={id}&enabled=false&csrf_token={CSRF}")))
            .unwrap(),
    )
    .await;
    assert_eq!(toggle.status, StatusCode::OK);
    assert_eq!(v2_probe(&app, Some(&robot)).await.status, StatusCode::UNAUTHORIZED);

    // Delete -> still rejected, and the row is gone.
    let del = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/admin/robots/delete")
            .header("x-auth-groups", "admins")
            .header(header::COOKIE, format!("__Host-csrf={CSRF}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!("id={id}&csrf_token={CSRF}")))
            .unwrap(),
    )
    .await;
    assert_eq!(del.status, StatusCode::OK);
    assert!(store.get_robot_by_name("tmp").await.unwrap().is_none());
}

#[tokio::test]
async fn minting_requires_admin_and_csrf() {
    let store = Arc::new(InMemoryStore::new());
    let app = auth_app(store.clone());

    // No admin group -> 403.
    let no_admin = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/admin/robots/create")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("name=x&scope=pull&repo_pattern=app&csrf_token=x"))
            .unwrap(),
    )
    .await;
    assert_eq!(no_admin.status, StatusCode::FORBIDDEN);

    // Admin but bad CSRF -> 400.
    let bad_csrf = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/admin/robots/create")
            .header("x-auth-groups", "admins")
            .header(header::COOKIE, "__Host-csrf=cookie")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("name=x&scope=pull&repo_pattern=app&csrf_token=form"))
            .unwrap(),
    )
    .await;
    assert_eq!(bad_csrf.status, StatusCode::BAD_REQUEST);
    assert!(store.list_robots().await.unwrap().is_empty());
}

#[tokio::test]
async fn existing_human_auth_path_is_unchanged() {
    let store = Arc::new(InMemoryStore::new());
    let app = auth_app(store.clone());
    let good = basic("ci", "s3cret");
    let wrong = basic("ci", "nope");

    // Mint an (unrelated) robot to prove its presence doesn't perturb the human path.
    mint(&app, "name=noise&scope=pull&repo_pattern=app").await;

    // 1. No creds -> 401 challenge on the probe.
    let anon = v2_probe(&app, None).await;
    assert_eq!(anon.status, StatusCode::UNAUTHORIZED);

    // 2. Valid human creds -> 200, and a human push succeeds (full access, every repo).
    assert_eq!(v2_probe(&app, Some(&good)).await.status, StatusCode::OK);
    assert_eq!(put_manifest(&app, "anything/here", Some(&good)).await.status, StatusCode::CREATED);

    // 3. Anonymous READ of an existing manifest is still allowed (public pull).
    assert_eq!(get_manifest(&app, "anything/here", None).await.status, StatusCode::OK);

    // 4. WRONG human creds are still rejected (not silently anonymous).
    assert_eq!(get_manifest(&app, "anything/here", Some(&wrong)).await.status, StatusCode::UNAUTHORIZED);

    // 5. An unknown robot username with any secret is rejected (present-but-invalid), and anonymous
    //    reads keep working (the robot path never weakens the anonymous/human contract).
    let ghost = basic("robot$ghost", "whatever");
    assert_eq!(v2_probe(&app, Some(&ghost)).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(get_manifest(&app, "anything/here", None).await.status, StatusCode::OK);
}
