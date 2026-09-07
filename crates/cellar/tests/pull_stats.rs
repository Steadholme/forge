//! End-to-end tests for repository PULL STATISTICS: a real `/v2/` manifest GET increments the
//! counter; a HEAD (existence probe) and a request carrying a gateway SSO identity (the web
//! console's own reads) do NOT. Driven against the in-memory store (a held handle lets the test
//! read `pull_stat` directly), NO database / volume required.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use cellar::blobs::MemoryBlobStore;
use cellar::config::Config;
use cellar::store::{InMemoryStore, Store};
use cellar::{app, AppState};
use tower::ServiceExt;

const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

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

fn image_manifest() -> String {
    format!(
        r#"{{"schemaVersion":2,"mediaType":"{OCI_MANIFEST}","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{c:064x}","size":10}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:{l:064x}","size":20}}]}}"#,
        c = 1u32,
        l = 2u32,
    )
}

#[tokio::test]
async fn pull_count_increments_only_on_real_manifest_get() {
    let store = Arc::new(InMemoryStore::new());
    let state = AppState {
        config: Arc::new(Config::dev()),
        store: store.clone(),
        blobs: Arc::new(MemoryBlobStore::new()),
    };
    let app = app(state);
    let name = "app";

    // Seed a manifest at tag `latest` (a manifest PUT does NOT count as a pull).
    let put = send(
        &app,
        Request::builder()
            .method("PUT")
            .uri(format!("/v2/{name}/manifests/latest"))
            .header(header::CONTENT_TYPE, OCI_MANIFEST)
            .body(Body::from(image_manifest()))
            .unwrap(),
    )
    .await;
    assert_eq!(put.status, StatusCode::CREATED, "{}", put.text());
    assert_eq!(
        store.pull_stat(name).await.unwrap(),
        None,
        "PUT must not count as a pull"
    );

    // A HEAD (docker's existence probe) must NOT count.
    let head = send(
        &app,
        Request::builder()
            .method("HEAD")
            .uri(format!("/v2/{name}/manifests/latest"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(head.status, StatusCode::OK);
    assert_eq!(
        store.pull_stat(name).await.unwrap(),
        None,
        "HEAD must not count as a pull"
    );

    // A real GET by a docker/oci client counts.
    let get1 = send(
        &app,
        Request::builder()
            .method("GET")
            .uri(format!("/v2/{name}/manifests/latest"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(get1.status, StatusCode::OK);
    let s = store.pull_stat(name).await.unwrap().unwrap();
    assert_eq!(s.pulls, 1);
    assert!(s.last_pulled_at > 0);

    // A second real GET (by digest this time) also counts.
    let get2 = send(
        &app,
        Request::builder()
            .method("GET")
            .uri(format!("/v2/{name}/manifests/latest"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(get2.status, StatusCode::OK);
    assert_eq!(store.pull_stat(name).await.unwrap().unwrap().pulls, 2);

    // The web console's own read (a `/v2/` GET that arrives WITH a gateway SSO identity) does NOT
    // count — only genuine registry clients do.
    let console = send(
        &app,
        Request::builder()
            .method("GET")
            .uri(format!("/v2/{name}/manifests/latest"))
            .header("x-auth-subject", "usr_alice")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(console.status, StatusCode::OK);
    assert_eq!(
        store.pull_stat(name).await.unwrap().unwrap().pulls,
        2,
        "a request with a gateway identity must not be counted"
    );
}

#[tokio::test]
async fn pull_stats_surface_on_web_console() {
    let store = Arc::new(InMemoryStore::new());
    let state = AppState {
        config: Arc::new(Config::dev()),
        store: store.clone(),
        blobs: Arc::new(MemoryBlobStore::new()),
    };
    let app = app(state);
    let name = "app";

    send(
        &app,
        Request::builder()
            .method("PUT")
            .uri(format!("/v2/{name}/manifests/latest"))
            .header(header::CONTENT_TYPE, OCI_MANIFEST)
            .body(Body::from(image_manifest()))
            .unwrap(),
    )
    .await;

    // Before any pull: "Never pulled" on the repo detail page.
    let before = send(
        &app,
        Request::builder()
            .method("GET")
            .uri(format!("/r/{name}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(before.status, StatusCode::OK);
    assert!(
        before.text().contains("Never pulled"),
        "expected 'Never pulled' pre-pull"
    );

    // One real pull.
    send(
        &app,
        Request::builder()
            .method("GET")
            .uri(format!("/v2/{name}/manifests/latest"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    // The repo detail page AND the repository list both surface "1 pull · last pulled ...".
    let detail = send(
        &app,
        Request::builder()
            .method("GET")
            .uri(format!("/r/{name}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert!(
        detail.text().contains("1 pull"),
        "repo page missing pull line: {}",
        detail.text()
    );

    let index = send(
        &app,
        Request::builder()
            .method("GET")
            .uri("/")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert!(
        index.text().contains("1 pull"),
        "repo list missing pull line"
    );
}
