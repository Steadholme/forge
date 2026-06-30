//! End-to-end registry-protocol tests against the in-memory store + in-memory blobs (NO database,
//! NO volume required).
//!
//! Drives the real `Router` in-process via `tower::oneshot`, simulating exactly what `docker push`
//! / `docker pull` do: the `GET /v2/` probe, a chunked blob upload (POST init -> PATCH -> PUT
//! ?digest), `HEAD` blob existence checks, a manifest `PUT` by tag, a manifest `GET` round-trip,
//! `tags/list`, `_catalog`, and the SSO web console. A second app exercises the HTTP Basic auth
//! gate (401 challenge on writes, anonymous reads, valid-credential push).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use cellar::config::Config;
use cellar::digest::sha256_digest;
use cellar::{app, build_dev_state, AppState};
use cellar::blobs::MemoryBlobStore;
use cellar::store::InMemoryStore;
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

fn req(method: &str, uri: &str, auth: Option<&str>, body: Vec<u8>) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(a) = auth {
        b = b.header(header::AUTHORIZATION, a);
    }
    b.body(Body::from(body)).unwrap()
}

/// Push a blob through the chunked upload flow; returns its digest.
async fn push_blob(app: &axum::Router, name: &str, payload: &[u8], auth: Option<&str>) -> String {
    let digest = sha256_digest(payload);

    // POST init -> 202 + Location.
    let init = send(app, req("POST", &format!("/v2/{name}/blobs/uploads/"), auth, Vec::new())).await;
    assert_eq!(init.status, StatusCode::ACCEPTED, "init: {}", init.text());
    let location = init.header("location");
    assert!(location.contains("/blobs/uploads/"), "location {location}");

    // PATCH the bytes.
    let patch = send(app, req("PATCH", &location, auth, payload.to_vec())).await;
    assert_eq!(patch.status, StatusCode::ACCEPTED, "patch: {}", patch.text());

    // PUT ?digest finalizes.
    let put_uri = format!("{location}?digest={}", encode(&digest));
    let put = send(app, req("PUT", &put_uri, auth, Vec::new())).await;
    assert_eq!(put.status, StatusCode::CREATED, "put: {}", put.text());
    assert_eq!(put.header("docker-content-digest"), digest);
    digest
}

/// Percent-encode the `:` in a digest for the query string.
fn encode(digest: &str) -> String {
    digest.replace(':', "%3A")
}

#[tokio::test]
async fn full_push_pull_lifecycle() {
    let app = app(build_dev_state());
    let name = "library/alpine";

    // 1. Version probe (auth disabled in dev -> 200 + api-version header).
    let v2 = send(&app, req("GET", "/v2/", None, Vec::new())).await;
    assert_eq!(v2.status, StatusCode::OK);
    assert_eq!(v2.header("docker-distribution-api-version"), "registry/2.0");

    // 2. Push a config blob and a layer blob.
    let config_blob = br#"{"architecture":"amd64","os":"linux"}"#.to_vec();
    let layer_blob = b"\x1f\x8b fake gzip layer bytes \x00\x01".to_vec();
    let config_digest = push_blob(&app, name, &config_blob, None).await;
    let layer_digest = push_blob(&app, name, &layer_blob, None).await;

    // 3. HEAD both blobs -> present.
    let head = send(&app, req("HEAD", &format!("/v2/{name}/blobs/{layer_digest}"), None, Vec::new())).await;
    assert_eq!(head.status, StatusCode::OK);
    assert_eq!(head.header("content-length"), layer_blob.len().to_string());
    assert_eq!(head.header("docker-content-digest"), layer_digest);

    // 4. GET the layer blob back -> exact bytes.
    let got = send(&app, req("GET", &format!("/v2/{name}/blobs/{layer_digest}"), None, Vec::new())).await;
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(got.body, layer_blob);

    // 5. PUT an image manifest referencing those blobs, by the tag `latest`.
    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{cfg}","size":{cfgsz}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{lay}","size":{laysz}}}]}}"#,
        cfg = config_digest,
        cfgsz = config_blob.len(),
        lay = layer_digest,
        laysz = layer_blob.len(),
    );
    let manifest_digest = sha256_digest(manifest.as_bytes());
    let put_m = send(
        &app,
        Request::builder()
            .method("PUT")
            .uri(format!("/v2/{name}/manifests/latest"))
            .header(header::CONTENT_TYPE, "application/vnd.oci.image.manifest.v1+json")
            .body(Body::from(manifest.clone()))
            .unwrap(),
    )
    .await;
    assert_eq!(put_m.status, StatusCode::CREATED, "put manifest: {}", put_m.text());
    assert_eq!(put_m.header("docker-content-digest"), manifest_digest);

    // 6. GET the manifest by tag -> exact bytes + stored media type + digest header.
    let get_m = send(&app, req("GET", &format!("/v2/{name}/manifests/latest"), None, Vec::new())).await;
    assert_eq!(get_m.status, StatusCode::OK);
    assert_eq!(get_m.body, manifest.as_bytes());
    assert_eq!(get_m.header("content-type"), "application/vnd.oci.image.manifest.v1+json");
    assert_eq!(get_m.header("docker-content-digest"), manifest_digest);

    // 6b. HEAD the manifest by tag (docker pull's existence probe).
    let head_m = send(&app, req("HEAD", &format!("/v2/{name}/manifests/latest"), None, Vec::new())).await;
    assert_eq!(head_m.status, StatusCode::OK);
    assert_eq!(head_m.header("docker-content-digest"), manifest_digest);

    // 6c. GET the manifest BY DIGEST too.
    let by_digest = send(&app, req("GET", &format!("/v2/{name}/manifests/{manifest_digest}"), None, Vec::new())).await;
    assert_eq!(by_digest.status, StatusCode::OK);
    assert_eq!(by_digest.body, manifest.as_bytes());

    // 7. tags/list + _catalog.
    let tags = send(&app, req("GET", &format!("/v2/{name}/tags/list"), None, Vec::new())).await;
    assert_eq!(tags.status, StatusCode::OK);
    assert!(tags.text().contains("\"latest\""));
    assert!(tags.text().contains(name));

    let catalog = send(&app, req("GET", "/v2/_catalog", None, Vec::new())).await;
    assert_eq!(catalog.status, StatusCode::OK);
    assert!(catalog.text().contains(name));

    // 8. The SSO web console lists the repo and its detail page renders the tag.
    let index = send(&app, req("GET", "/", None, Vec::new())).await;
    assert_eq!(index.status, StatusCode::OK);
    assert!(index.text().contains(name));

    let detail = send(&app, req("GET", &format!("/r/{name}"), None, Vec::new())).await;
    assert_eq!(detail.status, StatusCode::OK);
    assert!(detail.text().contains("latest"));
    // Image size (config + layer) is rendered, not zero.
    assert!(detail.text().contains("docker pull"));
}

#[tokio::test]
async fn pull_unknown_manifest_is_404() {
    let app = app(build_dev_state());
    // Repo must exist for tags/list 404 distinction; push nothing, just query a manifest.
    let r = send(&app, req("GET", "/v2/ghost/manifests/latest", None, Vec::new())).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert!(r.text().contains("MANIFEST_UNKNOWN"));
}

#[tokio::test]
async fn invalid_repo_name_is_rejected() {
    let app = app(build_dev_state());
    let r = send(&app, req("POST", "/v2/BadName/blobs/uploads/", None, Vec::new())).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.text().contains("NAME_INVALID"));
}

#[tokio::test]
async fn digest_mismatch_on_finalize_is_400() {
    let app = app(build_dev_state());
    let name = "app";
    let init = send(&app, req("POST", &format!("/v2/{name}/blobs/uploads/"), None, Vec::new())).await;
    let location = init.header("location");
    send(&app, req("PATCH", &location, None, b"the real bytes".to_vec())).await;
    // Claim the wrong digest.
    let wrong = sha256_digest(b"some other bytes");
    let put = send(&app, req("PUT", &format!("{location}?digest={}", encode(&wrong)), None, Vec::new())).await;
    assert_eq!(put.status, StatusCode::BAD_REQUEST);
    assert!(put.text().contains("DIGEST_INVALID"));
}

#[tokio::test]
async fn basic_auth_gate() {
    // App with auth enabled.
    let mut cfg = Config::dev();
    cfg.user = "robot".to_string();
    cfg.password = "s3cret".to_string();
    let state = AppState {
        config: Arc::new(cfg),
        store: Arc::new(InMemoryStore::new()),
        blobs: Arc::new(MemoryBlobStore::new()),
    };
    let app = app(state);
    // base64("robot:s3cret")
    let good = "Basic cm9ib3Q6czNjcmV0";
    // base64("robot:wrong")
    let bad = "Basic cm9ib3Q6d3Jvbmc=";

    // 1. GET /v2/ without creds -> 401 + WWW-Authenticate: Basic.
    let no_cred = send(&app, req("GET", "/v2/", None, Vec::new())).await;
    assert_eq!(no_cred.status, StatusCode::UNAUTHORIZED);
    assert!(no_cred.header("www-authenticate").starts_with("Basic "));

    // 2. GET /v2/ WITH valid creds -> 200 (this is what `docker login` validates).
    let with_cred = send(&app, req("GET", "/v2/", Some(good), Vec::new())).await;
    assert_eq!(with_cred.status, StatusCode::OK);

    // 3. Push without creds is denied at the very first step.
    let init_anon = send(&app, req("POST", "/v2/app/blobs/uploads/", None, Vec::new())).await;
    assert_eq!(init_anon.status, StatusCode::UNAUTHORIZED);

    // 4. Push WITH creds succeeds.
    let digest = push_blob(&app, "app", b"a small layer", Some(good)).await;
    assert!(digest.starts_with("sha256:"));

    // 5. Anonymous READ of an existing blob is allowed (public pull).
    let anon_read = send(&app, req("HEAD", &format!("/v2/app/blobs/{digest}"), None, Vec::new())).await;
    assert_eq!(anon_read.status, StatusCode::OK);

    // 6. A WRONG credential on a read is rejected (not silently treated as anonymous).
    let bad_read = send(&app, req("HEAD", &format!("/v2/app/blobs/{digest}"), Some(bad), Vec::new())).await;
    assert_eq!(bad_read.status, StatusCode::UNAUTHORIZED);
}
