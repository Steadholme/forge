//! End-to-end tests for the human-facing image detail pages (the SSO web console), driven in-process
//! against the in-memory store + blobs (NO database, NO volume). Exercises:
//! - the tag/manifest detail page for a single-platform image (config + layers with sizes, the pull
//!   command, the manifest digest, and the tags pointing at it),
//! - the manifest-list detail page (per-platform children, each linking to its own manifest page),
//! - resolution by tag AND by digest,
//! - the repository page linking each tag/digest to its manifest detail page, and
//! - the 404 branded error page for an unknown repo/tag.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use cellar::digest::sha256_digest;
use cellar::{app, build_dev_state};
use tower::ServiceExt;

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

fn get(_app: &axum::Router, uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

/// PUT a manifest body at `reference` with an explicit `Content-Type`.
async fn put_manifest(
    app: &axum::Router,
    name: &str,
    reference: &str,
    ctype: &str,
    body: &str,
) -> Resp {
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/v2/{name}/manifests/{reference}"))
        .header(header::CONTENT_TYPE, ctype)
        .body(Body::from(body.to_string()))
        .unwrap();
    send(app, req).await
}

const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";

/// A single-platform image manifest: config size 1024, one 1 MiB layer.
fn image_manifest() -> String {
    format!(
        r#"{{"schemaVersion":2,"mediaType":"{OCI_MANIFEST}","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{c:064x}","size":1024}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:{l:064x}","size":1048576}}]}}"#,
        c = 1u32,
        l = 2u32,
    )
}

#[tokio::test]
async fn image_manifest_detail_by_tag_and_digest() {
    let app = app(build_dev_state());
    let name = "library/alpine";

    let manifest = image_manifest();
    let digest = sha256_digest(manifest.as_bytes());
    let put = put_manifest(&app, name, "latest", OCI_MANIFEST, &manifest).await;
    assert_eq!(put.status, StatusCode::CREATED, "put: {}", put.text());

    // 1. Detail page BY TAG.
    let by_tag = send(&app, get(&app, &format!("/m/{name}?ref=latest"))).await;
    assert_eq!(by_tag.status, StatusCode::OK, "by tag: {}", by_tag.text());
    let html = by_tag.text();
    // The full manifest digest is rendered (in the metadata table title / mono cell).
    assert!(html.contains(&digest), "detail missing full digest");
    // The stored media type surfaces.
    assert!(html.contains(OCI_MANIFEST), "detail missing media type");
    // Config + Layers sections with sizes.
    assert!(html.contains("Layers"), "detail missing layers section");
    assert!(html.contains("Config"), "detail missing config section");
    assert!(html.contains("1.0 MB"), "detail missing layer size: {html}");
    // The canonical (by-digest) pull command.
    assert!(
        html.contains(&format!("docker pull registry.w33d.xyz/{name}@{digest}")),
        "detail missing pull command"
    );
    // The tag pointing at this manifest is listed, linking back to the repo.
    assert!(html.contains(">latest</a>"), "detail missing tag chip");
    assert!(
        html.contains(&format!("href=\"/r/{name}\"")),
        "detail missing back-to-repo link"
    );

    // 2. Same page resolved BY DIGEST (percent-encoded colon, as the links emit it).
    let dref = digest.replace(':', "%3A");
    let by_digest = send(&app, get(&app, &format!("/m/{name}?ref={dref}"))).await;
    assert_eq!(
        by_digest.status,
        StatusCode::OK,
        "by digest: {}",
        by_digest.text()
    );
    assert!(by_digest.text().contains(OCI_MANIFEST));

    // 3. The repository page links each tag AND its digest to the manifest detail page.
    let repo = send(&app, get(&app, &format!("/r/{name}"))).await;
    assert_eq!(repo.status, StatusCode::OK);
    let rhtml = repo.text();
    assert!(
        rhtml.contains(&format!("/m/{name}?ref=latest")),
        "repo page missing tag->manifest link"
    );
    assert!(
        rhtml.contains(&format!("/m/{name}?ref={dref}")),
        "repo page missing digest->manifest link"
    );
}

#[tokio::test]
async fn manifest_list_detail_lists_platforms() {
    let app = app(build_dev_state());
    let name = "library/multi";

    // Two per-arch image manifests pushed BY DIGEST.
    let amd64 = image_manifest();
    // A distinct arm64 body (different config size) so it has its own digest.
    let arm64 = amd64.replace("\"size\":1024", "\"size\":2048");
    let amd64_digest = sha256_digest(amd64.as_bytes());
    let arm64_digest = sha256_digest(arm64.as_bytes());
    for (d, b) in [(&amd64_digest, &amd64), (&arm64_digest, &arm64)] {
        let r = put_manifest(&app, name, d, OCI_MANIFEST, b).await;
        assert_eq!(r.status, StatusCode::CREATED, "child: {}", r.text());
    }

    // The image index pushed BY TAG, referencing the two children + their platforms.
    let index = format!(
        r#"{{"schemaVersion":2,"mediaType":"{OCI_INDEX}","manifests":[{{"mediaType":"{OCI_MANIFEST}","digest":"{amd}","size":{amdlen},"platform":{{"os":"linux","architecture":"amd64"}}}},{{"mediaType":"{OCI_MANIFEST}","digest":"{arm}","size":{armlen},"platform":{{"os":"linux","architecture":"arm64","variant":"v8"}}}}]}}"#,
        amd = amd64_digest,
        arm = arm64_digest,
        amdlen = amd64.len(),
        armlen = arm64.len(),
    );
    let put_idx = put_manifest(&app, name, "latest", OCI_INDEX, &index).await;
    assert_eq!(
        put_idx.status,
        StatusCode::CREATED,
        "index: {}",
        put_idx.text()
    );

    let detail = send(&app, get(&app, &format!("/m/{name}?ref=latest"))).await;
    assert_eq!(
        detail.status,
        StatusCode::OK,
        "index detail: {}",
        detail.text()
    );
    let html = detail.text();
    assert!(
        html.contains("Platforms"),
        "index detail missing platforms section"
    );
    assert!(html.contains("linux/amd64"), "missing amd64 platform");
    assert!(
        html.contains("linux/arm64/v8"),
        "missing arm64 platform + variant"
    );
    // Each child digest links to ITS OWN manifest detail page (list -> image manifests).
    let arm_ref = arm64_digest.replace(':', "%3A");
    assert!(
        html.contains(&format!("/m/{name}?ref={arm_ref}")),
        "index detail missing child manifest link"
    );
    assert!(
        html.contains("manifest list"),
        "index detail missing kind badge"
    );
}

#[tokio::test]
async fn unknown_repo_and_tag_render_branded_404() {
    let app = app(build_dev_state());

    // Unknown repository.
    let ghost = send(&app, get(&app, "/m/ghost?ref=latest")).await;
    assert_eq!(ghost.status, StatusCode::NOT_FOUND);
    assert!(
        ghost.text().contains("No repository"),
        "expected branded not-found"
    );

    // Existing repo, unknown tag.
    let name = "library/present";
    let manifest = image_manifest();
    put_manifest(&app, name, "latest", OCI_MANIFEST, &manifest).await;
    let missing = send(&app, get(&app, &format!("/m/{name}?ref=nope"))).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert!(
        missing.text().contains("No tag"),
        "expected unknown-tag not-found"
    );
}
