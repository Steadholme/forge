//! End-to-end tests for RETENTION: the dry-run Preview vs the mutating Apply, keep-rule protection
//! (newest-N kept), and the absolute `latest` protection. Tags are seeded through a held
//! `InMemoryStore` handle so their push times are controlled; the panel is driven over HTTP.

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

/// POST an admin form (admin group + double-submit CSRF cookie/token supplied).
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

/// Seed repo `app` with four distinctly-timed tags + their manifests. Note `latest` is deliberately
/// NOT the newest (t=150 < mid's t=200), so keeping it can only come from the latest-protection.
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
async fn preview_lists_candidates_without_mutating_then_apply_deletes() {
    let store = Arc::new(InMemoryStore::new());
    seed(&store).await;
    // keep_last = 1 keeps only the single newest tag (`new`, t=300); `latest` is kept by protection.
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

    // --- Preview: a DRY RUN. It lists `old` + `mid`, and NOT `new` (newest, kept) or `latest`. ---
    let preview = admin_post(
        &app,
        "/admin/retention/preview",
        format!("csrf_token={CSRF}"),
    )
    .await;
    assert_eq!(preview.status, StatusCode::OK, "{}", preview.text());
    let html = preview.text();
    assert!(html.contains(">old<"), "preview should list 'old': {html}");
    assert!(html.contains(">mid<"), "preview should list 'mid'");
    assert!(
        !html.contains(">new<"),
        "preview must NOT list the newest tag 'new'"
    );
    // Preview must not mutate: all four tags still present.
    assert_eq!(
        store.tags_for("app").await.unwrap().len(),
        4,
        "preview mutated the store"
    );

    // --- Apply: deletes the non-kept tags, keeps `new` + `latest`, and GC-reclaims orphans. ---
    let apply = admin_post(&app, "/admin/retention/apply", format!("csrf_token={CSRF}")).await;
    assert_eq!(apply.status, StatusCode::OK, "{}", apply.text());
    assert!(
        apply.text().contains("Retention applied"),
        "{}",
        apply.text()
    );

    let mut remaining: Vec<String> = store
        .tags_for("app")
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.tag)
        .collect();
    remaining.sort();
    assert_eq!(remaining, vec!["latest".to_string(), "new".to_string()]);

    // The orphaned manifests (old/mid) were reclaimed through the shared GC path; new/latest remain.
    let mut digests: Vec<String> = store
        .manifests_for("app")
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.digest)
        .collect();
    digests.sort();
    assert_eq!(
        digests,
        vec!["sha256:bb".to_string(), "sha256:dd".to_string()]
    );
}

#[tokio::test]
async fn keep_days_window_keeps_recent_tags() {
    let store = Arc::new(InMemoryStore::new());
    let now = cellar::now_secs();
    store.ensure_repository("svc", now).await.unwrap();
    store
        .put_manifest(&manifest("svc", "sha256:11"))
        .await
        .unwrap();
    store
        .put_manifest(&manifest("svc", "sha256:22"))
        .await
        .unwrap();
    // `recent` pushed an hour ago; `stale` pushed 100 days ago.
    store
        .put_tag("svc", "recent", "sha256:11", now - 3_600)
        .await
        .unwrap();
    store
        .put_tag("svc", "stale", "sha256:22", now - 100 * 86_400)
        .await
        .unwrap();
    // keep_last = 0 (ignored), keep_days = 1: only tags pushed within the last day survive.
    store
        .create_retention_rule(&RetentionRule {
            id: "ret-days".into(),
            repo_pattern: "svc".into(),
            keep_last: 0,
            keep_days: 1,
            enabled: true,
        })
        .await
        .unwrap();
    let app = app(state_with(store.clone()));

    let preview = admin_post(
        &app,
        "/admin/retention/preview",
        format!("csrf_token={CSRF}"),
    )
    .await;
    let html = preview.text();
    assert!(
        html.contains(">stale<"),
        "stale (out of window) should be a candidate"
    );
    assert!(
        !html.contains(">recent<"),
        "recent (in window) must be kept"
    );
}

#[tokio::test]
async fn disabled_rule_deletes_nothing() {
    let store = Arc::new(InMemoryStore::new());
    seed(&store).await;
    store
        .create_retention_rule(&RetentionRule {
            id: "ret-off".into(),
            repo_pattern: "app".into(),
            keep_last: 1,
            keep_days: 0,
            enabled: false, // disabled => no effect
        })
        .await
        .unwrap();
    let app = app(state_with(store.clone()));

    let apply = admin_post(&app, "/admin/retention/apply", format!("csrf_token={CSRF}")).await;
    assert_eq!(apply.status, StatusCode::OK);
    assert!(
        apply.text().contains("Nothing to delete"),
        "{}",
        apply.text()
    );
    assert_eq!(
        store.tags_for("app").await.unwrap().len(),
        4,
        "disabled rule must not delete"
    );
}

#[tokio::test]
async fn create_requires_admin_csrf_and_valid_input() {
    let store = Arc::new(InMemoryStore::new());
    let app = app(state_with(store.clone()));

    // Not an admin -> 403 (before any CSRF/validation).
    let anon = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/admin/retention/create")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(
                "repo_pattern=app&keep_last=5&keep_days=0&csrf_token=x",
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(anon.status, StatusCode::FORBIDDEN);

    // Admin but mismatched CSRF -> 400.
    let bad_csrf = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/admin/retention/create")
            .header("x-auth-groups", "admins")
            .header(header::COOKIE, "__Host-csrf=cookie")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(
                "repo_pattern=app&keep_last=5&keep_days=0&csrf_token=form",
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(bad_csrf.status, StatusCode::BAD_REQUEST);

    // A rule keeping nothing (keep_last=0 AND keep_days=0) is rejected.
    let both_zero = admin_post(
        &app,
        "/admin/retention/create",
        format!("repo_pattern=app&keep_last=0&keep_days=0&csrf_token={CSRF}"),
    )
    .await;
    assert_eq!(
        both_zero.status,
        StatusCode::BAD_REQUEST,
        "{}",
        both_zero.text()
    );
    assert!(store.list_retention_rules().await.unwrap().is_empty());

    // A valid rule is created.
    let ok = admin_post(
        &app,
        "/admin/retention/create",
        format!("repo_pattern=library/%2A&keep_last=10&keep_days=0&csrf_token={CSRF}"),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text());
    let rules = store.list_retention_rules().await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].repo_pattern, "library/*");
    assert_eq!(rules[0].keep_last, 10);
    assert!(rules[0].enabled);
}
