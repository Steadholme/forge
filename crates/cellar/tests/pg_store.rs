//! PostgreSQL `Store` integration test.
//!
//! Runs ONLY when `TEST_DATABASE_URL` is set (it needs an external Postgres). When unset the test
//! prints a note and returns early — it never fails the default `cargo test` run, which stays
//! database-free. Spin up a throwaway Postgres and run:
//!
//! ```text
//! docker run --rm -d --name cellar-testpg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=cellar \
//!   -p 127.0.0.1:55491:5432 postgres:18-alpine
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55491/cellar \
//!   cargo test --test pg_store -- --nocapture
//! docker rm -f cellar-testpg
//! ```
//!
//! Uses a multi-threaded runtime (matching production); the `Store` trait is async, so the
//! handlers `.await` sqlx natively with no sync-over-async bridge.

use std::sync::Arc;

use cellar::blobs::MemoryBlobStore;
use cellar::digest::sha256_digest;
use cellar::model::ManifestRec;
use cellar::store::{PgStore, Store};
use cellar::{app, build_dev_state, now_secs, AppState};
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use tower::ServiceExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_store_full_integration() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!(
            "NOTE: TEST_DATABASE_URL not set — skipping Postgres integration test (needs external \
             Postgres). This is expected for the default test run."
        );
        return;
    };

    // --- connect / migrate (idempotent: run twice) -------------------------
    let pg = PgStore::connect(&url).await.expect("connect to TEST_DATABASE_URL");
    pg.migrate().await.expect("migrate");
    pg.migrate().await.expect("migrate is idempotent");

    // Raw pool to reset the tables for a clean run.
    let raw = PgPoolOptions::new().max_connections(2).connect(&url).await.unwrap();
    for t in ["tags", "manifests", "blobs", "repositories"] {
        sqlx::query(&format!("DELETE FROM {t}")).execute(&raw).await.unwrap();
    }

    let store: Arc<dyn Store> = Arc::new(pg);
    let now = now_secs();
    let repo = "library/alpine";

    // --- repository + blob ------------------------------------------------
    store.ensure_repository(repo, now).await.unwrap();
    store.ensure_repository(repo, now + 1).await.unwrap(); // idempotent
    assert!(store.repo_exists(repo).await.unwrap());
    let names: Vec<String> = store.list_repositories().await.unwrap().into_iter().map(|r| r.name).collect();
    assert_eq!(names, vec![repo.to_string()]);

    let layer = b"a fake image layer blob";
    let layer_digest = sha256_digest(layer);
    store.put_blob(&layer_digest, layer.len() as i64, now).await.unwrap();
    store.put_blob(&layer_digest, 999, now).await.unwrap(); // idempotent (size unchanged)
    assert_eq!(store.blob_size(&layer_digest).await.unwrap(), Some(layer.len() as i64));
    assert_eq!(store.blob_size("sha256:missing").await.unwrap(), None);

    // --- manifest upsert + fetch ------------------------------------------
    let raw_manifest = format!(
        r#"{{"schemaVersion":2,"config":{{"size":10}},"layers":[{{"digest":"{layer_digest}","size":{}}}]}}"#,
        layer.len()
    );
    let digest = sha256_digest(raw_manifest.as_bytes());
    let rec = ManifestRec {
        id: ManifestRec::make_id(repo, &digest),
        repo: repo.to_string(),
        digest: digest.clone(),
        media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
        raw: raw_manifest.clone(),
        size: raw_manifest.len() as i64,
        created_at: now,
    };
    store.put_manifest(&rec).await.unwrap();
    store.put_manifest(&rec).await.unwrap(); // idempotent upsert on (repo,digest)
    let fetched = store.get_manifest(repo, &digest).await.unwrap().expect("manifest persisted");
    assert_eq!(fetched.raw, raw_manifest);
    assert_eq!(store.manifests_for(repo).await.unwrap().len(), 1);

    // --- tag pointer + list -----------------------------------------------
    store.put_tag(repo, "latest", &digest, now).await.unwrap();
    store.put_tag(repo, "v1", &digest, now).await.unwrap();
    assert_eq!(store.get_tag(repo, "latest").await.unwrap().unwrap(), digest);
    let tags: Vec<String> = store.tags_for(repo).await.unwrap().into_iter().map(|t| t.tag).collect();
    assert_eq!(tags, vec!["latest".to_string(), "v1".to_string()]);

    // last-writer-wins on the same tag
    let digest2 = sha256_digest(b"another manifest");
    store.put_tag(repo, "latest", &digest2, now + 5).await.unwrap();
    assert_eq!(store.get_tag(repo, "latest").await.unwrap().unwrap(), digest2);

    // --- delete a tag ------------------------------------------------------
    assert!(store.delete_tag(repo, "v1").await.unwrap());
    assert!(!store.delete_tag(repo, "v1").await.unwrap());
    let remaining: Vec<String> = store.tags_for(repo).await.unwrap().into_iter().map(|t| t.tag).collect();
    assert_eq!(remaining, vec!["latest".to_string()]);

    // --- the full HTTP app boots against Postgres (healthz) ----------------
    let state = AppState {
        config: build_dev_state().config,
        store: store.clone(),
        blobs: Arc::new(MemoryBlobStore::new()),
    };
    let app = app(state);
    let res = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/healthz")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);

    // Confirm row counts via raw queries (portable SQL path is live).
    let n: i64 = sqlx::query("SELECT count(*) AS n FROM manifests")
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("n")
        .unwrap();
    assert_eq!(n, 1);

    for t in ["tags", "manifests", "blobs", "repositories"] {
        sqlx::query(&format!("DELETE FROM {t}")).execute(&raw).await.unwrap();
    }
    eprintln!("pg_store integration test passed.");
}
