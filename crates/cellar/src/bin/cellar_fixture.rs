//! Synthetic Cellar server for local UI review — in-memory store and blobs, no database,
//! no registry traffic. Seeds clearly synthetic repositories, manifests and tags so the console
//! renders exactly as the real handlers build it. `main.rs` remains the only production entry.

use std::net::SocketAddr;

use cellar::model::ManifestRec;
use cellar::{app, build_dev_state, AppState};

const LISTEN_ADDR: &str = "127.0.0.1:9136";
const MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let state = build_dev_state();
    if std::env::var("CELLAR_FIXTURE").as_deref() != Ok("empty") {
        seed(&state).await;
    }

    let addr: SocketAddr = LISTEN_ADDR.parse().expect("fixed fixture address is valid");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|error| panic!("failed to bind fixture server at {addr}: {error}"));

    tracing::info!(%addr, "Cellar synthetic fixture listening");
    axum::serve(listener, app(state))
        .await
        .expect("fixture server");
}

async fn seed(state: &AppState) {
    let now = 1_757_000_000_i64;
    let repos: [(&str, &[&str], i64); 8] = [
        (
            "steadholme/portal",
            &["v2-20260907", "latest", "rollback"],
            3_600,
        ),
        ("steadholme/beacon", &["v2-20260907", "latest"], 18_000),
        (
            "steadholme/loom",
            &["v2-20260907-r2", "latest", "rollback"],
            180_000,
        ),
        ("steadholme/corvid", &["latest", "rollback"], 200_000),
        ("steadholme/skiff", &["a21d52e", "latest"], 260_000),
        ("steadholme/anvil-runner", &["307eecc", "latest"], 300_000),
        ("library/postgres", &["16", "16-alpine"], 400_000),
        ("library/nginx", &["1.27"], 460_000),
    ];

    for (index, (name, tags, age)) in repos.iter().enumerate() {
        let created = now - age;
        state
            .store
            .ensure_repository(name, created)
            .await
            .expect("in-memory seed never fails");

        for (tag_index, tag) in tags.iter().enumerate() {
            // A stable synthetic digest per (repo, tag) — no real image is involved.
            let digest = format!("sha256:{:064x}", (index * 16 + tag_index + 1) as u128);
            let raw = format!(
                r#"{{"schemaVersion":2,"mediaType":"{MEDIA_TYPE}","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{digest}","size":1024}},"layers":[]}}"#
            );
            let size = raw.len() as i64;
            state
                .store
                .put_manifest(&ManifestRec {
                    id: ManifestRec::make_id(name, &digest),
                    repo: (*name).to_string(),
                    digest: digest.clone(),
                    media_type: MEDIA_TYPE.to_string(),
                    raw,
                    size,
                    created_at: created,
                })
                .await
                .expect("in-memory seed never fails");
            state
                .store
                .put_tag(name, tag, &digest, created)
                .await
                .expect("in-memory seed never fails");
        }
    }
}
