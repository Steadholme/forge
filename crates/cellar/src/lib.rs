//! Cellar — an OCI / Docker Registry HTTP API V2 container registry for the HOLDFAST stack.
//!
//! Two surfaces on one subdomain (`registry.w33d.xyz`), split at the gateway:
//! - **`/` web console — `auth=sso`.** The browser UI: list repositories, drill into a repo's
//!   tags, delete a tag. The gateway injects the verified `X-Auth-*` identity; Cellar trusts it.
//! - **`/v2/` registry protocol — `auth=public` at the gateway, Cellar's OWN HTTP Basic auth.**
//!   The CLI surface `docker login`/`push`/`pull` talks to, because the docker client cannot do the
//!   browser OIDC/cookie SSO. Pushes (and the `docker login` probe) require Basic credentials;
//!   public repos may be pulled anonymously.
//!
//! Storage: manifests/tags/repositories/blob-metadata in Postgres (db `cellar`, portable standard
//! SQL, runtime queries — no macros, no database needed to BUILD); blob BYTES content-addressed on
//! the `CELLAR_DATA` volume at `blobs/sha256/<hex>`. Both seams have an in-memory implementation so
//! the default `cargo test` run is database- and volume-free.

pub mod auth;
pub mod blobs;
pub mod config;
pub mod digest;
pub mod error;
pub mod handlers;
pub mod model;
pub mod names;
pub mod store;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::DefaultBodyLimit;
use axum::routing::{any, get, post};
use axum::Router;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::blobs::{BlobStore, FsBlobStore, MemoryBlobStore};
use crate::config::Config;
use crate::store::{InMemoryStore, PgStore, Store};

/// Hard cap on a single uploaded blob/manifest body (1 GiB). Generous so real image layers push
/// in one request; streaming-to-disk for arbitrarily large layers is a DEFERRED refinement.
const BODY_LIMIT: usize = 1024 * 1024 * 1024;

/// Shared application state. Cheap to clone (everything behind `Arc`).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub blobs: Arc<dyn BlobStore>,
}

/// Build the router wiring both surfaces onto `state`.
///
/// `/v2/{*path}` is a single catch-all dispatched in [`handlers::registry`] because repository
/// names contain slashes and cannot mix with fixed suffixes in axum's path matcher.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        // --- SSO web console ---
        .route("/", get(handlers::web::index))
        .route("/r/{*name}", get(handlers::web::repo_detail))
        .route("/m/{*name}", get(handlers::web::manifest_detail))
        .route("/delete-tag", post(handlers::web::delete_tag))
        // --- /admin subtree (admin-gated: storage accounting + garbage collection) ---
        .route("/admin", get(handlers::admin::index))
        .route("/admin/gc", post(handlers::admin::gc))
        // Retention: keep-rules, dry-run preview, and an apply (delete + GC) action.
        .route("/admin/retention", get(handlers::retention::index))
        .route("/admin/retention/create", post(handlers::retention::create))
        .route("/admin/retention/toggle", post(handlers::retention::toggle))
        .route("/admin/retention/delete", post(handlers::retention::delete))
        .route("/admin/retention/preview", post(handlers::retention::preview))
        .route("/admin/retention/apply", post(handlers::retention::apply))
        // Robot accounts: mint (token shown once), list, disable, delete.
        .route("/admin/robots", get(handlers::robots::index))
        .route("/admin/robots/create", post(handlers::robots::create))
        .route("/admin/robots/toggle", post(handlers::robots::toggle))
        .route("/admin/robots/delete", post(handlers::robots::delete))
        // --- /v2/ registry protocol (Basic auth done inside the handlers) ---
        .route("/v2", any(handlers::registry::version_check))
        .route("/v2/", any(handlers::registry::version_check))
        .route("/v2/{*path}", any(handlers::registry::dispatch))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        // Reject a forged gateway identity (spoofed X-Auth-* from a rogue in-network peer):
        // when GATEWAY_HMAC_KEY is set, an injected identity MUST carry a valid X-Auth-Sig.
        // No-op when the key is unset or no identity is present (/v2/ CLI paths / dev).
        .layer(axum::middleware::from_fn(require_gateway_sig))
        .with_state(state)
}

/// Middleware enforcing [`auth::gateway_identity_ok`] — 401 on a missing/invalid signature.
async fn require_gateway_sig(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if auth::gateway_identity_ok(req.headers()) {
        next.run(req).await
    } else {
        (
            axum::http::StatusCode::UNAUTHORIZED,
            "invalid or missing gateway identity signature",
        )
            .into_response()
    }
}

/// Construct dev state: dev [`Config`] + empty in-memory metadata + in-memory blobs. Used by
/// `main`'s memory mode and by the integration tests, so they need NO database and NO volume.
pub fn build_dev_state() -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store: Arc::new(InMemoryStore::new()),
        blobs: Arc::new(MemoryBlobStore::new()),
    }
}

/// Build runtime state from the environment.
///
/// The metadata store is selected by `CELLAR_STORE` (`memory` default | `postgres`). The blob
/// backend defaults to `fs` (the `CELLAR_DATA` volume) when the store is `postgres`, else
/// `memory`; `CELLAR_BLOBS` (`memory` | `fs`) overrides. Returns an error string on
/// misconfiguration so `main` can fail loudly.
pub async fn build_state_from_env() -> Result<AppState, String> {
    let config = Config::from_env();

    let store_kind = std::env::var("CELLAR_STORE").unwrap_or_else(|_| "memory".to_string());
    let store: Arc<dyn Store> = match store_kind.as_str() {
        "postgres" => {
            let database_url = std::env::var("DATABASE_URL")
                .map_err(|_| "CELLAR_STORE=postgres requires DATABASE_URL".to_string())?;
            tracing::info!("CELLAR_STORE=postgres — connecting to database");
            let pg = PgStore::connect(&database_url)
                .await
                .map_err(|e| format!("connect postgres: {e}"))?;
            pg.migrate()
                .await
                .map_err(|e| format!("run migration: {e}"))?;
            tracing::info!("postgres metadata store ready (migrated)");
            Arc::new(pg)
        }
        "memory" => Arc::new(InMemoryStore::new()),
        other => return Err(format!("unknown CELLAR_STORE={other} (use memory|postgres)")),
    };

    let default_blobs = if store_kind == "postgres" { "fs" } else { "memory" };
    let blobs_kind = std::env::var("CELLAR_BLOBS").unwrap_or_else(|_| default_blobs.to_string());
    let blobs: Arc<dyn BlobStore> = match blobs_kind.as_str() {
        "fs" => {
            tracing::info!(data_dir = config.data_dir, "CELLAR_BLOBS=fs — content-addressed volume");
            Arc::new(
                FsBlobStore::open(&config.data_dir)
                    .await
                    .map_err(|e| format!("open blob volume: {e}"))?,
            )
        }
        "memory" => Arc::new(MemoryBlobStore::new()),
        other => return Err(format!("unknown CELLAR_BLOBS={other} (use memory|fs)")),
    };

    if config.auth_enabled() {
        tracing::info!(user = config.user, "/v2/ HTTP Basic auth ENABLED");
    } else {
        tracing::warn!("/v2/ HTTP Basic auth DISABLED (CELLAR_USER empty) — dev mode");
    }

    Ok(AppState {
        config: Arc::new(config),
        store,
        blobs,
    })
}

/// Current wall-clock time in epoch seconds.
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
}

/// Generate a random URL-safe alphanumeric string of `len` characters (62-symbol alphabet), via
/// the OS CSPRNG. Used for the double-submit CSRF token.
pub fn random_alnum(len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect()
}
