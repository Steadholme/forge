//! Loom — self-hosted git forge for the HOLDFAST stack.
//!
//! Loom serves TWO surfaces on one subdomain (`git.w33d.xyz`), split at the Sluice gateway:
//!
//! - The WEB UI at `/` is `auth=sso` (gateway-injected `X-Auth-*`): repo list + create, repo
//!   browse (files of the default branch + commit history + branches), an Issues tab, and a
//!   personal-access-token management page. Loom is internal-only and trusts the injected
//!   identity headers.
//! - The git SMART-HTTP protocol under `/git/` is `auth=public` at the gateway — `git` cannot
//!   speak the browser OIDC/cookie SSO — so Loom enforces its OWN HTTP Basic auth there against a
//!   PAT. `git http-backend` runs as a CGI to serve `info/refs` + `git-upload-pack`/`git-receive-pack`.
//!
//! Repository BYTES are bare git repos on a mounted volume (`<LOOM_DATA>/repos/{owner}/{name}.git`);
//! the Postgres store (db `loom`) keeps only the metadata (repos, issues, pats). The store trait
//! is async (handlers `.await` it directly; PgStore drives sqlx natively — no `block_in_place`).

pub mod auth;
pub mod config;
pub mod error;
pub mod gitops;
pub mod handlers;
pub mod model;
pub mod store;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::config::Config;
use crate::gitops::GitOps;
use crate::store::{InMemoryStore, PgStore, Store};

/// Outer request-body cap on the git smart-HTTP routes (1 GiB). A push body is buffered in
/// memory before being streamed to `git http-backend`; this is the guard against an unbounded
/// upload. (Streaming the body straight through is a deferred enhancement.)
pub const MAX_GIT_BODY: usize = 1024 * 1024 * 1024;

/// Shared application state. Cheap to clone (everything behind `Arc` / cheap string handles).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub git: GitOps,
}

/// Build the router wiring all endpoints onto `state`.
///
/// The web routes sit at the service root (Sluice forwards them unmodified). The `/git/` subtree
/// is a separate router with a large body limit (so pushes are not truncated) merged in.
pub fn app(state: AppState) -> Router {
    let git = Router::new()
        .route(
            "/git/{*path}",
            get(handlers::smart_http::handle).post(handlers::smart_http::handle),
        )
        .layer(DefaultBodyLimit::max(MAX_GIT_BODY))
        .with_state(state.clone());

    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        .route("/", get(handlers::repos::index))
        .route("/new", post(handlers::repos::create))
        .route("/r/{owner}/{name}", get(handlers::repos::view))
        .route("/r/{owner}/{name}/tree/{*path}", get(handlers::repos::tree))
        .route("/r/{owner}/{name}/blob/{*path}", get(handlers::repos::blob))
        .route(
            "/r/{owner}/{name}/issues",
            get(handlers::issues::list).post(handlers::issues::create),
        )
        .route(
            "/r/{owner}/{name}/issues/{number}/toggle",
            post(handlers::issues::toggle),
        )
        .route("/pats", get(handlers::pats::index).post(handlers::pats::create))
        .route("/pats/{id}/revoke", post(handlers::pats::revoke))
        // Reject a forged gateway identity (spoofed X-Auth-* from a rogue in-network peer):
        // when GATEWAY_HMAC_KEY is set, an injected identity MUST carry a valid X-Auth-Sig.
        // No-op when the key is unset or no identity is present (git smart-HTTP / dev).
        .layer(axum::middleware::from_fn(require_gateway_sig))
        .with_state(state)
        .merge(git)
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

/// Construct dev state: dev [`Config`] + an empty [`InMemoryStore`], with repo bytes under a
/// per-process temp directory so concurrent dev runs / tests never collide.
pub fn build_dev_state() -> AppState {
    let dir = std::env::temp_dir().join(format!("loom-dev-{}", random_alnum(8)));
    build_dev_state_at(dir.to_string_lossy())
}

/// Dev state with an explicit data dir (used by the integration tests for an isolated repo root).
pub fn build_dev_state_at(data_dir: impl Into<String>) -> AppState {
    let mut config = Config::dev();
    config.data_dir = data_dir.into();
    let git = GitOps::new(&config);
    AppState {
        config: Arc::new(config),
        store: Arc::new(InMemoryStore::new()),
        git,
    }
}

/// Build runtime state from the environment.
///
/// [`Config`] comes from [`Config::from_env`]. The store is selected by `LOOM_STORE`:
/// - `memory` (default): empty [`InMemoryStore`] — no database required.
/// - `postgres`: connect `DATABASE_URL` (db `loom`), run the idempotent migration, wire [`PgStore`].
///
/// The repos root (`<LOOM_DATA>/repos`) is created on startup so the first repo create succeeds.
pub async fn build_state_from_env() -> Result<AppState, String> {
    let config = Config::from_env();
    let git = GitOps::new(&config);

    tokio::fs::create_dir_all(git.repos_root())
        .await
        .map_err(|e| format!("create repos root {}: {e}", git.repos_root()))?;

    let store_kind = std::env::var("LOOM_STORE").unwrap_or_else(|_| "memory".to_string());
    let store: Arc<dyn Store> = match store_kind.as_str() {
        "postgres" => {
            let database_url = std::env::var("DATABASE_URL")
                .map_err(|_| "LOOM_STORE=postgres requires DATABASE_URL".to_string())?;
            tracing::info!("LOOM_STORE=postgres — connecting to database");
            let pg = PgStore::connect(&database_url)
                .await
                .map_err(|e| format!("connect postgres: {e}"))?;
            pg.migrate()
                .await
                .map_err(|e| format!("run migration: {e}"))?;
            tracing::info!("postgres store ready (migrated)");
            Arc::new(pg)
        }
        "memory" => Arc::new(InMemoryStore::new()),
        other => return Err(format!("unknown LOOM_STORE={other} (use memory|postgres)")),
    };

    Ok(AppState {
        config: Arc::new(config),
        store,
        git,
    })
}

/// Current wall-clock time in epoch seconds (created_at granularity).
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
}

/// Generate a random URL-safe alphanumeric string of `len` characters from a 62-symbol alphabet,
/// via the OS CSPRNG. Used for ids, the PAT secret, and the CSRF token.
pub fn random_alnum(len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect()
}
