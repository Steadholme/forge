//! Forge — one container hosting the HOLDFAST devplatform surfaces (git forge / container
//! registry / infrastructure catalog).
//!
//! Each surface is its OWN library crate (Loom/Cellar/Atlas), reused verbatim: same schema, same
//! routes, same templates, same OWN database, same subdomain, same on-disk data volume. This
//! binary only adds a **Host-based vhost demux** so the estate runs ONE deployable instead of
//! three. The gateway points `git.w33d.xyz`, `registry.w33d.xyz` and `atlas.w33d.xyz` all at this
//! container; each request is dispatched to the matching surface's router by its `Host` header.
//! Because the surfaces keep their exact paths and separate databases, everything downstream is
//! unchanged — in particular:
//!
//! - **Loom (`git.w33d.xyz`)** keeps its SSO web UI at `/` AND its git smart-HTTP under `/git/`
//!   (`auth=public` at the gateway, Loom's OWN HTTP Basic/PAT auth). `git http-backend` runs as a
//!   CGI exactly as standalone; bare repos live on the `LOOM_DATA` volume.
//! - **Cellar (`registry.w33d.xyz`)** keeps its SSO web console at `/` AND the Docker Registry
//!   HTTP API V2 under `/v2/`. The demux forwards the FULL request (headers + body) to Cellar's
//!   router by Host, so the `/v2/` HTTP **Basic** auth (NOT SSO — the docker CLI cannot do OIDC)
//!   is evaluated by Cellar exactly as it was standalone. Blob bytes live on the `CELLAR_DATA`
//!   volume.
//! - **Atlas (`atlas.w33d.xyz`)** keeps its catalog/topology UI and READS the gateway `routes`
//!   table READ-ONLY via `ATLAS_ROUTES_DSN` (lazily-connected pool — a down route table degrades
//!   to a banner, never blocks startup), overlaying live Beacon status.
//!
//! The demux also matches the bare internal service-name labels (`loom` / `cellar` / `atlas`) so
//! in-cluster callers that POST to `http://<name>:9030` still resolve.
//!
//! `healthcheck` subcommand: a dependency-free loopback `GET /healthz` (host-agnostic) used as the
//! container HEALTHCHECK, so the image needs no curl.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tower::ServiceExt;

/// Default listen address — internal-only; the gateway fronts the three subdomains at this upstream.
const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9030";

/// The three composed per-surface routers, dispatched by Host. Cheap to clone (each `Router` is
/// `Arc`-backed internally).
#[derive(Clone)]
struct Vhosts {
    git: Router,
    registry: Router,
    atlas: Router,
}

#[tokio::main]
async fn main() {
    // Container HEALTHCHECK path — handled before any setup, exits the process.
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(run_healthcheck());
    }

    tracing_subscriber::fmt::init();

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());

    // Each surface connects to its OWN database and migrates idempotently — exactly what the
    // standalone service did. A failure here is fatal (the surface cannot serve without its DB).
    let git = build_git().await.unwrap_or_else(|e| fatal("git (loom)", e));
    let registry = build_registry()
        .await
        .unwrap_or_else(|e| fatal("registry (cellar)", e));
    let atlas = build_atlas().await.unwrap_or_else(|e| fatal("atlas", e));

    let app = Router::new()
        // Host-agnostic liveness for the container HEALTHCHECK + estate probes.
        .route("/healthz", get(|| async { "ok" }))
        .fallback(dispatch)
        .with_state(Vhosts {
            git,
            registry,
            atlas,
        });

    let addr: SocketAddr = bind_addr.parse().expect("invalid BIND_ADDR");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));
    tracing::info!(%addr, "Forge listening (git/registry/atlas vhost demux)");
    axum::serve(listener, app).await.expect("server error");
}

/// Dispatch one request to the surface matching its `Host` header. An unknown host is a 404 — we
/// never silently serve one surface under another's vhost. The full request (headers + body) is
/// forwarded, so Cellar's `/v2/` Basic auth and Loom's `/git/` PAT auth still apply unchanged.
async fn dispatch(State(v): State<Vhosts>, req: Request) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    // Match on the leading label, ignoring any port. Accept BOTH the gateway subdomain label
    // (`git`/`registry`/`atlas`) AND the bare internal service-name label (`loom`/`cellar`/`atlas`)
    // a caller uses when POSTing to `http://<name>:9030`.
    let label = host
        .split(':')
        .next()
        .unwrap_or("")
        .split('.')
        .next()
        .unwrap_or("");
    let router = match label {
        "git" | "loom" => v.git,
        "registry" | "cellar" => v.registry,
        "atlas" => v.atlas,
        _ => return (StatusCode::NOT_FOUND, "unknown devplatform host").into_response(),
    };
    // `Router` is a tower `Service` (the exact `app(state).oneshot(req)` path the surfaces' own
    // tests use); its error type is `Infallible`.
    match router.oneshot(req).await {
        Ok(resp) => resp,
        Err(e) => match e {},
    }
}

/// Build the git (Loom) surface router against `LOOM_DATABASE_URL`.
///
/// State is built EXPLICITLY (not via `loom::build_state_from_env`, which reads the bare
/// `DATABASE_URL` and would collide with the other in-process surfaces): connect + migrate Loom's
/// OWN database, construct `GitOps` from `Config::from_env()` (so `LOOM_DATA`, `GIT_HTTP_BACKEND`,
/// `GIT_BIN` and `PUBLIC_BASE_URL` are honored), and ensure the bare-repo root exists — exactly as
/// Loom's own `build_state_from_env` does. Loom shells out to `git`/`git http-backend` per request
/// (no persistent background task), so nothing else needs spawning here.
async fn build_git() -> Result<Router, String> {
    let dsn = require_env("LOOM_DATABASE_URL")?;
    let config = loom::config::Config::from_env();
    let git = loom::gitops::GitOps::new(&config);

    tokio::fs::create_dir_all(git.repos_root())
        .await
        .map_err(|e| format!("create repos root {}: {e}", git.repos_root()))?;

    let pg = loom::store::PgStore::connect(&dsn)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    pg.migrate().await.map_err(|e| format!("migrate: {e}"))?;
    tracing::info!("git (loom) store ready");

    let state = loom::AppState {
        config: Arc::new(config),
        store: Arc::new(pg),
        git,
    };
    Ok(loom::app(state))
}

/// Build the registry (Cellar) surface router against `CELLAR_DATABASE_URL`, with the on-disk blob
/// volume at `CELLAR_DATA`.
///
/// State is built EXPLICITLY (not via `cellar::build_state_from_env`): connect + migrate Cellar's
/// OWN database, then open the content-addressed `FsBlobStore` on `CELLAR_DATA` — the production
/// pairing Cellar's own env path picks (`CELLAR_STORE=postgres` => `fs` blobs). `Config::from_env()`
/// carries `CELLAR_USER`/`CELLAR_PASSWORD`, so the `/v2/` HTTP Basic auth is enforced by Cellar's
/// router exactly as standalone.
async fn build_registry() -> Result<Router, String> {
    let dsn = require_env("CELLAR_DATABASE_URL")?;
    let config = cellar::config::Config::from_env();

    let pg = cellar::store::PgStore::connect(&dsn)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    pg.migrate().await.map_err(|e| format!("migrate: {e}"))?;
    tracing::info!("registry (cellar) metadata store ready");

    let blobs = cellar::blobs::FsBlobStore::open(&config.data_dir)
        .await
        .map_err(|e| format!("open blob volume: {e}"))?;
    tracing::info!(data_dir = config.data_dir, "registry (cellar) blob volume ready");

    if config.auth_enabled() {
        tracing::info!(user = config.user, "/v2/ HTTP Basic auth ENABLED");
    } else {
        tracing::warn!("/v2/ HTTP Basic auth DISABLED (CELLAR_USER empty) — dev mode");
    }

    let state = cellar::AppState {
        config: Arc::new(config),
        store: Arc::new(pg),
        blobs: Arc::new(blobs),
    };
    Ok(cellar::app(state))
}

/// Build the atlas surface router against `ATLAS_DATABASE_URL`, with the READ-ONLY routes source
/// and the Watchtower audit emitter.
///
/// State is built EXPLICITLY (not via `atlas::build_state_from_env`): connect + migrate Atlas's OWN
/// `atlas` database (the operator annotations), wire the READ-ONLY `PgRoutesSource` over
/// `ATLAS_ROUTES_DSN` (lazily-connected — a down route table degrades, never blocks startup;
/// unset => the in-memory demo seed), and start Atlas's audit sink exactly as Atlas does
/// (`AUDIT_ENABLED` + `WATCHTOWER_URL` + `AUDIT_INGEST_TOKEN`). The audit worker is `tokio::spawn`ed
/// inside `AuditSink::start`, so its background task is preserved.
async fn build_atlas() -> Result<Router, String> {
    let dsn = require_env("ATLAS_DATABASE_URL")?;
    let config = atlas::config::Config::from_env();

    let pg = atlas::store::PgStore::connect(&dsn)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    pg.migrate().await.map_err(|e| format!("migrate: {e}"))?;
    tracing::info!("atlas store ready");

    let routes: Arc<dyn atlas::routes_src::RoutesSource> =
        match atlas::config::env_nonempty("ATLAS_ROUTES_DSN") {
            Some(routes_dsn) => {
                tracing::info!(
                    "ATLAS_ROUTES_DSN set — reading the gateway routes table (read-only)"
                );
                let src = atlas::routes_src::PgRoutesSource::connect_lazy(&routes_dsn)
                    .map_err(|e| format!("open routes DSN pool: {e}"))?;
                Arc::new(src)
            }
            None => {
                tracing::warn!(
                    "ATLAS_ROUTES_DSN unset — serving the built-in demo route seed (no live route table)"
                );
                Arc::new(atlas::routes_src::InMemoryRoutes::demo())
            }
        };

    let audit = atlas::audit::AuditSink::start(
        env_truthy("AUDIT_ENABLED"),
        &atlas::config::env_nonempty("WATCHTOWER_URL").unwrap_or_default(),
        atlas::config::env_nonempty("AUDIT_INGEST_TOKEN").as_deref(),
    );

    let state = atlas::AppState {
        config: Arc::new(config),
        store: Arc::new(pg),
        routes,
        audit,
    };
    Ok(atlas::app(state))
}

/// Interpret a boolean-ish env var (`on` / `true` / `1` / `yes`, case-insensitive). Mirrors the
/// private `env_truthy` Atlas uses in its own `build_state_from_env`, so audit is gated identically.
fn env_truthy(key: &str) -> bool {
    matches!(
        std::env::var(key)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "on" | "true" | "1" | "yes"
    )
}

/// Read a required env var, returning a descriptive error when unset/empty.
fn require_env(key: &str) -> Result<String, String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(format!("{key} is required")),
    }
}

/// Log a fatal startup error for one surface and exit.
fn fatal(surface: &str, err: String) -> ! {
    tracing::error!(surface, error = %err, "failed to build devplatform surface");
    std::process::exit(1);
}

/// GET `/healthz` over a raw TCP socket on the loopback. Returns the process exit code.
fn run_healthcheck() -> i32 {
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());
    let port = bind_addr.rsplit(':').next().unwrap_or("9030");
    let target = format!("127.0.0.1:{port}");
    match healthcheck_once(&target) {
        Ok(true) => 0,
        Ok(false) => {
            eprintln!("healthcheck: {target} did not return 200");
            1
        }
        Err(e) => {
            eprintln!("healthcheck: {target} error: {e}");
            1
        }
    }
}

fn healthcheck_once(target: &str) -> std::io::Result<bool> {
    let addr: SocketAddr = target
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{e}")))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    Ok(buf.lines().next().unwrap_or("").contains("200"))
}
