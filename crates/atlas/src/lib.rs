//! Atlas — infrastructure catalog & topology map for the HOLDFAST estate.
//!
//! Library root: defines [`AppState`], wires the routes via [`app`], and provides
//! [`build_dev_state`] (in-memory annotation store + the demo route seed, no database) and
//! [`build_state_from_env`] (env-selected store + the read-only routes source + Watchtower audit).
//! Integration tests consume [`app`] directly via `tower::oneshot`.
//!
//! Atlas is the IaC/portal capstone: it READS the gateway `routes` table (read-only, via
//! `ATLAS_ROUTES_DSN`) to discover every public service + its upstream + auth mode, overlays live
//! component status from Beacon, and lets an operator layer free-text metadata (owner/tier/notes)
//! on each service. It sits behind a Sluice `auth=sso` route at the subdomain ROOT
//! (`atlas.w33d.xyz`); the gateway forwards the path UNMODIFIED, so the routes below are real paths.
//!
//! Endpoints:
//! - `GET  /healthz`        liveness (container HEALTHCHECK, no auth)
//! - `GET  /`               the catalog: every host grouped by upstream service + status + notes
//! - `GET  /service/{key}`  one service's detail + the annotation edit form
//! - `POST /api/annotate`   save operator metadata for a service key (CSRF)
//! - `GET  /graph`          inline-SVG topology: the gateway -> each upstream, colored by auth mode
//! - `GET  /api/inventory`  the full inventory as JSON

pub mod audit;
pub mod auth;
pub mod beacon;
pub mod config;
pub mod error;
pub mod handlers;
pub mod http;
pub mod inventory;
pub mod routes_src;
pub mod store;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::routing::{get, post};
use axum::Router;

use crate::audit::AuditSink;
use crate::config::{env_nonempty, Config};
use crate::routes_src::{InMemoryRoutes, PgRoutesSource, RoutesSource};
use crate::store::{InMemoryStore, PgStore, Store};

/// Shared application state. Cheap to clone (everything behind `Arc` / a cloneable sink).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    /// Operator annotations (Atlas's OWN `atlas` database).
    pub store: Arc<dyn Store>,
    /// READ-ONLY view of the gateway `routes` table.
    pub routes: Arc<dyn RoutesSource>,
    pub audit: AuditSink,
}

/// Build the router wiring all endpoints onto `state`. Routes are explicit (no fallback): the
/// service owns its subdomain, so Sluice forwards these exact paths.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        .route("/", get(handlers::catalog::index))
        .route("/service/{key}", get(handlers::catalog::detail))
        .route("/api/annotate", post(handlers::catalog::annotate))
        .route("/graph", get(handlers::catalog::graph))
        .route("/api/inventory", get(handlers::catalog::api_inventory))
        .with_state(state)
}

/// Construct dev state: dev [`Config`], an empty [`InMemoryStore`], the demo route seed, and a
/// disabled audit sink (no network). Tests reuse this shape.
pub fn build_dev_state() -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store: Arc::new(InMemoryStore::new()),
        routes: Arc::new(InMemoryRoutes::demo()),
        audit: AuditSink::disabled(),
    }
}

/// Build runtime state from the environment.
///
/// The annotation store is selected by `ATLAS_STORE`:
/// - `memory` (default): empty [`InMemoryStore`] — no database required.
/// - `postgres`: connect `DATABASE_URL` (the `atlas` db), run the idempotent migration, wire
///   [`PgStore`].
///
/// The routes source is selected by `ATLAS_ROUTES_DSN`: set -> a READ-ONLY lazily-connected
/// [`PgRoutesSource`] over the shared `holdfast` DB; unset -> the in-memory demo seed (so a
/// zero-config boot still shows the known estate, with a warning). The audit sink is enabled by
/// `AUDIT_ENABLED` + `WATCHTOWER_URL` + `AUDIT_INGEST_TOKEN`. Returns an error string on
/// misconfiguration so `main` can fail loudly.
pub async fn build_state_from_env() -> Result<AppState, String> {
    let config = Config::from_env();

    let store_kind = env_nonempty("ATLAS_STORE").unwrap_or_else(|| "memory".to_string());
    let store: Arc<dyn Store> = match store_kind.as_str() {
        "postgres" => {
            let database_url = env_nonempty("DATABASE_URL")
                .ok_or_else(|| "ATLAS_STORE=postgres requires DATABASE_URL".to_string())?;
            tracing::info!("ATLAS_STORE=postgres — connecting to database");
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
        other => return Err(format!("unknown ATLAS_STORE={other} (use memory|postgres)")),
    };

    let routes: Arc<dyn RoutesSource> = match env_nonempty("ATLAS_ROUTES_DSN") {
        Some(dsn) => {
            tracing::info!("ATLAS_ROUTES_DSN set — reading the gateway routes table (read-only)");
            let src = PgRoutesSource::connect_lazy(&dsn)
                .map_err(|e| format!("open routes DSN pool: {e}"))?;
            Arc::new(src)
        }
        None => {
            tracing::warn!(
                "ATLAS_ROUTES_DSN unset — serving the built-in demo route seed (no live route table)"
            );
            Arc::new(InMemoryRoutes::demo())
        }
    };

    let audit = AuditSink::start(
        env_truthy("AUDIT_ENABLED"),
        &env_nonempty("WATCHTOWER_URL").unwrap_or_default(),
        env_nonempty("AUDIT_INGEST_TOKEN").as_deref(),
    );

    Ok(AppState {
        config: Arc::new(config),
        store,
        routes,
        audit,
    })
}

/// Interpret a boolean-ish env var (`on` / `true` / `1` / `yes`, case-insensitive).
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

/// Current wall-clock time in epoch seconds (the annotation `updated_at`).
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
}
