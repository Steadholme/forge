//! Read-only view of the gateway's `routes` table.
//!
//! Atlas never owns this data — Sluice does. Atlas reads it READ-ONLY via `ATLAS_ROUTES_DSN`
//! (the shared `holdfast` DB) to inventory every public service, its upstream, and its auth mode.
//! The seam mirrors the rest of the estate: handlers + the inventory builder depend only on the
//! async trait, so an in-memory fake ([`InMemoryRoutes`], used by dev + tests) and a live
//! [`PgRoutesSource`] are interchangeable behind `Arc<dyn RoutesSource>`.
//!
//! RESILIENCE: the Pg source uses a LAZILY-connected pool ([`PgPoolOptions::connect_lazy`]), so a
//! down/misconfigured route DB never blocks startup; the failure surfaces only when a query runs,
//! and the handler degrades to an "route table unavailable" banner (never a page error).
//!
//! The table is exactly Sluice's portable schema:
//! `routes(name TEXT PK, host TEXT, path_prefix TEXT, upstream TEXT, protected BOOLEAN, auth TEXT,
//! waf BOOLEAN)`.

use std::time::Duration;

use async_trait::async_trait;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

/// Per-query acquire timeout — a down route DB fails fast (and degrades) instead of hanging.
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(3);

/// One row of the gateway `routes` table.
#[derive(Clone, Debug)]
pub struct Route {
    pub name: String,
    pub host: String,
    pub path_prefix: String,
    pub upstream: String,
    pub protected: bool,
    pub auth: String,
    pub waf: bool,
}

/// Read-only source of gateway routes. `Err` means the route table is unreachable/broken and the
/// caller should DEGRADE (show a banner), never surface a page error.
#[async_trait]
pub trait RoutesSource: Send + Sync {
    async fn list_routes(&self) -> Result<Vec<Route>, String>;
}

// ---------------------------------------------------------------------------
// In-memory routes (dev + tests). `demo()` seeds the known estate so the dashboard is useful
// with no database; `down()` simulates an unreachable route table.
// ---------------------------------------------------------------------------

pub struct InMemoryRoutes {
    routes: Vec<Route>,
    down: bool,
}

impl InMemoryRoutes {
    pub fn new(routes: Vec<Route>) -> Self {
        Self {
            routes,
            down: false,
        }
    }

    /// A source that always errors (to exercise the degrade-on-outage path).
    pub fn down() -> Self {
        Self {
            routes: Vec::new(),
            down: true,
        }
    }

    /// A representative seed of the live Steadholme route table — so dev/`cargo run` (and the
    /// integration tests) show a meaningful catalog with no database configured.
    pub fn demo() -> Self {
        Self::new(demo_routes())
    }
}

#[async_trait]
impl RoutesSource for InMemoryRoutes {
    async fn list_routes(&self) -> Result<Vec<Route>, String> {
        if self.down {
            return Err("simulated route-table outage".to_string());
        }
        Ok(self.routes.clone())
    }
}

fn r(name: &str, host: &str, path: &str, upstream: &str, auth: &str, waf: bool) -> Route {
    Route {
        name: name.to_string(),
        host: host.to_string(),
        path_prefix: path.to_string(),
        upstream: upstream.to_string(),
        protected: auth != "public",
        auth: auth.to_string(),
        waf,
    }
}

/// The estate's host-based routes (mirrors `deploy/routes.seed.json`).
fn demo_routes() -> Vec<Route> {
    vec![
        r(
            "id-api",
            "id.w33d.xyz",
            "/api",
            "http://whoami:80",
            "bearer",
            false,
        ),
        r(
            "id-root",
            "id.w33d.xyz",
            "/",
            "https://keystone:8443",
            "public",
            true,
        ),
        r(
            "status-root",
            "status.w33d.xyz",
            "/",
            "http://beacon:8400",
            "public",
            false,
        ),
        r(
            "vitals-root",
            "vitals.w33d.xyz",
            "/",
            "http://vitals:8300",
            "sso",
            false,
        ),
        r(
            "audit-root",
            "audit.w33d.xyz",
            "/",
            "http://watchtower:8500",
            "sso",
            false,
        ),
        r(
            "portal-root",
            "w33d.xyz",
            "/",
            "http://portal:8600",
            "sso",
            false,
        ),
        r(
            "blog-root",
            "blog.w33d.xyz",
            "/",
            "http://inkwell:8700",
            "sso",
            false,
        ),
        r(
            "forum-root",
            "forum.w33d.xyz",
            "/",
            "http://agora:8710",
            "sso",
            false,
        ),
        r(
            "wiki-root",
            "wiki.w33d.xyz",
            "/",
            "http://lattice:8720",
            "sso",
            false,
        ),
        r(
            "paste-root",
            "paste.w33d.xyz",
            "/",
            "http://pastefire:8730",
            "sso",
            false,
        ),
        r(
            "drive-share",
            "drive.w33d.xyz",
            "/s/",
            "http://aperture:8900",
            "public",
            false,
        ),
        r(
            "drive-root",
            "drive.w33d.xyz",
            "/",
            "http://aperture:8900",
            "sso",
            false,
        ),
        r(
            "search-root",
            "search.w33d.xyz",
            "/",
            "http://cortex:8950",
            "sso",
            false,
        ),
        r(
            "cal-root",
            "cal.w33d.xyz",
            "/",
            "http://almanac:8960",
            "sso",
            false,
        ),
        r(
            "rss-root",
            "rss.w33d.xyz",
            "/",
            "http://current:8970",
            "sso",
            false,
        ),
        r(
            "clip-root",
            "clip.w33d.xyz",
            "/",
            "http://magpie:8980",
            "sso",
            false,
        ),
        r(
            "vault-root",
            "vault.w33d.xyz",
            "/",
            "http://sanctum:8990",
            "sso",
            false,
        ),
        r(
            "intel-root",
            "intel.w33d.xyz",
            "/",
            "http://oracle:9010",
            "sso",
            false,
        ),
        r(
            "canary-trip",
            "canary.w33d.xyz",
            "/t/",
            "http://mirage:9020",
            "public",
            false,
        ),
        r(
            "canary-root",
            "canary.w33d.xyz",
            "/",
            "http://mirage:9020",
            "sso",
            false,
        ),
        r(
            "registry-v2",
            "registry.w33d.xyz",
            "/v2/",
            "http://cellar:9040",
            "public",
            false,
        ),
        r(
            "registry-root",
            "registry.w33d.xyz",
            "/",
            "http://cellar:9040",
            "sso",
            false,
        ),
        r(
            "git-protocol",
            "git.w33d.xyz",
            "/git/",
            "http://loom:9030",
            "public",
            false,
        ),
        r(
            "git-root",
            "git.w33d.xyz",
            "/",
            "http://loom:9030",
            "sso",
            false,
        ),
        r(
            "atlas-root",
            "atlas.w33d.xyz",
            "/",
            "http://atlas:9250",
            "sso",
            false,
        ),
    ]
}

// ---------------------------------------------------------------------------
// Postgres-backed routes source (READ-ONLY, portable standard SQL, runtime queries).
// ---------------------------------------------------------------------------

/// READ-ONLY [`RoutesSource`] over the gateway `routes` table. Holds a lazily-connected pool.
pub struct PgRoutesSource {
    pool: PgPool,
}

impl PgRoutesSource {
    /// Build a lazily-connected, read-only pool to the routes DSN. Never touches the network here —
    /// a down route DB is discovered (and degraded) only when the first query runs.
    pub fn connect_lazy(dsn: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(ACQUIRE_TIMEOUT)
            .connect_lazy(dsn)?;
        Ok(Self { pool })
    }

    /// Construct from an existing pool (used by tests that share a pool).
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RoutesSource for PgRoutesSource {
    async fn list_routes(&self) -> Result<Vec<Route>, String> {
        let rows = sqlx::query(
            "SELECT name, host, path_prefix, upstream, protected, auth, waf \
             FROM routes ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| e.to_string())?;

        rows.iter()
            .map(|row| {
                Ok(Route {
                    name: row.try_get("name").map_err(|e| e.to_string())?,
                    host: row.try_get("host").map_err(|e| e.to_string())?,
                    path_prefix: row.try_get("path_prefix").map_err(|e| e.to_string())?,
                    upstream: row.try_get("upstream").map_err(|e| e.to_string())?,
                    protected: row.try_get("protected").map_err(|e| e.to_string())?,
                    auth: row.try_get("auth").map_err(|e| e.to_string())?,
                    waf: row.try_get("waf").map_err(|e| e.to_string())?,
                })
            })
            .collect()
    }
}
