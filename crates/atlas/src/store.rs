//! Operator annotation storage (the `services` table).
//!
//! Atlas layers operator-maintained metadata (display name, owner, tier, free-text notes) over the
//! services it DISCOVERS from the gateway routes table. That metadata is the only data Atlas owns,
//! and it lives in its own `atlas` database. `Store` is a small async trait with an in-memory and a
//! PostgreSQL implementation, mirroring the inkwell/sanctum seam: handlers depend only on the
//! trait. The PostgreSQL layer uses ONLY portable standard SQL (TEXT/BIGINT, PK/NOT NULL/DEFAULT,
//! INSERT .. ON CONFLICT) and runtime queries (no compile-time macros), so the build needs NO
//! database and the same statements later run unchanged on FusionDB over pgwire.

use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

/// An operator annotation for one service key (maps 1:1 to a `services` row).
#[derive(Clone, Debug, Default)]
pub struct Service {
    /// The upstream service key (e.g. `inkwell`) — the discovered identity this metadata layers on.
    pub key: String,
    pub display_name: String,
    pub owner: String,
    pub tier: String,
    pub notes: String,
    pub updated_at: i64,
}

/// Storage failure surfaced to the handler layer.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Backend I/O failure (mapped to a 500).
    #[error("store error: {0}")]
    Backend(String),
}

/// Pluggable annotation store.
#[async_trait]
pub trait Store: Send + Sync {
    /// All annotations (used to layer metadata onto the discovered services).
    async fn list_services(&self) -> Vec<Service>;
    /// One annotation by service key.
    async fn get_service(&self, key: &str) -> Option<Service>;
    /// Create or replace the annotation for a service key (idempotent upsert).
    async fn upsert_service(&self, service: &Service) -> Result<(), StoreError>;
}

// ---------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct InMemoryStore {
    services: Mutex<Vec<Service>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    // The std `Mutex` is fine throughout: each critical section is fully synchronous (no `.await`
    // inside), so a guard is never held across a yield point.
    async fn list_services(&self) -> Vec<Service> {
        self.services.lock().expect("services lock poisoned").clone()
    }

    async fn get_service(&self, key: &str) -> Option<Service> {
        self.services
            .lock()
            .expect("services lock poisoned")
            .iter()
            .find(|s| s.key == key)
            .cloned()
    }

    async fn upsert_service(&self, service: &Service) -> Result<(), StoreError> {
        let mut services = self.services.lock().expect("services lock poisoned");
        match services.iter_mut().find(|s| s.key == service.key) {
            Some(existing) => *existing = service.clone(),
            None => services.push(service.clone()),
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PostgreSQL-backed store (portable: standard SQL, runtime queries, no macros).
// ---------------------------------------------------------------------------
//
// Selected at runtime by `ATLAS_STORE=postgres`. Each method drives sqlx natively and the handlers
// `.await` it on the serving runtime — NO `block_in_place`, NO sync-over-async. The upsert is an
// atomic INSERT .. ON CONFLICT, so no in-process serializer is needed.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

/// PostgreSQL-backed [`Store`]. Holds just a `PgPool`.
pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    /// Open a pooled connection. Async; call from within a Tokio runtime.
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(database_url)
            .await?;
        Ok(Self::from_pool(pool))
    }

    /// Construct from an existing pool (used by tests that share a pool).
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Idempotent, portable migration. Standard SQL only — safe to run on every startup.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS services (\
                 key TEXT PRIMARY KEY, \
                 display_name TEXT NOT NULL DEFAULT '', \
                 owner TEXT NOT NULL DEFAULT '', \
                 tier TEXT NOT NULL DEFAULT '', \
                 notes TEXT NOT NULL DEFAULT '', \
                 updated_at BIGINT NOT NULL DEFAULT 0\
             )",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn service_from_row(row: &sqlx::postgres::PgRow) -> Result<Service, sqlx::Error> {
        Ok(Service {
            key: row.try_get("key")?,
            display_name: row.try_get("display_name")?,
            owner: row.try_get("owner")?,
            tier: row.try_get("tier")?,
            notes: row.try_get("notes")?,
            updated_at: row.try_get("updated_at")?,
        })
    }

    async fn list_services_async(&self) -> Result<Vec<Service>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT key, display_name, owner, tier, notes, updated_at FROM services ORDER BY key",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::service_from_row).collect()
    }

    async fn get_service_async(&self, key: &str) -> Result<Option<Service>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT key, display_name, owner, tier, notes, updated_at FROM services WHERE key = $1",
        )
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(r) => Ok(Some(Self::service_from_row(&r)?)),
            None => Ok(None),
        }
    }

    async fn upsert_service_async(&self, s: &Service) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO services (key, display_name, owner, tier, notes, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (key) DO UPDATE SET \
                 display_name = EXCLUDED.display_name, \
                 owner = EXCLUDED.owner, \
                 tier = EXCLUDED.tier, \
                 notes = EXCLUDED.notes, \
                 updated_at = EXCLUDED.updated_at",
        )
        .bind(&s.key)
        .bind(&s.display_name)
        .bind(&s.owner)
        .bind(&s.tier)
        .bind(&s.notes)
        .bind(s.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl Store for PgStore {
    async fn list_services(&self) -> Vec<Service> {
        self.list_services_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_services failed");
            Vec::new()
        })
    }

    async fn get_service(&self, key: &str) -> Option<Service> {
        self.get_service_async(key).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_service failed");
            None
        })
    }

    async fn upsert_service(&self, service: &Service) -> Result<(), StoreError> {
        self.upsert_service_async(service)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }
}
