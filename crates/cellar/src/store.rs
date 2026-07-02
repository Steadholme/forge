//! Registry metadata storage.
//!
//! `Store` is an async trait with an in-memory and a PostgreSQL implementation, mirroring the
//! aperture/keystone seam: handlers depend only on the trait. The PostgreSQL layer uses ONLY
//! portable standard SQL (TEXT/BIGINT, PRIMARY KEY/UNIQUE/NOT NULL, parameterized queries,
//! `INSERT .. ON CONFLICT`, plain indexes) and runtime queries (no compile-time macros), so the
//! build needs NO database and the same statements later run unchanged on FusionDB over pgwire.
//!
//! The trait is async: the axum handlers `.await` it directly on the serving runtime, and
//! `PgStore` drives sqlx natively — there is NO `block_in_place` and NO sync-over-async bridge.

use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::model::{
    BlobRec, ManifestRec, PullStat, Repository, RetentionRule, RobotAccount, TagRec,
};

/// Storage failure surfaced to the handler layer (mapped to an internal error).
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store error: {0}")]
    Backend(String),
}

/// Pluggable registry metadata store. Blob/manifest writes are idempotent (content-addressed by
/// digest); tag writes are last-writer-wins (a tag is a mutable pointer).
#[async_trait]
pub trait Store: Send + Sync {
    /// Idempotently record that `name` exists (first push of any repo).
    async fn ensure_repository(&self, name: &str, now: i64) -> Result<(), StoreError>;

    /// True when the repository row exists.
    async fn repo_exists(&self, name: &str) -> Result<bool, StoreError>;

    /// All repositories, name-sorted (backs `GET /v2/_catalog` and the web index).
    async fn list_repositories(&self) -> Result<Vec<Repository>, StoreError>;

    /// Idempotently record a finalized blob's metadata (bytes live on the volume).
    async fn put_blob(&self, digest: &str, size: i64, now: i64) -> Result<(), StoreError>;

    /// A blob's recorded size, or `None` when unknown to the registry.
    async fn blob_size(&self, digest: &str) -> Result<Option<i64>, StoreError>;

    /// All recorded blobs (backs the admin storage accounting + garbage collection sweep).
    async fn list_blobs(&self) -> Result<Vec<BlobRec>, StoreError>;

    /// Delete a blob's metadata row. Returns `true` when a row was removed. The caller also drops
    /// the bytes from the [`crate::blobs::BlobStore`]; used only by garbage collection.
    async fn delete_blob(&self, digest: &str) -> Result<bool, StoreError>;

    /// Upsert a manifest (idempotent over `(repo,digest)`; re-push refreshes media_type/raw/size).
    async fn put_manifest(&self, m: &ManifestRec) -> Result<(), StoreError>;

    /// Fetch a manifest by repo + digest.
    async fn get_manifest(&self, repo: &str, digest: &str) -> Result<Option<ManifestRec>, StoreError>;

    /// All manifests in a repo (for web size aggregation).
    async fn manifests_for(&self, repo: &str) -> Result<Vec<ManifestRec>, StoreError>;

    /// Delete a manifest row by repo + digest. Returns `true` when a row was removed. Used only by
    /// garbage collection (removing an untagged/orphaned manifest).
    async fn delete_manifest(&self, repo: &str, digest: &str) -> Result<bool, StoreError>;

    /// Upsert a tag pointer (last-writer-wins on `(repo,tag)`).
    async fn put_tag(&self, repo: &str, tag: &str, manifest_digest: &str, now: i64) -> Result<(), StoreError>;

    /// Resolve a tag to its manifest digest.
    async fn get_tag(&self, repo: &str, tag: &str) -> Result<Option<String>, StoreError>;

    /// All tags in a repo (web detail + `GET /v2/{name}/tags/list`).
    async fn tags_for(&self, repo: &str) -> Result<Vec<TagRec>, StoreError>;

    /// Delete a tag pointer. Returns `true` when a row was removed. The manifest + blobs remain
    /// (untagged); reclaiming unreferenced content is a DEFERRED garbage-collection sweep.
    async fn delete_tag(&self, repo: &str, tag: &str) -> Result<bool, StoreError>;

    // ---- pull statistics --------------------------------------------------
    /// Record one real `/v2/` manifest pull for `repo`: increments the counter and stamps
    /// `last_pulled_at` (creates the row on the first pull).
    async fn increment_pull(&self, repo: &str, now: i64) -> Result<(), StoreError>;

    /// The pull statistics for `repo`, or `None` when it has never been pulled.
    async fn pull_stat(&self, repo: &str) -> Result<Option<PullStat>, StoreError>;

    // ---- retention rules --------------------------------------------------
    /// Insert a retention rule (the caller mints `id`).
    async fn create_retention_rule(&self, rule: &RetentionRule) -> Result<(), StoreError>;

    /// All retention rules, id-sorted.
    async fn list_retention_rules(&self) -> Result<Vec<RetentionRule>, StoreError>;

    /// Toggle a rule's `enabled` flag. Returns `true` when a row was updated.
    async fn set_retention_enabled(&self, id: &str, enabled: bool) -> Result<bool, StoreError>;

    /// Delete a retention rule. Returns `true` when a row was removed.
    async fn delete_retention_rule(&self, id: &str) -> Result<bool, StoreError>;

    // ---- robot accounts ---------------------------------------------------
    /// Insert a robot account (the caller mints `id`, hashes the token). `name` is UNIQUE.
    async fn create_robot(&self, robot: &RobotAccount) -> Result<(), StoreError>;

    /// All robot accounts, name-sorted.
    async fn list_robots(&self) -> Result<Vec<RobotAccount>, StoreError>;

    /// Look up a robot by its bare `name` (the `/v2/` Basic username is `robot$<name>`).
    async fn get_robot_by_name(&self, name: &str) -> Result<Option<RobotAccount>, StoreError>;

    /// Toggle a robot's `enabled` flag. Returns `true` when a row was updated.
    async fn set_robot_enabled(&self, id: &str, enabled: bool) -> Result<bool, StoreError>;

    /// Stamp a robot's `last_used_at` on a successful authentication.
    async fn touch_robot(&self, id: &str, now: i64) -> Result<(), StoreError>;

    /// Delete a robot account. Returns `true` when a row was removed.
    async fn delete_robot(&self, id: &str) -> Result<bool, StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

#[derive(Default)]
struct Inner {
    repos: Vec<Repository>,
    manifests: Vec<ManifestRec>,
    tags: Vec<TagRec>,
    blobs: Vec<(String, i64, i64)>, // (digest, size, created_at)
    pull_stats: Vec<PullStat>,
    retention_rules: Vec<RetentionRule>,
    robots: Vec<RobotAccount>,
}

/// In-memory `Store`. The `Mutex` critical sections are fully synchronous (no `.await` held
/// across the guard), so the std `Mutex` is correct here.
#[derive(Default)]
pub struct InMemoryStore {
    inner: Mutex<Inner>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    async fn ensure_repository(&self, name: &str, now: i64) -> Result<(), StoreError> {
        let mut g = self.inner.lock().expect("store lock poisoned");
        if !g.repos.iter().any(|r| r.name == name) {
            g.repos.push(Repository {
                name: name.to_string(),
                created_at: now,
            });
        }
        Ok(())
    }

    async fn repo_exists(&self, name: &str) -> Result<bool, StoreError> {
        let g = self.inner.lock().expect("store lock poisoned");
        Ok(g.repos.iter().any(|r| r.name == name))
    }

    async fn list_repositories(&self) -> Result<Vec<Repository>, StoreError> {
        let g = self.inner.lock().expect("store lock poisoned");
        let mut out = g.repos.clone();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn put_blob(&self, digest: &str, size: i64, now: i64) -> Result<(), StoreError> {
        let mut g = self.inner.lock().expect("store lock poisoned");
        if !g.blobs.iter().any(|(d, _, _)| d == digest) {
            g.blobs.push((digest.to_string(), size, now));
        }
        Ok(())
    }

    async fn blob_size(&self, digest: &str) -> Result<Option<i64>, StoreError> {
        let g = self.inner.lock().expect("store lock poisoned");
        Ok(g.blobs.iter().find(|(d, _, _)| d == digest).map(|(_, s, _)| *s))
    }

    async fn list_blobs(&self) -> Result<Vec<BlobRec>, StoreError> {
        let g = self.inner.lock().expect("store lock poisoned");
        Ok(g
            .blobs
            .iter()
            .map(|(digest, size, created_at)| BlobRec {
                digest: digest.clone(),
                size: *size,
                created_at: *created_at,
            })
            .collect())
    }

    async fn delete_blob(&self, digest: &str) -> Result<bool, StoreError> {
        let mut g = self.inner.lock().expect("store lock poisoned");
        let before = g.blobs.len();
        g.blobs.retain(|(d, _, _)| d != digest);
        Ok(g.blobs.len() != before)
    }

    async fn put_manifest(&self, m: &ManifestRec) -> Result<(), StoreError> {
        let mut g = self.inner.lock().expect("store lock poisoned");
        if let Some(existing) = g.manifests.iter_mut().find(|x| x.id == m.id) {
            existing.media_type = m.media_type.clone();
            existing.raw = m.raw.clone();
            existing.size = m.size;
        } else {
            g.manifests.push(m.clone());
        }
        Ok(())
    }

    async fn get_manifest(&self, repo: &str, digest: &str) -> Result<Option<ManifestRec>, StoreError> {
        let g = self.inner.lock().expect("store lock poisoned");
        Ok(g
            .manifests
            .iter()
            .find(|m| m.repo == repo && m.digest == digest)
            .cloned())
    }

    async fn manifests_for(&self, repo: &str) -> Result<Vec<ManifestRec>, StoreError> {
        let g = self.inner.lock().expect("store lock poisoned");
        Ok(g.manifests.iter().filter(|m| m.repo == repo).cloned().collect())
    }

    async fn delete_manifest(&self, repo: &str, digest: &str) -> Result<bool, StoreError> {
        let mut g = self.inner.lock().expect("store lock poisoned");
        let before = g.manifests.len();
        g.manifests.retain(|m| !(m.repo == repo && m.digest == digest));
        Ok(g.manifests.len() != before)
    }

    async fn put_tag(&self, repo: &str, tag: &str, manifest_digest: &str, now: i64) -> Result<(), StoreError> {
        let mut g = self.inner.lock().expect("store lock poisoned");
        if let Some(t) = g.tags.iter_mut().find(|t| t.repo == repo && t.tag == tag) {
            t.manifest_digest = manifest_digest.to_string();
            t.updated_at = now;
        } else {
            g.tags.push(TagRec {
                repo: repo.to_string(),
                tag: tag.to_string(),
                manifest_digest: manifest_digest.to_string(),
                updated_at: now,
            });
        }
        Ok(())
    }

    async fn get_tag(&self, repo: &str, tag: &str) -> Result<Option<String>, StoreError> {
        let g = self.inner.lock().expect("store lock poisoned");
        Ok(g
            .tags
            .iter()
            .find(|t| t.repo == repo && t.tag == tag)
            .map(|t| t.manifest_digest.clone()))
    }

    async fn tags_for(&self, repo: &str) -> Result<Vec<TagRec>, StoreError> {
        let g = self.inner.lock().expect("store lock poisoned");
        let mut out: Vec<TagRec> = g.tags.iter().filter(|t| t.repo == repo).cloned().collect();
        out.sort_by(|a, b| a.tag.cmp(&b.tag));
        Ok(out)
    }

    async fn delete_tag(&self, repo: &str, tag: &str) -> Result<bool, StoreError> {
        let mut g = self.inner.lock().expect("store lock poisoned");
        let before = g.tags.len();
        g.tags.retain(|t| !(t.repo == repo && t.tag == tag));
        Ok(g.tags.len() != before)
    }

    async fn increment_pull(&self, repo: &str, now: i64) -> Result<(), StoreError> {
        let mut g = self.inner.lock().expect("store lock poisoned");
        if let Some(s) = g.pull_stats.iter_mut().find(|s| s.repo == repo) {
            s.pulls += 1;
            s.last_pulled_at = now;
        } else {
            g.pull_stats.push(PullStat {
                repo: repo.to_string(),
                pulls: 1,
                last_pulled_at: now,
            });
        }
        Ok(())
    }

    async fn pull_stat(&self, repo: &str) -> Result<Option<PullStat>, StoreError> {
        let g = self.inner.lock().expect("store lock poisoned");
        Ok(g.pull_stats.iter().find(|s| s.repo == repo).cloned())
    }

    async fn create_retention_rule(&self, rule: &RetentionRule) -> Result<(), StoreError> {
        let mut g = self.inner.lock().expect("store lock poisoned");
        g.retention_rules.push(rule.clone());
        Ok(())
    }

    async fn list_retention_rules(&self) -> Result<Vec<RetentionRule>, StoreError> {
        let g = self.inner.lock().expect("store lock poisoned");
        let mut out = g.retention_rules.clone();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    async fn set_retention_enabled(&self, id: &str, enabled: bool) -> Result<bool, StoreError> {
        let mut g = self.inner.lock().expect("store lock poisoned");
        match g.retention_rules.iter_mut().find(|r| r.id == id) {
            Some(r) => {
                r.enabled = enabled;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn delete_retention_rule(&self, id: &str) -> Result<bool, StoreError> {
        let mut g = self.inner.lock().expect("store lock poisoned");
        let before = g.retention_rules.len();
        g.retention_rules.retain(|r| r.id != id);
        Ok(g.retention_rules.len() != before)
    }

    async fn create_robot(&self, robot: &RobotAccount) -> Result<(), StoreError> {
        let mut g = self.inner.lock().expect("store lock poisoned");
        if g.robots.iter().any(|r| r.name == robot.name) {
            return Err(StoreError::Backend(format!(
                "robot name {} already exists",
                robot.name
            )));
        }
        g.robots.push(robot.clone());
        Ok(())
    }

    async fn list_robots(&self) -> Result<Vec<RobotAccount>, StoreError> {
        let g = self.inner.lock().expect("store lock poisoned");
        let mut out = g.robots.clone();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn get_robot_by_name(&self, name: &str) -> Result<Option<RobotAccount>, StoreError> {
        let g = self.inner.lock().expect("store lock poisoned");
        Ok(g.robots.iter().find(|r| r.name == name).cloned())
    }

    async fn set_robot_enabled(&self, id: &str, enabled: bool) -> Result<bool, StoreError> {
        let mut g = self.inner.lock().expect("store lock poisoned");
        match g.robots.iter_mut().find(|r| r.id == id) {
            Some(r) => {
                r.enabled = enabled;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn touch_robot(&self, id: &str, now: i64) -> Result<(), StoreError> {
        let mut g = self.inner.lock().expect("store lock poisoned");
        if let Some(r) = g.robots.iter_mut().find(|r| r.id == id) {
            r.last_used_at = now;
        }
        Ok(())
    }

    async fn delete_robot(&self, id: &str) -> Result<bool, StoreError> {
        let mut g = self.inner.lock().expect("store lock poisoned");
        let before = g.robots.len();
        g.robots.retain(|r| r.id != id);
        Ok(g.robots.len() != before)
    }
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed store (portable: standard SQL, runtime queries, no macros).
// --------------------------------------------------------------------------------------

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

/// PostgreSQL-backed [`Store`]. Holds a pooled connection; the async trait methods drive sqlx
/// natively, so no worker thread is ever blocked on a DB round-trip.
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
            "CREATE TABLE IF NOT EXISTS repositories (\
                 name TEXT PRIMARY KEY, \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS manifests (\
                 id TEXT PRIMARY KEY, \
                 repo TEXT NOT NULL, \
                 digest TEXT NOT NULL, \
                 media_type TEXT NOT NULL, \
                 raw TEXT NOT NULL, \
                 size BIGINT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 UNIQUE(repo, digest)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_manifests_repo ON manifests (repo)")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS tags (\
                 repo TEXT NOT NULL, \
                 tag TEXT NOT NULL, \
                 manifest_digest TEXT NOT NULL, \
                 updated_at BIGINT NOT NULL, \
                 PRIMARY KEY(repo, tag)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS blobs (\
                 digest TEXT PRIMARY KEY, \
                 size BIGINT NOT NULL, \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pull_stats (\
                 repo TEXT PRIMARY KEY, \
                 pulls BIGINT NOT NULL, \
                 last_pulled_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS retention_rules (\
                 id TEXT PRIMARY KEY, \
                 repo_pattern TEXT NOT NULL, \
                 keep_last BIGINT NOT NULL, \
                 keep_days BIGINT NOT NULL, \
                 enabled BOOLEAN NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS robot_accounts (\
                 id TEXT PRIMARY KEY, \
                 name TEXT NOT NULL, \
                 token_hash TEXT NOT NULL, \
                 scope TEXT NOT NULL, \
                 repo_pattern TEXT NOT NULL, \
                 enabled BOOLEAN NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 last_used_at BIGINT NOT NULL, \
                 UNIQUE(name)\
             )",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn manifest_from_row(row: &sqlx::postgres::PgRow) -> Result<ManifestRec, sqlx::Error> {
        Ok(ManifestRec {
            id: row.try_get("id")?,
            repo: row.try_get("repo")?,
            digest: row.try_get("digest")?,
            media_type: row.try_get("media_type")?,
            raw: row.try_get("raw")?,
            size: row.try_get("size")?,
            created_at: row.try_get("created_at")?,
        })
    }

    fn retention_from_row(row: &sqlx::postgres::PgRow) -> Result<RetentionRule, sqlx::Error> {
        Ok(RetentionRule {
            id: row.try_get("id")?,
            repo_pattern: row.try_get("repo_pattern")?,
            keep_last: row.try_get("keep_last")?,
            keep_days: row.try_get("keep_days")?,
            enabled: row.try_get("enabled")?,
        })
    }

    fn robot_from_row(row: &sqlx::postgres::PgRow) -> Result<RobotAccount, sqlx::Error> {
        Ok(RobotAccount {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            token_hash: row.try_get("token_hash")?,
            scope: row.try_get("scope")?,
            repo_pattern: row.try_get("repo_pattern")?,
            enabled: row.try_get("enabled")?,
            created_at: row.try_get("created_at")?,
            last_used_at: row.try_get("last_used_at")?,
        })
    }
}

const ROBOT_COLS: &str =
    "id, name, token_hash, scope, repo_pattern, enabled, created_at, last_used_at";

const MANIFEST_COLS: &str = "id, repo, digest, media_type, raw, size, created_at";

#[async_trait]
impl Store for PgStore {
    async fn ensure_repository(&self, name: &str, now: i64) -> Result<(), StoreError> {
        sqlx::query("INSERT INTO repositories (name, created_at) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING")
            .bind(name)
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(be)?;
        Ok(())
    }

    async fn repo_exists(&self, name: &str) -> Result<bool, StoreError> {
        let row = sqlx::query("SELECT 1 AS x FROM repositories WHERE name = $1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(be)?;
        Ok(row.is_some())
    }

    async fn list_repositories(&self) -> Result<Vec<Repository>, StoreError> {
        let rows = sqlx::query("SELECT name, created_at FROM repositories ORDER BY name ASC")
            .fetch_all(&self.pool)
            .await
            .map_err(be)?;
        rows.iter()
            .map(|r| {
                Ok(Repository {
                    name: r.try_get("name").map_err(be)?,
                    created_at: r.try_get("created_at").map_err(be)?,
                })
            })
            .collect()
    }

    async fn put_blob(&self, digest: &str, size: i64, now: i64) -> Result<(), StoreError> {
        sqlx::query("INSERT INTO blobs (digest, size, created_at) VALUES ($1, $2, $3) ON CONFLICT (digest) DO NOTHING")
            .bind(digest)
            .bind(size)
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(be)?;
        Ok(())
    }

    async fn blob_size(&self, digest: &str) -> Result<Option<i64>, StoreError> {
        let row = sqlx::query("SELECT size FROM blobs WHERE digest = $1")
            .bind(digest)
            .fetch_optional(&self.pool)
            .await
            .map_err(be)?;
        match row {
            Some(r) => Ok(Some(r.try_get("size").map_err(be)?)),
            None => Ok(None),
        }
    }

    async fn list_blobs(&self) -> Result<Vec<BlobRec>, StoreError> {
        let rows = sqlx::query("SELECT digest, size, created_at FROM blobs ORDER BY digest ASC")
            .fetch_all(&self.pool)
            .await
            .map_err(be)?;
        rows.iter()
            .map(|r| {
                Ok(BlobRec {
                    digest: r.try_get("digest").map_err(be)?,
                    size: r.try_get("size").map_err(be)?,
                    created_at: r.try_get("created_at").map_err(be)?,
                })
            })
            .collect()
    }

    async fn delete_blob(&self, digest: &str) -> Result<bool, StoreError> {
        let res = sqlx::query("DELETE FROM blobs WHERE digest = $1")
            .bind(digest)
            .execute(&self.pool)
            .await
            .map_err(be)?;
        Ok(res.rows_affected() > 0)
    }

    async fn put_manifest(&self, m: &ManifestRec) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO manifests (id, repo, digest, media_type, raw, size, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (id) DO UPDATE SET \
                 media_type = EXCLUDED.media_type, raw = EXCLUDED.raw, size = EXCLUDED.size",
        )
        .bind(&m.id)
        .bind(&m.repo)
        .bind(&m.digest)
        .bind(&m.media_type)
        .bind(&m.raw)
        .bind(m.size)
        .bind(m.created_at)
        .execute(&self.pool)
        .await
        .map_err(be)?;
        Ok(())
    }

    async fn get_manifest(&self, repo: &str, digest: &str) -> Result<Option<ManifestRec>, StoreError> {
        let row = sqlx::query(&format!(
            "SELECT {MANIFEST_COLS} FROM manifests WHERE repo = $1 AND digest = $2"
        ))
        .bind(repo)
        .bind(digest)
        .fetch_optional(&self.pool)
        .await
        .map_err(be)?;
        row.as_ref().map(Self::manifest_from_row).transpose().map_err(be)
    }

    async fn manifests_for(&self, repo: &str) -> Result<Vec<ManifestRec>, StoreError> {
        let rows = sqlx::query(&format!("SELECT {MANIFEST_COLS} FROM manifests WHERE repo = $1"))
            .bind(repo)
            .fetch_all(&self.pool)
            .await
            .map_err(be)?;
        rows.iter().map(Self::manifest_from_row).collect::<Result<_, _>>().map_err(be)
    }

    async fn delete_manifest(&self, repo: &str, digest: &str) -> Result<bool, StoreError> {
        let res = sqlx::query("DELETE FROM manifests WHERE repo = $1 AND digest = $2")
            .bind(repo)
            .bind(digest)
            .execute(&self.pool)
            .await
            .map_err(be)?;
        Ok(res.rows_affected() > 0)
    }

    async fn put_tag(&self, repo: &str, tag: &str, manifest_digest: &str, now: i64) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO tags (repo, tag, manifest_digest, updated_at) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (repo, tag) DO UPDATE SET \
                 manifest_digest = EXCLUDED.manifest_digest, updated_at = EXCLUDED.updated_at",
        )
        .bind(repo)
        .bind(tag)
        .bind(manifest_digest)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(be)?;
        Ok(())
    }

    async fn get_tag(&self, repo: &str, tag: &str) -> Result<Option<String>, StoreError> {
        let row = sqlx::query("SELECT manifest_digest FROM tags WHERE repo = $1 AND tag = $2")
            .bind(repo)
            .bind(tag)
            .fetch_optional(&self.pool)
            .await
            .map_err(be)?;
        match row {
            Some(r) => Ok(Some(r.try_get("manifest_digest").map_err(be)?)),
            None => Ok(None),
        }
    }

    async fn tags_for(&self, repo: &str) -> Result<Vec<TagRec>, StoreError> {
        let rows = sqlx::query(
            "SELECT repo, tag, manifest_digest, updated_at FROM tags WHERE repo = $1 ORDER BY tag ASC",
        )
        .bind(repo)
        .fetch_all(&self.pool)
        .await
        .map_err(be)?;
        rows.iter()
            .map(|r| {
                Ok(TagRec {
                    repo: r.try_get("repo").map_err(be)?,
                    tag: r.try_get("tag").map_err(be)?,
                    manifest_digest: r.try_get("manifest_digest").map_err(be)?,
                    updated_at: r.try_get("updated_at").map_err(be)?,
                })
            })
            .collect()
    }

    async fn delete_tag(&self, repo: &str, tag: &str) -> Result<bool, StoreError> {
        let res = sqlx::query("DELETE FROM tags WHERE repo = $1 AND tag = $2")
            .bind(repo)
            .bind(tag)
            .execute(&self.pool)
            .await
            .map_err(be)?;
        Ok(res.rows_affected() > 0)
    }

    async fn increment_pull(&self, repo: &str, now: i64) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO pull_stats (repo, pulls, last_pulled_at) VALUES ($1, 1, $2) \
             ON CONFLICT (repo) DO UPDATE SET \
                 pulls = pull_stats.pulls + 1, last_pulled_at = EXCLUDED.last_pulled_at",
        )
        .bind(repo)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(be)?;
        Ok(())
    }

    async fn pull_stat(&self, repo: &str) -> Result<Option<PullStat>, StoreError> {
        let row = sqlx::query("SELECT repo, pulls, last_pulled_at FROM pull_stats WHERE repo = $1")
            .bind(repo)
            .fetch_optional(&self.pool)
            .await
            .map_err(be)?;
        match row {
            Some(r) => Ok(Some(PullStat {
                repo: r.try_get("repo").map_err(be)?,
                pulls: r.try_get("pulls").map_err(be)?,
                last_pulled_at: r.try_get("last_pulled_at").map_err(be)?,
            })),
            None => Ok(None),
        }
    }

    async fn create_retention_rule(&self, rule: &RetentionRule) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO retention_rules (id, repo_pattern, keep_last, keep_days, enabled) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&rule.id)
        .bind(&rule.repo_pattern)
        .bind(rule.keep_last)
        .bind(rule.keep_days)
        .bind(rule.enabled)
        .execute(&self.pool)
        .await
        .map_err(be)?;
        Ok(())
    }

    async fn list_retention_rules(&self) -> Result<Vec<RetentionRule>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, repo_pattern, keep_last, keep_days, enabled FROM retention_rules ORDER BY id ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(be)?;
        rows.iter()
            .map(Self::retention_from_row)
            .collect::<Result<_, _>>()
            .map_err(be)
    }

    async fn set_retention_enabled(&self, id: &str, enabled: bool) -> Result<bool, StoreError> {
        let res = sqlx::query("UPDATE retention_rules SET enabled = $2 WHERE id = $1")
            .bind(id)
            .bind(enabled)
            .execute(&self.pool)
            .await
            .map_err(be)?;
        Ok(res.rows_affected() > 0)
    }

    async fn delete_retention_rule(&self, id: &str) -> Result<bool, StoreError> {
        let res = sqlx::query("DELETE FROM retention_rules WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(be)?;
        Ok(res.rows_affected() > 0)
    }

    async fn create_robot(&self, robot: &RobotAccount) -> Result<(), StoreError> {
        sqlx::query(&format!(
            "INSERT INTO robot_accounts ({ROBOT_COLS}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
        ))
        .bind(&robot.id)
        .bind(&robot.name)
        .bind(&robot.token_hash)
        .bind(&robot.scope)
        .bind(&robot.repo_pattern)
        .bind(robot.enabled)
        .bind(robot.created_at)
        .bind(robot.last_used_at)
        .execute(&self.pool)
        .await
        .map_err(be)?;
        Ok(())
    }

    async fn list_robots(&self) -> Result<Vec<RobotAccount>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {ROBOT_COLS} FROM robot_accounts ORDER BY name ASC"
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(be)?;
        rows.iter()
            .map(Self::robot_from_row)
            .collect::<Result<_, _>>()
            .map_err(be)
    }

    async fn get_robot_by_name(&self, name: &str) -> Result<Option<RobotAccount>, StoreError> {
        let row = sqlx::query(&format!(
            "SELECT {ROBOT_COLS} FROM robot_accounts WHERE name = $1"
        ))
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(be)?;
        row.as_ref().map(Self::robot_from_row).transpose().map_err(be)
    }

    async fn set_robot_enabled(&self, id: &str, enabled: bool) -> Result<bool, StoreError> {
        let res = sqlx::query("UPDATE robot_accounts SET enabled = $2 WHERE id = $1")
            .bind(id)
            .bind(enabled)
            .execute(&self.pool)
            .await
            .map_err(be)?;
        Ok(res.rows_affected() > 0)
    }

    async fn touch_robot(&self, id: &str, now: i64) -> Result<(), StoreError> {
        sqlx::query("UPDATE robot_accounts SET last_used_at = $2 WHERE id = $1")
            .bind(id)
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(be)?;
        Ok(())
    }

    async fn delete_robot(&self, id: &str) -> Result<bool, StoreError> {
        let res = sqlx::query("DELETE FROM robot_accounts WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(be)?;
        Ok(res.rows_affected() > 0)
    }
}

/// Map any sqlx error to a backend `StoreError`.
fn be<E: std::fmt::Display>(e: E) -> StoreError {
    StoreError::Backend(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ManifestRec;

    fn manifest(repo: &str, digest: &str) -> ManifestRec {
        ManifestRec {
            id: ManifestRec::make_id(repo, digest),
            repo: repo.to_string(),
            digest: digest.to_string(),
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            raw: "{}".to_string(),
            size: 2,
            created_at: 100,
        }
    }

    #[tokio::test]
    async fn blob_and_manifest_idempotent() {
        let s = InMemoryStore::new();
        s.put_blob("sha256:aa", 10, 1).await.unwrap();
        s.put_blob("sha256:aa", 999, 2).await.unwrap(); // ignored (idempotent)
        assert_eq!(s.blob_size("sha256:aa").await.unwrap(), Some(10));
        assert_eq!(s.blob_size("sha256:bb").await.unwrap(), None);

        s.ensure_repository("library/alpine", 1).await.unwrap();
        s.put_manifest(&manifest("library/alpine", "sha256:m1")).await.unwrap();
        assert_eq!(
            s.get_manifest("library/alpine", "sha256:m1").await.unwrap().unwrap().digest,
            "sha256:m1"
        );
    }

    #[tokio::test]
    async fn tag_pointer_is_mutable_and_listed() {
        let s = InMemoryStore::new();
        s.ensure_repository("app", 1).await.unwrap();
        s.put_tag("app", "latest", "sha256:m1", 1).await.unwrap();
        s.put_tag("app", "v2", "sha256:m2", 2).await.unwrap();
        // last-writer-wins on the same tag
        s.put_tag("app", "latest", "sha256:m3", 3).await.unwrap();
        assert_eq!(s.get_tag("app", "latest").await.unwrap().unwrap(), "sha256:m3");
        let tags: Vec<String> = s.tags_for("app").await.unwrap().into_iter().map(|t| t.tag).collect();
        assert_eq!(tags, vec!["latest", "v2"]);
        assert!(s.delete_tag("app", "v2").await.unwrap());
        assert!(!s.delete_tag("app", "v2").await.unwrap());
    }

    #[tokio::test]
    async fn pull_stats_increment_and_read() {
        let s = InMemoryStore::new();
        assert_eq!(s.pull_stat("app").await.unwrap(), None);
        s.increment_pull("app", 100).await.unwrap();
        s.increment_pull("app", 200).await.unwrap();
        let stat = s.pull_stat("app").await.unwrap().unwrap();
        assert_eq!(stat.pulls, 2);
        assert_eq!(stat.last_pulled_at, 200); // stamped with the latest pull
        // A different repo is tracked independently.
        assert_eq!(s.pull_stat("other").await.unwrap(), None);
    }

    #[tokio::test]
    async fn retention_rule_crud() {
        let s = InMemoryStore::new();
        let rule = RetentionRule {
            id: "ret-1".into(),
            repo_pattern: "team/*".into(),
            keep_last: 5,
            keep_days: 30,
            enabled: true,
        };
        s.create_retention_rule(&rule).await.unwrap();
        assert_eq!(s.list_retention_rules().await.unwrap(), vec![rule.clone()]);
        // Toggle enabled.
        assert!(s.set_retention_enabled("ret-1", false).await.unwrap());
        assert!(!s.list_retention_rules().await.unwrap()[0].enabled);
        assert!(!s.set_retention_enabled("nope", true).await.unwrap());
        // Delete.
        assert!(s.delete_retention_rule("ret-1").await.unwrap());
        assert!(!s.delete_retention_rule("ret-1").await.unwrap());
        assert!(s.list_retention_rules().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn robot_crud_and_name_uniqueness() {
        let s = InMemoryStore::new();
        let robot = RobotAccount {
            id: "rob-1".into(),
            name: "ci".into(),
            token_hash: "hash".into(),
            scope: "pushpull".into(),
            repo_pattern: "*".into(),
            enabled: true,
            created_at: 1,
            last_used_at: 0,
        };
        s.create_robot(&robot).await.unwrap();
        // Duplicate name is rejected.
        assert!(s.create_robot(&robot).await.is_err());
        assert_eq!(s.get_robot_by_name("ci").await.unwrap().unwrap().id, "rob-1");
        assert_eq!(s.get_robot_by_name("missing").await.unwrap(), None);
        // Touch stamps last_used_at.
        s.touch_robot("rob-1", 999).await.unwrap();
        assert_eq!(s.get_robot_by_name("ci").await.unwrap().unwrap().last_used_at, 999);
        // Disable + delete.
        assert!(s.set_robot_enabled("rob-1", false).await.unwrap());
        assert!(!s.get_robot_by_name("ci").await.unwrap().unwrap().enabled);
        assert!(s.delete_robot("rob-1").await.unwrap());
        assert!(!s.delete_robot("rob-1").await.unwrap());
        assert!(s.list_robots().await.unwrap().is_empty());
    }
}
