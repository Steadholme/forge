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

use crate::model::{ManifestRec, Repository, TagRec};

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

    /// Upsert a manifest (idempotent over `(repo,digest)`; re-push refreshes media_type/raw/size).
    async fn put_manifest(&self, m: &ManifestRec) -> Result<(), StoreError>;

    /// Fetch a manifest by repo + digest.
    async fn get_manifest(&self, repo: &str, digest: &str) -> Result<Option<ManifestRec>, StoreError>;

    /// All manifests in a repo (for web size aggregation).
    async fn manifests_for(&self, repo: &str) -> Result<Vec<ManifestRec>, StoreError>;

    /// Upsert a tag pointer (last-writer-wins on `(repo,tag)`).
    async fn put_tag(&self, repo: &str, tag: &str, manifest_digest: &str, now: i64) -> Result<(), StoreError>;

    /// Resolve a tag to its manifest digest.
    async fn get_tag(&self, repo: &str, tag: &str) -> Result<Option<String>, StoreError>;

    /// All tags in a repo (web detail + `GET /v2/{name}/tags/list`).
    async fn tags_for(&self, repo: &str) -> Result<Vec<TagRec>, StoreError>;

    /// Delete a tag pointer. Returns `true` when a row was removed. The manifest + blobs remain
    /// (untagged); reclaiming unreferenced content is a DEFERRED garbage-collection sweep.
    async fn delete_tag(&self, repo: &str, tag: &str) -> Result<bool, StoreError>;
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
}

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
}
