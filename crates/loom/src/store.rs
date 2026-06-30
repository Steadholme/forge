//! Metadata storage: repositories, issues, personal access tokens.
//!
//! `Store` is a small async trait with an in-memory and a PostgreSQL implementation, mirroring
//! the keystone/cairn/pastefire seam: handlers depend only on the trait, so a FusionDB-backed
//! store can drop in later. The PostgreSQL layer uses ONLY portable standard SQL
//! (TEXT/BIGINT/BOOLEAN, PRIMARY KEY/NOT NULL/UNIQUE, parameterized queries, `INSERT .. ON
//! CONFLICT`, plain indexes) and runtime queries (no compile-time macros), so the build needs NO
//! database and the same statements later run unchanged on FusionDB over pgwire.
//!
//! The trait is async: the axum handlers `.await` it directly on the serving runtime, and
//! `PgStore` drives sqlx natively — there is NO `block_in_place` and NO sync-over-async bridge.
//!
//! NOTE: the git BYTES (objects/refs) live on the filesystem as bare repos (see [`crate::gitops`]);
//! this store keeps only the metadata. Repo BLOB content is never stored here.

use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::config::REPO_LIST_LIMIT;
use crate::model::{Issue, Pat, Repo};

/// Storage failure surfaced to the handler layer (mapped to a 500 `server_error`).
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store error: {0}")]
    Backend(String),
}

/// Pluggable metadata store.
#[async_trait]
pub trait Store: Send + Sync {
    // --- repos ---------------------------------------------------------------
    /// Insert a repo. Returns `Ok(true)` when inserted, `Ok(false)` when the `(owner_sub, name)`
    /// pair already exists (the caller surfaces a "name taken" conflict).
    async fn create_repo(&self, repo: &Repo) -> Result<bool, StoreError>;

    /// Fetch a repo by its `(owner_sub, name)` natural key.
    async fn get_repo(&self, owner_sub: &str, name: &str) -> Result<Option<Repo>, StoreError>;

    /// Repos visible to `viewer_sub`: every public repo plus the viewer's own private repos,
    /// newest-first, capped at [`REPO_LIST_LIMIT`].
    async fn list_visible_repos(&self, viewer_sub: &str) -> Result<Vec<Repo>, StoreError>;

    /// Delete a repo row by id (used to roll back a half-created repo when `git init` fails).
    async fn delete_repo(&self, id: &str) -> Result<bool, StoreError>;

    // --- issues --------------------------------------------------------------
    /// Create an issue, atomically allocating the next per-repo `number`. Returns the stored
    /// issue (with its assigned number and `open` state).
    async fn create_issue(
        &self,
        id: &str,
        repo_id: &str,
        title: &str,
        body: &str,
        author_sub: &str,
        created_at: i64,
    ) -> Result<Issue, StoreError>;

    /// All issues on a repo, newest number first.
    async fn list_issues(&self, repo_id: &str) -> Result<Vec<Issue>, StoreError>;

    /// One issue by its per-repo number.
    async fn get_issue(&self, repo_id: &str, number: i64)
        -> Result<Option<Issue>, StoreError>;

    /// Set an issue's state (`open`/`closed`) by id. Returns whether a row changed.
    async fn set_issue_state(&self, id: &str, state: &str) -> Result<bool, StoreError>;

    /// Count of OPEN issues on a repo (for the repo header badge).
    async fn open_issue_count(&self, repo_id: &str) -> Result<i64, StoreError>;

    // --- pats ----------------------------------------------------------------
    /// Insert a personal access token (only the hash is stored).
    async fn create_pat(&self, pat: &Pat) -> Result<(), StoreError>;

    /// A user's tokens, newest-first (the hash is never shown; this is for revoke/list).
    async fn list_pats(&self, owner_sub: &str) -> Result<Vec<Pat>, StoreError>;

    /// Find a token by its hash — the verification path for Basic-auth on the `/git/` routes.
    async fn find_pat_by_hash(&self, token_hash: &str) -> Result<Option<Pat>, StoreError>;

    /// Revoke (delete) a token, scoped to its owner. Returns whether a row was removed.
    async fn revoke_pat(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

/// In-memory `Store`. Each `Mutex<Vec<_>>` critical section is fully synchronous (no `.await`
/// held across the guard), so the std `Mutex` is correct here.
#[derive(Default)]
pub struct InMemoryStore {
    repos: Mutex<Vec<Repo>>,
    issues: Mutex<Vec<Issue>>,
    pats: Mutex<Vec<Pat>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    async fn create_repo(&self, repo: &Repo) -> Result<bool, StoreError> {
        let mut repos = self.repos.lock().expect("repos lock poisoned");
        if repos
            .iter()
            .any(|r| r.owner_sub == repo.owner_sub && r.name == repo.name)
        {
            return Ok(false);
        }
        repos.push(repo.clone());
        Ok(true)
    }

    async fn get_repo(&self, owner_sub: &str, name: &str) -> Result<Option<Repo>, StoreError> {
        let repos = self.repos.lock().expect("repos lock poisoned");
        Ok(repos
            .iter()
            .find(|r| r.owner_sub == owner_sub && r.name == name)
            .cloned())
    }

    async fn list_visible_repos(&self, viewer_sub: &str) -> Result<Vec<Repo>, StoreError> {
        let repos = self.repos.lock().expect("repos lock poisoned");
        let mut out: Vec<Repo> = repos
            .iter()
            .filter(|r| !r.is_private || r.owner_sub == viewer_sub)
            .cloned()
            .collect();
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| b.id.cmp(&a.id)));
        out.truncate(REPO_LIST_LIMIT);
        Ok(out)
    }

    async fn delete_repo(&self, id: &str) -> Result<bool, StoreError> {
        let mut repos = self.repos.lock().expect("repos lock poisoned");
        let before = repos.len();
        repos.retain(|r| r.id != id);
        Ok(repos.len() != before)
    }

    async fn create_issue(
        &self,
        id: &str,
        repo_id: &str,
        title: &str,
        body: &str,
        author_sub: &str,
        created_at: i64,
    ) -> Result<Issue, StoreError> {
        let mut issues = self.issues.lock().expect("issues lock poisoned");
        let number = issues
            .iter()
            .filter(|i| i.repo_id == repo_id)
            .map(|i| i.number)
            .max()
            .unwrap_or(0)
            + 1;
        let issue = Issue {
            id: id.to_string(),
            repo_id: repo_id.to_string(),
            number,
            title: title.to_string(),
            body: body.to_string(),
            author_sub: author_sub.to_string(),
            state: "open".to_string(),
            created_at,
        };
        issues.push(issue.clone());
        Ok(issue)
    }

    async fn list_issues(&self, repo_id: &str) -> Result<Vec<Issue>, StoreError> {
        let issues = self.issues.lock().expect("issues lock poisoned");
        let mut out: Vec<Issue> = issues
            .iter()
            .filter(|i| i.repo_id == repo_id)
            .cloned()
            .collect();
        out.sort_by_key(|i| std::cmp::Reverse(i.number));
        Ok(out)
    }

    async fn get_issue(
        &self,
        repo_id: &str,
        number: i64,
    ) -> Result<Option<Issue>, StoreError> {
        let issues = self.issues.lock().expect("issues lock poisoned");
        Ok(issues
            .iter()
            .find(|i| i.repo_id == repo_id && i.number == number)
            .cloned())
    }

    async fn set_issue_state(&self, id: &str, state: &str) -> Result<bool, StoreError> {
        let mut issues = self.issues.lock().expect("issues lock poisoned");
        for i in issues.iter_mut() {
            if i.id == id {
                let changed = i.state != state;
                i.state = state.to_string();
                return Ok(changed);
            }
        }
        Ok(false)
    }

    async fn open_issue_count(&self, repo_id: &str) -> Result<i64, StoreError> {
        let issues = self.issues.lock().expect("issues lock poisoned");
        Ok(issues
            .iter()
            .filter(|i| i.repo_id == repo_id && i.is_open())
            .count() as i64)
    }

    async fn create_pat(&self, pat: &Pat) -> Result<(), StoreError> {
        let mut pats = self.pats.lock().expect("pats lock poisoned");
        pats.push(pat.clone());
        Ok(())
    }

    async fn list_pats(&self, owner_sub: &str) -> Result<Vec<Pat>, StoreError> {
        let pats = self.pats.lock().expect("pats lock poisoned");
        let mut out: Vec<Pat> = pats
            .iter()
            .filter(|p| p.owner_sub == owner_sub)
            .cloned()
            .collect();
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| b.id.cmp(&a.id)));
        Ok(out)
    }

    async fn find_pat_by_hash(&self, token_hash: &str) -> Result<Option<Pat>, StoreError> {
        let pats = self.pats.lock().expect("pats lock poisoned");
        Ok(pats.iter().find(|p| p.token_hash == token_hash).cloned())
    }

    async fn revoke_pat(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError> {
        let mut pats = self.pats.lock().expect("pats lock poisoned");
        let before = pats.len();
        pats.retain(|p| !(p.id == id && p.owner_sub == owner_sub));
        Ok(pats.len() != before)
    }
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed store (portable: standard SQL, runtime queries, no macros).
// --------------------------------------------------------------------------------------
//
// Selected at runtime by `LOOM_STORE=postgres`. The `Store` trait is async, so each method uses
// sqlx natively and the handlers `.await` it on the serving runtime — there is NO `block_in_place`
// and NO sync-over-async, so a query never blocks a worker thread.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

const REPO_COLS: &str =
    "id, owner_sub, name, description, is_private, default_branch, created_at";
const ISSUE_COLS: &str =
    "id, repo_id, number, title, body, author_sub, state, created_at";
const PAT_COLS: &str = "id, owner_sub, name, token_hash, created_at";

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
            "CREATE TABLE IF NOT EXISTS repos (\
                 id TEXT PRIMARY KEY, \
                 owner_sub TEXT NOT NULL, \
                 name TEXT NOT NULL, \
                 description TEXT NOT NULL DEFAULT '', \
                 is_private BOOLEAN NOT NULL DEFAULT FALSE, \
                 default_branch TEXT NOT NULL DEFAULT 'main', \
                 created_at BIGINT NOT NULL, \
                 UNIQUE(owner_sub, name)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS issues (\
                 id TEXT PRIMARY KEY, \
                 repo_id TEXT NOT NULL, \
                 number BIGINT NOT NULL, \
                 title TEXT NOT NULL, \
                 body TEXT NOT NULL DEFAULT '', \
                 author_sub TEXT NOT NULL, \
                 state TEXT NOT NULL DEFAULT 'open', \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pats (\
                 id TEXT PRIMARY KEY, \
                 owner_sub TEXT NOT NULL, \
                 name TEXT NOT NULL, \
                 token_hash TEXT NOT NULL, \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Per-repo issue numbering uniqueness (backs the race-safe ON CONFLICT retry).
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_issues_repo_number \
             ON issues (repo_id, number)",
        )
        .execute(&self.pool)
        .await?;
        // Token verification lookup on the hot /git/ path.
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_pats_token_hash ON pats (token_hash)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_repos_owner ON repos (owner_sub)",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn repo_from_row(row: &sqlx::postgres::PgRow) -> Result<Repo, sqlx::Error> {
        Ok(Repo {
            id: row.try_get("id")?,
            owner_sub: row.try_get("owner_sub")?,
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            is_private: row.try_get("is_private")?,
            default_branch: row.try_get("default_branch")?,
            created_at: row.try_get("created_at")?,
        })
    }

    fn issue_from_row(row: &sqlx::postgres::PgRow) -> Result<Issue, sqlx::Error> {
        Ok(Issue {
            id: row.try_get("id")?,
            repo_id: row.try_get("repo_id")?,
            number: row.try_get("number")?,
            title: row.try_get("title")?,
            body: row.try_get("body")?,
            author_sub: row.try_get("author_sub")?,
            state: row.try_get("state")?,
            created_at: row.try_get("created_at")?,
        })
    }

    fn pat_from_row(row: &sqlx::postgres::PgRow) -> Result<Pat, sqlx::Error> {
        Ok(Pat {
            id: row.try_get("id")?,
            owner_sub: row.try_get("owner_sub")?,
            name: row.try_get("name")?,
            token_hash: row.try_get("token_hash")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[async_trait]
impl Store for PgStore {
    async fn create_repo(&self, repo: &Repo) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "INSERT INTO repos \
                 (id, owner_sub, name, description, is_private, default_branch, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (owner_sub, name) DO NOTHING",
        )
        .bind(&repo.id)
        .bind(&repo.owner_sub)
        .bind(&repo.name)
        .bind(&repo.description)
        .bind(repo.is_private)
        .bind(&repo.default_branch)
        .bind(repo.created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected() == 1)
    }

    async fn get_repo(&self, owner_sub: &str, name: &str) -> Result<Option<Repo>, StoreError> {
        let row = sqlx::query(&format!(
            "SELECT {REPO_COLS} FROM repos WHERE owner_sub = $1 AND name = $2"
        ))
        .bind(owner_sub)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        row.as_ref()
            .map(Self::repo_from_row)
            .transpose()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_visible_repos(&self, viewer_sub: &str) -> Result<Vec<Repo>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {REPO_COLS} FROM repos \
             WHERE is_private = FALSE OR owner_sub = $1 \
             ORDER BY created_at DESC LIMIT $2"
        ))
        .bind(viewer_sub)
        .bind(REPO_LIST_LIMIT as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        rows.iter()
            .map(Self::repo_from_row)
            .collect::<Result<_, _>>()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn delete_repo(&self, id: &str) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM repos WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    async fn create_issue(
        &self,
        id: &str,
        repo_id: &str,
        title: &str,
        body: &str,
        author_sub: &str,
        created_at: i64,
    ) -> Result<Issue, StoreError> {
        // Allocate the next per-repo number and insert; on the rare concurrent collision the
        // unique index rejects the row (0 affected) and we retry with a fresh max.
        for _ in 0..8 {
            let row = sqlx::query(
                "SELECT COALESCE(MAX(number), 0) + 1 AS next FROM issues WHERE repo_id = $1",
            )
            .bind(repo_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
            let number: i64 = row
                .try_get("next")
                .map_err(|e| StoreError::Backend(e.to_string()))?;

            let result = sqlx::query(
                "INSERT INTO issues \
                     (id, repo_id, number, title, body, author_sub, state, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, 'open', $7) \
                 ON CONFLICT (repo_id, number) DO NOTHING",
            )
            .bind(id)
            .bind(repo_id)
            .bind(number)
            .bind(title)
            .bind(body)
            .bind(author_sub)
            .bind(created_at)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

            if result.rows_affected() == 1 {
                return Ok(Issue {
                    id: id.to_string(),
                    repo_id: repo_id.to_string(),
                    number,
                    title: title.to_string(),
                    body: body.to_string(),
                    author_sub: author_sub.to_string(),
                    state: "open".to_string(),
                    created_at,
                });
            }
        }
        Err(StoreError::Backend(
            "could not allocate an issue number".to_string(),
        ))
    }

    async fn list_issues(&self, repo_id: &str) -> Result<Vec<Issue>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {ISSUE_COLS} FROM issues WHERE repo_id = $1 ORDER BY number DESC"
        ))
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        rows.iter()
            .map(Self::issue_from_row)
            .collect::<Result<_, _>>()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_issue(
        &self,
        repo_id: &str,
        number: i64,
    ) -> Result<Option<Issue>, StoreError> {
        let row = sqlx::query(&format!(
            "SELECT {ISSUE_COLS} FROM issues WHERE repo_id = $1 AND number = $2"
        ))
        .bind(repo_id)
        .bind(number)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        row.as_ref()
            .map(Self::issue_from_row)
            .transpose()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn set_issue_state(&self, id: &str, state: &str) -> Result<bool, StoreError> {
        let result = sqlx::query("UPDATE issues SET state = $1 WHERE id = $2")
            .bind(state)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    async fn open_issue_count(&self, repo_id: &str) -> Result<i64, StoreError> {
        let row = sqlx::query(
            "SELECT count(*) AS n FROM issues WHERE repo_id = $1 AND state = 'open'",
        )
        .bind(repo_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        row.try_get("n").map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn create_pat(&self, pat: &Pat) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO pats (id, owner_sub, name, token_hash, created_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&pat.id)
        .bind(&pat.owner_sub)
        .bind(&pat.name)
        .bind(&pat.token_hash)
        .bind(pat.created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn list_pats(&self, owner_sub: &str) -> Result<Vec<Pat>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {PAT_COLS} FROM pats WHERE owner_sub = $1 ORDER BY created_at DESC"
        ))
        .bind(owner_sub)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        rows.iter()
            .map(Self::pat_from_row)
            .collect::<Result<_, _>>()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn find_pat_by_hash(&self, token_hash: &str) -> Result<Option<Pat>, StoreError> {
        let row = sqlx::query(&format!(
            "SELECT {PAT_COLS} FROM pats WHERE token_hash = $1"
        ))
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        row.as_ref()
            .map(Self::pat_from_row)
            .transpose()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn revoke_pat(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM pats WHERE id = $1 AND owner_sub = $2")
            .bind(id)
            .bind(owner_sub)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(owner: &str, name: &str, private: bool, created: i64) -> Repo {
        Repo {
            id: format!("rp_{owner}_{name}"),
            owner_sub: owner.into(),
            name: name.into(),
            description: "d".into(),
            is_private: private,
            default_branch: "main".into(),
            created_at: created,
        }
    }

    #[tokio::test]
    async fn repo_create_is_unique_per_owner_and_name() {
        let s = InMemoryStore::new();
        assert!(s.create_repo(&repo("u", "a", false, 1)).await.unwrap());
        assert!(!s.create_repo(&repo("u", "a", false, 2)).await.unwrap());
        // Same name under a different owner is fine.
        assert!(s.create_repo(&repo("v", "a", false, 3)).await.unwrap());
    }

    #[tokio::test]
    async fn visibility_filters_private_repos() {
        let s = InMemoryStore::new();
        s.create_repo(&repo("u", "pub", false, 1)).await.unwrap();
        s.create_repo(&repo("u", "sec", true, 2)).await.unwrap();
        s.create_repo(&repo("v", "vsec", true, 3)).await.unwrap();

        let seen: Vec<String> = s
            .list_visible_repos("u")
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.name)
            .collect();
        // u sees its own private + the public; never v's private.
        assert!(seen.contains(&"pub".to_string()));
        assert!(seen.contains(&"sec".to_string()));
        assert!(!seen.contains(&"vsec".to_string()));
    }

    #[tokio::test]
    async fn issue_numbers_are_sequential_per_repo() {
        let s = InMemoryStore::new();
        let i1 = s.create_issue("i1", "r", "first", "", "u", 1).await.unwrap();
        let i2 = s.create_issue("i2", "r", "second", "", "u", 2).await.unwrap();
        let other = s.create_issue("i3", "other", "x", "", "u", 3).await.unwrap();
        assert_eq!(i1.number, 1);
        assert_eq!(i2.number, 2);
        assert_eq!(other.number, 1); // independent per repo

        assert_eq!(s.open_issue_count("r").await.unwrap(), 2);
        assert!(s.set_issue_state("i1", "closed").await.unwrap());
        assert_eq!(s.open_issue_count("r").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn pat_lookup_and_revoke() {
        let s = InMemoryStore::new();
        let pat = Pat {
            id: "p1".into(),
            owner_sub: "u".into(),
            name: "laptop".into(),
            token_hash: "deadbeef".into(),
            created_at: 1,
        };
        s.create_pat(&pat).await.unwrap();
        assert_eq!(s.find_pat_by_hash("deadbeef").await.unwrap().unwrap().id, "p1");
        assert!(s.find_pat_by_hash("nope").await.unwrap().is_none());
        // Wrong owner cannot revoke.
        assert!(!s.revoke_pat("p1", "v").await.unwrap());
        assert!(s.revoke_pat("p1", "u").await.unwrap());
        assert!(s.find_pat_by_hash("deadbeef").await.unwrap().is_none());
    }
}
