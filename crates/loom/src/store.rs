//! Metadata storage: repositories, releases, issues, personal access tokens.
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
use crate::model::{
    CommitStatus, Issue, IssueComment, Label, Milestone, Pat, PrFileViewed, Pull, PullReview,
    PullReviewComment, Release, Repo,
};

/// Storage failure surfaced to the handler layer (mapped to a 500 `server_error`).
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store error: {0}")]
    Backend(String),
}

/// Aggregate latest per-context commit statuses:
/// failure/error wins, then pending, then success; no rows means no aggregate status.
pub fn aggregate_commit_statuses(statuses: &[CommitStatus]) -> Option<String> {
    if statuses.is_empty() {
        return None;
    }
    let mut saw_pending = false;
    let mut saw_success = false;
    for status in statuses {
        match status.state.as_str() {
            "failure" | "error" => return Some("failure".to_string()),
            "pending" => saw_pending = true,
            "success" => saw_success = true,
            _ => saw_pending = true,
        }
    }
    if saw_pending {
        Some("pending".to_string())
    } else if saw_success {
        Some("success".to_string())
    } else {
        None
    }
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

    /// Update a repo's editable settings (description + default branch) by id. Returns whether a
    /// row changed.
    async fn update_repo_settings(
        &self,
        id: &str,
        description: &str,
        default_branch: &str,
        require_approval: bool,
        protect_default_branch: bool,
    ) -> Result<bool, StoreError>;

    /// Fetch a repo by opaque id (used for fork attribution links).
    async fn get_repo_by_id(&self, id: &str) -> Result<Option<Repo>, StoreError>;

    // --- releases ------------------------------------------------------------
    /// Create a release. Returns `Ok(None)` when the repo already has a release for the tag.
    async fn create_release(&self, release: &Release) -> Result<Option<Release>, StoreError>;

    /// Replace release metadata by id. Returns whether a row changed.
    async fn update_release(&self, release: &Release) -> Result<bool, StoreError>;

    /// Delete a release by repo + id. Returns whether a row was removed.
    async fn delete_release(&self, repo_id: &str, id: &str) -> Result<bool, StoreError>;

    /// Fetch one release by repo + id.
    async fn get_release(&self, repo_id: &str, id: &str) -> Result<Option<Release>, StoreError>;

    /// Fetch one release by repo + tag name.
    async fn get_release_by_tag(
        &self,
        repo_id: &str,
        tag_name: &str,
    ) -> Result<Option<Release>, StoreError>;

    /// All releases on a repo, newest created first.
    async fn list_releases_by_repo(&self, repo_id: &str) -> Result<Vec<Release>, StoreError>;

    /// Count releases on a repo. Drafts are optionally included for writer-visible badges.
    async fn release_count(&self, repo_id: &str, include_drafts: bool) -> Result<i64, StoreError>;

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

    /// A page of issues on a repo, newest number first, optionally filtered by state. `state_filter`
    /// is `""` (all), `"open"`, or `"closed"`. `limit`/`offset` drive simple pagination.
    async fn list_issues_page(
        &self,
        repo_id: &str,
        state_filter: &str,
        label_filter: &str,
        milestone_filter: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Issue>, StoreError>;

    /// Count of issues on a repo matching state/label/milestone filters — the pager total.
    async fn count_issues(
        &self,
        repo_id: &str,
        state_filter: &str,
        label_filter: &str,
        milestone_filter: &str,
    ) -> Result<i64, StoreError>;

    /// One issue by its per-repo number.
    async fn get_issue(&self, repo_id: &str, number: i64) -> Result<Option<Issue>, StoreError>;

    /// Set an issue's state (`open`/`closed`) by id, stamping `updated_at`. Returns whether a row
    /// changed.
    async fn set_issue_state(
        &self,
        id: &str,
        state: &str,
        updated_at: i64,
    ) -> Result<bool, StoreError>;

    /// Count of OPEN issues on a repo (for the repo header badge).
    async fn open_issue_count(&self, repo_id: &str) -> Result<i64, StoreError>;

    // --- issue comments ------------------------------------------------------
    /// Append a comment to an issue and stamp the parent issue's `updated_at` to `created_at`
    /// (last-activity). Returns the stored comment.
    async fn create_comment(
        &self,
        id: &str,
        issue_id: &str,
        author_sub: &str,
        body: &str,
        created_at: i64,
    ) -> Result<IssueComment, StoreError>;

    /// All comments on an issue, oldest first (chronological thread order).
    async fn list_comments(&self, issue_id: &str) -> Result<Vec<IssueComment>, StoreError>;

    /// Replace issue assignee/milestone/label metadata in one operation.
    async fn set_issue_metadata(
        &self,
        issue_id: &str,
        assignee_sub: &str,
        milestone_id: &str,
        label_ids: &[String],
    ) -> Result<bool, StoreError>;

    /// All labels assigned to one issue, ordered by label name.
    async fn issue_labels(&self, issue_id: &str) -> Result<Vec<Label>, StoreError>;

    /// All issue-label assignments on a repo.
    async fn list_issue_labels(&self, repo_id: &str) -> Result<Vec<(String, Label)>, StoreError>;

    // --- pulls ---------------------------------------------------------------
    /// Create a pull request, atomically allocating the next per-repo `number`. Returns the stored
    /// PR (with its assigned number and `open` state).
    #[allow(clippy::too_many_arguments)]
    async fn create_pull(
        &self,
        id: &str,
        repo_id: &str,
        title: &str,
        body: &str,
        base: &str,
        head: &str,
        author_sub: &str,
        created_at: i64,
    ) -> Result<Pull, StoreError>;

    /// All pull requests on a repo, newest number first.
    async fn list_pulls(&self, repo_id: &str) -> Result<Vec<Pull>, StoreError>;

    /// Pull requests on a repo, newest number first, optionally filtered by label/milestone.
    async fn list_pulls_filtered(
        &self,
        repo_id: &str,
        label_filter: &str,
        milestone_filter: &str,
    ) -> Result<Vec<Pull>, StoreError>;

    /// One pull request by its per-repo number.
    async fn get_pull(&self, repo_id: &str, number: i64) -> Result<Option<Pull>, StoreError>;

    /// Set a PR's state (`open`/`closed`) by id. Returns whether a row changed.
    async fn set_pull_state(&self, id: &str, state: &str) -> Result<bool, StoreError>;

    /// Mark a PR merged: sets `state='merged'` and records `merged_at`. Returns whether a row
    /// changed (false when the PR is already non-open, guarding a double-merge).
    async fn merge_pull(&self, id: &str, merged_at: i64) -> Result<bool, StoreError>;

    /// Count of OPEN pull requests on a repo (for the repo header badge).
    async fn open_pull_count(&self, repo_id: &str) -> Result<i64, StoreError>;

    /// Replace pull-request assignee/reviewer/milestone/label metadata in one operation.
    async fn set_pull_metadata(
        &self,
        pull_id: &str,
        assignee_sub: &str,
        reviewer_sub: &str,
        milestone_id: &str,
        label_ids: &[String],
    ) -> Result<bool, StoreError>;

    /// All labels assigned to one pull request, ordered by label name.
    async fn pull_labels(&self, pull_id: &str) -> Result<Vec<Label>, StoreError>;

    /// All pull-label assignments on a repo.
    async fn list_pull_labels(&self, repo_id: &str) -> Result<Vec<(String, Label)>, StoreError>;

    /// Upsert one viewer's per-file viewed state for a PR.
    async fn set_pr_file_viewed(
        &self,
        pr_id: &str,
        user_sub: &str,
        file_path: &str,
        viewed: bool,
        updated_at: i64,
    ) -> Result<PrFileViewed, StoreError>;

    /// Viewed rows for one PR and viewer.
    async fn list_pr_file_viewed_for_pr(
        &self,
        pr_id: &str,
        user_sub: &str,
    ) -> Result<Vec<PrFileViewed>, StoreError>;

    // --- labels + milestones -------------------------------------------------
    /// Create a repo-scoped label. Returns `Ok(None)` when the label name already exists.
    async fn create_label(
        &self,
        id: &str,
        repo_id: &str,
        name: &str,
        color: &str,
        created_at: i64,
    ) -> Result<Option<Label>, StoreError>;

    /// Repo labels ordered by name.
    async fn list_labels(&self, repo_id: &str) -> Result<Vec<Label>, StoreError>;

    /// Create a repo-scoped milestone. Returns `Ok(None)` when the title already exists.
    async fn create_milestone(
        &self,
        id: &str,
        repo_id: &str,
        title: &str,
        due: &str,
        created_at: i64,
    ) -> Result<Option<Milestone>, StoreError>;

    /// Repo milestones ordered by open-first then created time.
    async fn list_milestones(&self, repo_id: &str) -> Result<Vec<Milestone>, StoreError>;

    /// Toggle a milestone state (`open`/`closed`).
    async fn set_milestone_state(&self, id: &str, state: &str) -> Result<bool, StoreError>;

    /// Closed/total progress for a milestone across issues and PRs.
    async fn milestone_progress(
        &self,
        repo_id: &str,
        milestone_id: &str,
    ) -> Result<(i64, i64), StoreError>;

    // --- pull reviews --------------------------------------------------------
    /// Add a PR review verdict.
    async fn create_pull_review(
        &self,
        id: &str,
        pull_id: &str,
        reviewer_sub: &str,
        verdict: &str,
        body: &str,
        created_at: i64,
    ) -> Result<PullReview, StoreError>;

    /// All reviews on a PR, oldest first.
    async fn list_pull_reviews(&self, pull_id: &str) -> Result<Vec<PullReview>, StoreError>;

    /// Add an inline PR review comment anchored to file + line.
    #[allow(clippy::too_many_arguments)]
    async fn create_pull_review_comment(
        &self,
        id: &str,
        pull_id: &str,
        review_id: &str,
        path: &str,
        line: i64,
        author_sub: &str,
        body: &str,
        created_at: i64,
    ) -> Result<PullReviewComment, StoreError>;

    /// All inline comments on a PR, ordered by anchor then time.
    async fn list_pull_review_comments(
        &self,
        pull_id: &str,
    ) -> Result<Vec<PullReviewComment>, StoreError>;

    // --- commit statuses -------------------------------------------------------
    /// Insert or replace the latest status for `(repo_id, commit_sha, context)`.
    async fn upsert_commit_status(&self, status: &CommitStatus)
    -> Result<CommitStatus, StoreError>;

    /// Latest statuses for every context on one commit, ordered by context.
    async fn list_commit_statuses(
        &self,
        repo_id: &str,
        commit_sha: &str,
    ) -> Result<Vec<CommitStatus>, StoreError>;

    /// Aggregate state for one commit after considering each context's latest status.
    async fn aggregate_state_for_commit(
        &self,
        repo_id: &str,
        commit_sha: &str,
    ) -> Result<Option<String>, StoreError>;

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
    releases: Mutex<Vec<Release>>,
    issues: Mutex<Vec<Issue>>,
    issue_comments: Mutex<Vec<IssueComment>>,
    issue_labels: Mutex<Vec<(String, String)>>,
    pulls: Mutex<Vec<Pull>>,
    pull_labels: Mutex<Vec<(String, String)>>,
    labels: Mutex<Vec<Label>>,
    milestones: Mutex<Vec<Milestone>>,
    pull_reviews: Mutex<Vec<PullReview>>,
    pull_review_comments: Mutex<Vec<PullReviewComment>>,
    pr_file_viewed: Mutex<Vec<PrFileViewed>>,
    commit_statuses: Mutex<Vec<CommitStatus>>,
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
        out.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        out.truncate(REPO_LIST_LIMIT);
        Ok(out)
    }

    async fn delete_repo(&self, id: &str) -> Result<bool, StoreError> {
        let mut repos = self.repos.lock().expect("repos lock poisoned");
        let before = repos.len();
        repos.retain(|r| r.id != id);
        Ok(repos.len() != before)
    }

    async fn update_repo_settings(
        &self,
        id: &str,
        description: &str,
        default_branch: &str,
        require_approval: bool,
        protect_default_branch: bool,
    ) -> Result<bool, StoreError> {
        let mut repos = self.repos.lock().expect("repos lock poisoned");
        for r in repos.iter_mut() {
            if r.id == id {
                r.description = description.to_string();
                r.default_branch = default_branch.to_string();
                r.require_approval = require_approval;
                r.protect_default_branch = protect_default_branch;
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn get_repo_by_id(&self, id: &str) -> Result<Option<Repo>, StoreError> {
        let repos = self.repos.lock().expect("repos lock poisoned");
        Ok(repos.iter().find(|r| r.id == id).cloned())
    }

    async fn create_release(&self, release: &Release) -> Result<Option<Release>, StoreError> {
        let mut releases = self.releases.lock().expect("releases lock poisoned");
        if releases
            .iter()
            .any(|r| r.repo_id == release.repo_id && r.tag_name == release.tag_name)
        {
            return Ok(None);
        }
        releases.push(release.clone());
        Ok(Some(release.clone()))
    }

    async fn update_release(&self, release: &Release) -> Result<bool, StoreError> {
        let mut releases = self.releases.lock().expect("releases lock poisoned");
        for r in releases.iter_mut() {
            if r.repo_id == release.repo_id && r.id == release.id {
                *r = release.clone();
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn delete_release(&self, repo_id: &str, id: &str) -> Result<bool, StoreError> {
        let mut releases = self.releases.lock().expect("releases lock poisoned");
        let before = releases.len();
        releases.retain(|r| !(r.repo_id == repo_id && r.id == id));
        Ok(releases.len() != before)
    }

    async fn get_release(&self, repo_id: &str, id: &str) -> Result<Option<Release>, StoreError> {
        let releases = self.releases.lock().expect("releases lock poisoned");
        Ok(releases
            .iter()
            .find(|r| r.repo_id == repo_id && r.id == id)
            .cloned())
    }

    async fn get_release_by_tag(
        &self,
        repo_id: &str,
        tag_name: &str,
    ) -> Result<Option<Release>, StoreError> {
        let releases = self.releases.lock().expect("releases lock poisoned");
        Ok(releases
            .iter()
            .find(|r| r.repo_id == repo_id && r.tag_name == tag_name)
            .cloned())
    }

    async fn list_releases_by_repo(&self, repo_id: &str) -> Result<Vec<Release>, StoreError> {
        let releases = self.releases.lock().expect("releases lock poisoned");
        let mut out: Vec<Release> = releases
            .iter()
            .filter(|r| r.repo_id == repo_id)
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        Ok(out)
    }

    async fn release_count(&self, repo_id: &str, include_drafts: bool) -> Result<i64, StoreError> {
        let releases = self.releases.lock().expect("releases lock poisoned");
        Ok(releases
            .iter()
            .filter(|r| r.repo_id == repo_id && (include_drafts || !r.is_draft))
            .count() as i64)
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
            assignee_sub: String::new(),
            milestone_id: String::new(),
            state: "open".to_string(),
            created_at,
            updated_at: created_at,
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

    async fn list_issues_page(
        &self,
        repo_id: &str,
        state_filter: &str,
        label_filter: &str,
        milestone_filter: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Issue>, StoreError> {
        let issues = self.issues.lock().expect("issues lock poisoned");
        let issue_labels = self
            .issue_labels
            .lock()
            .expect("issue_labels lock poisoned");
        let mut out: Vec<Issue> = issues
            .iter()
            .filter(|i| {
                i.repo_id == repo_id
                    && (state_filter.is_empty() || i.state == state_filter)
                    && (milestone_filter.is_empty() || i.milestone_id == milestone_filter)
                    && (label_filter.is_empty()
                        || issue_labels.iter().any(|(issue_id, label_id)| {
                            issue_id == &i.id && label_id == label_filter
                        }))
            })
            .cloned()
            .collect();
        out.sort_by_key(|i| std::cmp::Reverse(i.number));
        Ok(out
            .into_iter()
            .skip(offset.max(0) as usize)
            .take(limit.max(0) as usize)
            .collect())
    }

    async fn count_issues(
        &self,
        repo_id: &str,
        state_filter: &str,
        label_filter: &str,
        milestone_filter: &str,
    ) -> Result<i64, StoreError> {
        let issues = self.issues.lock().expect("issues lock poisoned");
        let issue_labels = self
            .issue_labels
            .lock()
            .expect("issue_labels lock poisoned");
        Ok(issues
            .iter()
            .filter(|i| {
                i.repo_id == repo_id
                    && (state_filter.is_empty() || i.state == state_filter)
                    && (milestone_filter.is_empty() || i.milestone_id == milestone_filter)
                    && (label_filter.is_empty()
                        || issue_labels.iter().any(|(issue_id, label_id)| {
                            issue_id == &i.id && label_id == label_filter
                        }))
            })
            .count() as i64)
    }

    async fn get_issue(&self, repo_id: &str, number: i64) -> Result<Option<Issue>, StoreError> {
        let issues = self.issues.lock().expect("issues lock poisoned");
        Ok(issues
            .iter()
            .find(|i| i.repo_id == repo_id && i.number == number)
            .cloned())
    }

    async fn set_issue_state(
        &self,
        id: &str,
        state: &str,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        let mut issues = self.issues.lock().expect("issues lock poisoned");
        for i in issues.iter_mut() {
            if i.id == id {
                let changed = i.state != state;
                i.state = state.to_string();
                i.updated_at = updated_at;
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

    async fn create_comment(
        &self,
        id: &str,
        issue_id: &str,
        author_sub: &str,
        body: &str,
        created_at: i64,
    ) -> Result<IssueComment, StoreError> {
        let comment = IssueComment {
            id: id.to_string(),
            issue_id: issue_id.to_string(),
            author_sub: author_sub.to_string(),
            body: body.to_string(),
            created_at,
        };
        self.issue_comments
            .lock()
            .expect("issue_comments lock poisoned")
            .push(comment.clone());
        // Last-activity bump on the parent issue.
        if let Some(i) = self
            .issues
            .lock()
            .expect("issues lock poisoned")
            .iter_mut()
            .find(|i| i.id == issue_id)
        {
            i.updated_at = created_at;
        }
        Ok(comment)
    }

    async fn list_comments(&self, issue_id: &str) -> Result<Vec<IssueComment>, StoreError> {
        let comments = self
            .issue_comments
            .lock()
            .expect("issue_comments lock poisoned");
        let mut out: Vec<IssueComment> = comments
            .iter()
            .filter(|c| c.issue_id == issue_id)
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(out)
    }

    async fn set_issue_metadata(
        &self,
        issue_id: &str,
        assignee_sub: &str,
        milestone_id: &str,
        label_ids: &[String],
    ) -> Result<bool, StoreError> {
        let mut issues = self.issues.lock().expect("issues lock poisoned");
        let Some(issue) = issues.iter_mut().find(|i| i.id == issue_id) else {
            return Ok(false);
        };
        issue.assignee_sub = assignee_sub.to_string();
        issue.milestone_id = milestone_id.to_string();
        drop(issues);

        let mut issue_labels = self
            .issue_labels
            .lock()
            .expect("issue_labels lock poisoned");
        issue_labels.retain(|(id, _)| id != issue_id);
        for label_id in label_ids {
            if !label_id.is_empty()
                && !issue_labels
                    .iter()
                    .any(|(id, existing)| id == issue_id && existing == label_id)
            {
                issue_labels.push((issue_id.to_string(), label_id.clone()));
            }
        }
        Ok(true)
    }

    async fn issue_labels(&self, issue_id: &str) -> Result<Vec<Label>, StoreError> {
        let labels = self.labels.lock().expect("labels lock poisoned");
        let issue_labels = self
            .issue_labels
            .lock()
            .expect("issue_labels lock poisoned");
        let mut out: Vec<Label> = issue_labels
            .iter()
            .filter(|(id, _)| id == issue_id)
            .filter_map(|(_, label_id)| labels.iter().find(|l| &l.id == label_id).cloned())
            .collect();
        out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        Ok(out)
    }

    async fn list_issue_labels(&self, repo_id: &str) -> Result<Vec<(String, Label)>, StoreError> {
        let labels = self.labels.lock().expect("labels lock poisoned");
        let issue_labels = self
            .issue_labels
            .lock()
            .expect("issue_labels lock poisoned");
        let mut out = Vec::new();
        for (issue_id, label_id) in issue_labels.iter() {
            if let Some(label) = labels
                .iter()
                .find(|l| l.repo_id == repo_id && &l.id == label_id)
                .cloned()
            {
                out.push((issue_id.clone(), label));
            }
        }
        out.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.name.to_lowercase().cmp(&b.1.name.to_lowercase()))
        });
        Ok(out)
    }

    async fn create_pull(
        &self,
        id: &str,
        repo_id: &str,
        title: &str,
        body: &str,
        base: &str,
        head: &str,
        author_sub: &str,
        created_at: i64,
    ) -> Result<Pull, StoreError> {
        let mut pulls = self.pulls.lock().expect("pulls lock poisoned");
        let number = pulls
            .iter()
            .filter(|p| p.repo_id == repo_id)
            .map(|p| p.number)
            .max()
            .unwrap_or(0)
            + 1;
        let pull = Pull {
            id: id.to_string(),
            repo_id: repo_id.to_string(),
            number,
            title: title.to_string(),
            body: body.to_string(),
            base: base.to_string(),
            head: head.to_string(),
            author_sub: author_sub.to_string(),
            assignee_sub: String::new(),
            reviewer_sub: String::new(),
            milestone_id: String::new(),
            state: "open".to_string(),
            created_at,
            merged_at: 0,
        };
        pulls.push(pull.clone());
        Ok(pull)
    }

    async fn list_pulls(&self, repo_id: &str) -> Result<Vec<Pull>, StoreError> {
        self.list_pulls_filtered(repo_id, "", "").await
    }

    async fn list_pulls_filtered(
        &self,
        repo_id: &str,
        label_filter: &str,
        milestone_filter: &str,
    ) -> Result<Vec<Pull>, StoreError> {
        let pulls = self.pulls.lock().expect("pulls lock poisoned");
        let pull_labels = self.pull_labels.lock().expect("pull_labels lock poisoned");
        let mut out: Vec<Pull> = pulls
            .iter()
            .filter(|p| {
                p.repo_id == repo_id
                    && (milestone_filter.is_empty() || p.milestone_id == milestone_filter)
                    && (label_filter.is_empty()
                        || pull_labels.iter().any(|(pull_id, label_id)| {
                            pull_id == &p.id && label_id == label_filter
                        }))
            })
            .cloned()
            .collect();
        out.sort_by_key(|p| std::cmp::Reverse(p.number));
        Ok(out)
    }

    async fn get_pull(&self, repo_id: &str, number: i64) -> Result<Option<Pull>, StoreError> {
        let pulls = self.pulls.lock().expect("pulls lock poisoned");
        Ok(pulls
            .iter()
            .find(|p| p.repo_id == repo_id && p.number == number)
            .cloned())
    }

    async fn set_pull_state(&self, id: &str, state: &str) -> Result<bool, StoreError> {
        let mut pulls = self.pulls.lock().expect("pulls lock poisoned");
        for p in pulls.iter_mut() {
            if p.id == id {
                let changed = p.state != state;
                p.state = state.to_string();
                return Ok(changed);
            }
        }
        Ok(false)
    }

    async fn merge_pull(&self, id: &str, merged_at: i64) -> Result<bool, StoreError> {
        let mut pulls = self.pulls.lock().expect("pulls lock poisoned");
        for p in pulls.iter_mut() {
            // Only an OPEN PR can transition to merged (guards a concurrent double-merge).
            if p.id == id && p.is_open() {
                p.state = "merged".to_string();
                p.merged_at = merged_at;
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn open_pull_count(&self, repo_id: &str) -> Result<i64, StoreError> {
        let pulls = self.pulls.lock().expect("pulls lock poisoned");
        Ok(pulls
            .iter()
            .filter(|p| p.repo_id == repo_id && p.is_open())
            .count() as i64)
    }

    async fn set_pull_metadata(
        &self,
        pull_id: &str,
        assignee_sub: &str,
        reviewer_sub: &str,
        milestone_id: &str,
        label_ids: &[String],
    ) -> Result<bool, StoreError> {
        let mut pulls = self.pulls.lock().expect("pulls lock poisoned");
        let Some(pull) = pulls.iter_mut().find(|p| p.id == pull_id) else {
            return Ok(false);
        };
        pull.assignee_sub = assignee_sub.to_string();
        pull.reviewer_sub = reviewer_sub.to_string();
        pull.milestone_id = milestone_id.to_string();
        drop(pulls);

        let mut pull_labels = self.pull_labels.lock().expect("pull_labels lock poisoned");
        pull_labels.retain(|(id, _)| id != pull_id);
        for label_id in label_ids {
            if !label_id.is_empty()
                && !pull_labels
                    .iter()
                    .any(|(id, existing)| id == pull_id && existing == label_id)
            {
                pull_labels.push((pull_id.to_string(), label_id.clone()));
            }
        }
        Ok(true)
    }

    async fn pull_labels(&self, pull_id: &str) -> Result<Vec<Label>, StoreError> {
        let labels = self.labels.lock().expect("labels lock poisoned");
        let pull_labels = self.pull_labels.lock().expect("pull_labels lock poisoned");
        let mut out: Vec<Label> = pull_labels
            .iter()
            .filter(|(id, _)| id == pull_id)
            .filter_map(|(_, label_id)| labels.iter().find(|l| &l.id == label_id).cloned())
            .collect();
        out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        Ok(out)
    }

    async fn list_pull_labels(&self, repo_id: &str) -> Result<Vec<(String, Label)>, StoreError> {
        let labels = self.labels.lock().expect("labels lock poisoned");
        let pull_labels = self.pull_labels.lock().expect("pull_labels lock poisoned");
        let mut out = Vec::new();
        for (pull_id, label_id) in pull_labels.iter() {
            if let Some(label) = labels
                .iter()
                .find(|l| l.repo_id == repo_id && &l.id == label_id)
                .cloned()
            {
                out.push((pull_id.clone(), label));
            }
        }
        out.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.name.to_lowercase().cmp(&b.1.name.to_lowercase()))
        });
        Ok(out)
    }

    async fn set_pr_file_viewed(
        &self,
        pr_id: &str,
        user_sub: &str,
        file_path: &str,
        viewed: bool,
        updated_at: i64,
    ) -> Result<PrFileViewed, StoreError> {
        let mut rows = self
            .pr_file_viewed
            .lock()
            .expect("pr_file_viewed lock poisoned");
        if let Some(existing) = rows.iter_mut().find(|row| {
            row.pr_id == pr_id && row.user_sub == user_sub && row.file_path == file_path
        }) {
            existing.viewed = viewed;
            existing.updated_at = updated_at;
            return Ok(existing.clone());
        }
        let row = PrFileViewed {
            pr_id: pr_id.to_string(),
            user_sub: user_sub.to_string(),
            file_path: file_path.to_string(),
            viewed,
            updated_at,
        };
        rows.push(row.clone());
        Ok(row)
    }

    async fn list_pr_file_viewed_for_pr(
        &self,
        pr_id: &str,
        user_sub: &str,
    ) -> Result<Vec<PrFileViewed>, StoreError> {
        let rows = self
            .pr_file_viewed
            .lock()
            .expect("pr_file_viewed lock poisoned");
        let mut out: Vec<PrFileViewed> = rows
            .iter()
            .filter(|row| row.pr_id == pr_id && row.user_sub == user_sub)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.file_path.cmp(&b.file_path));
        Ok(out)
    }

    async fn create_label(
        &self,
        id: &str,
        repo_id: &str,
        name: &str,
        color: &str,
        created_at: i64,
    ) -> Result<Option<Label>, StoreError> {
        let mut labels = self.labels.lock().expect("labels lock poisoned");
        if labels
            .iter()
            .any(|l| l.repo_id == repo_id && l.name == name)
        {
            return Ok(None);
        }
        let label = Label {
            id: id.to_string(),
            repo_id: repo_id.to_string(),
            name: name.to_string(),
            color: color.to_string(),
            created_at,
        };
        labels.push(label.clone());
        Ok(Some(label))
    }

    async fn list_labels(&self, repo_id: &str) -> Result<Vec<Label>, StoreError> {
        let labels = self.labels.lock().expect("labels lock poisoned");
        let mut out: Vec<Label> = labels
            .iter()
            .filter(|l| l.repo_id == repo_id)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        Ok(out)
    }

    async fn create_milestone(
        &self,
        id: &str,
        repo_id: &str,
        title: &str,
        due: &str,
        created_at: i64,
    ) -> Result<Option<Milestone>, StoreError> {
        let mut milestones = self.milestones.lock().expect("milestones lock poisoned");
        if milestones
            .iter()
            .any(|m| m.repo_id == repo_id && m.title == title)
        {
            return Ok(None);
        }
        let milestone = Milestone {
            id: id.to_string(),
            repo_id: repo_id.to_string(),
            title: title.to_string(),
            due: due.to_string(),
            state: "open".to_string(),
            created_at,
        };
        milestones.push(milestone.clone());
        Ok(Some(milestone))
    }

    async fn list_milestones(&self, repo_id: &str) -> Result<Vec<Milestone>, StoreError> {
        let milestones = self.milestones.lock().expect("milestones lock poisoned");
        let mut out: Vec<Milestone> = milestones
            .iter()
            .filter(|m| m.repo_id == repo_id)
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            b.is_open()
                .cmp(&a.is_open())
                .then_with(|| b.created_at.cmp(&a.created_at))
                .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
        });
        Ok(out)
    }

    async fn set_milestone_state(&self, id: &str, state: &str) -> Result<bool, StoreError> {
        let mut milestones = self.milestones.lock().expect("milestones lock poisoned");
        for m in milestones.iter_mut() {
            if m.id == id {
                let changed = m.state != state;
                m.state = state.to_string();
                return Ok(changed);
            }
        }
        Ok(false)
    }

    async fn milestone_progress(
        &self,
        repo_id: &str,
        milestone_id: &str,
    ) -> Result<(i64, i64), StoreError> {
        let issues = self.issues.lock().expect("issues lock poisoned");
        let pulls = self.pulls.lock().expect("pulls lock poisoned");
        let issue_total = issues
            .iter()
            .filter(|i| i.repo_id == repo_id && i.milestone_id == milestone_id)
            .count() as i64;
        let issue_closed = issues
            .iter()
            .filter(|i| i.repo_id == repo_id && i.milestone_id == milestone_id && !i.is_open())
            .count() as i64;
        let pull_total = pulls
            .iter()
            .filter(|p| p.repo_id == repo_id && p.milestone_id == milestone_id)
            .count() as i64;
        let pull_closed = pulls
            .iter()
            .filter(|p| p.repo_id == repo_id && p.milestone_id == milestone_id && !p.is_open())
            .count() as i64;
        Ok((issue_closed + pull_closed, issue_total + pull_total))
    }

    async fn create_pull_review(
        &self,
        id: &str,
        pull_id: &str,
        reviewer_sub: &str,
        verdict: &str,
        body: &str,
        created_at: i64,
    ) -> Result<PullReview, StoreError> {
        let review = PullReview {
            id: id.to_string(),
            pull_id: pull_id.to_string(),
            reviewer_sub: reviewer_sub.to_string(),
            verdict: verdict.to_string(),
            body: body.to_string(),
            created_at,
        };
        self.pull_reviews
            .lock()
            .expect("pull_reviews lock poisoned")
            .push(review.clone());
        Ok(review)
    }

    async fn list_pull_reviews(&self, pull_id: &str) -> Result<Vec<PullReview>, StoreError> {
        let reviews = self
            .pull_reviews
            .lock()
            .expect("pull_reviews lock poisoned");
        let mut out: Vec<PullReview> = reviews
            .iter()
            .filter(|r| r.pull_id == pull_id)
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(out)
    }

    async fn create_pull_review_comment(
        &self,
        id: &str,
        pull_id: &str,
        review_id: &str,
        path: &str,
        line: i64,
        author_sub: &str,
        body: &str,
        created_at: i64,
    ) -> Result<PullReviewComment, StoreError> {
        let comment = PullReviewComment {
            id: id.to_string(),
            pull_id: pull_id.to_string(),
            review_id: review_id.to_string(),
            path: path.to_string(),
            line,
            author_sub: author_sub.to_string(),
            body: body.to_string(),
            created_at,
        };
        self.pull_review_comments
            .lock()
            .expect("pull_review_comments lock poisoned")
            .push(comment.clone());
        Ok(comment)
    }

    async fn list_pull_review_comments(
        &self,
        pull_id: &str,
    ) -> Result<Vec<PullReviewComment>, StoreError> {
        let comments = self
            .pull_review_comments
            .lock()
            .expect("pull_review_comments lock poisoned");
        let mut out: Vec<PullReviewComment> = comments
            .iter()
            .filter(|c| c.pull_id == pull_id)
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            a.path
                .cmp(&b.path)
                .then_with(|| a.line.cmp(&b.line))
                .then_with(|| a.created_at.cmp(&b.created_at))
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(out)
    }

    async fn upsert_commit_status(
        &self,
        status: &CommitStatus,
    ) -> Result<CommitStatus, StoreError> {
        let mut statuses = self
            .commit_statuses
            .lock()
            .expect("commit_statuses lock poisoned");
        if let Some(existing) = statuses.iter_mut().find(|s| {
            s.repo_id == status.repo_id
                && s.commit_sha == status.commit_sha
                && s.context == status.context
        }) {
            existing.state = status.state.clone();
            existing.description = status.description.clone();
            existing.target_url = status.target_url.clone();
            existing.updated_at = status.updated_at;
            return Ok(existing.clone());
        }
        statuses.push(status.clone());
        Ok(status.clone())
    }

    async fn list_commit_statuses(
        &self,
        repo_id: &str,
        commit_sha: &str,
    ) -> Result<Vec<CommitStatus>, StoreError> {
        let statuses = self
            .commit_statuses
            .lock()
            .expect("commit_statuses lock poisoned");
        let mut out: Vec<CommitStatus> = statuses
            .iter()
            .filter(|s| s.repo_id == repo_id && s.commit_sha == commit_sha)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.context.cmp(&b.context));
        Ok(out)
    }

    async fn aggregate_state_for_commit(
        &self,
        repo_id: &str,
        commit_sha: &str,
    ) -> Result<Option<String>, StoreError> {
        let statuses = self.list_commit_statuses(repo_id, commit_sha).await?;
        Ok(aggregate_commit_statuses(&statuses))
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
        out.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.id.cmp(&a.id))
        });
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

use sqlx::Row;
use sqlx::postgres::{PgPool, PgPoolOptions};

const REPO_COLS: &str = "id, owner_sub, name, description, is_private, default_branch, require_approval, protect_default_branch, forked_from_id, created_at";
const RELEASE_COLS: &str = "id, repo_id, tag_name, target_commit, title, body_md, is_prerelease, is_draft, created_by, created_at, published_at";
const ISSUE_COLS: &str = "id, repo_id, number, title, body, author_sub, assignee_sub, milestone_id, state, created_at, updated_at";
const COMMENT_COLS: &str = "id, issue_id, author_sub, body, created_at";
const PULL_COLS: &str = "id, repo_id, number, title, body, base_branch, head_branch, author_sub, assignee_sub, reviewer_sub, milestone_id, state, created_at, merged_at";
const PAT_COLS: &str = "id, owner_sub, name, token_hash, created_at";
const LABEL_COLS: &str = "id, repo_id, name, color, created_at";
const MILESTONE_COLS: &str = "id, repo_id, title, due, state, created_at";
const REVIEW_COLS: &str = "id, pull_id, reviewer_sub, verdict, body, created_at";
const REVIEW_COMMENT_COLS: &str =
    "id, pull_id, review_id, path, line, author_sub, body, created_at";
const PR_FILE_VIEWED_COLS: &str = "pr_id, user_sub, file_path, viewed, updated_at";
const COMMIT_STATUS_COLS: &str =
    "id, repo_id, commit_sha, state, context, description, target_url, created_at, updated_at";

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
                 require_approval BOOLEAN NOT NULL DEFAULT FALSE, \
                 protect_default_branch BOOLEAN NOT NULL DEFAULT FALSE, \
                 forked_from_id TEXT NOT NULL DEFAULT '', \
                 created_at BIGINT NOT NULL, \
                 UNIQUE(owner_sub, name)\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Editable-settings columns, added idempotently for tables created before they existed.
        sqlx::query(
            "ALTER TABLE repos ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT ''",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE repos ADD COLUMN IF NOT EXISTS default_branch TEXT NOT NULL DEFAULT 'main'",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE repos ADD COLUMN IF NOT EXISTS require_approval BOOLEAN NOT NULL DEFAULT FALSE",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE repos ADD COLUMN IF NOT EXISTS protect_default_branch BOOLEAN NOT NULL DEFAULT FALSE",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE repos ADD COLUMN IF NOT EXISTS forked_from_id TEXT NOT NULL DEFAULT ''",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS releases (\
                 id TEXT PRIMARY KEY, \
                 repo_id TEXT NOT NULL, \
                 tag_name TEXT NOT NULL, \
                 target_commit TEXT NOT NULL, \
                 title TEXT NOT NULL, \
                 body_md TEXT NOT NULL DEFAULT '', \
                 is_prerelease BOOLEAN NOT NULL DEFAULT FALSE, \
                 is_draft BOOLEAN NOT NULL DEFAULT FALSE, \
                 created_by TEXT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 published_at BIGINT NOT NULL DEFAULT 0\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_releases_repo_tag \
             ON releases (repo_id, tag_name)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_releases_repo_created \
             ON releases (repo_id, created_at)",
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
                 assignee_sub TEXT NOT NULL DEFAULT '', \
                 milestone_id TEXT NOT NULL DEFAULT '', \
                 state TEXT NOT NULL DEFAULT 'open', \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Last-activity column, added idempotently for tables created before it existed.
        sqlx::query(
            "ALTER TABLE issues ADD COLUMN IF NOT EXISTS updated_at BIGINT NOT NULL DEFAULT 0",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE issues ADD COLUMN IF NOT EXISTS assignee_sub TEXT NOT NULL DEFAULT ''",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE issues ADD COLUMN IF NOT EXISTS milestone_id TEXT NOT NULL DEFAULT ''",
        )
        .execute(&self.pool)
        .await?;
        // Backfill legacy rows so updated_at is never behind created_at.
        sqlx::query("UPDATE issues SET updated_at = created_at WHERE updated_at < created_at")
            .execute(&self.pool)
            .await?;
        // Threaded comments on an issue (foreign key issue_id -> issues.id, application-enforced).
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS issue_comments (\
                 id TEXT PRIMARY KEY, \
                 issue_id TEXT NOT NULL, \
                 author_sub TEXT NOT NULL, \
                 body TEXT NOT NULL DEFAULT '', \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Thread lookup for the issue detail page.
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_issue_comments_issue \
             ON issue_comments (issue_id)",
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
        // Pull requests. `base`/`head` are branch names; stored as `base_branch`/`head_branch`
        // to avoid any brush with reserved words. `merged_at` is BIGINT (0 = never merged) rather
        // than a nullable column, so the row mapping stays a plain non-Option BIGINT read.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pulls (\
                 id TEXT PRIMARY KEY, \
                 repo_id TEXT NOT NULL, \
                 number BIGINT NOT NULL, \
                 title TEXT NOT NULL, \
                 body TEXT NOT NULL DEFAULT '', \
                 base_branch TEXT NOT NULL, \
                 head_branch TEXT NOT NULL, \
                 author_sub TEXT NOT NULL, \
                 assignee_sub TEXT NOT NULL DEFAULT '', \
                 reviewer_sub TEXT NOT NULL DEFAULT '', \
                 milestone_id TEXT NOT NULL DEFAULT '', \
                 state TEXT NOT NULL DEFAULT 'open', \
                 created_at BIGINT NOT NULL, \
                 merged_at BIGINT NOT NULL DEFAULT 0\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE pulls ADD COLUMN IF NOT EXISTS assignee_sub TEXT NOT NULL DEFAULT ''",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE pulls ADD COLUMN IF NOT EXISTS reviewer_sub TEXT NOT NULL DEFAULT ''",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE pulls ADD COLUMN IF NOT EXISTS milestone_id TEXT NOT NULL DEFAULT ''",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS labels (\
                 id TEXT PRIMARY KEY, \
                 repo_id TEXT NOT NULL, \
                 name TEXT NOT NULL, \
                 color TEXT NOT NULL, \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_labels_repo_name \
             ON labels (repo_id, name)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS milestones (\
                 id TEXT PRIMARY KEY, \
                 repo_id TEXT NOT NULL, \
                 title TEXT NOT NULL, \
                 due TEXT NOT NULL DEFAULT '', \
                 state TEXT NOT NULL DEFAULT 'open', \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_milestones_repo_title \
             ON milestones (repo_id, title)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS issue_labels (\
                 issue_id TEXT NOT NULL, \
                 label_id TEXT NOT NULL, \
                 PRIMARY KEY (issue_id, label_id)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_issue_labels_label \
             ON issue_labels (label_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pull_labels (\
                 pull_id TEXT NOT NULL, \
                 label_id TEXT NOT NULL, \
                 PRIMARY KEY (pull_id, label_id)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_pull_labels_label \
             ON pull_labels (label_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pr_reviews (\
                 id TEXT PRIMARY KEY, \
                 pull_id TEXT NOT NULL, \
                 reviewer_sub TEXT NOT NULL, \
                 verdict TEXT NOT NULL, \
                 body TEXT NOT NULL DEFAULT '', \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_pr_reviews_pull \
             ON pr_reviews (pull_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pr_review_comments (\
                 id TEXT PRIMARY KEY, \
                 pull_id TEXT NOT NULL, \
                 review_id TEXT NOT NULL DEFAULT '', \
                 path TEXT NOT NULL, \
                 line BIGINT NOT NULL DEFAULT 0, \
                 author_sub TEXT NOT NULL, \
                 body TEXT NOT NULL DEFAULT '', \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_pr_review_comments_pull \
             ON pr_review_comments (pull_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pr_file_viewed (\
                 pr_id TEXT NOT NULL, \
                 user_sub TEXT NOT NULL, \
                 file_path TEXT NOT NULL, \
                 viewed BOOLEAN NOT NULL DEFAULT FALSE, \
                 updated_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_pr_file_viewed_pr_user_path \
             ON pr_file_viewed (pr_id, user_sub, file_path)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS commit_statuses (\
                 id TEXT PRIMARY KEY, \
                 repo_id TEXT NOT NULL, \
                 commit_sha TEXT NOT NULL, \
                 state TEXT NOT NULL, \
                 context TEXT NOT NULL, \
                 description TEXT NOT NULL DEFAULT '', \
                 target_url TEXT NOT NULL DEFAULT '', \
                 created_at BIGINT NOT NULL, \
                 updated_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_commit_statuses_repo_sha_context \
             ON commit_statuses (repo_id, commit_sha, context)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_commit_statuses_repo_sha \
             ON commit_statuses (repo_id, commit_sha)",
        )
        .execute(&self.pool)
        .await?;
        // Per-repo PR numbering uniqueness (backs the race-safe ON CONFLICT retry).
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_pulls_repo_number \
             ON pulls (repo_id, number)",
        )
        .execute(&self.pool)
        .await?;
        // Token verification lookup on the hot /git/ path.
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_pats_token_hash ON pats (token_hash)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_repos_owner ON repos (owner_sub)")
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
            require_approval: row.try_get("require_approval")?,
            protect_default_branch: row.try_get("protect_default_branch")?,
            forked_from_id: row.try_get("forked_from_id")?,
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
            assignee_sub: row.try_get("assignee_sub")?,
            milestone_id: row.try_get("milestone_id")?,
            state: row.try_get("state")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }

    fn release_from_row(row: &sqlx::postgres::PgRow) -> Result<Release, sqlx::Error> {
        Ok(Release {
            id: row.try_get("id")?,
            repo_id: row.try_get("repo_id")?,
            tag_name: row.try_get("tag_name")?,
            target_commit: row.try_get("target_commit")?,
            title: row.try_get("title")?,
            body_md: row.try_get("body_md")?,
            is_prerelease: row.try_get("is_prerelease")?,
            is_draft: row.try_get("is_draft")?,
            created_by: row.try_get("created_by")?,
            created_at: row.try_get("created_at")?,
            published_at: row.try_get("published_at")?,
        })
    }

    fn comment_from_row(row: &sqlx::postgres::PgRow) -> Result<IssueComment, sqlx::Error> {
        Ok(IssueComment {
            id: row.try_get("id")?,
            issue_id: row.try_get("issue_id")?,
            author_sub: row.try_get("author_sub")?,
            body: row.try_get("body")?,
            created_at: row.try_get("created_at")?,
        })
    }

    fn pull_from_row(row: &sqlx::postgres::PgRow) -> Result<Pull, sqlx::Error> {
        Ok(Pull {
            id: row.try_get("id")?,
            repo_id: row.try_get("repo_id")?,
            number: row.try_get("number")?,
            title: row.try_get("title")?,
            body: row.try_get("body")?,
            base: row.try_get("base_branch")?,
            head: row.try_get("head_branch")?,
            author_sub: row.try_get("author_sub")?,
            assignee_sub: row.try_get("assignee_sub")?,
            reviewer_sub: row.try_get("reviewer_sub")?,
            milestone_id: row.try_get("milestone_id")?,
            state: row.try_get("state")?,
            created_at: row.try_get("created_at")?,
            merged_at: row.try_get("merged_at")?,
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

    fn label_from_row(row: &sqlx::postgres::PgRow) -> Result<Label, sqlx::Error> {
        Ok(Label {
            id: row.try_get("id")?,
            repo_id: row.try_get("repo_id")?,
            name: row.try_get("name")?,
            color: row.try_get("color")?,
            created_at: row.try_get("created_at")?,
        })
    }

    fn milestone_from_row(row: &sqlx::postgres::PgRow) -> Result<Milestone, sqlx::Error> {
        Ok(Milestone {
            id: row.try_get("id")?,
            repo_id: row.try_get("repo_id")?,
            title: row.try_get("title")?,
            due: row.try_get("due")?,
            state: row.try_get("state")?,
            created_at: row.try_get("created_at")?,
        })
    }

    fn review_from_row(row: &sqlx::postgres::PgRow) -> Result<PullReview, sqlx::Error> {
        Ok(PullReview {
            id: row.try_get("id")?,
            pull_id: row.try_get("pull_id")?,
            reviewer_sub: row.try_get("reviewer_sub")?,
            verdict: row.try_get("verdict")?,
            body: row.try_get("body")?,
            created_at: row.try_get("created_at")?,
        })
    }

    fn review_comment_from_row(
        row: &sqlx::postgres::PgRow,
    ) -> Result<PullReviewComment, sqlx::Error> {
        Ok(PullReviewComment {
            id: row.try_get("id")?,
            pull_id: row.try_get("pull_id")?,
            review_id: row.try_get("review_id")?,
            path: row.try_get("path")?,
            line: row.try_get("line")?,
            author_sub: row.try_get("author_sub")?,
            body: row.try_get("body")?,
            created_at: row.try_get("created_at")?,
        })
    }

    fn pr_file_viewed_from_row(row: &sqlx::postgres::PgRow) -> Result<PrFileViewed, sqlx::Error> {
        Ok(PrFileViewed {
            pr_id: row.try_get("pr_id")?,
            user_sub: row.try_get("user_sub")?,
            file_path: row.try_get("file_path")?,
            viewed: row.try_get("viewed")?,
            updated_at: row.try_get("updated_at")?,
        })
    }

    fn commit_status_from_row(row: &sqlx::postgres::PgRow) -> Result<CommitStatus, sqlx::Error> {
        Ok(CommitStatus {
            id: row.try_get("id")?,
            repo_id: row.try_get("repo_id")?,
            commit_sha: row.try_get("commit_sha")?,
            state: row.try_get("state")?,
            context: row.try_get("context")?,
            description: row.try_get("description")?,
            target_url: row.try_get("target_url")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

#[async_trait]
impl Store for PgStore {
    async fn create_repo(&self, repo: &Repo) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "INSERT INTO repos \
                 (id, owner_sub, name, description, is_private, default_branch, \
                  require_approval, protect_default_branch, forked_from_id, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (owner_sub, name) DO NOTHING",
        )
        .bind(&repo.id)
        .bind(&repo.owner_sub)
        .bind(&repo.name)
        .bind(&repo.description)
        .bind(repo.is_private)
        .bind(&repo.default_branch)
        .bind(repo.require_approval)
        .bind(repo.protect_default_branch)
        .bind(&repo.forked_from_id)
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

    async fn update_repo_settings(
        &self,
        id: &str,
        description: &str,
        default_branch: &str,
        require_approval: bool,
        protect_default_branch: bool,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE repos SET description = $1, default_branch = $2, \
             require_approval = $3, protect_default_branch = $4 WHERE id = $5",
        )
        .bind(description)
        .bind(default_branch)
        .bind(require_approval)
        .bind(protect_default_branch)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    async fn get_repo_by_id(&self, id: &str) -> Result<Option<Repo>, StoreError> {
        let row = sqlx::query(&format!("SELECT {REPO_COLS} FROM repos WHERE id = $1"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        row.as_ref()
            .map(Self::repo_from_row)
            .transpose()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn create_release(&self, release: &Release) -> Result<Option<Release>, StoreError> {
        let result = sqlx::query(
            "INSERT INTO releases \
                 (id, repo_id, tag_name, target_commit, title, body_md, is_prerelease, is_draft, \
                  created_by, created_at, published_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             ON CONFLICT (repo_id, tag_name) DO NOTHING",
        )
        .bind(&release.id)
        .bind(&release.repo_id)
        .bind(&release.tag_name)
        .bind(&release.target_commit)
        .bind(&release.title)
        .bind(&release.body_md)
        .bind(release.is_prerelease)
        .bind(release.is_draft)
        .bind(&release.created_by)
        .bind(release.created_at)
        .bind(release.published_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        if result.rows_affected() == 1 {
            Ok(Some(release.clone()))
        } else {
            Ok(None)
        }
    }

    async fn update_release(&self, release: &Release) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE releases SET tag_name = $1, target_commit = $2, title = $3, body_md = $4, \
             is_prerelease = $5, is_draft = $6, published_at = $7 \
             WHERE repo_id = $8 AND id = $9",
        )
        .bind(&release.tag_name)
        .bind(&release.target_commit)
        .bind(&release.title)
        .bind(&release.body_md)
        .bind(release.is_prerelease)
        .bind(release.is_draft)
        .bind(release.published_at)
        .bind(&release.repo_id)
        .bind(&release.id)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_release(&self, repo_id: &str, id: &str) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM releases WHERE repo_id = $1 AND id = $2")
            .bind(repo_id)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    async fn get_release(&self, repo_id: &str, id: &str) -> Result<Option<Release>, StoreError> {
        let row = sqlx::query(&format!(
            "SELECT {RELEASE_COLS} FROM releases WHERE repo_id = $1 AND id = $2"
        ))
        .bind(repo_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        row.as_ref()
            .map(Self::release_from_row)
            .transpose()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_release_by_tag(
        &self,
        repo_id: &str,
        tag_name: &str,
    ) -> Result<Option<Release>, StoreError> {
        let row = sqlx::query(&format!(
            "SELECT {RELEASE_COLS} FROM releases WHERE repo_id = $1 AND tag_name = $2"
        ))
        .bind(repo_id)
        .bind(tag_name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        row.as_ref()
            .map(Self::release_from_row)
            .transpose()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_releases_by_repo(&self, repo_id: &str) -> Result<Vec<Release>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {RELEASE_COLS} FROM releases \
             WHERE repo_id = $1 ORDER BY created_at DESC, id DESC"
        ))
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        rows.iter()
            .map(Self::release_from_row)
            .collect::<Result<_, _>>()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn release_count(&self, repo_id: &str, include_drafts: bool) -> Result<i64, StoreError> {
        let row = sqlx::query(
            "SELECT count(*) AS n FROM releases \
             WHERE repo_id = $1 AND ($2 = TRUE OR is_draft = FALSE)",
        )
        .bind(repo_id)
        .bind(include_drafts)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        row.try_get("n")
            .map_err(|e| StoreError::Backend(e.to_string()))
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
                     (id, repo_id, number, title, body, author_sub, assignee_sub, milestone_id, \
                      state, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, '', '', 'open', $7, $7) \
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
                    assignee_sub: String::new(),
                    milestone_id: String::new(),
                    state: "open".to_string(),
                    created_at,
                    updated_at: created_at,
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

    async fn list_issues_page(
        &self,
        repo_id: &str,
        state_filter: &str,
        label_filter: &str,
        milestone_filter: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Issue>, StoreError> {
        // `state_filter = ''` selects every state; otherwise it is bound (never interpolated).
        let rows = sqlx::query(&format!(
            "SELECT {ISSUE_COLS} FROM issues \
             WHERE repo_id = $1 AND ($2 = '' OR state = $2) \
               AND ($3 = '' OR milestone_id = $3) \
               AND ($4 = '' OR EXISTS (\
                    SELECT 1 FROM issue_labels \
                    WHERE issue_labels.issue_id = issues.id AND issue_labels.label_id = $4\
               )) \
             ORDER BY number DESC LIMIT $5 OFFSET $6"
        ))
        .bind(repo_id)
        .bind(state_filter)
        .bind(milestone_filter)
        .bind(label_filter)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        rows.iter()
            .map(Self::issue_from_row)
            .collect::<Result<_, _>>()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn count_issues(
        &self,
        repo_id: &str,
        state_filter: &str,
        label_filter: &str,
        milestone_filter: &str,
    ) -> Result<i64, StoreError> {
        let row = sqlx::query(
            "SELECT count(*) AS n FROM issues \
             WHERE repo_id = $1 AND ($2 = '' OR state = $2) \
               AND ($3 = '' OR milestone_id = $3) \
               AND ($4 = '' OR EXISTS (\
                    SELECT 1 FROM issue_labels \
                    WHERE issue_labels.issue_id = issues.id AND issue_labels.label_id = $4\
               ))",
        )
        .bind(repo_id)
        .bind(state_filter)
        .bind(milestone_filter)
        .bind(label_filter)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        row.try_get("n")
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_issue(&self, repo_id: &str, number: i64) -> Result<Option<Issue>, StoreError> {
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

    async fn set_issue_state(
        &self,
        id: &str,
        state: &str,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query("UPDATE issues SET state = $1, updated_at = $2 WHERE id = $3")
            .bind(state)
            .bind(updated_at)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    async fn open_issue_count(&self, repo_id: &str) -> Result<i64, StoreError> {
        let row =
            sqlx::query("SELECT count(*) AS n FROM issues WHERE repo_id = $1 AND state = 'open'")
                .bind(repo_id)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
        row.try_get("n")
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn create_comment(
        &self,
        id: &str,
        issue_id: &str,
        author_sub: &str,
        body: &str,
        created_at: i64,
    ) -> Result<IssueComment, StoreError> {
        sqlx::query(
            "INSERT INTO issue_comments (id, issue_id, author_sub, body, created_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(issue_id)
        .bind(author_sub)
        .bind(body)
        .bind(created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        // Last-activity bump on the parent issue (only forward).
        sqlx::query("UPDATE issues SET updated_at = $1 WHERE id = $2 AND updated_at < $1")
            .bind(created_at)
            .bind(issue_id)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(IssueComment {
            id: id.to_string(),
            issue_id: issue_id.to_string(),
            author_sub: author_sub.to_string(),
            body: body.to_string(),
            created_at,
        })
    }

    async fn list_comments(&self, issue_id: &str) -> Result<Vec<IssueComment>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {COMMENT_COLS} FROM issue_comments \
             WHERE issue_id = $1 ORDER BY created_at ASC, id ASC"
        ))
        .bind(issue_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        rows.iter()
            .map(Self::comment_from_row)
            .collect::<Result<_, _>>()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn set_issue_metadata(
        &self,
        issue_id: &str,
        assignee_sub: &str,
        milestone_id: &str,
        label_ids: &[String],
    ) -> Result<bool, StoreError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let result =
            sqlx::query("UPDATE issues SET assignee_sub = $1, milestone_id = $2 WHERE id = $3")
                .bind(assignee_sub)
                .bind(milestone_id)
                .bind(issue_id)
                .execute(&mut *tx)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
        if result.rows_affected() == 0 {
            tx.rollback()
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            return Ok(false);
        }
        sqlx::query("DELETE FROM issue_labels WHERE issue_id = $1")
            .bind(issue_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        for label_id in label_ids {
            if label_id.is_empty() {
                continue;
            }
            sqlx::query(
                "INSERT INTO issue_labels (issue_id, label_id) VALUES ($1, $2) \
                 ON CONFLICT (issue_id, label_id) DO NOTHING",
            )
            .bind(issue_id)
            .bind(label_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        }
        tx.commit()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(true)
    }

    async fn issue_labels(&self, issue_id: &str) -> Result<Vec<Label>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {LABEL_COLS} FROM labels \
             WHERE id IN (SELECT label_id FROM issue_labels WHERE issue_id = $1) \
             ORDER BY name ASC"
        ))
        .bind(issue_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        rows.iter()
            .map(Self::label_from_row)
            .collect::<Result<_, _>>()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_issue_labels(&self, repo_id: &str) -> Result<Vec<(String, Label)>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT issue_labels.issue_id AS subject_id, {LABEL_COLS} FROM issue_labels \
             JOIN labels ON labels.id = issue_labels.label_id \
             WHERE labels.repo_id = $1 \
             ORDER BY issue_labels.issue_id ASC, labels.name ASC"
        ))
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows.iter() {
            let issue_id: String = row
                .try_get("subject_id")
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let label =
                Self::label_from_row(row).map_err(|e| StoreError::Backend(e.to_string()))?;
            out.push((issue_id, label));
        }
        Ok(out)
    }

    async fn create_pull(
        &self,
        id: &str,
        repo_id: &str,
        title: &str,
        body: &str,
        base: &str,
        head: &str,
        author_sub: &str,
        created_at: i64,
    ) -> Result<Pull, StoreError> {
        // Allocate the next per-repo number and insert; on the rare concurrent collision the
        // unique index rejects the row (0 affected) and we retry with a fresh max.
        for _ in 0..8 {
            let row = sqlx::query(
                "SELECT COALESCE(MAX(number), 0) + 1 AS next FROM pulls WHERE repo_id = $1",
            )
            .bind(repo_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
            let number: i64 = row
                .try_get("next")
                .map_err(|e| StoreError::Backend(e.to_string()))?;

            let result = sqlx::query(
                "INSERT INTO pulls \
                     (id, repo_id, number, title, body, base_branch, head_branch, author_sub, \
                      assignee_sub, reviewer_sub, milestone_id, state, created_at, merged_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, '', '', '', 'open', $9, 0) \
                 ON CONFLICT (repo_id, number) DO NOTHING",
            )
            .bind(id)
            .bind(repo_id)
            .bind(number)
            .bind(title)
            .bind(body)
            .bind(base)
            .bind(head)
            .bind(author_sub)
            .bind(created_at)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

            if result.rows_affected() == 1 {
                return Ok(Pull {
                    id: id.to_string(),
                    repo_id: repo_id.to_string(),
                    number,
                    title: title.to_string(),
                    body: body.to_string(),
                    base: base.to_string(),
                    head: head.to_string(),
                    author_sub: author_sub.to_string(),
                    assignee_sub: String::new(),
                    reviewer_sub: String::new(),
                    milestone_id: String::new(),
                    state: "open".to_string(),
                    created_at,
                    merged_at: 0,
                });
            }
        }
        Err(StoreError::Backend(
            "could not allocate a pull-request number".to_string(),
        ))
    }

    async fn list_pulls(&self, repo_id: &str) -> Result<Vec<Pull>, StoreError> {
        self.list_pulls_filtered(repo_id, "", "").await
    }

    async fn list_pulls_filtered(
        &self,
        repo_id: &str,
        label_filter: &str,
        milestone_filter: &str,
    ) -> Result<Vec<Pull>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {PULL_COLS} FROM pulls \
             WHERE repo_id = $1 \
               AND ($2 = '' OR milestone_id = $2) \
               AND ($3 = '' OR EXISTS (\
                    SELECT 1 FROM pull_labels \
                    WHERE pull_labels.pull_id = pulls.id AND pull_labels.label_id = $3\
               )) \
             ORDER BY number DESC"
        ))
        .bind(repo_id)
        .bind(milestone_filter)
        .bind(label_filter)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        rows.iter()
            .map(Self::pull_from_row)
            .collect::<Result<_, _>>()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_pull(&self, repo_id: &str, number: i64) -> Result<Option<Pull>, StoreError> {
        let row = sqlx::query(&format!(
            "SELECT {PULL_COLS} FROM pulls WHERE repo_id = $1 AND number = $2"
        ))
        .bind(repo_id)
        .bind(number)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        row.as_ref()
            .map(Self::pull_from_row)
            .transpose()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn set_pull_state(&self, id: &str, state: &str) -> Result<bool, StoreError> {
        let result = sqlx::query("UPDATE pulls SET state = $1 WHERE id = $2")
            .bind(state)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    async fn merge_pull(&self, id: &str, merged_at: i64) -> Result<bool, StoreError> {
        // Guard the transition in SQL: only an OPEN row flips to merged, so two racing merges
        // cannot both succeed (the second sees 0 rows affected).
        let result = sqlx::query(
            "UPDATE pulls SET state = 'merged', merged_at = $1 \
             WHERE id = $2 AND state = 'open'",
        )
        .bind(merged_at)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    async fn open_pull_count(&self, repo_id: &str) -> Result<i64, StoreError> {
        let row =
            sqlx::query("SELECT count(*) AS n FROM pulls WHERE repo_id = $1 AND state = 'open'")
                .bind(repo_id)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
        row.try_get("n")
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn set_pull_metadata(
        &self,
        pull_id: &str,
        assignee_sub: &str,
        reviewer_sub: &str,
        milestone_id: &str,
        label_ids: &[String],
    ) -> Result<bool, StoreError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let result = sqlx::query(
            "UPDATE pulls SET assignee_sub = $1, reviewer_sub = $2, milestone_id = $3 WHERE id = $4",
        )
        .bind(assignee_sub)
        .bind(reviewer_sub)
        .bind(milestone_id)
        .bind(pull_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        if result.rows_affected() == 0 {
            tx.rollback()
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            return Ok(false);
        }
        sqlx::query("DELETE FROM pull_labels WHERE pull_id = $1")
            .bind(pull_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        for label_id in label_ids {
            if label_id.is_empty() {
                continue;
            }
            sqlx::query(
                "INSERT INTO pull_labels (pull_id, label_id) VALUES ($1, $2) \
                 ON CONFLICT (pull_id, label_id) DO NOTHING",
            )
            .bind(pull_id)
            .bind(label_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        }
        tx.commit()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(true)
    }

    async fn pull_labels(&self, pull_id: &str) -> Result<Vec<Label>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {LABEL_COLS} FROM labels \
             WHERE id IN (SELECT label_id FROM pull_labels WHERE pull_id = $1) \
             ORDER BY name ASC"
        ))
        .bind(pull_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        rows.iter()
            .map(Self::label_from_row)
            .collect::<Result<_, _>>()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_pull_labels(&self, repo_id: &str) -> Result<Vec<(String, Label)>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT pull_labels.pull_id AS subject_id, {LABEL_COLS} FROM pull_labels \
             JOIN labels ON labels.id = pull_labels.label_id \
             WHERE labels.repo_id = $1 \
             ORDER BY pull_labels.pull_id ASC, labels.name ASC"
        ))
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows.iter() {
            let pull_id: String = row
                .try_get("subject_id")
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let label =
                Self::label_from_row(row).map_err(|e| StoreError::Backend(e.to_string()))?;
            out.push((pull_id, label));
        }
        Ok(out)
    }

    async fn set_pr_file_viewed(
        &self,
        pr_id: &str,
        user_sub: &str,
        file_path: &str,
        viewed: bool,
        updated_at: i64,
    ) -> Result<PrFileViewed, StoreError> {
        sqlx::query(
            "INSERT INTO pr_file_viewed \
                 (pr_id, user_sub, file_path, viewed, updated_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (pr_id, user_sub, file_path) DO UPDATE SET \
                 viewed = EXCLUDED.viewed, \
                 updated_at = EXCLUDED.updated_at",
        )
        .bind(pr_id)
        .bind(user_sub)
        .bind(file_path)
        .bind(viewed)
        .bind(updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let row = sqlx::query(&format!(
            "SELECT {PR_FILE_VIEWED_COLS} FROM pr_file_viewed \
             WHERE pr_id = $1 AND user_sub = $2 AND file_path = $3"
        ))
        .bind(pr_id)
        .bind(user_sub)
        .bind(file_path)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        row.as_ref()
            .map(Self::pr_file_viewed_from_row)
            .transpose()
            .map_err(|e| StoreError::Backend(e.to_string()))?
            .ok_or_else(|| StoreError::Backend("PR file viewed upsert did not persist".to_string()))
    }

    async fn list_pr_file_viewed_for_pr(
        &self,
        pr_id: &str,
        user_sub: &str,
    ) -> Result<Vec<PrFileViewed>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {PR_FILE_VIEWED_COLS} FROM pr_file_viewed \
             WHERE pr_id = $1 AND user_sub = $2 \
             ORDER BY file_path ASC"
        ))
        .bind(pr_id)
        .bind(user_sub)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        rows.iter()
            .map(Self::pr_file_viewed_from_row)
            .collect::<Result<_, _>>()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn create_label(
        &self,
        id: &str,
        repo_id: &str,
        name: &str,
        color: &str,
        created_at: i64,
    ) -> Result<Option<Label>, StoreError> {
        let result = sqlx::query(
            "INSERT INTO labels (id, repo_id, name, color, created_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (repo_id, name) DO NOTHING",
        )
        .bind(id)
        .bind(repo_id)
        .bind(name)
        .bind(color)
        .bind(created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        if result.rows_affected() == 0 {
            return Ok(None);
        }
        Ok(Some(Label {
            id: id.to_string(),
            repo_id: repo_id.to_string(),
            name: name.to_string(),
            color: color.to_string(),
            created_at,
        }))
    }

    async fn list_labels(&self, repo_id: &str) -> Result<Vec<Label>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {LABEL_COLS} FROM labels WHERE repo_id = $1 ORDER BY name ASC"
        ))
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        rows.iter()
            .map(Self::label_from_row)
            .collect::<Result<_, _>>()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn create_milestone(
        &self,
        id: &str,
        repo_id: &str,
        title: &str,
        due: &str,
        created_at: i64,
    ) -> Result<Option<Milestone>, StoreError> {
        let result = sqlx::query(
            "INSERT INTO milestones (id, repo_id, title, due, state, created_at) \
             VALUES ($1, $2, $3, $4, 'open', $5) \
             ON CONFLICT (repo_id, title) DO NOTHING",
        )
        .bind(id)
        .bind(repo_id)
        .bind(title)
        .bind(due)
        .bind(created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        if result.rows_affected() == 0 {
            return Ok(None);
        }
        Ok(Some(Milestone {
            id: id.to_string(),
            repo_id: repo_id.to_string(),
            title: title.to_string(),
            due: due.to_string(),
            state: "open".to_string(),
            created_at,
        }))
    }

    async fn list_milestones(&self, repo_id: &str) -> Result<Vec<Milestone>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {MILESTONE_COLS} FROM milestones \
             WHERE repo_id = $1 ORDER BY state ASC, created_at DESC, title ASC"
        ))
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        rows.iter()
            .map(Self::milestone_from_row)
            .collect::<Result<_, _>>()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn set_milestone_state(&self, id: &str, state: &str) -> Result<bool, StoreError> {
        let result = sqlx::query("UPDATE milestones SET state = $1 WHERE id = $2")
            .bind(state)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    async fn milestone_progress(
        &self,
        repo_id: &str,
        milestone_id: &str,
    ) -> Result<(i64, i64), StoreError> {
        let issue_total: i64 = sqlx::query(
            "SELECT count(*) AS n FROM issues WHERE repo_id = $1 AND milestone_id = $2",
        )
        .bind(repo_id)
        .bind(milestone_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .try_get("n")
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        let issue_closed: i64 = sqlx::query(
            "SELECT count(*) AS n FROM issues \
             WHERE repo_id = $1 AND milestone_id = $2 AND state <> 'open'",
        )
        .bind(repo_id)
        .bind(milestone_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .try_get("n")
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        let pull_total: i64 =
            sqlx::query("SELECT count(*) AS n FROM pulls WHERE repo_id = $1 AND milestone_id = $2")
                .bind(repo_id)
                .bind(milestone_id)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?
                .try_get("n")
                .map_err(|e| StoreError::Backend(e.to_string()))?;
        let pull_closed: i64 = sqlx::query(
            "SELECT count(*) AS n FROM pulls \
             WHERE repo_id = $1 AND milestone_id = $2 AND state <> 'open'",
        )
        .bind(repo_id)
        .bind(milestone_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .try_get("n")
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok((issue_closed + pull_closed, issue_total + pull_total))
    }

    async fn create_pull_review(
        &self,
        id: &str,
        pull_id: &str,
        reviewer_sub: &str,
        verdict: &str,
        body: &str,
        created_at: i64,
    ) -> Result<PullReview, StoreError> {
        sqlx::query(
            "INSERT INTO pr_reviews (id, pull_id, reviewer_sub, verdict, body, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(id)
        .bind(pull_id)
        .bind(reviewer_sub)
        .bind(verdict)
        .bind(body)
        .bind(created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(PullReview {
            id: id.to_string(),
            pull_id: pull_id.to_string(),
            reviewer_sub: reviewer_sub.to_string(),
            verdict: verdict.to_string(),
            body: body.to_string(),
            created_at,
        })
    }

    async fn list_pull_reviews(&self, pull_id: &str) -> Result<Vec<PullReview>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {REVIEW_COLS} FROM pr_reviews \
             WHERE pull_id = $1 ORDER BY created_at ASC, id ASC"
        ))
        .bind(pull_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        rows.iter()
            .map(Self::review_from_row)
            .collect::<Result<_, _>>()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn create_pull_review_comment(
        &self,
        id: &str,
        pull_id: &str,
        review_id: &str,
        path: &str,
        line: i64,
        author_sub: &str,
        body: &str,
        created_at: i64,
    ) -> Result<PullReviewComment, StoreError> {
        sqlx::query(
            "INSERT INTO pr_review_comments \
                 (id, pull_id, review_id, path, line, author_sub, body, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(id)
        .bind(pull_id)
        .bind(review_id)
        .bind(path)
        .bind(line)
        .bind(author_sub)
        .bind(body)
        .bind(created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(PullReviewComment {
            id: id.to_string(),
            pull_id: pull_id.to_string(),
            review_id: review_id.to_string(),
            path: path.to_string(),
            line,
            author_sub: author_sub.to_string(),
            body: body.to_string(),
            created_at,
        })
    }

    async fn list_pull_review_comments(
        &self,
        pull_id: &str,
    ) -> Result<Vec<PullReviewComment>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {REVIEW_COMMENT_COLS} FROM pr_review_comments \
             WHERE pull_id = $1 ORDER BY path ASC, line ASC, created_at ASC, id ASC"
        ))
        .bind(pull_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        rows.iter()
            .map(Self::review_comment_from_row)
            .collect::<Result<_, _>>()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn upsert_commit_status(
        &self,
        status: &CommitStatus,
    ) -> Result<CommitStatus, StoreError> {
        sqlx::query(
            "INSERT INTO commit_statuses \
                 (id, repo_id, commit_sha, state, context, description, target_url, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (repo_id, commit_sha, context) DO UPDATE SET \
                 state = EXCLUDED.state, \
                 description = EXCLUDED.description, \
                 target_url = EXCLUDED.target_url, \
                 updated_at = EXCLUDED.updated_at",
        )
        .bind(&status.id)
        .bind(&status.repo_id)
        .bind(&status.commit_sha)
        .bind(&status.state)
        .bind(&status.context)
        .bind(&status.description)
        .bind(&status.target_url)
        .bind(status.created_at)
        .bind(status.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let row = sqlx::query(&format!(
            "SELECT {COMMIT_STATUS_COLS} FROM commit_statuses \
             WHERE repo_id = $1 AND commit_sha = $2 AND context = $3"
        ))
        .bind(&status.repo_id)
        .bind(&status.commit_sha)
        .bind(&status.context)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        row.as_ref()
            .map(Self::commit_status_from_row)
            .transpose()
            .map_err(|e| StoreError::Backend(e.to_string()))?
            .ok_or_else(|| StoreError::Backend("commit status upsert did not persist".to_string()))
    }

    async fn list_commit_statuses(
        &self,
        repo_id: &str,
        commit_sha: &str,
    ) -> Result<Vec<CommitStatus>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {COMMIT_STATUS_COLS} FROM commit_statuses \
             WHERE repo_id = $1 AND commit_sha = $2 ORDER BY context ASC"
        ))
        .bind(repo_id)
        .bind(commit_sha)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        rows.iter()
            .map(Self::commit_status_from_row)
            .collect::<Result<_, _>>()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn aggregate_state_for_commit(
        &self,
        repo_id: &str,
        commit_sha: &str,
    ) -> Result<Option<String>, StoreError> {
        let statuses = self.list_commit_statuses(repo_id, commit_sha).await?;
        Ok(aggregate_commit_statuses(&statuses))
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
            require_approval: false,
            protect_default_branch: false,
            forked_from_id: String::new(),
            created_at: created,
        }
    }

    fn commit_status(context: &str, state: &str, updated_at: i64) -> CommitStatus {
        CommitStatus {
            id: format!("cs_{}", context.replace('/', "_")),
            repo_id: "r".into(),
            commit_sha: "abc123".into(),
            state: state.into(),
            context: context.into(),
            description: format!("{context} {state}"),
            target_url: format!("https://ci.example/{context}"),
            created_at: 1,
            updated_at,
        }
    }

    fn release(id: &str, repo_id: &str, tag: &str, created: i64, draft: bool) -> Release {
        Release {
            id: id.into(),
            repo_id: repo_id.into(),
            tag_name: tag.into(),
            target_commit: format!("{tag}-commit"),
            title: format!("Release {tag}"),
            body_md: format!("notes for {tag}"),
            is_prerelease: false,
            is_draft: draft,
            created_by: "u".into(),
            created_at: created,
            published_at: if draft { 0 } else { created },
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
    async fn repo_settings_update() {
        let s = InMemoryStore::new();
        s.create_repo(&repo("u", "a", false, 1)).await.unwrap();
        assert!(
            s.update_repo_settings("rp_u_a", "new words", "develop", true, true)
                .await
                .unwrap()
        );
        let updated = s.get_repo("u", "a").await.unwrap().unwrap();
        assert_eq!(updated.description, "new words");
        assert_eq!(updated.default_branch, "develop");
        assert!(updated.require_approval);
        assert!(updated.protect_default_branch);
        // Unknown id changes nothing.
        assert!(
            !s.update_repo_settings("nope", "x", "main", false, false)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn releases_are_unique_by_repo_tag_and_visible_counts_skip_drafts() {
        let s = InMemoryStore::new();
        let r1 = release("rl1", "r", "v1.0.0", 10, false);
        let r2 = release("rl2", "r", "v2.0.0", 20, true);
        let other = release("rl3", "other", "v1.0.0", 30, false);

        assert_eq!(s.create_release(&r1).await.unwrap(), Some(r1.clone()));
        assert!(
            s.create_release(&release("rl_dup", "r", "v1.0.0", 11, false))
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(s.create_release(&r2).await.unwrap(), Some(r2.clone()));
        assert_eq!(s.create_release(&other).await.unwrap(), Some(other));

        let listed = s.list_releases_by_repo("r").await.unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|r| r.tag_name.as_str())
                .collect::<Vec<_>>(),
            vec!["v2.0.0", "v1.0.0"]
        );
        assert_eq!(s.release_count("r", false).await.unwrap(), 1);
        assert_eq!(s.release_count("r", true).await.unwrap(), 2);
        assert_eq!(
            s.get_release_by_tag("r", "v1.0.0").await.unwrap().unwrap(),
            r1
        );

        let mut edited = r2.clone();
        edited.is_draft = false;
        edited.published_at = 25;
        edited.title = "Release v2".to_string();
        assert!(s.update_release(&edited).await.unwrap());
        assert_eq!(
            s.get_release("r", "rl2").await.unwrap().unwrap().title,
            "Release v2"
        );
        assert_eq!(s.release_count("r", false).await.unwrap(), 2);
        assert!(s.delete_release("r", "rl1").await.unwrap());
        assert!(s.get_release("r", "rl1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn issue_numbers_are_sequential_per_repo() {
        let s = InMemoryStore::new();
        let i1 = s
            .create_issue("i1", "r", "first", "", "u", 1)
            .await
            .unwrap();
        let i2 = s
            .create_issue("i2", "r", "second", "", "u", 2)
            .await
            .unwrap();
        let other = s
            .create_issue("i3", "other", "x", "", "u", 3)
            .await
            .unwrap();
        assert_eq!(i1.number, 1);
        assert_eq!(i2.number, 2);
        assert_eq!(other.number, 1); // independent per repo

        assert_eq!(s.open_issue_count("r").await.unwrap(), 2);
        assert!(s.set_issue_state("i1", "closed", 42).await.unwrap());
        assert_eq!(s.open_issue_count("r").await.unwrap(), 1);
        // Closing stamps updated_at.
        assert_eq!(s.get_issue("r", 1).await.unwrap().unwrap().updated_at, 42);
    }

    #[tokio::test]
    async fn issue_filter_pagination_and_comments() {
        let s = InMemoryStore::new();
        for n in 0..5 {
            s.create_issue(&format!("i{n}"), "r", "t", "", "u", n)
                .await
                .unwrap();
        }
        // Close #2 and #4.
        s.set_issue_state("i1", "closed", 100).await.unwrap(); // issue number 2
        s.set_issue_state("i3", "closed", 100).await.unwrap(); // issue number 4

        assert_eq!(s.count_issues("r", "", "", "").await.unwrap(), 5);
        assert_eq!(s.count_issues("r", "open", "", "").await.unwrap(), 3);
        assert_eq!(s.count_issues("r", "closed", "", "").await.unwrap(), 2);

        // Page 1 (limit 2) of ALL issues, newest number first.
        let page1: Vec<i64> = s
            .list_issues_page("r", "", "", "", 2, 0)
            .await
            .unwrap()
            .into_iter()
            .map(|i| i.number)
            .collect();
        assert_eq!(page1, vec![5, 4]);
        let page2: Vec<i64> = s
            .list_issues_page("r", "", "", "", 2, 2)
            .await
            .unwrap()
            .into_iter()
            .map(|i| i.number)
            .collect();
        assert_eq!(page2, vec![3, 2]);

        // Filter to closed only.
        let closed: Vec<i64> = s
            .list_issues_page("r", "closed", "", "", 10, 0)
            .await
            .unwrap()
            .into_iter()
            .map(|i| i.number)
            .collect();
        assert_eq!(closed, vec![4, 2]);

        // Comments: chronological + last-activity bump on the parent issue.
        s.create_comment("c1", "i0", "u", "first", 200)
            .await
            .unwrap();
        s.create_comment("c2", "i0", "v", "second", 210)
            .await
            .unwrap();
        let thread: Vec<String> = s
            .list_comments("i0")
            .await
            .unwrap()
            .into_iter()
            .map(|c| c.body)
            .collect();
        assert_eq!(thread, vec!["first".to_string(), "second".to_string()]);
        assert_eq!(s.get_issue("r", 1).await.unwrap().unwrap().updated_at, 210);
        // A comment on a foreign issue does not appear in this thread.
        assert!(s.list_comments("nope").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn pull_numbers_state_and_merge_guard() {
        let s = InMemoryStore::new();
        let p1 = s
            .create_pull("pl1", "r", "first", "b", "main", "feat", "u", 10)
            .await
            .unwrap();
        let p2 = s
            .create_pull("pl2", "r", "second", "", "main", "fix", "v", 11)
            .await
            .unwrap();
        let other = s
            .create_pull("pl3", "other", "x", "", "main", "wip", "u", 12)
            .await
            .unwrap();
        assert_eq!(p1.number, 1);
        assert_eq!(p2.number, 2);
        assert_eq!(other.number, 1); // independent per repo
        assert!(p1.is_open());
        assert_eq!(s.open_pull_count("r").await.unwrap(), 2);

        // newest number first
        let listed: Vec<i64> = s
            .list_pulls("r")
            .await
            .unwrap()
            .into_iter()
            .map(|p| p.number)
            .collect();
        assert_eq!(listed, vec![2, 1]);

        // Close p2, merge p1.
        assert!(s.set_pull_state("pl2", "closed").await.unwrap());
        assert!(s.merge_pull("pl1", 99).await.unwrap());
        let merged = s.get_pull("r", 1).await.unwrap().unwrap();
        assert!(merged.is_merged());
        assert_eq!(merged.merged_at, 99);
        // A second merge is refused (already non-open) — the double-merge guard.
        assert!(!s.merge_pull("pl1", 100).await.unwrap());
        assert_eq!(s.open_pull_count("r").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn labels_milestones_metadata_and_reviews() {
        let s = InMemoryStore::new();
        let label = s
            .create_label("lb1", "r", "bug", "dc2626", 1)
            .await
            .unwrap()
            .unwrap();
        assert!(
            s.create_label("lb2", "r", "bug", "000000", 2)
                .await
                .unwrap()
                .is_none()
        );
        let milestone = s
            .create_milestone("ms1", "r", "v1", "2026-08-01", 3)
            .await
            .unwrap()
            .unwrap();
        let issue = s
            .create_issue("i1", "r", "first", "", "u", 4)
            .await
            .unwrap();
        assert!(
            s.set_issue_metadata(
                &issue.id,
                "bob",
                &milestone.id,
                std::slice::from_ref(&label.id),
            )
            .await
            .unwrap()
        );
        assert_eq!(
            s.issue_labels(&issue.id).await.unwrap(),
            vec![label.clone()]
        );
        assert_eq!(
            s.list_issues_page("r", "", &label.id, &milestone.id, 10, 0)
                .await
                .unwrap()
                .len(),
            1
        );

        let pull = s
            .create_pull("pl1", "r", "first", "", "main", "feat", "u", 5)
            .await
            .unwrap();
        assert!(
            s.set_pull_metadata(
                &pull.id,
                "bob",
                "carol",
                &milestone.id,
                std::slice::from_ref(&label.id),
            )
            .await
            .unwrap()
        );
        let pull = s.get_pull("r", 1).await.unwrap().unwrap();
        assert_eq!(pull.assignee_sub, "bob");
        assert_eq!(pull.reviewer_sub, "carol");
        assert_eq!(s.pull_labels(&pull.id).await.unwrap(), vec![label.clone()]);
        assert_eq!(
            s.list_pulls_filtered("r", &label.id, &milestone.id)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            s.milestone_progress("r", &milestone.id).await.unwrap(),
            (0, 2)
        );

        s.create_pull_review("rv1", &pull.id, "alice", "approve", "ok", 6)
            .await
            .unwrap();
        s.create_pull_review_comment("rc1", &pull.id, "rv1", "file.txt", 2, "alice", "note", 7)
            .await
            .unwrap();
        assert_eq!(s.list_pull_reviews(&pull.id).await.unwrap().len(), 1);
        assert_eq!(
            s.list_pull_review_comments(&pull.id).await.unwrap().len(),
            1
        );
    }

    #[tokio::test]
    async fn pr_file_viewed_is_per_user_and_upserts() {
        let s = InMemoryStore::new();

        let first = s
            .set_pr_file_viewed("pl1", "alice", "src/lib.rs", true, 10)
            .await
            .unwrap();
        assert!(first.viewed);
        assert_eq!(first.updated_at, 10);
        assert_eq!(
            s.list_pr_file_viewed_for_pr("pl1", "alice").await.unwrap(),
            vec![first.clone()]
        );

        let updated = s
            .set_pr_file_viewed("pl1", "alice", "src/lib.rs", false, 20)
            .await
            .unwrap();
        assert!(!updated.viewed);
        assert_eq!(updated.updated_at, 20);
        assert_eq!(
            s.list_pr_file_viewed_for_pr("pl1", "alice").await.unwrap(),
            vec![updated]
        );

        s.set_pr_file_viewed("pl1", "bob", "src/lib.rs", true, 30)
            .await
            .unwrap();
        assert_eq!(
            s.list_pr_file_viewed_for_pr("pl1", "bob")
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            s.list_pr_file_viewed_for_pr("pl1", "alice")
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn commit_status_upsert_and_aggregate() {
        let s = InMemoryStore::new();
        assert!(
            s.aggregate_state_for_commit("r", "abc123")
                .await
                .unwrap()
                .is_none()
        );

        let build = s
            .upsert_commit_status(&commit_status("build", "pending", 10))
            .await
            .unwrap();
        assert_eq!(build.state, "pending");
        assert_eq!(
            s.aggregate_state_for_commit("r", "abc123").await.unwrap(),
            Some("pending".to_string())
        );

        s.upsert_commit_status(&commit_status("test", "success", 11))
            .await
            .unwrap();
        assert_eq!(
            s.aggregate_state_for_commit("r", "abc123").await.unwrap(),
            Some("pending".to_string()),
            "pending wins over all-success until every context succeeds"
        );

        let updated = s
            .upsert_commit_status(&commit_status("build", "success", 12))
            .await
            .unwrap();
        assert_eq!(updated.state, "success");
        assert_eq!(
            updated.created_at, 1,
            "upsert preserves first creation time"
        );
        assert_eq!(updated.updated_at, 12);
        assert_eq!(
            s.aggregate_state_for_commit("r", "abc123").await.unwrap(),
            Some("success".to_string())
        );

        s.upsert_commit_status(&commit_status("lint", "error", 13))
            .await
            .unwrap();
        assert_eq!(
            s.aggregate_state_for_commit("r", "abc123").await.unwrap(),
            Some("failure".to_string()),
            "failure/error wins over every other state"
        );
        let contexts: Vec<String> = s
            .list_commit_statuses("r", "abc123")
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.context)
            .collect();
        assert_eq!(contexts, vec!["build", "lint", "test"]);
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
        assert_eq!(
            s.find_pat_by_hash("deadbeef").await.unwrap().unwrap().id,
            "p1"
        );
        assert!(s.find_pat_by_hash("nope").await.unwrap().is_none());
        // Wrong owner cannot revoke.
        assert!(!s.revoke_pat("p1", "v").await.unwrap());
        assert!(s.revoke_pat("p1", "u").await.unwrap());
        assert!(s.find_pat_by_hash("deadbeef").await.unwrap().is_none());
    }
}
