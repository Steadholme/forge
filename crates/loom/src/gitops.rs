//! Git on-disk operations: bare-repo lifecycle, read-only browsing, and the smart-HTTP CGI.
//!
//! Loom stores each repository as a BARE git repo on a mounted volume at
//! `<LOOM_DATA>/repos/{owner}/{name}.git`. We manage them by shelling out to the installed `git`
//! binary (which the runtime image already needs for `git http-backend`), so there is NO C-linked
//! `libgit2`/`git2` dependency — consistent with the estate's rustls-only, no-OpenSSL posture.
//!
//! Browsing uses git PLUMBING (`symbolic-ref`, `rev-parse`, `for-each-ref`, `ls-tree`,
//! `cat-file`, `log`) on resolved commit OIDs, so the inputs we hand git are hex object ids and a
//! path that never starts with `-` (no option injection). Clone/pull/push are served by invoking
//! `git http-backend` as a CGI: we set the documented environment, stream the request body to its
//! stdin while concurrently reading its stdout (so a large push never deadlocks the pipe), and
//! translate the CGI header block into an axum response.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

use crate::config::Config;

/// A single entry in a tree listing (one row of `git ls-tree`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeEntry {
    /// `blob` (file), `tree` (directory), or `commit` (submodule).
    pub kind: String,
    /// Object id (hex).
    pub oid: String,
    /// Entry name (the last path component).
    pub name: String,
    /// File size in bytes for a blob; `None` for a tree.
    pub size: Option<i64>,
}

impl TreeEntry {
    pub fn is_dir(&self) -> bool {
        self.kind == "tree"
    }
}

/// One commit row for the history list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitInfo {
    pub oid: String,
    pub author_name: String,
    pub author_email: String,
    /// Author time, epoch seconds.
    pub time: i64,
    pub subject: String,
}

/// Full metadata for ONE commit (the commit page). Superset of [`CommitInfo`]: adds the parent
/// OIDs and the complete message body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitDetail {
    pub oid: String,
    pub author_name: String,
    pub author_email: String,
    /// Author time, epoch seconds.
    pub time: i64,
    /// Parent commit OIDs (empty for a root commit, two for a merge).
    pub parents: Vec<String>,
    /// The full commit message (`%B`), subject line included.
    pub message: String,
}

impl CommitDetail {
    /// The message's first line (the subject).
    pub fn subject(&self) -> &str {
        self.message.lines().next().unwrap_or("")
    }
}

/// One rendered line from `git blame --porcelain`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlameLine {
    pub oid: String,
    pub author_name: String,
    /// Author time, epoch seconds.
    pub time: i64,
    /// Final line number in the blamed file.
    pub lineno: usize,
    pub content: String,
}

/// One fixed-string `git grep` hit in a repository tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeSearchHit {
    pub path: String,
    pub line: usize,
    pub content: String,
}

/// Hits grouped by file for repository code search.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeSearchFile {
    pub path: String,
    pub hits: Vec<CodeSearchHit>,
}

/// Bounded repository code-search results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeSearchResults {
    pub files: Vec<CodeSearchFile>,
    pub total_hits: usize,
    pub limited: bool,
    pub per_file_limited: bool,
}

/// One branch row for the branches page: head OID + head-commit subject and time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchInfo {
    pub name: String,
    /// Head commit OID.
    pub oid: String,
    /// Head committer time, epoch seconds.
    pub time: i64,
    /// Head commit subject.
    pub subject: String,
}

/// One tag row for the branches page. For an annotated tag `message` carries the tag message's
/// subject line; for a lightweight tag it is empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagInfo {
    pub name: String,
    /// The COMMIT the tag ultimately points at (peeled for annotated tags).
    pub oid: String,
    /// Tag creation time (annotated) or target committer time (lightweight), epoch seconds.
    pub time: i64,
    /// Annotated tag message subject; empty for a lightweight tag.
    pub message: String,
    /// True when the ref points at a tag OBJECT (annotated) rather than directly at a commit.
    pub annotated: bool,
}

/// Outcome of a server-side [`GitOps::merge`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeOutcome {
    /// `head` was already contained in `base`; the ref was not moved.
    AlreadyUpToDate,
    /// `base` was fast-forwarded to `head` (no merge commit created).
    FastForward,
    /// A two-parent merge commit (its OID) was created and `base` advanced to it.
    MergeCommit(String),
}

/// Parsed CGI response from `git http-backend`.
pub struct CgiOut {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// On-disk git operations bound to the configured data root + binaries.
#[derive(Clone)]
pub struct GitOps {
    repos_root: String,
    git_bin: String,
    http_backend: String,
}

impl GitOps {
    pub fn new(config: &Config) -> Self {
        Self {
            repos_root: config.repos_root(),
            git_bin: config.git_bin.clone(),
            http_backend: config.git_http_backend.clone(),
        }
    }

    /// Filesystem root handed to `git http-backend` as `GIT_PROJECT_ROOT`.
    pub fn repos_root(&self) -> &str {
        &self.repos_root
    }

    /// Absolute path to a bare repo: `<repos_root>/{owner}/{name}.git`.
    pub fn repo_path(&self, owner: &str, name: &str) -> PathBuf {
        PathBuf::from(&self.repos_root)
            .join(owner)
            .join(format!("{name}.git"))
    }

    /// Create a bare repository with HEAD pointing at `default_branch`. Idempotent: re-running on
    /// an existing repo is harmless. Also enables smart-HTTP receive-pack (push).
    pub async fn init_bare(
        &self,
        owner: &str,
        name: &str,
        default_branch: &str,
    ) -> std::io::Result<()> {
        let path = self.repo_path(owner, name);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let path_str = path.to_string_lossy().to_string();
        // `git init --bare --initial-branch=<b> <path>` sets HEAD even with no commits yet.
        self.run_git(&[
            "init",
            "--bare",
            "--initial-branch",
            default_branch,
            &path_str,
        ])
        .await?;
        // Enable push over smart-HTTP for this repo (auth is enforced by Loom, not git).
        self.run_git_in(&path_str, &["config", "http.receivepack", "true"])
            .await?;
        Ok(())
    }

    /// Best-effort removal of a repo's on-disk directory (rollback when DB insert/`init` fails).
    pub async fn remove_repo(&self, owner: &str, name: &str) {
        let path = self.repo_path(owner, name);
        let _ = tokio::fs::remove_dir_all(path).await;
    }

    /// Fork a repository by cloning the source bare repo into a new bare repo path. The caller
    /// creates metadata first and rolls it back if this fails.
    pub async fn clone_bare(
        &self,
        src_owner: &str,
        src_name: &str,
        dst_owner: &str,
        dst_name: &str,
    ) -> std::io::Result<()> {
        let src = self.repo_path(src_owner, src_name);
        let dst = self.repo_path(dst_owner, dst_name);
        if let Some(parent) = dst.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let src_str = src.to_string_lossy().to_string();
        let dst_str = dst.to_string_lossy().to_string();
        self.run_git(&["clone", "--bare", &src_str, &dst_str])
            .await?;
        self.run_git_in(&dst_str, &["config", "http.receivepack", "true"])
            .await?;
        Ok(())
    }

    /// Resolve the default-branch HEAD to a commit OID, or `None` when the repo has no commits
    /// yet (a freshly created/empty repo).
    pub async fn head_commit(&self, owner: &str, name: &str) -> Option<String> {
        let path = self.repo_path(owner, name);
        let out = self
            .run_git_in_capture(&path.to_string_lossy(), &["rev-parse", "--verify", "HEAD"])
            .await
            .ok()?;
        if !out.status {
            return None;
        }
        let oid = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if oid.is_empty() {
            None
        } else {
            Some(oid)
        }
    }

    /// List the local branch names (`refs/heads/*`).
    pub async fn branches(&self, owner: &str, name: &str) -> Vec<String> {
        let path = self.repo_path(owner, name);
        match self
            .run_git_in_capture(
                &path.to_string_lossy(),
                &["for-each-ref", "--format=%(refname:short)", "refs/heads/"],
            )
            .await
        {
            Ok(out) if out.status => String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect(),
            _ => Vec::new(),
        }
    }

    /// List a tree at `path` (empty = repo root) for the given commit OID. `commit_oid` is a
    /// resolved 40-hex id, so the `git` argument is never option-like.
    pub async fn list_tree(
        &self,
        owner: &str,
        name: &str,
        commit_oid: &str,
        path: &str,
    ) -> Vec<TreeEntry> {
        let repo = self.repo_path(owner, name);
        // `<oid>:<path>` addresses the subtree; a trailing slash is required by git for subtrees.
        let spec = if path.is_empty() {
            commit_oid.to_string()
        } else {
            format!("{commit_oid}:{}", path.trim_end_matches('/'))
        };
        let out = match self
            .run_git_in_capture(&repo.to_string_lossy(), &["ls-tree", "--long", "-z", &spec])
            .await
        {
            Ok(out) if out.status => out,
            _ => return Vec::new(),
        };
        parse_ls_tree(&String::from_utf8_lossy(&out.stdout))
    }

    /// Read a blob's bytes at `path` for the given commit OID. `None` when the path is absent or
    /// is not a blob.
    pub async fn read_blob(
        &self,
        owner: &str,
        name: &str,
        commit_oid: &str,
        path: &str,
    ) -> Option<Vec<u8>> {
        if !is_safe_repo_path(path) {
            return None;
        }
        let repo = self.repo_path(owner, name);
        let spec = format!("{commit_oid}:{path}");
        // Confirm the object is a blob before dumping it (avoids dumping a whole tree).
        let kind = self
            .run_git_in_capture(&repo.to_string_lossy(), &["cat-file", "-t", &spec])
            .await
            .ok()?;
        if !kind.status || String::from_utf8_lossy(&kind.stdout).trim() != "blob" {
            return None;
        }
        let out = self
            .run_git_in_capture(&repo.to_string_lossy(), &["cat-file", "-p", &spec])
            .await
            .ok()?;
        if out.status {
            Some(out.stdout)
        } else {
            None
        }
    }

    /// Line-level blame for a blob at `path` in a resolved commit OID.
    pub async fn blame(
        &self,
        owner: &str,
        name: &str,
        commit_oid: &str,
        path: &str,
    ) -> Option<Vec<BlameLine>> {
        if !is_safe_repo_path(path) {
            return None;
        }
        let repo = self.repo_path(owner, name);
        let out = self
            .run_git_in_capture(
                &repo.to_string_lossy(),
                &["blame", "--porcelain", commit_oid, "--", path],
            )
            .await
            .ok()?;
        if out.status {
            Some(parse_blame_porcelain(&String::from_utf8_lossy(&out.stdout)))
        } else {
            None
        }
    }

    /// Recent commit history for the given commit OID, newest first, capped at `limit`.
    pub async fn log(
        &self,
        owner: &str,
        name: &str,
        commit_oid: &str,
        limit: usize,
    ) -> Vec<CommitInfo> {
        let repo = self.repo_path(owner, name);
        // Records separated by US (0x1f) fields and a NUL between records, so subjects with any
        // byte survive intact.
        let fmt = "--pretty=format:%H%x1f%an%x1f%ae%x1f%at%x1f%s%x00";
        let max = format!("--max-count={limit}");
        let out = match self
            .run_git_in_capture(&repo.to_string_lossy(), &["log", &max, fmt, commit_oid])
            .await
        {
            Ok(out) if out.status => out,
            _ => return Vec::new(),
        };
        parse_log(&String::from_utf8_lossy(&out.stdout))
    }

    /// Commit history for one file path, newest first, following renames, capped at `limit`.
    pub async fn file_log(
        &self,
        owner: &str,
        name: &str,
        commit_oid: &str,
        path: &str,
        limit: usize,
    ) -> Vec<CommitInfo> {
        if !is_safe_repo_path(path) {
            return Vec::new();
        }
        let repo = self.repo_path(owner, name);
        let fmt = "--pretty=format:%H%x1f%an%x1f%ae%x1f%at%x1f%s%x00";
        let max = format!("--max-count={limit}");
        let out = match self
            .run_git_in_capture(
                &repo.to_string_lossy(),
                &["log", "--follow", &max, fmt, commit_oid, "--", path],
            )
            .await
        {
            Ok(out) if out.status => out,
            _ => return Vec::new(),
        };
        parse_log(&String::from_utf8_lossy(&out.stdout))
    }

    /// Fixed-string repository code search using `git grep`.
    ///
    /// The query is passed as an argv value after `-e`, never through a shell, and `-F` keeps user
    /// input out of git's regex engine. `-m` caps matches per file; stdout is streamed and stopped
    /// after `result_limit` stored hits so large repos do not require capturing all output.
    pub async fn code_search(
        &self,
        owner: &str,
        name: &str,
        commit_oid: &str,
        query: &str,
        ignore_case: bool,
        result_limit: usize,
        per_file_limit: usize,
    ) -> std::io::Result<CodeSearchResults> {
        let result_limit = result_limit.max(1);
        let per_file_limit = per_file_limit.max(1);
        let repo = self.repo_path(owner, name);
        let repo_dir = repo.to_string_lossy();
        let per_file_arg = format!("-m{per_file_limit}");

        let mut cmd = Command::new(&self.git_bin);
        cmd.arg("--git-dir")
            .arg(repo_dir.as_ref())
            .arg("grep")
            .arg("-n")
            .arg("-F")
            .arg("-I")
            .arg(&per_file_arg);
        if ignore_case {
            cmd.arg("-i");
        }
        cmd.arg("-e")
            .arg(query)
            .arg(commit_oid)
            .arg("--")
            .arg(".")
            // safe.directory=* so a uid-mismatched bind mount never trips "dubious ownership".
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "safe.directory")
            .env("GIT_CONFIG_VALUE_0", "*")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let mut child = cmd.spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("git grep stdout unavailable"))?;
        let mut reader = BufReader::new(stdout);
        let mut buf = Vec::new();
        let mut files = Vec::new();
        let mut total_hits = 0usize;
        let mut limited = false;

        loop {
            buf.clear();
            let n = reader.read_until(b'\n', &mut buf).await?;
            if n == 0 {
                break;
            }
            while matches!(buf.last(), Some(b'\n' | b'\r')) {
                buf.pop();
            }
            let line = String::from_utf8_lossy(&buf);
            let Some(hit) = parse_git_grep_line(&line, commit_oid) else {
                continue;
            };
            if total_hits >= result_limit {
                limited = true;
                let _ = child.start_kill();
                break;
            }
            push_code_search_hit(&mut files, hit);
            total_hits += 1;
        }

        let _status = child.wait().await?;
        let per_file_limited = files.iter().any(|f| f.hits.len() >= per_file_limit);
        Ok(CodeSearchResults {
            files,
            total_hits,
            limited,
            per_file_limited,
        })
    }

    // -----------------------------------------------------------------------
    // History browsing: commit resolve/detail/diff, branch + tag listings.
    // -----------------------------------------------------------------------

    /// Resolve a (caller-validated, HEX-ONLY) abbreviated or full commit id to its full OID, or
    /// `None` when it does not name a commit in this repo. The `^{commit}` peel also rejects
    /// non-commit objects (blobs/trees/tags addressed by hash).
    pub async fn resolve_commit(&self, owner: &str, name: &str, hexspec: &str) -> Option<String> {
        let repo = self.repo_path(owner, name);
        self.rev(&repo.to_string_lossy(), &format!("{hexspec}^{{commit}}"))
            .await
    }

    /// Full metadata for one commit (a resolved OID): author, time, parents, complete message.
    pub async fn commit_detail(
        &self,
        owner: &str,
        name: &str,
        commit_oid: &str,
    ) -> Option<CommitDetail> {
        let repo = self.repo_path(owner, name);
        // %B (the raw body) goes LAST so a message containing the 0x1f separator stays intact
        // (the parse splits at most 5 times).
        let fmt = "--pretty=format:%H%x1f%an%x1f%ae%x1f%at%x1f%P%x1f%B";
        let out = self
            .run_git_in_capture(
                &repo.to_string_lossy(),
                &["log", "--max-count=1", fmt, commit_oid],
            )
            .await
            .ok()?;
        if !out.status {
            return None;
        }
        parse_commit_detail(&String::from_utf8_lossy(&out.stdout))
    }

    /// One-line change summary for a commit (`git show --shortstat`), e.g.
    /// `1 file changed, 2 insertions(+)`. Empty for a merge commit (no combined stat).
    pub async fn commit_stat(&self, owner: &str, name: &str, commit_oid: &str) -> String {
        let repo = self.repo_path(owner, name);
        match self
            .run_git_in_capture(
                &repo.to_string_lossy(),
                &["show", "--format=", "--shortstat", commit_oid],
            )
            .await
        {
            Ok(out) if out.status => String::from_utf8_lossy(&out.stdout).trim().to_string(),
            _ => String::new(),
        }
    }

    /// The unified diff a commit introduced (`git show` against its first parent; a root commit
    /// diffs against the empty tree). `None` when the git invocation fails. For a merge commit
    /// git emits the combined diff, which is empty unless the merge itself changed files.
    pub async fn commit_patch(&self, owner: &str, name: &str, commit_oid: &str) -> Option<String> {
        let repo = self.repo_path(owner, name);
        let out = self
            .run_git_in_capture(&repo.to_string_lossy(), &["show", "--format=", commit_oid])
            .await
            .ok()?;
        if out.status {
            Some(String::from_utf8_lossy(&out.stdout).to_string())
        } else {
            None
        }
    }

    /// Branch rows (name + head OID/subject/time), most recently committed first.
    pub async fn branch_infos(&self, owner: &str, name: &str) -> Vec<BranchInfo> {
        let repo = self.repo_path(owner, name);
        // One line per ref; the subject is a single line by definition, so line parsing is safe.
        let fmt = "--format=%(refname:short)%1f%(objectname)%1f%(committerdate:unix)%1f%(subject)";
        match self
            .run_git_in_capture(
                &repo.to_string_lossy(),
                &["for-each-ref", "--sort=-committerdate", fmt, "refs/heads/"],
            )
            .await
        {
            Ok(out) if out.status => parse_branch_refs(&String::from_utf8_lossy(&out.stdout)),
            _ => Vec::new(),
        }
    }

    /// Tag rows (annotated tags peeled to their target commit, message subject included),
    /// newest first.
    pub async fn tag_infos(&self, owner: &str, name: &str) -> Vec<TagInfo> {
        let repo = self.repo_path(owner, name);
        let fmt = "--format=%(refname:short)%1f%(objectname)%1f%(*objectname)%1f%(objecttype)%1f%(creatordate:unix)%1f%(contents:subject)";
        match self
            .run_git_in_capture(
                &repo.to_string_lossy(),
                &["for-each-ref", "--sort=-creatordate", fmt, "refs/tags/"],
            )
            .await
        {
            Ok(out) if out.status => parse_tag_refs(&String::from_utf8_lossy(&out.stdout)),
            _ => Vec::new(),
        }
    }

    /// Create a lightweight tag pointing at `target_commit`. The empty old-value argument makes this
    /// a create-only update, so an existing tag is never overwritten.
    pub async fn create_lightweight_tag(
        &self,
        owner: &str,
        name: &str,
        tag: &str,
        target_commit: &str,
    ) -> std::io::Result<()> {
        let path = self.repo_path(owner, name).to_string_lossy().to_string();
        self.run_git_in(
            &path,
            &["update-ref", &format!("refs/tags/{tag}"), target_commit, ""],
        )
        .await
    }

    /// Point the bare repo's HEAD at `refs/heads/{branch}` (the default-branch setting). The
    /// branch name is caller-validated, so the argument is never option-like.
    pub async fn set_head(&self, owner: &str, name: &str, branch: &str) -> std::io::Result<()> {
        let path = self.repo_path(owner, name).to_string_lossy().to_string();
        self.run_git_in(
            &path,
            &["symbolic-ref", "HEAD", &format!("refs/heads/{branch}")],
        )
        .await
    }

    // -----------------------------------------------------------------------
    // Pull-request plumbing: branch compare (commits ahead + diff) and merge.
    // -----------------------------------------------------------------------

    /// Resolve a local branch name to its commit OID, or `None` when the branch is absent. The ref
    /// is addressed as `refs/heads/{branch}`, which never starts with `-` (no option injection).
    pub async fn branch_oid(&self, owner: &str, name: &str, branch: &str) -> Option<String> {
        let repo = self.repo_path(owner, name);
        self.rev(&repo.to_string_lossy(), &format!("refs/heads/{branch}"))
            .await
    }

    /// Commits on `head` that are NOT on `base` (`git log base..head`), newest first, capped at
    /// `limit` — i.e. the commits a PR from `head` into `base` would add. Both branch names are
    /// resolved through `refs/heads/…`, so neither is ever option-like.
    pub async fn commits_between(
        &self,
        owner: &str,
        name: &str,
        base: &str,
        head: &str,
        limit: usize,
    ) -> Vec<CommitInfo> {
        let repo = self.repo_path(owner, name);
        let fmt = "--pretty=format:%H%x1f%an%x1f%ae%x1f%at%x1f%s%x00";
        let max = format!("--max-count={limit}");
        let range = format!("refs/heads/{base}..refs/heads/{head}");
        let out = match self
            .run_git_in_capture(&repo.to_string_lossy(), &["log", &max, fmt, &range])
            .await
        {
            Ok(out) if out.status => out,
            _ => return Vec::new(),
        };
        parse_log(&String::from_utf8_lossy(&out.stdout))
    }

    /// Unified diff of `base..head` (`git diff base..head`) as a UTF-8 string. `None` when the git
    /// invocation fails (e.g. a branch was deleted). An empty string means the ranges are equal.
    pub async fn diff(&self, owner: &str, name: &str, base: &str, head: &str) -> Option<String> {
        let repo = self.repo_path(owner, name);
        let range = format!("refs/heads/{base}..refs/heads/{head}");
        let out = self
            .run_git_in_capture(&repo.to_string_lossy(), &["diff", &range])
            .await
            .ok()?;
        if out.status {
            Some(String::from_utf8_lossy(&out.stdout).to_string())
        } else {
            None
        }
    }

    /// Server-side merge of `head` into `base` on the bare repo, using ONLY git plumbing (no
    /// working tree). Fast-forwards when possible, otherwise writes a real merge commit via
    /// `git merge-tree --write-tree` + `git commit-tree`. The `base` ref is advanced with a
    /// compare-and-swap (old value pinned), so a concurrent push cannot be clobbered. Conflicts
    /// abort the merge with an error; nothing is written.
    pub async fn merge(
        &self,
        owner: &str,
        name: &str,
        base: &str,
        head: &str,
        message: &str,
        author_name: &str,
        author_email: &str,
    ) -> Result<MergeOutcome, String> {
        let repo = self.repo_path(owner, name);
        let dir = repo.to_string_lossy().to_string();
        let base_ref = format!("refs/heads/{base}");
        let head_ref = format!("refs/heads/{head}");

        let base_oid = self
            .rev(&dir, &base_ref)
            .await
            .ok_or_else(|| format!("base branch '{base}' no longer exists"))?;
        let head_oid = self
            .rev(&dir, &head_ref)
            .await
            .ok_or_else(|| format!("head branch '{head}' no longer exists"))?;

        // Head already contained in base (or identical) — nothing to merge.
        if base_oid == head_oid || self.is_ancestor(&dir, &head_oid, &base_oid).await {
            return Ok(MergeOutcome::AlreadyUpToDate);
        }

        // Base is an ancestor of head — a clean fast-forward.
        if self.is_ancestor(&dir, &base_oid, &head_oid).await {
            self.update_ref(&dir, &base_ref, &head_oid, &base_oid)
                .await?;
            return Ok(MergeOutcome::FastForward);
        }

        // Divergent histories — compute a merged tree and record a two-parent merge commit.
        let tree = self.merge_tree(&dir, &base_oid, &head_oid).await?;
        let commit = self
            .commit_tree(
                &dir,
                &tree,
                &[&base_oid, &head_oid],
                message,
                author_name,
                author_email,
            )
            .await?;
        self.update_ref(&dir, &base_ref, &commit, &base_oid).await?;
        Ok(MergeOutcome::MergeCommit(commit))
    }

    /// `git rev-parse --verify --quiet <refspec>` → the resolved OID, or `None` if it does not
    /// resolve.
    async fn rev(&self, dir: &str, refspec: &str) -> Option<String> {
        let out = self
            .run_git_in_capture(dir, &["rev-parse", "--verify", "--quiet", refspec])
            .await
            .ok()?;
        if !out.status {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    /// True when `ancestor` is an ancestor of (or equal to) `descendant`
    /// (`git merge-base --is-ancestor`). Both inputs are resolved 40-hex OIDs.
    async fn is_ancestor(&self, dir: &str, ancestor: &str, descendant: &str) -> bool {
        matches!(
            self.run_git_in_capture(dir, &["merge-base", "--is-ancestor", ancestor, descendant])
                .await,
            Ok(out) if out.status
        )
    }

    /// `git merge-tree --write-tree <base> <head>` → the merged tree OID. Errors (with git's
    /// conflict summary) when the three-way merge does not apply cleanly.
    async fn merge_tree(&self, dir: &str, base: &str, head: &str) -> Result<String, String> {
        let out = self
            .run_git_in_capture(dir, &["merge-tree", "--write-tree", base, head])
            .await
            .map_err(|e| format!("merge-tree failed: {e}"))?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        if !out.status {
            return Err(
                "the branches have conflicting changes that must be resolved manually".to_string(),
            );
        }
        // On success the first line is the merged tree OID.
        stdout
            .lines()
            .next()
            .map(|l| l.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "merge-tree produced no tree".to_string())
    }

    /// `git commit-tree <tree> -p <parent>… -m <message>` with the merging user's identity as both
    /// author and committer → the new commit OID.
    async fn commit_tree(
        &self,
        dir: &str,
        tree: &str,
        parents: &[&str],
        message: &str,
        author_name: &str,
        author_email: &str,
    ) -> Result<String, String> {
        let mut args: Vec<&str> = vec!["commit-tree", tree];
        for p in parents {
            args.push("-p");
            args.push(p);
        }
        args.push("-m");
        args.push(message);
        let env = [
            ("GIT_AUTHOR_NAME", author_name),
            ("GIT_AUTHOR_EMAIL", author_email),
            ("GIT_COMMITTER_NAME", author_name),
            ("GIT_COMMITTER_EMAIL", author_email),
        ];
        let out = self
            .run_git_capture_env(dir, &args, &env)
            .await
            .map_err(|e| format!("commit-tree failed: {e}"))?;
        if !out.status {
            return Err("could not create the merge commit".to_string());
        }
        let oid = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if oid.is_empty() {
            Err("commit-tree produced no commit".to_string())
        } else {
            Ok(oid)
        }
    }

    /// `git update-ref <ref> <new> <old>` — a compare-and-swap advance of a branch ref (fails if
    /// the ref moved off `old` since we read it).
    async fn update_ref(
        &self,
        dir: &str,
        refname: &str,
        new_oid: &str,
        old_oid: &str,
    ) -> Result<(), String> {
        let out = self
            .run_git_in_capture(dir, &["update-ref", refname, new_oid, old_oid])
            .await
            .map_err(|e| format!("update-ref failed: {e}"))?;
        if out.status {
            Ok(())
        } else {
            Err("the base branch moved during the merge; retry".to_string())
        }
    }

    // -----------------------------------------------------------------------
    // Smart-HTTP CGI (`git http-backend`)
    // -----------------------------------------------------------------------

    /// Invoke `git http-backend` as a CGI. `path_info` is the request path relative to the repos
    /// root (e.g. `/owner/name.git/info/refs`); `query` is the raw query string; `extra` carries
    /// the request-derived CGI variables (REQUEST_METHOD, CONTENT_TYPE, GIT_PROTOCOL, …). The
    /// request body is streamed to stdin concurrently with reading stdout.
    pub async fn http_backend(
        &self,
        path_info: &str,
        query: &str,
        extra: &[(String, String)],
        body: Vec<u8>,
    ) -> std::io::Result<CgiOut> {
        let mut cmd = Command::new(&self.http_backend);
        cmd.env_clear();
        cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/lib/git-core");
        cmd.env("GIT_PROJECT_ROOT", &self.repos_root);
        // Serve every repo under the root without per-repo `git-daemon-export-ok` marker files.
        cmd.env("GIT_HTTP_EXPORT_ALL", "1");
        // Tolerate the repo dir being owned by a different uid in edge cases.
        cmd.env("GIT_CONFIG_COUNT", "1");
        cmd.env("GIT_CONFIG_KEY_0", "safe.directory");
        cmd.env("GIT_CONFIG_VALUE_0", "*");
        cmd.env("PATH_INFO", path_info);
        cmd.env("QUERY_STRING", query);
        cmd.env("CONTENT_LENGTH", body.len().to_string());
        for (k, v) in extra {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn()?;
        // Write the body on a separate task so a large request can't deadlock against a full
        // stdout pipe that we are not yet draining.
        if let Some(mut stdin) = child.stdin.take() {
            tokio::spawn(async move {
                let _ = stdin.write_all(&body).await;
                let _ = stdin.shutdown().await;
            });
        }
        let output = child.wait_with_output().await?;
        Ok(parse_cgi(&output.stdout))
    }

    // -----------------------------------------------------------------------
    // git invocation helpers
    // -----------------------------------------------------------------------

    async fn run_git(&self, args: &[&str]) -> std::io::Result<()> {
        let out = Command::new(&self.git_bin)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .await?;
        if out.status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other(format!(
                "git {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    }

    /// Run `git -C <repo_dir> --git-dir=<repo_dir> <args>` and treat a non-zero exit as an error.
    async fn run_git_in(&self, repo_dir: &str, args: &[&str]) -> std::io::Result<()> {
        let mut full: Vec<&str> = vec!["--git-dir", repo_dir];
        full.extend_from_slice(args);
        self.run_git(&full).await
    }

    /// Run `git --git-dir=<repo_dir> <args>` and CAPTURE stdout (status flag = exit success).
    async fn run_git_in_capture(
        &self,
        repo_dir: &str,
        args: &[&str],
    ) -> std::io::Result<CapturedOut> {
        let mut full: Vec<&str> = vec!["--git-dir", repo_dir];
        full.extend_from_slice(args);
        let out = Command::new(&self.git_bin)
            .args(&full)
            // safe.directory=* so a uid-mismatched bind mount never trips "dubious ownership".
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "safe.directory")
            .env("GIT_CONFIG_VALUE_0", "*")
            .stdin(Stdio::null())
            .output()
            .await?;
        Ok(CapturedOut {
            status: out.status.success(),
            stdout: out.stdout,
        })
    }

    /// Like [`run_git_in_capture`], but also injects the given environment pairs (used to set the
    /// committer identity for `commit-tree`). `safe.directory=*` is preserved via GIT_CONFIG.
    async fn run_git_capture_env(
        &self,
        repo_dir: &str,
        args: &[&str],
        env: &[(&str, &str)],
    ) -> std::io::Result<CapturedOut> {
        let mut full: Vec<&str> = vec!["--git-dir", repo_dir];
        full.extend_from_slice(args);
        let mut cmd = Command::new(&self.git_bin);
        cmd.args(&full)
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "safe.directory")
            .env("GIT_CONFIG_VALUE_0", "*")
            .stdin(Stdio::null());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = cmd.output().await?;
        Ok(CapturedOut {
            status: out.status.success(),
            stdout: out.stdout,
        })
    }
}

struct CapturedOut {
    status: bool,
    stdout: Vec<u8>,
}

fn push_code_search_hit(files: &mut Vec<CodeSearchFile>, hit: CodeSearchHit) {
    if let Some(file) = files.iter_mut().find(|f| f.path == hit.path) {
        file.hits.push(hit);
    } else {
        files.push(CodeSearchFile {
            path: hit.path.clone(),
            hits: vec![hit],
        });
    }
}

/// Parse one `git grep -n <tree>` output row.
///
/// With a tree-ish argument git prefixes each row with `<tree>:`; callers pass a resolved commit
/// OID, so that prefix is deterministic and can be stripped before reading `path:line:content`.
fn parse_git_grep_line(line: &str, commit_oid: &str) -> Option<CodeSearchHit> {
    let body = line
        .strip_prefix(commit_oid)
        .and_then(|rest| rest.strip_prefix(':'))
        .unwrap_or(line);

    for (idx, ch) in body.char_indices() {
        if ch != ':' {
            continue;
        }
        let rest = &body[idx + 1..];
        let digits_len = rest.bytes().take_while(|b| b.is_ascii_digit()).count();
        if digits_len == 0 || !rest[digits_len..].starts_with(':') {
            continue;
        }
        let line_no = rest[..digits_len].parse::<usize>().ok()?;
        if line_no == 0 {
            return None;
        }
        let path = &body[..idx];
        if path.is_empty() {
            return None;
        }
        return Some(CodeSearchHit {
            path: path.to_string(),
            line: line_no,
            content: rest[digits_len + 1..].to_string(),
        });
    }

    None
}

/// Parse `git ls-tree --long -z` output into [`TreeEntry`] rows.
///
/// Each record (NUL-separated) is `<mode> SP <type> SP <oid> SP* <size> TAB <name>`. For a tree
/// the size column is `-`.
fn parse_ls_tree(text: &str) -> Vec<TreeEntry> {
    let mut out = Vec::new();
    for record in text.split('\0') {
        if record.is_empty() {
            continue;
        }
        let Some((meta, name)) = record.split_once('\t') else {
            continue;
        };
        let mut parts = meta.split_whitespace();
        let _mode = parts.next();
        let Some(kind) = parts.next() else { continue };
        let Some(oid) = parts.next() else { continue };
        let size = parts.next().and_then(|s| s.parse::<i64>().ok());
        out.push(TreeEntry {
            kind: kind.to_string(),
            oid: oid.to_string(),
            name: name.to_string(),
            size,
        });
    }
    // Directories first, then files, each alphabetical — the familiar forge ordering.
    out.sort_by(|a, b| {
        b.is_dir()
            .cmp(&a.is_dir())
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    out
}

/// Parse the custom `git log` format into [`CommitInfo`] rows.
fn parse_log(text: &str) -> Vec<CommitInfo> {
    let mut out = Vec::new();
    for record in text.split('\0') {
        let record = record.trim_start_matches('\n');
        if record.is_empty() {
            continue;
        }
        let fields: Vec<&str> = record.split('\u{1f}').collect();
        if fields.len() < 5 {
            continue;
        }
        out.push(CommitInfo {
            oid: fields[0].to_string(),
            author_name: fields[1].to_string(),
            author_email: fields[2].to_string(),
            time: fields[3].trim().parse::<i64>().unwrap_or(0),
            subject: fields[4].to_string(),
        });
    }
    out
}

/// Parse the single-record `git log -1` format into a [`CommitDetail`]. The message (`%B`) is the
/// LAST field, so `splitn` keeps a message containing the 0x1f separator intact.
fn parse_commit_detail(text: &str) -> Option<CommitDetail> {
    let fields: Vec<&str> = text.splitn(6, '\u{1f}').collect();
    if fields.len() < 6 || fields[0].trim().is_empty() {
        return None;
    }
    Some(CommitDetail {
        oid: fields[0].trim().to_string(),
        author_name: fields[1].to_string(),
        author_email: fields[2].to_string(),
        time: fields[3].trim().parse::<i64>().unwrap_or(0),
        parents: fields[4].split_whitespace().map(str::to_string).collect(),
        message: fields[5].trim_end_matches('\n').to_string(),
    })
}

#[derive(Clone, Debug, Default)]
struct BlameCommitMeta {
    author_name: String,
    time: i64,
}

/// Parse `git blame --porcelain` output. Git emits commit metadata only when it has not already
/// been seen in the stream, so metadata is cached by commit OID and reused by later rows.
fn parse_blame_porcelain(text: &str) -> Vec<BlameLine> {
    let mut metas: HashMap<String, BlameCommitMeta> = HashMap::new();
    let mut rows = Vec::new();
    let mut lines = text.lines();

    while let Some(header) = lines.next() {
        let Some((oid, lineno)) = parse_blame_header(header) else {
            continue;
        };
        let mut author_name = None;
        let mut author_time = None;
        let mut content = None;

        for line in lines.by_ref() {
            if let Some(code) = line.strip_prefix('\t') {
                content = Some(code.to_string());
                break;
            }
            if let Some(value) = line.strip_prefix("author ") {
                author_name = Some(value.to_string());
            } else if let Some(value) = line.strip_prefix("author-time ") {
                author_time = value.trim().parse::<i64>().ok();
            }
        }

        if author_name.is_some() || author_time.is_some() {
            let previous = metas.get(&oid).cloned().unwrap_or_default();
            metas.insert(
                oid.clone(),
                BlameCommitMeta {
                    author_name: author_name.unwrap_or(previous.author_name),
                    time: author_time.unwrap_or(previous.time),
                },
            );
        }

        let Some(content) = content else { continue };
        let meta = metas.get(&oid).cloned().unwrap_or_default();
        rows.push(BlameLine {
            oid,
            author_name: meta.author_name,
            time: meta.time,
            lineno,
            content,
        });
    }

    rows
}

fn parse_blame_header(line: &str) -> Option<(String, usize)> {
    let mut parts = line.split_whitespace();
    let raw_oid = parts.next()?.trim_start_matches('^');
    if raw_oid.is_empty() || !raw_oid.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let _original_lineno = parts.next()?;
    let final_lineno = parts.next()?.parse::<usize>().ok()?;
    Some((raw_oid.to_string(), final_lineno))
}

fn is_safe_repo_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && path
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// Parse `for-each-ref` branch lines (`name US oid US unixtime US subject`) into [`BranchInfo`]s.
fn parse_branch_refs(text: &str) -> Vec<BranchInfo> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.splitn(4, '\u{1f}').collect();
        if fields.len() < 4 || fields[0].is_empty() {
            continue;
        }
        out.push(BranchInfo {
            name: fields[0].to_string(),
            oid: fields[1].to_string(),
            time: fields[2].trim().parse::<i64>().unwrap_or(0),
            subject: fields[3].to_string(),
        });
    }
    out
}

/// Parse `for-each-ref` tag lines (`name US oid US peeled US objecttype US unixtime US subject`)
/// into [`TagInfo`]s. An annotated tag ref points at a tag OBJECT (`objecttype == "tag"`); its
/// peeled OID is the target commit and its subject is the tag message's first line.
fn parse_tag_refs(text: &str) -> Vec<TagInfo> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.splitn(6, '\u{1f}').collect();
        if fields.len() < 6 || fields[0].is_empty() {
            continue;
        }
        let annotated = fields[3] == "tag";
        let peeled = fields[2].trim();
        out.push(TagInfo {
            name: fields[0].to_string(),
            oid: if annotated && !peeled.is_empty() {
                peeled.to_string()
            } else {
                fields[1].to_string()
            },
            time: fields[4].trim().parse::<i64>().unwrap_or(0),
            message: if annotated {
                fields[5].to_string()
            } else {
                String::new()
            },
            annotated,
        });
    }
    out
}

/// Split a CGI response (header block + body) produced by `git http-backend`. The header block
/// ends at the first blank line (`\r\n\r\n` or `\n\n`). A `Status:` header sets the HTTP status
/// (default 200); all other headers are forwarded verbatim.
fn parse_cgi(raw: &[u8]) -> CgiOut {
    let (head, body) = split_headers(raw);
    let head_text = String::from_utf8_lossy(head);
    let mut status = 200u16;
    let mut headers = Vec::new();
    for line in head_text.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let k = k.trim();
        let v = v.trim();
        if k.eq_ignore_ascii_case("status") {
            status = v
                .split_whitespace()
                .next()
                .and_then(|c| c.parse::<u16>().ok())
                .unwrap_or(200);
        } else {
            headers.push((k.to_string(), v.to_string()));
        }
    }
    CgiOut {
        status,
        headers,
        body: body.to_vec(),
    }
}

/// Return `(header_bytes, body_bytes)` splitting at the first CRLFCRLF or LFLF.
fn split_headers(raw: &[u8]) -> (&[u8], &[u8]) {
    if let Some(pos) = find_subslice(raw, b"\r\n\r\n") {
        (&raw[..pos], &raw[pos + 4..])
    } else if let Some(pos) = find_subslice(raw, b"\n\n") {
        (&raw[..pos], &raw[pos + 2..])
    } else {
        // No body — all headers (e.g. a redirect/notice).
        (raw, &[])
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ls_tree_parses_and_orders() {
        let raw = "100644 blob abc123    42\treadme.md\u{0}040000 tree def456    -\tsrc\u{0}";
        let entries = parse_ls_tree(raw);
        assert_eq!(entries.len(), 2);
        // Directory first.
        assert_eq!(entries[0].name, "src");
        assert!(entries[0].is_dir());
        assert_eq!(entries[1].name, "readme.md");
        assert_eq!(entries[1].size, Some(42));
        assert_eq!(entries[1].kind, "blob");
    }

    #[test]
    fn log_parses_records() {
        let raw = "deadbeef\u{1f}Ada\u{1f}ada@x\u{1f}1700000000\u{1f}Initial commit\0\
                   cafebabe\u{1f}Bob\u{1f}bob@x\u{1f}1700000100\u{1f}Second\0";
        let commits = parse_log(raw);
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0].oid, "deadbeef");
        assert_eq!(commits[0].author_name, "Ada");
        assert_eq!(commits[0].time, 1700000000);
        assert_eq!(commits[0].subject, "Initial commit");
        assert_eq!(commits[1].subject, "Second");
    }

    #[test]
    fn commit_detail_parses_parents_and_full_message() {
        let raw = "deadbeef\u{1f}Ada\u{1f}ada@x\u{1f}1700000000\u{1f}p1 p2\u{1f}Subject line\n\nBody paragraph.\n";
        let d = parse_commit_detail(raw).unwrap();
        assert_eq!(d.oid, "deadbeef");
        assert_eq!(d.author_name, "Ada");
        assert_eq!(d.time, 1700000000);
        assert_eq!(d.parents, vec!["p1".to_string(), "p2".to_string()]);
        assert_eq!(d.subject(), "Subject line");
        assert!(d.message.contains("Body paragraph."));
        // A root commit has no parents.
        let root = parse_commit_detail("abc\u{1f}A\u{1f}a@x\u{1f}1\u{1f}\u{1f}init").unwrap();
        assert!(root.parents.is_empty());
        assert!(parse_commit_detail("").is_none());
    }

    #[test]
    fn blame_porcelain_parses_metadata_reuse_and_content() {
        let raw = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 1 2\n\
author Ada\n\
author-time 1700000000\n\
filename src/main.rs\n\
\tfn main() {}\n\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2 2\n\
filename src/main.rs\n\
\t\tprintln!(\"<x>\");\n\
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 1 3 1\n\
author Bob\n\
author-time nope\n\
filename src/main.rs\n\
\tlast\n";
        let rows = parse_blame_porcelain(raw);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].oid, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(rows[0].author_name, "Ada");
        assert_eq!(rows[0].time, 1700000000);
        assert_eq!(rows[0].lineno, 1);
        assert_eq!(rows[1].author_name, "Ada");
        assert_eq!(rows[1].content, "\tprintln!(\"<x>\");");
        assert_eq!(rows[2].author_name, "Bob");
        assert_eq!(rows[2].time, 0);
        assert_eq!(rows[2].lineno, 3);
    }

    #[test]
    fn blame_paths_stay_relative_to_repo() {
        assert!(is_safe_repo_path("src/main.rs"));
        assert!(!is_safe_repo_path(""));
        assert!(!is_safe_repo_path("/etc/passwd"));
        assert!(!is_safe_repo_path("src/../secret"));
        assert!(!is_safe_repo_path("src//main.rs"));
    }

    #[test]
    fn git_grep_rows_parse_tree_prefix_colons_and_content() {
        let oid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let hit = parse_git_grep_line(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:src/main.rs:42:println!(\"a:b\")",
            oid,
        )
        .unwrap();
        assert_eq!(hit.path, "src/main.rs");
        assert_eq!(hit.line, 42);
        assert_eq!(hit.content, "println!(\"a:b\")");

        let path_with_colon = parse_git_grep_line(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:a:b.txt:7:needle",
            oid,
        )
        .unwrap();
        assert_eq!(path_with_colon.path, "a:b.txt");
        assert_eq!(path_with_colon.line, 7);
        assert_eq!(path_with_colon.content, "needle");

        assert!(parse_git_grep_line("no-line-number", oid).is_none());
    }

    #[test]
    fn branch_refs_parse() {
        let raw = "main\u{1f}aaa111\u{1f}1700000100\u{1f}Latest work\n\
                   feature\u{1f}bbb222\u{1f}1700000000\u{1f}WIP <thing>\n";
        let branches = parse_branch_refs(raw);
        assert_eq!(branches.len(), 2);
        assert_eq!(branches[0].name, "main");
        assert_eq!(branches[0].oid, "aaa111");
        assert_eq!(branches[0].time, 1700000100);
        assert_eq!(branches[1].subject, "WIP <thing>");
    }

    #[test]
    fn tag_refs_parse_annotated_and_lightweight() {
        // v1 is annotated (points at a tag object, peeled to ccc333); v0 is lightweight.
        let raw = "v1\u{1f}tag999\u{1f}ccc333\u{1f}tag\u{1f}1700000200\u{1f}first release\n\
                   v0\u{1f}ddd444\u{1f}\u{1f}commit\u{1f}1700000100\u{1f}some commit subject\n";
        let tags = parse_tag_refs(raw);
        assert_eq!(tags.len(), 2);
        assert!(tags[0].annotated);
        assert_eq!(
            tags[0].oid, "ccc333",
            "annotated tag peels to the target commit"
        );
        assert_eq!(tags[0].message, "first release");
        assert!(!tags[1].annotated);
        assert_eq!(tags[1].oid, "ddd444");
        assert_eq!(tags[1].message, "", "lightweight tag has no tag message");
    }

    #[test]
    fn cgi_split_with_status() {
        let raw = b"Status: 404 Not Found\r\nContent-Type: text/plain\r\n\r\nnope";
        let out = parse_cgi(raw);
        assert_eq!(out.status, 404);
        assert_eq!(out.body, b"nope");
        assert!(out
            .headers
            .iter()
            .any(|(k, v)| k == "Content-Type" && v == "text/plain"));
    }

    #[test]
    fn cgi_defaults_to_200_lf_only() {
        let raw = b"Content-Type: application/x-git-upload-pack-advertisement\n\nPACKDATA";
        let out = parse_cgi(raw);
        assert_eq!(out.status, 200);
        assert_eq!(out.body, b"PACKDATA");
    }
}
