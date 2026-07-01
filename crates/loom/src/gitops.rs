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

use std::path::PathBuf;
use std::process::Stdio;

use tokio::io::AsyncWriteExt;
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
            .run_git_in_capture(
                &repo.to_string_lossy(),
                &["ls-tree", "--long", "-z", &spec],
            )
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
        if path.is_empty() {
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
            .run_git_in_capture(
                &repo.to_string_lossy(),
                &["log", &max, fmt, commit_oid],
            )
            .await
        {
            Ok(out) if out.status => out,
            _ => return Vec::new(),
        };
        parse_log(&String::from_utf8_lossy(&out.stdout))
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
            self.update_ref(&dir, &base_ref, &head_oid, &base_oid).await?;
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
            return Err("the branches have conflicting changes that must be resolved manually"
                .to_string());
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
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
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
