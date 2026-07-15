//! The SSO web surface: repo list/create, browse (tree/blob), commit history, branches.
//!
//! Mounted behind a Sluice `auth=sso` route: the gateway authenticates the user and injects
//! `X-Auth-Subject` / `X-Auth-Email`, which we trust (Loom is internal-only). The OWNER of a repo
//! is ALWAYS the subject header — never a client field. Private repos are hidden from non-owners
//! (a private repo a viewer cannot see returns 404, so existence does not leak). Every
//! producer-supplied string — repo name, description, file path, commit subject — is HTML-escaped
//! on render; a non-markdown text blob is shown in a line-numbered, escaped/highlighted monospace view.
//! Markdown (a `.md` blob + the repo README, plus issue bodies) is rendered through the estate's
//! sanitising [`crate::markdown`] pipeline: raw HTML is downgraded to text and unsafe link schemes
//! are defused, so no producer-supplied markup ever executes.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Form;
use serde::Deserialize;

use crate::auth::{self, Identity};
use crate::error::AppError;
use crate::gitops::{
    BlameLine, CodeSearchFile, CodeSearchResults, CommitInfo, GitOps, LanguageStat, TreeEntry,
    TreeLastCommits,
};
use crate::handlers::{esc, fmt_rel, fmt_ts, html_ok, html_with_csrf, page, redirect, short_oid};
use crate::model::{repo_role_rank, validate_owner_sub, validate_repo_name, Release, Repo};
use crate::{now_secs, random_alnum, AppState};

/// Length of a repo/issue/pat id (62-symbol alphabet).
const ID_LEN: usize = 16;
const FILE_HISTORY_PER_PAGE: usize = 50;
const CODE_SEARCH_RESULT_LIMIT: usize = 200;
const CODE_SEARCH_FILE_LIMIT: usize = 20;
const CODE_SEARCH_QUERY_MAX_CHARS: usize = 128;

// ===========================================================================
// GET / — repo list + create form
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct IndexQuery {
    #[serde(default)]
    pub q: String,
}

pub async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<IndexQuery>,
) -> Response {
    let who = auth::identity(&headers);
    let csrf = auth::new_csrf_token();
    let mut repos = state
        .store
        .list_visible_repos(&who.subject)
        .await
        .unwrap_or_default();
    let query = q.q.trim().to_string();
    if !query.is_empty() {
        repos.retain(|repo| repo_matches_query(repo, &query));
    }
    let rows = repo_rows(&state, repos).await;
    let body = render_index(&who, &rows, &query);
    html_with_csrf(
        StatusCode::OK,
        page("Repositories", Some(&who.email), who.theme, &body),
        &csrf,
    )
}

pub async fn new_page(State(_state): State<AppState>, headers: HeaderMap) -> Response {
    let who = auth::identity(&headers);
    let csrf = auth::new_csrf_token();
    let body = render_new(&csrf, None, "", "", "main", false);
    html_with_csrf(
        StatusCode::OK,
        page("Create repository", Some(&who.email), who.theme, &body),
        &csrf,
    )
}

#[derive(Debug, Deserialize)]
pub struct CreateForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub visibility: String,
    #[serde(default)]
    pub default_branch: String,
}

/// `POST /new` — create a repo (DB row + bare repo on disk), then 302 to the repo page.
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and submit again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    validate_owner_sub(&who.subject).map_err(|e| AppError::BadRequest(e.to_string()))?;

    let name = form.name.trim().to_string();
    if let Err(msg) = validate_repo_name(&name) {
        return Ok(render_new_error(&who, msg, &form).await);
    }
    let default_branch = normalize_branch(&form.default_branch);
    if let Err(msg) = validate_branch_name(&default_branch) {
        return Ok(render_new_error(&who, msg, &form).await);
    }
    let is_private = matches!(form.visibility.as_str(), "private");

    let repo = Repo {
        id: format!("rp_{}", random_alnum(ID_LEN)),
        owner_sub: who.subject.clone(),
        name: name.clone(),
        description: form.description.trim().chars().take(500).collect(),
        is_private,
        default_branch: default_branch.clone(),
        require_approval: false,
        required_approvals: 0,
        require_code_owner_reviews: false,
        protect_default_branch: false,
        forked_from_id: String::new(),
        created_at: now_secs(),
    };

    if !state.store.create_repo(&repo).await? {
        return Ok(
            render_new_error(&who, "You already have a repository with that name.", &form).await,
        );
    }

    // Create the bare repo on disk; on failure roll back the metadata row so the two stay in sync.
    if let Err(e) = state
        .git
        .init_bare(&who.subject, &name, &default_branch)
        .await
    {
        let _ = state.store.delete_repo(&repo.id).await;
        return Err(AppError::Internal(format!("git init failed: {e}")));
    }

    tracing::info!(owner = who.subject, repo = name, "repository created");
    Ok(redirect(&format!("/r/{}/{}", who.subject, name)))
}

// ===========================================================================
// GET /r/{owner}/{name} — code view (root tree + commits + branches)
// ===========================================================================

pub async fn view(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let csrf = auth::new_csrf_token();
    let fork_popover = render_fork_popover(&repo, &who, &csrf);
    let toolbar_actions = format!(
        "{}{}",
        crate::handlers::deploy::render_deploy_button(&repo, &csrf),
        fork_popover
    );
    let body = render_code_page(&state, &repo, "", &toolbar_actions).await?;
    Ok(html_with_csrf(
        StatusCode::OK,
        page(
            &format!("{}/{}", owner, name),
            Some(&who.email),
            who.theme,
            &body,
        ),
        &csrf,
    ))
}

#[derive(Debug, Deserialize)]
pub struct ForkForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub name: String,
}

pub async fn fork(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
    Form(form): Form<ForkForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and submit again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    validate_owner_sub(&who.subject).map_err(|e| AppError::BadRequest(e.to_string()))?;
    let source = load_visible_repo(&state, &who, &owner, &name).await?;
    let fork_name = if form.name.trim().is_empty() {
        source.name.clone()
    } else {
        form.name.trim().to_string()
    };
    validate_repo_name(&fork_name).map_err(|e| AppError::BadRequest(e.to_string()))?;

    let repo = Repo {
        id: format!("rp_{}", random_alnum(ID_LEN)),
        owner_sub: who.subject.clone(),
        name: fork_name.clone(),
        description: format!("Fork of {}/{}", source.owner_sub, source.name),
        is_private: source.is_private,
        default_branch: source.default_branch.clone(),
        require_approval: false,
        required_approvals: 0,
        require_code_owner_reviews: false,
        protect_default_branch: false,
        forked_from_id: source.id.clone(),
        created_at: now_secs(),
    };
    if !state.store.create_repo(&repo).await? {
        return Err(AppError::BadRequest(
            "You already have a repository with that name.".to_string(),
        ));
    }
    if let Err(e) = state
        .git
        .clone_bare(&source.owner_sub, &source.name, &who.subject, &fork_name)
        .await
    {
        let _ = state.store.delete_repo(&repo.id).await;
        state.git.remove_repo(&who.subject, &fork_name).await;
        return Err(AppError::Internal(format!("git clone --bare failed: {e}")));
    }
    tracing::info!(
        source_repo = source.id,
        fork_repo = repo.id,
        actor = who.subject,
        "repository forked"
    );
    Ok(redirect(&format!("/r/{}/{}", who.subject, fork_name)))
}

// ===========================================================================
// GET /r/{owner}/{name}/tree/{*path} — browse a subdirectory
// ===========================================================================

pub async fn tree(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, path)): Path<(String, String, String)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let (commit, path, pinned) = resolve_tree_target(&state, &repo, &path).await?;
    let body = render_code_page_at_commit(&state, &repo, &path, "", &commit, pinned).await?;
    Ok(html_ok(page(
        &format!("{}/{}", owner, name),
        Some(&who.email),
        who.theme,
        &body,
    )))
}

// ===========================================================================
// GET /r/{owner}/{name}/blob/{*path} — view a file
// ===========================================================================

pub async fn blob(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, path)): Path<(String, String, String)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let (commit, path, pinned) = resolve_blob_target(&state, &repo, &path).await?;
    let bytes = state
        .git
        .read_blob(&repo.owner_sub, &repo.name, &commit, &path)
        .await
        .ok_or_else(|| AppError::NotFound("No such file at this ref.".to_string()))?;

    let open_issues = state.store.open_issue_count(&repo.id).await.unwrap_or(0);
    let open_pulls = state.store.open_pull_count(&repo.id).await.unwrap_or(0);
    let release_count = state
        .store
        .release_count(&repo.id, false)
        .await
        .unwrap_or(0);
    let commit_prefix = pinned.then_some(commit.as_str());
    let tree = render_file_tree(&state.git, &repo, &commit, commit_prefix, &path, true).await;
    let body = render_blob(
        &repo,
        &state.config.public_base_url,
        open_issues,
        open_pulls,
        release_count,
        &commit,
        &path,
        &bytes,
        pinned,
        &tree,
    );
    Ok(html_ok(page(
        &format!("{}/{}", owner, name),
        Some(&who.email),
        who.theme,
        &body,
    )))
}

// ===========================================================================
// GET /r/{owner}/{name}/search?q=<query>&ref=<ref> — repository code search
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct CodeSearchQuery {
    #[serde(default)]
    pub q: String,
    #[serde(default, rename = "ref")]
    pub ref_name: String,
    #[serde(default)]
    pub i: Option<String>,
}

impl CodeSearchQuery {
    fn ignore_case(&self) -> bool {
        matches!(self.i.as_deref(), Some("1" | "true" | "on" | "yes"))
    }
}

pub async fn code_search(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
    Query(q): Query<CodeSearchQuery>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let header = header_with_counts(&state, &repo, "code").await;
    let query = q.q.trim().to_string();
    let ref_name = normalize_search_ref(&q.ref_name);
    let ignore_case = q.ignore_case();
    let mut results = None;
    let mut notice = None;

    if query.is_empty() {
        notice = Some("Enter a search term.".to_string());
    } else if query.chars().count() > CODE_SEARCH_QUERY_MAX_CHARS {
        notice = Some(format!(
            "Search terms are limited to {CODE_SEARCH_QUERY_MAX_CHARS} characters."
        ));
    } else {
        match resolve_blame_ref(&state, &repo, &ref_name).await {
            Some(commit) => {
                let found = state
                    .git
                    .code_search(
                        &repo.owner_sub,
                        &repo.name,
                        &commit,
                        &query,
                        ignore_case,
                        CODE_SEARCH_RESULT_LIMIT,
                        CODE_SEARCH_FILE_LIMIT,
                    )
                    .await
                    .map_err(|e| AppError::Internal(format!("git grep failed: {e}")))?;
                results = Some(found);
            }
            None => {
                notice = Some("No such ref in this repository.".to_string());
            }
        }
    }

    let body = render_code_search_page(
        &repo,
        &header,
        &query,
        &ref_name,
        ignore_case,
        results.as_ref(),
        notice.as_deref(),
    );
    Ok(html_ok(page(
        &format!("{owner}/{name} · Code search"),
        Some(&who.email),
        who.theme,
        &body,
    )))
}

// ===========================================================================
// GET /r/{owner}/{name}/blame/{ref}/{*path} — line-level blame for a file
// ===========================================================================

pub async fn blame(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, ref_name, path)): Path<(String, String, String, String)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let path = clean_blame_subpath(&path)?;
    let ref_name = ref_name.trim();
    if ref_name.is_empty() {
        return Err(AppError::BadRequest("Invalid ref.".to_string()));
    }

    let header = header_with_counts(&state, &repo, "code").await;
    let title = format!("{owner}/{name} · Blame");
    let Some(commit) = resolve_blame_ref(&state, &repo, ref_name).await else {
        let body = render_blame_notice(
            &repo,
            &header,
            ref_name,
            &path,
            "No such ref in this repository.",
        );
        return Ok(html_ok(page(&title, Some(&who.email), who.theme, &body)));
    };
    let Some(bytes) = state
        .git
        .read_blob(&repo.owner_sub, &repo.name, &commit, &path)
        .await
    else {
        let body =
            render_blame_notice(&repo, &header, ref_name, &path, "No such file at this ref.");
        return Ok(html_ok(page(&title, Some(&who.email), who.theme, &body)));
    };

    let body = if bytes.contains(&0) {
        render_blame_notice(
            &repo,
            &header,
            ref_name,
            &path,
            "Binary file blame is not shown.",
        )
    } else if bytes.len() > crate::config::MAX_BLOB_RENDER_BYTES {
        render_blame_notice(
            &repo,
            &header,
            ref_name,
            &path,
            &format!(
                "File is too large to blame inline ({}).",
                human_size(bytes.len() as i64)
            ),
        )
    } else {
        match state
            .git
            .blame(&repo.owner_sub, &repo.name, &commit, &path)
            .await
        {
            Some(lines) => render_blame(&repo, &header, ref_name, &path, &commit, &lines),
            None => render_blame_notice(
                &repo,
                &header,
                ref_name,
                &path,
                "Could not compute blame for this file.",
            ),
        }
    };

    Ok(html_ok(page(&title, Some(&who.email), who.theme, &body)))
}

// ===========================================================================
// GET /r/{owner}/{name}/history/{ref}/{*path} — single-file commit history
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct FileHistoryQuery {
    /// Keyset anchor: the OID of the last commit on the previous page.
    #[serde(default)]
    pub after: Option<String>,
}

pub async fn file_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, ref_name, path)): Path<(String, String, String, String)>,
    Query(q): Query<FileHistoryQuery>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let path = clean_blame_subpath(&path)?;
    let ref_name = ref_name.trim();
    if ref_name.is_empty() {
        return Err(AppError::BadRequest("Invalid ref.".to_string()));
    }

    let header = header_with_counts(&state, &repo, "code").await;
    let title = format!("{owner}/{name} · File history");
    if path.is_empty() {
        let body = render_file_history_notice(&repo, &header, ref_name, &path, "No file path.");
        return Ok(html_ok(page(&title, Some(&who.email), who.theme, &body)));
    }

    let Some(commit) = resolve_blame_ref(&state, &repo, ref_name).await else {
        let body = render_file_history_notice(
            &repo,
            &header,
            ref_name,
            &path,
            "No such ref in this repository.",
        );
        return Ok(html_ok(page(&title, Some(&who.email), who.theme, &body)));
    };

    let after = match q.after.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(a) => {
            if !is_hex_oid(a) {
                return Err(AppError::BadRequest("Invalid commit id.".to_string()));
            }
            Some(
                state
                    .git
                    .resolve_commit(&repo.owner_sub, &repo.name, a)
                    .await
                    .ok_or_else(|| AppError::NotFound("No such commit.".to_string()))?,
            )
        }
        None => None,
    };

    let paged = after.is_some();
    let start = after.as_deref().unwrap_or(&commit);
    let limit = FILE_HISTORY_PER_PAGE + if paged { 2 } else { 1 };
    let mut commits = state
        .git
        .file_log(&repo.owner_sub, &repo.name, start, &path, limit)
        .await;
    if let Some(anchor) = after.as_deref() {
        if commits.first().map(|c| c.oid.as_str()) == Some(anchor) {
            commits.remove(0);
        }
    }
    let has_next = commits.len() > FILE_HISTORY_PER_PAGE;
    commits.truncate(FILE_HISTORY_PER_PAGE);

    let body = format!(
        "{header}{history}",
        history = render_file_history(&repo, ref_name, &path, &commits, paged, has_next),
    );
    Ok(html_ok(page(&title, Some(&who.email), who.theme, &body)))
}

// ===========================================================================
// Shared loaders
// ===========================================================================

/// Load a repo visible to `who`: a private repo owned by someone else returns 404 (no leak).
pub async fn load_visible_repo(
    state: &AppState,
    who: &Identity,
    owner: &str,
    name: &str,
) -> Result<Repo, AppError> {
    if let Some(repo) = state.store.get_repo(owner, name).await? {
        let collaborator = state
            .store
            .repo_collaborator_role(&repo.id, &who.subject)
            .await?
            .is_some();
        if !repo.is_private || repo.owner_sub == who.subject || collaborator {
            return Ok(repo);
        }
    }
    Err(AppError::NotFound(
        "No repository exists at that path.".to_string(),
    ))
}

pub(crate) async fn repo_access_rank(
    state: &AppState,
    repo: &Repo,
    subject: &str,
) -> Result<i64, AppError> {
    if repo.owner_sub == subject {
        return Ok(repo_role_rank("admin"));
    }
    Ok(state
        .store
        .repo_collaborator_role(&repo.id, subject)
        .await?
        .as_deref()
        .map(repo_role_rank)
        .unwrap_or(0))
}

pub(crate) async fn can_write_repo(
    state: &AppState,
    repo: &Repo,
    who: &Identity,
    headers: &HeaderMap,
) -> Result<bool, AppError> {
    Ok(
        repo_access_rank(state, repo, &who.subject).await? >= repo_role_rank("write")
            || auth::is_admin(headers),
    )
}

pub(crate) async fn can_admin_repo(
    state: &AppState,
    repo: &Repo,
    who: &Identity,
    headers: &HeaderMap,
) -> Result<bool, AppError> {
    Ok(
        repo_access_rank(state, repo, &who.subject).await? >= repo_role_rank("admin")
            || auth::is_admin(headers),
    )
}

/// Render the repo header for the `active` tab, fetching the open issue/PR badge counts (the
/// shared entry point for the commits/branches/settings pages).
pub(crate) async fn header_with_counts(state: &AppState, repo: &Repo, active: &str) -> String {
    header_with_counts_for(state, repo, active, false).await
}

pub(crate) async fn header_with_counts_for(
    state: &AppState,
    repo: &Repo,
    active: &str,
    include_drafts: bool,
) -> String {
    let open_issues = state.store.open_issue_count(&repo.id).await.unwrap_or(0);
    let open_pulls = state.store.open_pull_count(&repo.id).await.unwrap_or(0);
    let release_count = state
        .store
        .release_count(&repo.id, include_drafts)
        .await
        .unwrap_or(0);
    let parent = fork_parent(state, repo).await;
    render_repo_header_with_parent(
        repo,
        &state.config.public_base_url,
        open_issues,
        open_pulls,
        release_count,
        active,
        parent.as_ref(),
    )
}

pub(crate) async fn fork_parent(state: &AppState, repo: &Repo) -> Option<Repo> {
    if repo.forked_from_id.is_empty() {
        return None;
    }
    state
        .store
        .get_repo_by_id(&repo.forked_from_id)
        .await
        .ok()
        .flatten()
}

/// Reject a browse subpath that could escape the tree, then normalize it (no leading/trailing `/`).
fn clean_subpath(path: &str) -> Result<String, AppError> {
    let trimmed = path.trim_matches('/');
    for seg in trimmed.split('/') {
        if seg == ".." || seg == "." {
            return Err(AppError::BadRequest("Invalid path.".to_string()));
        }
    }
    Ok(trimmed.to_string())
}

fn clean_blame_subpath(path: &str) -> Result<String, AppError> {
    if path.starts_with('/') {
        return Err(AppError::BadRequest("Invalid path.".to_string()));
    }
    clean_subpath(path)
}

async fn resolve_blob_target(
    state: &AppState,
    repo: &Repo,
    raw_path: &str,
) -> Result<(String, String, bool), AppError> {
    let clean = clean_subpath(raw_path)?;
    if let Some((maybe_oid, rest)) = clean.split_once('/') {
        if is_full_oid(maybe_oid) {
            let path = clean_subpath(rest)?;
            let commit = state
                .git
                .resolve_commit(&repo.owner_sub, &repo.name, maybe_oid)
                .await
                .ok_or_else(|| AppError::NotFound("No such commit.".to_string()))?;
            return Ok((commit, path, true));
        }
    }

    let commit = state
        .git
        .head_commit(&repo.owner_sub, &repo.name)
        .await
        .ok_or_else(|| AppError::NotFound("This repository has no commits yet.".to_string()))?;
    Ok((commit, clean, false))
}

async fn resolve_tree_target(
    state: &AppState,
    repo: &Repo,
    raw_path: &str,
) -> Result<(String, String, bool), AppError> {
    let clean = clean_subpath(raw_path)?;
    if is_full_oid(&clean) {
        let commit = state
            .git
            .resolve_commit(&repo.owner_sub, &repo.name, &clean)
            .await
            .ok_or_else(|| AppError::NotFound("No such commit.".to_string()))?;
        return Ok((commit, String::new(), true));
    }
    if let Some((maybe_oid, rest)) = clean.split_once('/') {
        if is_full_oid(maybe_oid) {
            let subpath = clean_subpath(rest)?;
            let commit = state
                .git
                .resolve_commit(&repo.owner_sub, &repo.name, maybe_oid)
                .await
                .ok_or_else(|| AppError::NotFound("No such commit.".to_string()))?;
            return Ok((commit, subpath, true));
        }
    }

    let commit = state
        .git
        .head_commit(&repo.owner_sub, &repo.name)
        .await
        .ok_or_else(|| AppError::NotFound("This repository has no commits yet.".to_string()))?;
    Ok((commit, clean, false))
}

fn normalize_search_ref(ref_name: &str) -> String {
    let trimmed = ref_name.trim();
    if trimmed.is_empty() {
        "HEAD".to_string()
    } else {
        trimmed.to_string()
    }
}

async fn resolve_blame_ref(state: &AppState, repo: &Repo, ref_name: &str) -> Option<String> {
    if ref_name == "HEAD" {
        return state.git.head_commit(&repo.owner_sub, &repo.name).await;
    }
    if is_hex_oid(ref_name) {
        if let Some(oid) = state
            .git
            .resolve_commit(&repo.owner_sub, &repo.name, ref_name)
            .await
        {
            return Some(oid);
        }
    }
    let branches = state.git.branches(&repo.owner_sub, &repo.name).await;
    if branches.iter().any(|b| b == ref_name) {
        state
            .git
            .branch_oid(&repo.owner_sub, &repo.name, ref_name)
            .await
    } else {
        None
    }
}

fn is_hex_oid(s: &str) -> bool {
    (4..=64).contains(&s.len()) && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_full_oid(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

// ===========================================================================
// Rendering
// ===========================================================================

struct RepoRow {
    repo: Repo,
    head_time: Option<i64>,
    language: Option<LanguageStat>,
}

impl RepoRow {
    fn sort_time(&self) -> i64 {
        self.head_time.unwrap_or(self.repo.created_at)
    }
}

fn repo_matches_query(repo: &Repo, query: &str) -> bool {
    let needle = query.to_lowercase();
    repo.owner_sub.to_lowercase().contains(&needle)
        || repo.name.to_lowercase().contains(&needle)
        || repo.description.to_lowercase().contains(&needle)
}

async fn repo_rows(state: &AppState, repos: Vec<Repo>) -> Vec<RepoRow> {
    let mut rows = Vec::with_capacity(repos.len());
    for (idx, repo) in repos.into_iter().enumerate() {
        let (head_time, language) = if idx < 50 {
            (
                state
                    .git
                    .head_commit_time(&repo.owner_sub, &repo.name)
                    .await,
                state
                    .git
                    .dominant_language(&repo.owner_sub, &repo.name)
                    .await,
            )
        } else {
            (None, None)
        };
        rows.push(RepoRow {
            repo,
            head_time,
            language,
        });
    }

    let head_len = rows.len().min(50);
    rows[..head_len].sort_by(|a, b| {
        b.sort_time()
            .cmp(&a.sort_time())
            .then_with(|| b.repo.created_at.cmp(&a.repo.created_at))
            .then_with(|| b.repo.id.cmp(&a.repo.id))
    });
    rows
}

fn render_index(who: &Identity, rows: &[RepoRow], q: &str) -> String {
    let now = now_secs();
    let list = if rows.is_empty() {
        let title = if q.trim().is_empty() {
            "No repositories yet".to_string()
        } else {
            format!("No repositories matched &ldquo;{}&rdquo;", esc(q))
        };
        let cta = if !q.trim().is_empty() {
            ""
        } else if who.is_authenticated() {
            "<a class=\"btn btn-primary\" href=\"/new\">New repository</a>"
        } else {
            "<a class=\"btn btn-primary\" href=\"/signin\">Sign in</a>"
        };
        let text = if q.trim().is_empty() {
            "Create your first repository to get started."
        } else {
            "Try a different repository filter."
        };
        format!(
            r##"<div class="repo-rows__empty"><div class="empty"><svg class="empty__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg><div class="empty__title">{title}</div><p class="empty__text">{text}</p>{cta}</div></div>"##,
            title = title,
            text = text,
            cta = cta,
        )
    } else {
        let items = rows
            .iter()
            .map(|row| {
                let r = &row.repo;
                let chip = if r.is_private {
                    "<span class=\"vis-chip vis-chip--private\">Private</span>"
                } else {
                    "<span class=\"vis-chip\">Public</span>"
                };
                let desc = if r.description.trim().is_empty() {
                    "<p class=\"repo-card__desc repo-card__desc--empty\">No description</p>".to_string()
                } else {
                    format!("<p class=\"repo-card__desc\">{}</p>", esc(&r.description))
                };
                let lang = row
                    .language
                    .map(|language| {
                        format!(
                            "<span class=\"repo-card__lang\"><span class=\"lang-dot\" style=\"--lang-color:#{color}\" aria-hidden=\"true\"></span>{name}</span>",
                            color = language.color,
                            name = esc(language.name),
                        )
                    })
                    .unwrap_or_default();
                let (time_label, time_abs, time_rel) = match row.head_time {
                    Some(t) => ("Updated", fmt_ts(t), fmt_rel(now, t)),
                    None => ("Created", fmt_ts(r.created_at), fmt_rel(now, r.created_at)),
                };
                format!(
                    r##"<li class="repo-card"><a class="repo-card__link" href="/r/{owner}/{name}">
  <div class="repo-card__head">
    <span class="repo-card__glyph" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg></span>
    <span class="repo-card__name">{owner_e}/<b>{name_e}</b></span>
    {chip}
  </div>
  {desc}
  <div class="repo-card__meta">{lang}<span title="{time_abs}">{time_label} {time_rel}</span></div>
</a></li>"##,
                    owner = esc(&r.owner_sub),
                    name = esc(&r.name),
                    owner_e = esc(&r.owner_sub),
                    name_e = esc(&r.name),
                    chip = chip,
                    desc = desc,
                    lang = lang,
                    time_abs = esc(&time_abs),
                    time_label = time_label,
                    time_rel = esc(&time_rel),
                )
            })
            .collect::<String>();
        format!("<ul class=\"repo-grid\">{items}</ul>")
    };

    // The full branded hero is the landing masthead; a search collapses it to a compact head so
    // results dominate. Stats reflect the unfiltered estate (rows == everything when q is empty).
    let head = if q.trim().is_empty() {
        let repo_count = rows.len();
        let mut langs: Vec<&str> = rows
            .iter()
            .filter_map(|r| r.language.map(|l| l.name))
            .collect();
        langs.sort_unstable();
        langs.dedup();
        let lang_count = langs.len();
        let repo_label = if repo_count == 1 {
            "Repository"
        } else {
            "Repositories"
        };
        let lang_label = if lang_count == 1 {
            "Language"
        } else {
            "Languages"
        };
        let actions = if who.is_authenticated() {
            r##"<a class="btn btn-primary" href="/new">New repository</a>
      <a class="btn" href="/pats">Access tokens</a>"##
        } else {
            r##"<a class="btn btn-primary" href="/signin">Sign in</a>"##
        };
        format!(
            r##"<section class="home-hero">
  <div class="home-hero__body">
    <p class="eyebrow">Steadholme · SOVEREIGN ESTATE</p>
    <h1 class="home-hero__title">Built in the open.</h1>
    <p class="home-hero__lede">A sovereign, self-hosted estate — identity, mail, git, registry, search, AI and dozens more services, engineered from the ground up. Every service, open source. Clone any repository over HTTPS.</p>
    <div class="home-hero__actions">
      {actions}
    </div>
  </div>
  <dl class="home-stats" aria-label="Estate at a glance">
    <div class="home-stat"><dt>{repo_label}</dt><dd>{repo_count}</dd></div>
    <div class="home-stat"><dt>{lang_label}</dt><dd>{lang_count}</dd></div>
    <div class="home-stat"><dt>License</dt><dd class="home-stat__word">Open</dd></div>
  </dl>
</section>"##,
            repo_count = repo_count,
            repo_label = repo_label,
            lang_count = lang_count,
            lang_label = lang_label,
            actions = actions,
        )
    } else {
        let action = if who.is_authenticated() {
            r##"<a class="btn btn-primary" href="/new">New repository</a>"##
        } else {
            r##"<a class="btn btn-primary" href="/signin">Sign in</a>"##
        };
        format!(
            r##"<div class="console__head console__head--row">
  <div><p class="eyebrow">Steadholme · SOVEREIGN ESTATE</p><h1>Repositories</h1></div>
  {action}
</div>"##,
            action = action,
        )
    };

    format!(
        r##"{head}
<form class="repo-filter" method="get" action="/">
  <input class="input repo-filter__q" type="search" name="q" value="{q}" placeholder="Find a repository&hellip;" aria-label="Filter repositories">
</form>
{list}"##,
        head = head,
        q = esc(q),
        list = list,
    )
}

fn render_new(
    csrf: &str,
    error: Option<&str>,
    name: &str,
    description: &str,
    default_branch: &str,
    private: bool,
) -> String {
    let error_block = error
        .map(|msg| {
            format!(
                "<div class=\"alert alert-danger\" role=\"alert\">{}</div>",
                esc(msg)
            )
        })
        .unwrap_or_default();
    let checked = if private { " checked" } else { "" };
    format!(
        r##"<div class="console__head"><h1>Create a new repository</h1><p class="sub">A repository contains your project's files and history.</p></div>
{error_block}
<form class="new-repo-form" method="post" action="/new">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <div class="form-section">
    <div class="field"><label class="label" for="nr-name">Repository name</label><input class="input" type="text" id="nr-name" name="name" maxlength="64" autocomplete="off" spellcheck="false" required value="{name}"></div>
    <div class="field"><label class="label" for="nr-desc">Description <span class="hint--muted">(optional)</span></label><input class="input" type="text" id="nr-desc" name="description" maxlength="500" value="{description}"></div>
  </div>
  <div class="form-section">
    <div class="field"><label class="label" for="nr-branch">Default branch</label><input class="input" type="text" id="nr-branch" name="default_branch" maxlength="64" autocomplete="off" spellcheck="false" value="{default_branch}"></div>
    <div class="field field--check"><label class="check"><input type="checkbox" name="visibility" value="private"{checked}> Private repository</label></div>
  </div>
  <div class="actions"><button class="btn btn-primary" type="submit">Create repository</button></div>
</form>"##,
        error_block = error_block,
        csrf = esc(csrf),
        name = esc(name),
        description = esc(description),
        default_branch = esc(default_branch),
        checked = checked,
    )
}

fn render_fork_popover(repo: &Repo, who: &Identity, csrf: &str) -> String {
    let default_name = if repo.owner_sub == who.subject {
        format!("{}-fork", repo.name)
    } else {
        repo.name.clone()
    };
    format!(
        r##"<details class="popbtn popbtn--fork">
  <summary class="btn btn-ghost btn-sm"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><circle cx="18" cy="6" r="3"/><path d="M18 9v1a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V9"/><path d="M12 12v3"/></svg>Fork</summary>
  <div class="popbtn__pop">
    <form method="post" action="/r/{owner}/{name}/fork">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <div class="field">
        <label for="fork-name">Repository name</label>
        <input type="text" id="fork-name" name="name" maxlength="64" value="{default_name}" autocomplete="off" spellcheck="false" required>
      </div>
      <div class="actions">
        <button class="btn btn-primary btn-sm" type="submit">Fork repository</button>
      </div>
    </form>
  </div>
</details>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        csrf = esc(csrf),
        default_name = esc(&default_name),
    )
}

/// Re-render the create page with an inline error + a fresh CSRF token.
async fn render_new_error(who: &Identity, msg: &str, form: &CreateForm) -> Response {
    let csrf = auth::new_csrf_token();
    let branch = if form.default_branch.trim().is_empty() {
        "main"
    } else {
        form.default_branch.trim()
    };
    let body = render_new(
        &csrf,
        Some(msg),
        form.name.trim(),
        form.description.trim(),
        branch,
        matches!(form.visibility.as_str(), "private"),
    );
    html_with_csrf(
        StatusCode::BAD_REQUEST,
        page("Create repository", Some(&who.email), who.theme, &body),
        &csrf,
    )
}

/// Render the code page: repo header + code toolbar + file browser at `subpath`.
async fn render_code_page(
    state: &AppState,
    repo: &Repo,
    subpath: &str,
    fork_popover: &str,
) -> Result<String, AppError> {
    let commit = state.git.head_commit(&repo.owner_sub, &repo.name).await;
    let Some(commit) = commit else {
        let open_issues = state.store.open_issue_count(&repo.id).await.unwrap_or(0);
        let open_pulls = state.store.open_pull_count(&repo.id).await.unwrap_or(0);
        let release_count = state
            .store
            .release_count(&repo.id, false)
            .await
            .unwrap_or(0);
        let parent = fork_parent(state, repo).await;
        let header = render_repo_header_with_parent(
            repo,
            &state.config.public_base_url,
            open_issues,
            open_pulls,
            release_count,
            "code",
            parent.as_ref(),
        );
        let toolbar = render_code_toolbar(repo, &state.config.public_base_url, None, fork_popover);
        let push = render_empty_repo(repo, &state.config.public_base_url);
        return Ok(format!("{header}{toolbar}{push}"));
    };
    render_code_page_at_commit(state, repo, subpath, fork_popover, &commit, false).await
}

async fn render_code_page_at_commit(
    state: &AppState,
    repo: &Repo,
    subpath: &str,
    fork_popover: &str,
    commit: &str,
    pinned: bool,
) -> Result<String, AppError> {
    let open_issues = state.store.open_issue_count(&repo.id).await.unwrap_or(0);
    let open_pulls = state.store.open_pull_count(&repo.id).await.unwrap_or(0);
    let release_count = state
        .store
        .release_count(&repo.id, false)
        .await
        .unwrap_or(0);
    let parent = fork_parent(state, repo).await;
    let header = render_repo_header_with_parent(
        repo,
        &state.config.public_base_url,
        open_issues,
        open_pulls,
        release_count,
        "code",
        parent.as_ref(),
    );

    let branch_names = state.git.branches(&repo.owner_sub, &repo.name).await;
    let toolbar = if pinned {
        render_code_toolbar_at_commit(repo, commit)
    } else {
        render_code_toolbar(
            repo,
            &state.config.public_base_url,
            Some(branch_names.len()),
            fork_popover,
        )
    };
    let entries = state
        .git
        .list_tree(&repo.owner_sub, &repo.name, commit, subpath)
        .await;
    if !subpath.is_empty() && entries.is_empty() {
        return Err(AppError::NotFound("No such directory.".to_string()));
    }

    let entry_names: Vec<String> = entries.iter().map(|entry| entry.name.clone()).collect();
    let last = state
        .git
        .tree_last_commits(&repo.owner_sub, &repo.name, commit, subpath, &entry_names)
        .await;
    let now = now_secs();
    let commit_prefix = pinned.then_some(commit);
    let files = render_file_browser(repo, subpath, &entries, &last, now, commit_prefix);

    // A rendered README under the file browser at the repo root (GitHub-style), sanitised.
    let readme = if subpath.is_empty() {
        render_readme(state, repo, commit, &entries).await
    } else {
        String::new()
    };
    let latest_release = if subpath.is_empty() {
        render_latest_release(state, repo).await
    } else {
        String::new()
    };

    let content = if subpath.is_empty() && !latest_release.is_empty() {
        format!(
            r##"<div class="repo-layout">
  <div class="repo-layout__main">{files}{readme}</div>
  <aside class="side">{latest_release}</aside>
</div>"##
        )
    } else {
        format!("{files}{readme}")
    };

    let tree = render_file_tree(&state.git, repo, commit, commit_prefix, subpath, false).await;
    Ok(format!(
        "{header}<div class=\"ft-layout\"><aside class=\"ft-side\">{tree}</aside><div class=\"ft-main\">{toolbar}{content}</div></div>"
    ))
}

fn render_code_toolbar(
    repo: &Repo,
    base_url: &str,
    branch_count: Option<usize>,
    fork_popover: &str,
) -> String {
    let clone_url = format!(
        "{}/git/{}/{}.git",
        base_url.trim_end_matches('/'),
        repo.owner_sub,
        repo.name
    );
    let primary = if let Some(n_branches) = branch_count {
        format!(
            r##"<a class="branchbtn" href="/r/{owner}/{name}/branches">
    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="6" y1="3" x2="6" y2="15"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 9a9 9 0 0 1-9 9"/></svg><span class="branchbtn__name">{branch}</span><span class="branchbtn__count">{n_branches}</span>
  </a>
  <a class="code-toolbar__link" href="/r/{owner}/{name}/commits"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>Commits</a>
  <span class="code-toolbar__spacer"></span>
  <form class="code-toolbar__search" action="/r/{owner}/{name}/search" method="get" role="search">
    <input class="code-toolbar__q" type="search" name="q" placeholder="Search code" aria-label="Search code">
    <input type="hidden" name="ref" value="HEAD">
  </form>"##,
            owner = esc(&repo.owner_sub),
            name = esc(&repo.name),
            branch = esc(&repo.default_branch),
            n_branches = n_branches,
        )
    } else {
        r#"<span class="code-toolbar__spacer"></span>"#.to_string()
    };
    format!(
        r##"<div class="code-toolbar">
  {primary}
  <details class="popbtn popbtn--clone">
    <summary class="btn btn-primary btn-sm">Code<svg class="popbtn__caret" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="6 9 12 15 18 9"/></svg></summary>
    <div class="popbtn__pop">
      <div class="popbtn__label">Clone over HTTPS</div>
      <div class="clone-row">
        <input class="clone-row__url" type="text" readonly value="{clone_url}" onclick="this.select()">
        <button class="btn btn-ghost btn-sm" type="button" data-copy="{clone_url}">Copy</button>
      </div>
      <p class="popbtn__hint">Authenticate with a <a href="/pats">personal access token</a>.</p>
    </div>
  </details>
  {fork_popover}
</div>"##,
        primary = primary,
        clone_url = esc(&clone_url),
        fork_popover = fork_popover,
    )
}

fn render_code_toolbar_at_commit(repo: &Repo, commit: &str) -> String {
    format!(
        r##"<div class="code-toolbar code-toolbar--pinned">
  <a class="branchbtn" href="/r/{owner}/{name}/commit/{commit}">
    <svg viewBox="0 0 16 16" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M1.75 3.5a.75.75 0 0 0 0 1.5h8.69L7.22 8.22a.75.75 0 1 0 1.06 1.06l4.5-4.5a.75.75 0 0 0 0-1.06l-4.5-4.5a.75.75 0 0 0-1.06 1.06L10.44 3.5H1.75Zm12.5 7.5H5.56l3.22-3.22a.75.75 0 1 0-1.06-1.06l-4.5 4.5a.75.75 0 0 0 0 1.06l4.5 4.5a.75.75 0 1 0 1.06-1.06L5.56 12.5h8.69a.75.75 0 0 0 0-1.5Z"/></svg><span class="branchbtn__name">{short}</span>
  </a>
  <a class="code-toolbar__link" href="/r/{owner}/{name}/commits"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>Commits</a>
  <span class="code-toolbar__spacer"></span>
  <form class="code-toolbar__search" action="/r/{owner}/{name}/search" method="get" role="search">
    <input class="code-toolbar__q" type="search" name="q" placeholder="Search code" aria-label="Search code">
    <input type="hidden" name="ref" value="{commit}">
  </form>
</div>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        commit = esc(commit),
        short = esc(&short_oid(commit)),
    )
}

/// Render a repo-root README as sanitised markdown HTML (GitHub-style), or nothing when there is
/// no README blob (or it is binary / too large to render). The README name is HTML-escaped; the
/// body is rendered through [`crate::markdown::render`], which strips raw HTML and unsafe links.
async fn render_readme(
    state: &AppState,
    repo: &Repo,
    commit: &str,
    entries: &[TreeEntry],
) -> String {
    let Some(entry) = entries.iter().find(|e| !e.is_dir() && is_readme(&e.name)) else {
        return String::new();
    };
    let Some(bytes) = state
        .git
        .read_blob(&repo.owner_sub, &repo.name, commit, &entry.name)
        .await
    else {
        return String::new();
    };
    if bytes.contains(&0) || bytes.len() > crate::config::MAX_BLOB_RENDER_BYTES {
        return String::new();
    }
    let text = String::from_utf8_lossy(&bytes);
    format!(
        r##"<section class="card">
  <div class="card__head card__head--file"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg><span>{name}</span></div>
  <div class="card__body markdown-body">{html}</div>
</section>"##,
        name = esc(&entry.name),
        html = crate::markdown::render_for_repo(&text, &repo.owner_sub, &repo.name),
    )
}

async fn render_latest_release(state: &AppState, repo: &Repo) -> String {
    let releases = state
        .store
        .list_releases_by_repo(&repo.id)
        .await
        .unwrap_or_default();
    let Some(release) = releases.into_iter().find(|r| !r.is_draft) else {
        return String::new();
    };
    render_latest_release_card(repo, &release)
}

fn render_latest_release_card(repo: &Repo, release: &Release) -> String {
    let prerelease = if release.is_prerelease {
        "<span class=\"state-badge release-badge release-badge--prerelease\">Pre-release</span>"
    } else {
        ""
    };
    let now = now_secs();
    format!(
        r##"<section class="side__block">
  <h3 class="side__label">Latest release</h3>
  <div class="side-release">
    <a class="side-release__title" href="/r/{owner}/{name}/releases/tag/{tag}">{title}</a>
    <div class="side-release__meta"><span class="release-tag">{tag}</span>{prerelease}</div>
    <span class="side-release__age" title="{published_abs}">{published_rel}</span>
    <span class="side-release__assets">0 assets</span>
  </div>
  <a class="side__more" href="/r/{owner}/{name}/releases">All releases</a>
</section>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        tag = esc(&release.tag_name),
        title = esc(&release.title),
        published_abs = esc(&fmt_ts(release.published_at)),
        published_rel = esc(&fmt_rel(now, release.published_at)),
        prerelease = prerelease,
    )
}

/// Repo header: owner/name lockup, visibility badge, clone box, tab strip.
pub(crate) fn render_repo_header(
    repo: &Repo,
    base_url: &str,
    open_issues: i64,
    open_pulls: i64,
    release_count: i64,
    active: &str,
) -> String {
    render_repo_header_with_parent(
        repo,
        base_url,
        open_issues,
        open_pulls,
        release_count,
        active,
        None,
    )
}

pub(crate) fn render_repo_header_with_parent(
    repo: &Repo,
    _base_url: &str,
    open_issues: i64,
    open_pulls: i64,
    release_count: i64,
    active: &str,
    forked_from: Option<&Repo>,
) -> String {
    let badge = if repo.is_private {
        "<span class=\"vis-badge vis-badge--private\">Private</span>"
    } else {
        "<span class=\"vis-badge\">Public</span>"
    };
    let desc = if repo.description.trim().is_empty() {
        String::new()
    } else {
        format!("<p class=\"repohead__desc\">{}</p>", esc(&repo.description))
    };
    let fork_line = forked_from
        .map(|parent| {
            format!(
                "<p class=\"repohead__desc repohead__desc--fork\">Forked from <a href=\"/r/{owner}/{name}\">{owner}/{name}</a></p>",
                owner = esc(&parent.owner_sub),
                name = esc(&parent.name),
            )
        })
        .unwrap_or_default();
    let tab = |is_active: bool| {
        if is_active {
            (
                " tab--active",
                " aria-current=\"page\"",
                "<span class=\"tab__ind\" aria-hidden=\"true\"></span>",
            )
        } else {
            ("", "", "")
        }
    };
    let (code_active, code_current, code_ind) =
        tab(matches!(active, "code" | "commits" | "branches"));
    let (issues_active, issues_current, issues_ind) = tab(active == "issues");
    let (pulls_active, pulls_current, pulls_ind) = tab(active == "pulls");
    let (releases_active, releases_current, releases_ind) = tab(active == "releases");
    let (settings_active, settings_current, settings_ind) = tab(active == "settings");
    format!(
        r##"<header class="repohead">
  <div class="repohead__row">
    <svg class="repohead__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>
    <h1 class="repohead__title"><a class="repohead__owner" href="/">{owner}</a><span class="repohead__sep">/</span><a class="repohead__name" href="/r/{owner}/{name}">{name}</a></h1>
    {badge}
  </div>
  {desc}
  {fork_line}
</header>
<nav class="tabs" aria-label="Repository sections">
  <a class="tab{code_active}"{code_current} href="/r/{owner}/{name}">Code{code_ind}</a>
  <a class="tab{issues_active}"{issues_current} href="/r/{owner}/{name}/issues">Issues <span class="tab__count">{open_issues}</span>{issues_ind}</a>
  <a class="tab{pulls_active}"{pulls_current} href="/r/{owner}/{name}/pulls">Pull requests <span class="tab__count">{open_pulls}</span>{pulls_ind}</a>
  <a class="tab{releases_active}"{releases_current} href="/r/{owner}/{name}/releases">Releases <span class="tab__count">{release_count}</span>{releases_ind}</a>
  <a class="tab{settings_active}"{settings_current} href="/r/{owner}/{name}/settings">Settings{settings_ind}</a>
</nav>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        badge = badge,
        desc = desc,
        fork_line = fork_line,
        code_active = code_active,
        code_current = code_current,
        code_ind = code_ind,
        releases_active = releases_active,
        releases_current = releases_current,
        releases_ind = releases_ind,
        pulls_active = pulls_active,
        pulls_current = pulls_current,
        pulls_ind = pulls_ind,
        issues_active = issues_active,
        issues_current = issues_current,
        issues_ind = issues_ind,
        settings_active = settings_active,
        settings_current = settings_current,
        settings_ind = settings_ind,
        open_issues = open_issues,
        open_pulls = open_pulls,
        release_count = release_count,
    )
}

fn render_code_search_form(repo: &Repo, query: &str, ref_name: &str, ignore_case: bool) -> String {
    let checked = if ignore_case { " checked" } else { "" };
    format!(
        r##"<section class="card code-search">
  <div class="card__body">
    <form class="code-search__form" action="/r/{owner}/{name}/search" method="get" role="search">
      <input class="code-search__input" type="search" name="q" value="{query}" placeholder="Search code">
      <input class="code-search__ref" type="text" name="ref" value="{ref_name}" aria-label="Git ref">
      <label class="code-search__case"><input type="checkbox" name="i" value="1"{checked}> Ignore case</label>
      <button class="btn btn-sm" type="submit">Search</button>
    </form>
  </div>
</section>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        query = esc(query),
        ref_name = esc(ref_name),
        checked = checked,
    )
}

fn render_code_search_page(
    repo: &Repo,
    header: &str,
    query: &str,
    ref_name: &str,
    ignore_case: bool,
    results: Option<&CodeSearchResults>,
    notice: Option<&str>,
) -> String {
    let form = render_code_search_form(repo, query, ref_name, ignore_case);
    let body = if let Some(message) = notice {
        format!("<p class=\"muted code-search__empty\">{}</p>", esc(message))
    } else if let Some(results) = results {
        render_code_search_results(repo, query, ignore_case, results)
    } else {
        String::new()
    };

    format!(
        r##"{header}{form}
<section class="card code-search__results">
  <div class="card__head"><h2>Code search</h2><span class="muted">Ref {ref_name}</span></div>
  <div class="card__body">{body}</div>
</section>"##,
        header = header,
        form = form,
        ref_name = esc(ref_name),
        body = body,
    )
}

fn render_code_search_results(
    repo: &Repo,
    query: &str,
    ignore_case: bool,
    results: &CodeSearchResults,
) -> String {
    if results.total_hits == 0 {
        return "<p class=\"muted code-search__empty\">No code results found.</p>".to_string();
    }

    let mut html = format!(
        "<p class=\"muted code-search__summary\">{} result{} in {} file{}.</p>",
        results.total_hits,
        if results.total_hits == 1 { "" } else { "s" },
        results.files.len(),
        if results.files.len() == 1 { "" } else { "s" },
    );
    if results.limited {
        html.push_str(&format!(
            "<p class=\"muted code-search__limit\">Showing the first {CODE_SEARCH_RESULT_LIMIT} results.</p>"
        ));
    }
    if results.per_file_limited {
        html.push_str(&format!(
            "<p class=\"muted code-search__limit\">Showing up to {CODE_SEARCH_FILE_LIMIT} matches per file.</p>"
        ));
    }
    for file in &results.files {
        html.push_str(&render_code_search_file(repo, file, query, ignore_case));
    }
    html
}

fn render_code_search_file(
    repo: &Repo,
    file: &CodeSearchFile,
    query: &str,
    ignore_case: bool,
) -> String {
    let blob_href = format!("/r/{}/{}/blob/{}", repo.owner_sub, repo.name, file.path);
    let hits = file
        .hits
        .iter()
        .map(|hit| {
            let line_href = format!("{blob_href}#L{}", hit.line);
            format!(
                "<li class=\"code-search__hit\">\
                   <a class=\"code-search__line\" href=\"{href}\">L{line}</a>\
                   <code class=\"code-search__code\">{code}</code>\
                 </li>",
                href = esc(&line_href),
                line = hit.line,
                code = highlight_code_search_hit(&hit.content, query, ignore_case),
            )
        })
        .collect::<String>();

    format!(
        "<div class=\"code-search__file\">\
           <h3><a href=\"{href}\">{path}</a></h3>\
           <ol class=\"code-search__hits\">{hits}</ol>\
         </div>",
        href = esc(&blob_href),
        path = esc(&file.path),
        hits = hits,
    )
}

fn highlight_code_search_hit(content: &str, query: &str, ignore_case: bool) -> String {
    let escaped_content = esc(content);
    let escaped_query = esc(query);
    if escaped_query.is_empty() {
        return escaped_content;
    }

    let haystack = if ignore_case {
        escaped_content.to_ascii_lowercase()
    } else {
        escaped_content.clone()
    };
    let needle = if ignore_case {
        escaped_query.to_ascii_lowercase()
    } else {
        escaped_query
    };
    let mut out = String::with_capacity(escaped_content.len());
    let mut tail = 0usize;
    while let Some(rel) = haystack[tail..].find(&needle) {
        let start = tail + rel;
        let end = start + needle.len();
        out.push_str(&escaped_content[tail..start]);
        out.push_str("<mark class=\"code-search-hit\">");
        out.push_str(&escaped_content[start..end]);
        out.push_str("</mark>");
        tail = end;
    }
    out.push_str(&escaped_content[tail..]);
    out
}

/// Empty-repo helper: the exact commands to seed the first commit + push with a PAT.
fn render_empty_repo(repo: &Repo, base_url: &str) -> String {
    let clone_url = format!(
        "{}/git/{}/{}.git",
        base_url.trim_end_matches('/'),
        repo.owner_sub,
        repo.name
    );
    let quickstart = format!(
        "git clone {url}\ncd {name}\n# add files, then\ngit add .\ngit commit -m \"first commit\"\ngit push origin {branch}",
        url = clone_url,
        name = repo.name,
        branch = repo.default_branch,
    );
    format!(
        r##"<section class="card">
  <div class="card__head"><h2>Quick start</h2></div>
  <div class="card__body">
    <p class="muted">This repository is empty. Push your first commit (authenticate with a <a href="/pats">personal access token</a> as the password):</p>
    <pre class="code-pre"><code>{cmds}</code></pre>
  </div>
</section>"##,
        cmds = esc(&quickstart),
    )
}

/// The file browser card: latest commit + breadcrumb + tree/blob rows for `entries` at `subpath`.
fn render_file_browser(
    repo: &Repo,
    subpath: &str,
    entries: &[TreeEntry],
    last: &TreeLastCommits,
    now: i64,
    commit_prefix: Option<&str>,
) -> String {
    let commitbar = last
        .latest
        .as_ref()
        .map(|commit| {
            format!(
                r##"<div class="filebox__commit">
    <span class="filebox__commit-author">{author}</span>
    <a class="filebox__commit-msg" href="/r/{owner}/{name}/commit/{oid}">{subject}</a>
    <span class="filebox__commit-fill"></span>
    <a href="/r/{owner}/{name}/commit/{oid}"><code class="oid">{short}</code></a>
    <span class="filebox__commit-age" title="{when_abs}">{when_rel}</span>
    <a class="filebox__commit-more" href="/r/{owner}/{name}/commits">History</a>
  </div>"##,
                owner = esc(&repo.owner_sub),
                name = esc(&repo.name),
                oid = esc(&commit.oid),
                short = esc(&short_oid(&commit.oid)),
                author = esc(&commit.author_name),
                subject = esc(&commit.subject),
                when_abs = esc(&fmt_ts(commit.time)),
                when_rel = esc(&fmt_rel(now, commit.time)),
            )
        })
        .unwrap_or_default();
    let head = if subpath.is_empty() {
        String::new()
    } else {
        format!(
            "<div class=\"card__head filebox__head\">{}</div>",
            render_breadcrumb_at(repo, subpath, false, commit_prefix)
        )
    };
    let rows = entries
        .iter()
        .map(|e| {
            let child = if subpath.is_empty() {
                e.name.clone()
            } else {
                format!("{subpath}/{}", e.name)
            };
            let (href, icon) = if e.is_dir() {
                (tree_href(repo, &child, commit_prefix), "dir")
            } else {
                (blob_href(repo, &child, commit_prefix), "file")
            };
            let commit = last.by_name.get(&e.name);
            let message = commit
                .map(|c| {
                    format!(
                        "<a href=\"/r/{owner}/{name}/commit/{oid}\">{subject}</a>",
                        owner = esc(&repo.owner_sub),
                        name = esc(&repo.name),
                        oid = esc(&c.oid),
                        subject = esc(&c.subject),
                    )
                })
                .unwrap_or_default();
            let age = commit
                .map(|c| {
                    format!(
                        "<span class=\"tree-row__age\" title=\"{when_abs}\">{when_rel}</span>",
                        when_abs = esc(&fmt_ts(c.time)),
                        when_rel = esc(&fmt_rel(now, c.time)),
                    )
                })
                .unwrap_or_else(|| "<span class=\"tree-row__age\"></span>".to_string());
            format!(
                "<li class=\"tree-row tree-row--{icon}\">\
                   <a class=\"tree-row__name\" href=\"{href}\">{name}</a>\
                   <span class=\"tree-row__msg\">{message}</span>\
                   {age}\
                 </li>",
                icon = icon,
                href = esc(&href),
                name = esc(&e.name),
                message = message,
                age = age,
            )
        })
        .collect::<Vec<_>>()
        .join("");

    format!(
        r##"<section class="card filebox">
  {commitbar}
  {head}
  <div class="card__body card__body--list">
    <ul class="tree-list">{rows}</ul>
  </div>
</section>"##,
        commitbar = commitbar,
        head = head,
        rows = if rows.is_empty() {
            "<li class=\"tree-row tree-row--empty\">Empty directory.</li>".to_string()
        } else {
            rows
        },
    )
}

async fn render_file_tree(
    git: &GitOps,
    repo: &Repo,
    commit: &str,
    commit_prefix: Option<&str>,
    current_path: &str,
    current_is_blob: bool,
) -> String {
    if commit.is_empty() {
        return String::new();
    }

    let segs: Vec<&str> = current_path
        .split('/')
        .filter(|seg| !seg.is_empty())
        .collect();
    let expanded_len = if current_is_blob {
        segs.len().saturating_sub(1)
    } else {
        segs.len()
    };
    let spine = &segs[..expanded_len];

    let mut levels = Vec::with_capacity(spine.len() + 1);
    levels.push((
        String::new(),
        git.list_tree(&repo.owner_sub, &repo.name, commit, "").await,
    ));

    let mut dir_path = String::new();
    for seg in spine {
        if !dir_path.is_empty() {
            dir_path.push('/');
        }
        dir_path.push_str(seg);
        levels.push((
            dir_path.clone(),
            git.list_tree(&repo.owner_sub, &repo.name, commit, &dir_path)
                .await,
        ));
    }

    let rows = render_file_tree_level(
        &levels,
        0,
        spine,
        current_path,
        current_is_blob,
        repo,
        commit_prefix,
    );
    format!(
        r#"<nav class="filetree" aria-label="Files" style="view-transition-name:loom-filetree">{rows}</nav>"#
    )
}

fn render_file_tree_level(
    levels: &[(String, Vec<TreeEntry>)],
    level_idx: usize,
    spine: &[&str],
    current_path: &str,
    current_is_blob: bool,
    repo: &Repo,
    commit_prefix: Option<&str>,
) -> String {
    let Some((dir_path, entries)) = levels.get(level_idx) else {
        return "<ul class=\"ft-list\"></ul>".to_string();
    };
    let mut sorted: Vec<&TreeEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| {
        b.is_dir()
            .cmp(&a.is_dir())
            .then_with(|| {
                a.name
                    .to_ascii_lowercase()
                    .cmp(&b.name.to_ascii_lowercase())
            })
            .then_with(|| a.name.cmp(&b.name))
    });

    let mut rows = String::new();
    for entry in sorted {
        let entry_path = if dir_path.is_empty() {
            entry.name.clone()
        } else {
            format!("{dir_path}/{}", entry.name)
        };

        if entry.is_dir() {
            let href = tree_href(repo, &entry_path, commit_prefix);
            let is_open = spine.get(level_idx) == Some(&entry.name.as_str())
                && path_has_prefix(current_path, &entry_path);
            if is_open {
                let children = render_file_tree_level(
                    levels,
                    level_idx + 1,
                    spine,
                    current_path,
                    current_is_blob,
                    repo,
                    commit_prefix,
                );
                rows.push_str(&format!(
                    "<li class=\"ft-dir is-open\"><a class=\"ft-row ft-row--dir\" href=\"{href}\">{icon}{name}</a>{children}</li>",
                    href = esc(&href),
                    icon = icon_chevron_down(),
                    name = esc(&entry.name),
                    children = children,
                ));
            } else {
                rows.push_str(&format!(
                    "<li class=\"ft-dir\"><a class=\"ft-row ft-row--dir\" href=\"{href}\">{icon}{name}</a></li>",
                    href = esc(&href),
                    icon = icon_chevron_right(),
                    name = esc(&entry.name),
                ));
            }
        } else {
            let href = blob_href(repo, &entry_path, commit_prefix);
            let is_current = current_is_blob && entry_path == current_path;
            let current_class = if is_current { " is-current" } else { "" };
            let aria_current = if is_current {
                " aria-current=\"page\""
            } else {
                ""
            };
            rows.push_str(&format!(
                "<li class=\"ft-file\"><a class=\"ft-row ft-row--file{current_class}\" href=\"{href}\"{aria_current}>{icon}{name}</a></li>",
                current_class = current_class,
                href = esc(&href),
                aria_current = aria_current,
                icon = icon_file(),
                name = esc(&entry.name),
            ));
        }
    }

    format!("<ul class=\"ft-list\">{rows}</ul>")
}

fn path_has_prefix(path: &str, prefix: &str) -> bool {
    if path == prefix {
        return true;
    }
    match path.strip_prefix(prefix) {
        Some(rest) => rest.starts_with('/'),
        None => false,
    }
}

fn icon_chevron_right() -> &'static str {
    r#"<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 4 4 4-4 4"/></svg>"#
}

fn icon_chevron_down() -> &'static str {
    r#"<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m4 6 4 4 4-4"/></svg>"#
}

fn icon_file() -> &'static str {
    r#"<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M3.75 1A1.75 1.75 0 0 0 2 2.75v10.5C2 14.216 2.784 15 3.75 15h8.5A1.75 1.75 0 0 0 14 13.25V5.664c0-.464-.184-.909-.513-1.237L10.573 1.513A1.75 1.75 0 0 0 9.336 1H3.75Zm-.25 1.75a.25.25 0 0 1 .25-.25H9v2.75c0 .966.784 1.75 1.75 1.75h1.75v6.25a.25.25 0 0 1-.25.25h-8.5a.25.25 0 0 1-.25-.25V2.75Zm7 .81L11.94 5.5h-1.19a.25.25 0 0 1-.25-.25V3.56Z"/></svg>"#
}

fn file_history_href(repo: &Repo, ref_name: &str, path: &str) -> String {
    format!(
        "/r/{}/{}/history/{}/{}",
        repo.owner_sub, repo.name, ref_name, path
    )
}

fn tree_href(repo: &Repo, path: &str, commit_prefix: Option<&str>) -> String {
    let path = url_path(path);
    match commit_prefix {
        Some(commit) if path.is_empty() => {
            format!("/r/{}/{}/tree/{}", repo.owner_sub, repo.name, commit)
        }
        Some(commit) => {
            format!(
                "/r/{}/{}/tree/{}/{}",
                repo.owner_sub, repo.name, commit, path
            )
        }
        None => format!("/r/{}/{}/tree/{}", repo.owner_sub, repo.name, path),
    }
}

fn blob_href(repo: &Repo, path: &str, commit_prefix: Option<&str>) -> String {
    let path = url_path(path);
    match commit_prefix {
        Some(commit) => {
            format!(
                "/r/{}/{}/blob/{}/{}",
                repo.owner_sub, repo.name, commit, path
            )
        }
        None => format!("/r/{}/{}/blob/{}", repo.owner_sub, repo.name, path),
    }
}

fn url_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    path.split('/')
        .map(percent_encode_path_segment)
        .collect::<Vec<_>>()
        .join("/")
}

fn percent_encode_path_segment(input: &str) -> String {
    let mut out = String::new();
    for b in input.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// File-view card: repo header + breadcrumb + escaped file content (or a binary/too-large notice).
fn render_blob(
    repo: &Repo,
    base_url: &str,
    open_issues: i64,
    open_pulls: i64,
    release_count: i64,
    commit: &str,
    path: &str,
    bytes: &[u8],
    pinned: bool,
    file_tree: &str,
) -> String {
    let header = render_repo_header(
        repo,
        base_url,
        open_issues,
        open_pulls,
        release_count,
        "code",
    );
    let ref_name = if pinned { commit } else { "HEAD" };
    let history_href = file_history_href(repo, ref_name, path);
    let blame_href = format!(
        "/r/{}/{}/blame/{}/{}",
        repo.owner_sub, repo.name, ref_name, path
    );
    let permalink_href = format!(
        "/r/{}/{}/blob/{}/{}",
        repo.owner_sub, repo.name, commit, path
    );
    let search = render_code_search_form(repo, "", ref_name, false);
    let content = if bytes.contains(&0) {
        "<div class=\"card__body\"><p class=\"muted\">Binary file not shown.</p></div>".to_string()
    } else if bytes.len() > crate::config::MAX_BLOB_RENDER_BYTES {
        format!(
            "<div class=\"card__body\"><p class=\"muted\">File is too large to display ({}).</p></div>",
            esc(&human_size(bytes.len() as i64))
        )
    } else {
        let text = String::from_utf8_lossy(bytes);
        if is_markdown_path(path) {
            // A markdown file renders as sanitised HTML (raw HTML/unsafe links defused).
            format!(
                "<div class=\"card__body markdown-body\">{}</div>",
                crate::markdown::render_for_repo(&text, &repo.owner_sub, &repo.name)
            )
        } else {
            // Any other text blob gets a monospace, line-numbered view.
            format!(
                "<div class=\"card__body card__body--code\">{}</div>",
                render_text_blob(&text, path)
            )
        }
    };
    let blob = format!(
        r##"<section class="card">
  <div class="card__head">{breadcrumb}<span class="blob-actions"><a class="btn btn-ghost btn-sm btn-permalink" href="{permalink_href}" data-permalink="{permalink_href}">Permalink</a><a class="btn btn-ghost btn-sm" href="{history_href}">History</a><a class="btn btn-ghost btn-sm" href="{blame_href}">Blame</a><span class="muted">{size}</span></span></div>
  {content}
</section>"##,
        breadcrumb = render_breadcrumb_at(repo, path, true, pinned.then_some(commit)),
        history_href = esc(&history_href),
        blame_href = esc(&blame_href),
        permalink_href = esc(&permalink_href),
        size = esc(&human_size(bytes.len() as i64)),
        content = content,
    );
    format!(
        r##"{header}<div class="ft-layout"><aside class="ft-side">{file_tree}</aside><div class="ft-main">{search}{blob}</div></div>"##,
        header = header,
        file_tree = file_tree,
        search = search,
        blob = blob,
    )
}

fn render_blame_notice(
    repo: &Repo,
    header: &str,
    ref_name: &str,
    path: &str,
    message: &str,
) -> String {
    let history_href = file_history_href(repo, ref_name, path);
    format!(
        r##"{header}
<section class="card">
  <div class="card__head">{breadcrumb}<span class="blob-actions"><a class="btn btn-ghost btn-sm" href="{history_href}">History</a><span class="muted">Blame</span></span></div>
  <div class="card__body"><p class="muted">{message}</p></div>
</section>"##,
        header = header,
        breadcrumb = render_breadcrumb(repo, path, true),
        history_href = esc(&history_href),
        message = esc(message),
    )
}

fn render_blame(
    repo: &Repo,
    header: &str,
    ref_name: &str,
    path: &str,
    commit: &str,
    lines: &[BlameLine],
) -> String {
    let content = if lines.is_empty() {
        "<div class=\"card__body\"><p class=\"muted\">Empty file.</p></div>".to_string()
    } else {
        format!(
            "<div class=\"card__body card__body--code\">{}</div>",
            render_blame_table(repo, path, lines)
        )
    };
    let history_href = file_history_href(repo, ref_name, path);
    format!(
        r##"{header}
<section class="card">
  <div class="card__head">
    {breadcrumb}
    <span class="blob-actions"><a class="btn btn-ghost btn-sm" href="{history_href}">History</a><span class="muted">Blame {ref_name} at <a href="/r/{owner}/{name}/commit/{commit}"><code class="oid">{short}</code></a></span></span>
  </div>
  {content}
</section>"##,
        header = header,
        breadcrumb = render_breadcrumb(repo, path, true),
        history_href = esc(&history_href),
        ref_name = esc(ref_name),
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        commit = esc(commit),
        short = esc(&short_oid(commit)),
        content = content,
    )
}

fn render_file_history_notice(
    repo: &Repo,
    header: &str,
    ref_name: &str,
    path: &str,
    message: &str,
) -> String {
    format!(
        r##"{header}
<section class="card file-history">
  <div class="card__head">{breadcrumb}<span class="muted">History {ref_name}</span></div>
  <div class="card__body"><p class="muted">{message}</p></div>
</section>"##,
        header = header,
        breadcrumb = render_breadcrumb(repo, path, true),
        ref_name = esc(ref_name),
        message = esc(message),
    )
}

fn render_file_history(
    repo: &Repo,
    ref_name: &str,
    path: &str,
    commits: &[CommitInfo],
    paged: bool,
    has_next: bool,
) -> String {
    let now = now_secs();
    let rows = if commits.is_empty() {
        "<li class=\"commit-item commit-item--empty file-history__item\">No commits found for this file.</li>"
            .to_string()
    } else {
        commits
            .iter()
            .map(|c| {
                format!(
                    "<li class=\"commit-item file-history__item\">\
                       <a class=\"commit-item__subject file-history__message\" href=\"/r/{owner}/{name}/commit/{oid}\">{subject}</a>\
                       <span class=\"commit-item__meta file-history__meta\">\
                         <a href=\"/r/{owner}/{name}/commit/{oid}\"><code class=\"oid\">{short}</code></a>\
                         <span>{author}</span>\
                         <span title=\"{abs}\">{rel}</span>\
                       </span>\
                     </li>",
                    owner = esc(&repo.owner_sub),
                    name = esc(&repo.name),
                    oid = esc(&c.oid),
                    short = esc(&short_oid(&c.oid)),
                    subject = esc(&c.subject),
                    author = esc(&c.author_name),
                    abs = esc(&fmt_ts(c.time)),
                    rel = esc(&fmt_rel(now, c.time)),
                )
            })
            .collect::<String>()
    };

    let base_href = file_history_href(repo, ref_name, path);
    let newest = if paged {
        format!(
            "<a class=\"btn btn-ghost btn-sm\" href=\"{href}\">&larr; Newest</a>",
            href = esc(&base_href),
        )
    } else {
        String::new()
    };
    let older = match (has_next, commits.last()) {
        (true, Some(last)) => format!(
            "<a class=\"btn btn-ghost btn-sm\" href=\"{href}?after={oid}\">Older &rarr;</a>",
            href = esc(&base_href),
            oid = esc(&last.oid),
        ),
        _ => String::new(),
    };
    let pager = if newest.is_empty() && older.is_empty() {
        String::new()
    } else {
        format!(
            "<div class=\"pager file-history__pager\">{newest}<span class=\"spacer\"></span>{older}</div>"
        )
    };

    format!(
        r##"<section class="card file-history">
  <div class="card__head">{breadcrumb}<span class="muted">History {ref_name}</span></div>
  <div class="card__body">
    <ul class="commit-list file-history__list">{rows}</ul>
    {pager}
  </div>
</section>"##,
        breadcrumb = render_breadcrumb(repo, path, true),
        ref_name = esc(ref_name),
        rows = rows,
        pager = pager,
    )
}

fn render_blame_table(repo: &Repo, path: &str, lines: &[BlameLine]) -> String {
    let now = now_secs();
    let mut rows = String::new();
    let lang = highlight_lang_for_lines(path, lines);
    let mut i = 0usize;
    while i < lines.len() {
        let line = &lines[i];
        let mut run_len = 1usize;
        while i + run_len < lines.len() && lines[i + run_len].oid == line.oid {
            run_len += 1;
        }
        for offset in 0..run_len {
            let current = &lines[i + offset];
            let commit_cell = if offset == 0 {
                format!(
                    "<td class=\"blame-commit\" rowspan=\"{run_len}\">\
                       <a href=\"/r/{owner}/{name}/commit/{oid}\"><code class=\"oid\">{short}</code></a>\
                       <span class=\"blame-author\">{author}</span>\
                       <span class=\"blame-time\" title=\"{abs}\">{rel}</span>\
                     </td>",
                    run_len = run_len,
                    owner = esc(&repo.owner_sub),
                    name = esc(&repo.name),
                    oid = esc(&current.oid),
                    short = esc(&short_oid(&current.oid)),
                    author = esc(&current.author_name),
                    abs = esc(&fmt_ts(current.time)),
                    rel = esc(&fmt_rel(now, current.time)),
                )
            } else {
                String::new()
            };
            rows.push_str(&format!(
                "<tr class=\"blame-row\">\
                   {commit_cell}\
                   <td class=\"blame-lineno\">{lineno}</td>\
                   <td class=\"blame-code\"><code>{code}</code></td>\
                 </tr>",
                commit_cell = commit_cell,
                lineno = current.lineno,
                code = render_code_line(&current.content, lang),
            ));
        }
        i += run_len;
    }
    format!("<table class=\"blame-table\"><tbody>{rows}</tbody></table>")
}

/// Path breadcrumb. `is_blob` makes the final segment a non-link leaf.
fn render_breadcrumb(repo: &Repo, subpath: &str, is_blob: bool) -> String {
    render_breadcrumb_at(repo, subpath, is_blob, None)
}

fn render_breadcrumb_at(
    repo: &Repo,
    subpath: &str,
    is_blob: bool,
    commit_prefix: Option<&str>,
) -> String {
    let root_href = match commit_prefix {
        Some(commit) => tree_href(repo, "", Some(commit)),
        None => format!("/r/{}/{}", repo.owner_sub, repo.name),
    };
    let mut html = format!(
        "<nav class=\"breadcrumb\"><a href=\"{href}\">{name_e}</a>",
        href = esc(&root_href),
        name_e = esc(&repo.name),
    );
    if subpath.is_empty() {
        html.push_str("</nav>");
        return html;
    }
    let segs: Vec<&str> = subpath.split('/').collect();
    let mut acc = String::new();
    for (i, seg) in segs.iter().enumerate() {
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(seg);
        let last = i + 1 == segs.len();
        html.push_str("<span class=\"breadcrumb__sep\">/</span>");
        if last && is_blob {
            html.push_str(&format!("<span>{}</span>", esc(seg)));
        } else {
            let href = tree_href(repo, &acc, commit_prefix);
            html.push_str(&format!(
                "<a href=\"{href}\">{seg}</a>",
                href = esc(&href),
                seg = esc(seg),
            ));
        }
    }
    html.push_str("</nav>");
    html
}

// ===========================================================================
// Small helpers
// ===========================================================================

/// Default an empty branch to `main` and trim.
fn normalize_branch(b: &str) -> String {
    let t = b.trim();
    if t.is_empty() {
        "main".to_string()
    } else {
        t.to_string()
    }
}

/// Validate a git branch name (conservative subset; enough for a default branch).
pub(crate) fn validate_branch_name(b: &str) -> Result<(), &'static str> {
    if b.is_empty() || b.len() > 64 {
        return Err("Branch name must be 1–64 characters.");
    }
    if b.starts_with('-') || b.starts_with('/') || b.ends_with('/') || b.contains("..") {
        return Err("Invalid branch name.");
    }
    if !b
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
    {
        return Err("Branch name may only contain letters, digits, '-', '_', '.', '/'.");
    }
    Ok(())
}

/// True when `path`'s final component has a markdown extension (`.md` / `.markdown`).
fn is_markdown_path(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    name.ends_with(".md") || name.ends_with(".markdown")
}

/// True when `name` is a README file (`README`, `README.md`, `README.markdown`, …), case-insensitive.
fn is_readme(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "readme" || lower.starts_with("readme.")
}

/// Render a text blob as a line-numbered, monospace table. Each line's content is escaped before
/// optional syntax highlighting; the number gutter is generated, so it never contains producer
/// input. A single trailing newline is dropped so the last line is not a spurious empty row.
fn render_text_blob(text: &str, path: &str) -> String {
    let body = text.strip_suffix('\n').unwrap_or(text);
    let lang = crate::highlight::language_for_path(path)
        .filter(|_| crate::highlight::within_highlight_limits(body));
    let mut rows = String::new();
    for (i, raw_line) in body.split('\n').enumerate() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let n = i + 1;
        rows.push_str(&format!(
            "<tr id=\"L{n}\" class=\"blob-line\" data-line=\"{n}\">\
               <td class=\"blob-line__num\"><a href=\"#L{n}\">{n}</a></td>\
               <td class=\"blob-line__code\">{code}</td>\
             </tr>",
            n = n,
            code = render_code_line(line, lang),
        ));
    }
    format!("<table class=\"blob-code\"><tbody>{rows}</tbody></table>")
}

fn render_code_line(line: &str, lang: Option<&str>) -> String {
    match lang {
        Some(lang) => crate::highlight::highlight(line, lang),
        None => esc(line),
    }
}

fn highlight_lang_for_lines(path: &str, lines: &[BlameLine]) -> Option<&'static str> {
    let total_bytes = lines.iter().map(|line| line.content.len()).sum::<usize>();
    if lines.len() > crate::highlight::MAX_HIGHLIGHT_LINES
        || total_bytes > crate::highlight::MAX_HIGHLIGHT_BYTES
    {
        return None;
    }
    crate::highlight::language_for_path(path)
}

/// Human-readable byte size (B/KiB/MiB).
fn human_size(bytes: i64) -> String {
    const KIB: i64 = 1024;
    const MIB: i64 = 1024 * 1024;
    if bytes < KIB {
        format!("{bytes} B")
    } else if bytes < MIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subpath_rejects_traversal() {
        assert!(clean_subpath("a/../b").is_err());
        assert_eq!(clean_subpath("/src/main.rs/").unwrap(), "src/main.rs");
        assert_eq!(clean_subpath("").unwrap(), "");
        assert!(clean_blame_subpath("/src/main.rs").is_err());
        assert_eq!(clean_blame_subpath("src/main.rs").unwrap(), "src/main.rs");
        assert_eq!(normalize_search_ref(""), "HEAD");
        assert_eq!(normalize_search_ref(" feature/x "), "feature/x");
    }

    #[test]
    fn branch_validation() {
        assert!(validate_branch_name("main").is_ok());
        assert!(validate_branch_name("feature/x-1").is_ok());
        assert!(validate_branch_name("-bad").is_err());
        assert!(validate_branch_name("a..b").is_err());
        assert!(validate_branch_name("with space").is_err());
    }

    #[test]
    fn size_formatting() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(2048), "2.0 KiB");
    }

    #[test]
    fn markdown_path_detection() {
        assert!(is_markdown_path("README.md"));
        assert!(is_markdown_path("docs/GUIDE.Markdown"));
        assert!(!is_markdown_path("src/main.rs"));
        assert!(!is_markdown_path("Makefile"));
    }

    #[test]
    fn readme_detection() {
        assert!(is_readme("README.md"));
        assert!(is_readme("readme"));
        assert!(is_readme("Readme.markdown"));
        assert!(!is_readme("READMEISH.txt"));
        assert!(!is_readme("notes.md"));
    }

    #[test]
    fn text_blob_is_line_numbered_and_escaped() {
        let html = render_text_blob("let x = 1;\n<b>two</b>\n", "notes.txt");
        // Two lines, numbered 1 and 2 (the trailing newline does not add a third row).
        assert!(html.contains("id=\"L1\""));
        assert!(html.contains("data-line=\"2\""));
        assert!(html.contains("href=\"#L2\">2</a>"));
        assert!(!html.contains("id=\"L3\""));
        // HTML metacharacters in the content are escaped, never live markup.
        assert!(!html.contains("<b>two</b>"));
        assert!(html.contains("&lt;b&gt;two&lt;/b&gt;"));
    }

    #[test]
    fn text_blob_highlights_known_language_without_unescaped_markup() {
        let html = render_text_blob("fn main() { let x = \"<b>\"; }\n", "src/main.rs");
        assert!(html.contains("<span class=\"tok-kw\">fn</span>"));
        assert!(html.contains("<span class=\"tok-fn\">main</span>"));
        assert!(!html.contains("<b>"));
        assert!(html.contains("&lt;b&gt;"));
    }

    #[test]
    fn code_search_highlight_escapes_before_marking() {
        let html = highlight_code_search_hit("<script>Needle</script>", "<script>", false);
        assert!(!html.contains("<script>"));
        assert!(html.contains(
            "<mark class=\"code-search-hit\">&lt;script&gt;</mark>Needle&lt;/script&gt;"
        ));

        let insensitive = highlight_code_search_hit("Needle needle", "needle", true);
        assert!(insensitive.contains("<mark class=\"code-search-hit\">Needle</mark>"));
        assert!(insensitive.contains("<mark class=\"code-search-hit\">needle</mark>"));
    }

    #[test]
    fn blame_table_groups_commits_and_escapes_code() {
        let repo = Repo {
            id: "rp_test".to_string(),
            owner_sub: "alice".to_string(),
            name: "demo".to_string(),
            description: String::new(),
            is_private: false,
            default_branch: "main".to_string(),
            require_approval: false,
            required_approvals: 0,
            require_code_owner_reviews: false,
            protect_default_branch: false,
            forked_from_id: String::new(),
            created_at: 0,
        };
        let lines = vec![
            BlameLine {
                oid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                author_name: "Ada".to_string(),
                time: 0,
                lineno: 1,
                content: "let x = 1;".to_string(),
            },
            BlameLine {
                oid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                author_name: "Ada".to_string(),
                time: 0,
                lineno: 2,
                content: "<script>".to_string(),
            },
            BlameLine {
                oid: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                author_name: "Bob".to_string(),
                time: 0,
                lineno: 3,
                content: "done".to_string(),
            },
        ];
        let html = render_blame_table(&repo, "src/main.rs", &lines);
        assert!(html.contains("class=\"blame-table\""));
        assert!(html.contains("rowspan=\"2\""));
        assert!(html.contains("/r/alice/demo/commit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(html.contains("<span class=\"tok-kw\">let</span>"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
