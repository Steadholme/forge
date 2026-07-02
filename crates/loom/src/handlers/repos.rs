//! The SSO web surface: repo list/create, browse (tree/blob), commit history, branches.
//!
//! Mounted behind a Sluice `auth=sso` route: the gateway authenticates the user and injects
//! `X-Auth-Subject` / `X-Auth-Email`, which we trust (Loom is internal-only). The OWNER of a repo
//! is ALWAYS the subject header — never a client field. Private repos are hidden from non-owners
//! (a private repo a viewer cannot see returns 404, so existence does not leak). Every
//! producer-supplied string — repo name, description, file path, commit subject — is HTML-escaped
//! on render; a non-markdown text blob is shown in a line-numbered, escaped monospace view.
//! Markdown (a `.md` blob + the repo README, plus issue bodies) is rendered through the estate's
//! sanitising [`crate::markdown`] pipeline: raw HTML is downgraded to text and unsafe link schemes
//! are defused, so no producer-supplied markup ever executes.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Form;
use serde::Deserialize;

use crate::auth::{self, Identity};
use crate::config::COMMIT_LIMIT;
use crate::error::AppError;
use crate::gitops::TreeEntry;
use crate::handlers::{
    esc, fmt_ts, html_ok, html_with_csrf, page, redirect, short_oid,
};
use crate::model::{validate_owner_sub, validate_repo_name, Repo};
use crate::{now_secs, random_alnum, AppState};

/// Length of a repo/issue/pat id (62-symbol alphabet).
const ID_LEN: usize = 16;

// ===========================================================================
// GET / — repo list + create form
// ===========================================================================

pub async fn index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let who = auth::identity(&headers);
    let csrf = auth::new_csrf_token();
    let repos = state
        .store
        .list_visible_repos(&who.subject)
        .await
        .unwrap_or_default();
    let body = render_index(&who, &csrf, &repos, None);
    html_with_csrf(StatusCode::OK, page("Repositories", Some(&who.email), &body), &csrf)
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
        return Ok(render_index_error(&state, &who, msg).await);
    }
    let default_branch = normalize_branch(&form.default_branch);
    if let Err(msg) = validate_branch_name(&default_branch) {
        return Ok(render_index_error(&state, &who, msg).await);
    }
    let is_private = matches!(form.visibility.as_str(), "private");

    let repo = Repo {
        id: format!("rp_{}", random_alnum(ID_LEN)),
        owner_sub: who.subject.clone(),
        name: name.clone(),
        description: form.description.trim().chars().take(500).collect(),
        is_private,
        default_branch: default_branch.clone(),
        created_at: now_secs(),
    };

    if !state.store.create_repo(&repo).await? {
        return Ok(render_index_error(
            &state,
            &who,
            "You already have a repository with that name.",
        )
        .await);
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
    let body = render_code_page(&state, &repo, "").await?;
    Ok(html_ok(page(&format!("{}/{}", owner, name), Some(&who.email), &body)))
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
    let path = clean_subpath(&path)?;
    let body = render_code_page(&state, &repo, &path).await?;
    Ok(html_ok(page(&format!("{}/{}", owner, name), Some(&who.email), &body)))
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
    let path = clean_subpath(&path)?;

    let commit = state
        .git
        .head_commit(&repo.owner_sub, &repo.name)
        .await
        .ok_or_else(|| AppError::NotFound("This repository has no commits yet.".to_string()))?;
    let bytes = state
        .git
        .read_blob(&repo.owner_sub, &repo.name, &commit, &path)
        .await
        .ok_or_else(|| AppError::NotFound("No such file in the default branch.".to_string()))?;

    let open_issues = state.store.open_issue_count(&repo.id).await.unwrap_or(0);
    let open_pulls = state.store.open_pull_count(&repo.id).await.unwrap_or(0);
    let body = render_blob(
        &repo,
        &state.config.public_base_url,
        open_issues,
        open_pulls,
        &path,
        &bytes,
    );
    Ok(html_ok(page(
        &format!("{}/{}", owner, name),
        Some(&who.email),
        &body,
    )))
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
    match state.store.get_repo(owner, name).await? {
        Some(r) if !r.is_private || r.owner_sub == who.subject => Ok(r),
        _ => Err(AppError::NotFound(
            "No repository exists at that path.".to_string(),
        )),
    }
}

/// Render the repo header for the `active` tab, fetching the open issue/PR badge counts (the
/// shared entry point for the commits/branches/settings pages).
pub(crate) async fn header_with_counts(state: &AppState, repo: &Repo, active: &str) -> String {
    let open_issues = state.store.open_issue_count(&repo.id).await.unwrap_or(0);
    let open_pulls = state.store.open_pull_count(&repo.id).await.unwrap_or(0);
    render_repo_header(repo, &state.config.public_base_url, open_issues, open_pulls, active)
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

// ===========================================================================
// Rendering
// ===========================================================================

fn render_index(who: &Identity, csrf: &str, repos: &[Repo], error: Option<&str>) -> String {
    let error_block = match error {
        Some(msg) => format!(
            "<div class=\"alert alert-danger\" role=\"alert\">{}</div>",
            esc(msg)
        ),
        None => String::new(),
    };
    let list = if repos.is_empty() {
        "<li class=\"repo-item repo-item--empty\">No repositories yet. Create your first one.</li>"
            .to_string()
    } else {
        repos
            .iter()
            .map(|r| {
                let badge = if r.is_private {
                    "<span class=\"vis-badge vis-badge--private\">Private</span>"
                } else {
                    "<span class=\"vis-badge\">Public</span>"
                };
                let desc = if r.description.trim().is_empty() {
                    String::new()
                } else {
                    format!("<p class=\"repo-item__desc\">{}</p>", esc(&r.description))
                };
                format!(
                    "<li class=\"repo-item\">\
                       <div class=\"repo-item__head\">\
                         <a class=\"repo-item__name\" href=\"/r/{owner}/{name}\">{owner_e}/{name_e}</a>\
                         {badge}\
                       </div>\
                       {desc}\
                       <span class=\"repo-item__meta\">created {created}</span>\
                     </li>",
                    owner = esc(&r.owner_sub),
                    name = esc(&r.name),
                    owner_e = esc(&r.owner_sub),
                    name_e = esc(&r.name),
                    created = esc(&fmt_ts(r.created_at)),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    format!(
        r##"<div class="console__head">
  <h1>Repositories</h1>
  <p class="sub">Self-hosted git for the estate. Clone over HTTPS with a personal access token; browse here with single sign-on as {email}.</p>
</div>
<div class="layout">
  <section class="card">
    <div class="card__head"><h2>All repositories</h2></div>
    <div class="card__body">
      <ul class="repo-list">{list}</ul>
    </div>
  </section>
  <section class="card">
    <div class="card__head"><h2>New repository</h2></div>
    <div class="card__body">
      {error_block}
      <form method="post" action="/new">
        <input type="hidden" name="csrf_token" value="{csrf}">
        <div class="field">
          <label for="name">Name</label>
          <input type="text" id="name" name="name" maxlength="64" placeholder="e.g. holdfast-infra" autocomplete="off" spellcheck="false" required>
        </div>
        <div class="field">
          <label for="description">Description</label>
          <input type="text" id="description" name="description" maxlength="500" placeholder="Optional one-line summary">
        </div>
        <div class="field">
          <label for="default_branch">Default branch</label>
          <input type="text" id="default_branch" name="default_branch" maxlength="64" value="main" autocomplete="off" spellcheck="false">
        </div>
        <div class="field field--check">
          <label class="check"><input type="checkbox" name="visibility" value="private"> Private (only you can see and clone)</label>
        </div>
        <div class="actions">
          <button class="btn btn-primary" type="submit">Create repository</button>
        </div>
      </form>
    </div>
  </section>
</div>"##,
        email = esc(&who.email),
        list = list,
        error_block = error_block,
        csrf = esc(csrf),
    )
}

/// Re-render the index with an inline error + a fresh CSRF token (validation failures on create).
async fn render_index_error(state: &AppState, who: &Identity, msg: &str) -> Response {
    let csrf = auth::new_csrf_token();
    let repos = state
        .store
        .list_visible_repos(&who.subject)
        .await
        .unwrap_or_default();
    let body = render_index(who, &csrf, &repos, Some(msg));
    html_with_csrf(
        StatusCode::BAD_REQUEST,
        page("Repositories", Some(&who.email), &body),
        &csrf,
    )
}

/// Render the code page: repo header + clone box + (file browser at `subpath`) + branches +
/// commit history (history/branches shown at the repo root).
async fn render_code_page(
    state: &AppState,
    repo: &Repo,
    subpath: &str,
) -> Result<String, AppError> {
    let open_issues = state.store.open_issue_count(&repo.id).await.unwrap_or(0);
    let open_pulls = state.store.open_pull_count(&repo.id).await.unwrap_or(0);
    let header =
        render_repo_header(repo, &state.config.public_base_url, open_issues, open_pulls, "code");

    let head = state.git.head_commit(&repo.owner_sub, &repo.name).await;
    let Some(commit) = head else {
        // Empty repo: show how to push the first commit.
        let push = render_empty_repo(repo, &state.config.public_base_url);
        return Ok(format!("{header}{push}"));
    };

    let entries = state
        .git
        .list_tree(&repo.owner_sub, &repo.name, &commit, subpath)
        .await;
    if !subpath.is_empty() && entries.is_empty() {
        return Err(AppError::NotFound("No such directory.".to_string()));
    }

    let files = render_file_browser(repo, subpath, &entries);

    // A rendered README under the file browser at the repo root (GitHub-style), sanitised.
    let readme = if subpath.is_empty() {
        render_readme(state, repo, &commit, &entries).await
    } else {
        String::new()
    };

    // History + branches only at the repo root, to keep subdirectory pages focused.
    let extras = if subpath.is_empty() {
        let branches = state.git.branches(&repo.owner_sub, &repo.name).await;
        let commits = state
            .git
            .log(&repo.owner_sub, &repo.name, &commit, COMMIT_LIMIT)
            .await;
        let branch_html = branches
            .iter()
            .map(|b| {
                let current = if *b == repo.default_branch { " branch-badge--default" } else { "" };
                format!("<span class=\"branch-badge{current}\">{}</span>", esc(b))
            })
            .collect::<Vec<_>>()
            .join("");
        let commit_html = if commits.is_empty() {
            "<li class=\"commit-item commit-item--empty\">No commits.</li>".to_string()
        } else {
            commits
                .iter()
                .map(|c| {
                    format!(
                        "<li class=\"commit-item\">\
                           <span class=\"commit-item__subject\">{subject}</span>\
                           <span class=\"commit-item__meta\">\
                             <code class=\"oid\">{oid}</code>\
                             <span>{author}</span>\
                             <span>{when}</span>\
                           </span>\
                         </li>",
                        subject = esc(&c.subject),
                        oid = esc(&short_oid(&c.oid)),
                        author = esc(&c.author_name),
                        when = esc(&fmt_ts(c.time)),
                    )
                })
                .collect::<Vec<_>>()
                .join("")
        };
        format!(
            r##"<div class="layout layout--repo">
  <section class="card">
    <div class="card__head"><h2>Recent commits</h2></div>
    <div class="card__body"><ul class="commit-list">{commit_html}</ul></div>
  </section>
  <section class="card">
    <div class="card__head"><h2>Branches</h2></div>
    <div class="card__body"><div class="branch-row">{branch_html}</div></div>
  </section>
</div>"##
        )
    } else {
        String::new()
    };

    Ok(format!("{header}{files}{readme}{extras}"))
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
  <div class="card__head"><h2>{name}</h2></div>
  <div class="card__body markdown-body">{html}</div>
</section>"##,
        name = esc(&entry.name),
        html = crate::markdown::render(&text),
    )
}

/// Repo header: owner/name lockup, visibility badge, clone box, tab strip.
pub(crate) fn render_repo_header(
    repo: &Repo,
    base_url: &str,
    open_issues: i64,
    open_pulls: i64,
    active: &str,
) -> String {
    let badge = if repo.is_private {
        "<span class=\"vis-badge vis-badge--private\">Private</span>"
    } else {
        "<span class=\"vis-badge\">Public</span>"
    };
    let desc = if repo.description.trim().is_empty() {
        String::new()
    } else {
        format!("<p class=\"sub\">{}</p>", esc(&repo.description))
    };
    let clone_url = format!(
        "{}/git/{}/{}.git",
        base_url.trim_end_matches('/'),
        repo.owner_sub,
        repo.name
    );
    let tab = |name: &str| if active == name { " tab--active" } else { "" };
    format!(
        r##"<div class="console__head">
  <div class="repo-title">
    <h1>{owner}/{name}</h1>
    {badge}
  </div>
  {desc}
  <div class="clone-box">
    <span class="clone-box__label">Clone</span>
    <input class="clone-box__url" type="text" readonly value="{clone}" onclick="this.select()">
  </div>
</div>
<nav class="tabs">
  <a class="tab{code_active}" href="/r/{owner}/{name}">Code</a>
  <a class="tab{commits_active}" href="/r/{owner}/{name}/commits">Commits</a>
  <a class="tab{branches_active}" href="/r/{owner}/{name}/branches">Branches</a>
  <a class="tab{issues_active}" href="/r/{owner}/{name}/issues">Issues <span class="tab__count">{open_issues}</span></a>
  <a class="tab{pulls_active}" href="/r/{owner}/{name}/pulls">Pull requests <span class="tab__count">{open_pulls}</span></a>
  <a class="tab{settings_active}" href="/r/{owner}/{name}/settings">Settings</a>
</nav>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        badge = badge,
        desc = desc,
        clone = esc(&clone_url),
        code_active = tab("code"),
        commits_active = tab("commits"),
        branches_active = tab("branches"),
        pulls_active = tab("pulls"),
        issues_active = tab("issues"),
        settings_active = tab("settings"),
        open_issues = open_issues,
        open_pulls = open_pulls,
    )
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

/// The file browser card: breadcrumb + tree/blob rows for `entries` at `subpath`.
fn render_file_browser(repo: &Repo, subpath: &str, entries: &[TreeEntry]) -> String {
    let rows = entries
        .iter()
        .map(|e| {
            let child = if subpath.is_empty() {
                e.name.clone()
            } else {
                format!("{subpath}/{}", e.name)
            };
            let (href, icon) = if e.is_dir() {
                (
                    format!("/r/{}/{}/tree/{}", repo.owner_sub, repo.name, child),
                    "dir",
                )
            } else {
                (
                    format!("/r/{}/{}/blob/{}", repo.owner_sub, repo.name, child),
                    "file",
                )
            };
            let size = match e.size {
                Some(n) if !e.is_dir() => human_size(n),
                _ => String::new(),
            };
            format!(
                "<li class=\"tree-row tree-row--{icon}\">\
                   <a class=\"tree-row__name\" href=\"{href}\">{name}</a>\
                   <span class=\"tree-row__size\">{size}</span>\
                 </li>",
                icon = icon,
                href = esc(&href),
                name = esc(&e.name),
                size = esc(&size),
            )
        })
        .collect::<Vec<_>>()
        .join("");

    format!(
        r##"<section class="card">
  <div class="card__head">{breadcrumb}</div>
  <div class="card__body card__body--list">
    <ul class="tree-list">{rows}</ul>
  </div>
</section>"##,
        breadcrumb = render_breadcrumb(repo, subpath, false),
        rows = if rows.is_empty() {
            "<li class=\"tree-row tree-row--empty\">Empty directory.</li>".to_string()
        } else {
            rows
        },
    )
}

/// File-view card: repo header + breadcrumb + escaped file content (or a binary/too-large notice).
fn render_blob(
    repo: &Repo,
    base_url: &str,
    open_issues: i64,
    open_pulls: i64,
    path: &str,
    bytes: &[u8],
) -> String {
    let header = render_repo_header(repo, base_url, open_issues, open_pulls, "code");
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
                crate::markdown::render(&text)
            )
        } else {
            // Any other text blob gets a monospace, line-numbered view.
            format!(
                "<div class=\"card__body card__body--code\">{}</div>",
                render_text_blob(&text)
            )
        }
    };
    format!(
        r##"{header}
<section class="card">
  <div class="card__head">{breadcrumb}<span class="muted">{size}</span></div>
  {content}
</section>"##,
        header = header,
        breadcrumb = render_breadcrumb(repo, path, true),
        size = esc(&human_size(bytes.len() as i64)),
        content = content,
    )
}

/// Path breadcrumb. `is_blob` makes the final segment a non-link leaf.
fn render_breadcrumb(repo: &Repo, subpath: &str, is_blob: bool) -> String {
    let mut html = format!(
        "<nav class=\"breadcrumb\"><a href=\"/r/{owner}/{name}\">{name_e}</a>",
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
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
            html.push_str(&format!(
                "<a href=\"/r/{owner}/{name}/tree/{acc}\">{seg}</a>",
                owner = esc(&repo.owner_sub),
                name = esc(&repo.name),
                acc = esc(&acc),
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

/// Render a text blob as a line-numbered, monospace table. Each line's content is HTML-escaped;
/// the number gutter is generated, so it never contains producer input. A single trailing newline
/// is dropped so the last line is not a spurious empty row.
fn render_text_blob(text: &str) -> String {
    let body = text.strip_suffix('\n').unwrap_or(text);
    let mut rows = String::new();
    for (i, raw_line) in body.split('\n').enumerate() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        rows.push_str(&format!(
            "<tr class=\"blob-line\">\
               <td class=\"blob-line__num\">{n}</td>\
               <td class=\"blob-line__code\">{code}</td>\
             </tr>",
            n = i + 1,
            code = esc(line),
        ));
    }
    format!("<table class=\"blob-code\"><tbody>{rows}</tbody></table>")
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
        let html = render_text_blob("let x = 1;\n<b>two</b>\n");
        // Two lines, numbered 1 and 2 (the trailing newline does not add a third row).
        assert!(html.contains(">1<"));
        assert!(html.contains(">2<"));
        assert!(!html.contains(">3<"));
        // HTML metacharacters in the content are escaped, never live markup.
        assert!(!html.contains("<b>two</b>"));
        assert!(html.contains("&lt;b&gt;two&lt;/b&gt;"));
    }
}
