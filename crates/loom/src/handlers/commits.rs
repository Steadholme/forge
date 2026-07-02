//! Commit history + the single-commit page.
//!
//! - `GET /r/{owner}/{name}/commits` — the history of a branch (`?ref=`, default = the repo's
//!   default branch), KEYSET-paginated by commit order: the "Older" link carries
//!   `after=<last-shown OID>` and the next page is `git log <after>` minus the anchor itself, so
//!   a push landing between clicks never shifts the window the way an offset would.
//! - `GET /r/{owner}/{name}/commit/{sha}` — one commit: metadata (author, date, parents), the
//!   full message, the `--shortstat` summary, and the diff rendered with the crate's ONE diff
//!   renderer ([`crate::handlers::pulls::render_diff_card`]).
//!
//! Commit messages and author strings are REMOTE input (they arrive over `git push`), so every
//! rendered field is HTML-escaped. The `sha`/`after` parameters are validated to pure hex before
//! they are handed to git, and branch names are checked against the repo's actual branch list —
//! no user string ever reaches git in option position.

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use serde::Deserialize;

use crate::auth;
use crate::error::AppError;
use crate::gitops::{CommitDetail, CommitInfo};
use crate::handlers::repos::{header_with_counts, load_visible_repo};
use crate::handlers::{esc, fmt_rel, fmt_ts, html_ok, page, short_oid};
use crate::model::Repo;
use crate::{now_secs, AppState};

/// Commits shown per history page (keyset pagination).
const COMMITS_PER_PAGE: usize = 50;

/// True for a plausible (abbreviated or full) hex object id — the only shape we hand to git.
fn is_hex_oid(s: &str) -> bool {
    (4..=64).contains(&s.len()) && s.chars().all(|c| c.is_ascii_hexdigit())
}

// ===========================================================================
// GET /r/{owner}/{name}/commits — branch history, keyset-paginated
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    /// Branch to walk (`?ref=`); defaults to the repo's default branch.
    #[serde(default, rename = "ref")]
    pub ref_name: Option<String>,
    /// Keyset anchor: the OID of the last commit on the previous page.
    #[serde(default)]
    pub after: Option<String>,
}

pub async fn history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
    Query(q): Query<HistoryQuery>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let header = header_with_counts(&state, &repo, "commits").await;

    let branches = state.git.branches(&repo.owner_sub, &repo.name).await;
    if branches.is_empty() {
        let body = format!(
            r##"{header}
<section class="card"><div class="card__body">
  <p class="muted">This repository has no commits yet.</p>
</div></section>"##
        );
        return Ok(html_ok(page(
            &format!("{owner}/{name} · Commits"),
            Some(&who.email),
            &body,
        )));
    }

    // Resolve the branch to walk: an explicit ?ref= must exist (404 otherwise, like a bad path);
    // the default falls back to the first branch when the configured default has no ref yet.
    let ref_name = match q.ref_name.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(r) => {
            if !branches.iter().any(|b| b == r) {
                return Err(AppError::NotFound("No such branch.".to_string()));
            }
            r.to_string()
        }
        None => {
            if branches.contains(&repo.default_branch) {
                repo.default_branch.clone()
            } else {
                branches[0].clone()
            }
        }
    };
    let head_oid = state
        .git
        .branch_oid(&repo.owner_sub, &repo.name, &ref_name)
        .await
        .ok_or_else(|| AppError::NotFound("No such branch.".to_string()))?;

    // Keyset page: from the anchor (exclusive) or the branch head (inclusive).
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
    let mut commits = match &after {
        // `git log <after>` lists `after` first; drop it and keep one extra as the has-next probe.
        Some(anchor) => {
            let mut all = state
                .git
                .log(&repo.owner_sub, &repo.name, anchor, COMMITS_PER_PAGE + 2)
                .await;
            if all.first().map(|c| c.oid.as_str()) == Some(anchor.as_str()) {
                all.remove(0);
            }
            all
        }
        None => {
            state
                .git
                .log(&repo.owner_sub, &repo.name, &head_oid, COMMITS_PER_PAGE + 1)
                .await
        }
    };
    let has_next = commits.len() > COMMITS_PER_PAGE;
    commits.truncate(COMMITS_PER_PAGE);

    let body = format!(
        "{header}{list}",
        list = render_history(&repo, &branches, &ref_name, &commits, after.is_some(), has_next),
    );
    Ok(html_ok(page(
        &format!("{owner}/{name} · Commits"),
        Some(&who.email),
        &body,
    )))
}

/// The history card: a branch picker, the commit table, and the keyset pager.
fn render_history(
    repo: &Repo,
    branches: &[String],
    ref_name: &str,
    commits: &[CommitInfo],
    paged: bool,
    has_next: bool,
) -> String {
    let now = now_secs();
    let rows = if commits.is_empty() {
        "<tr><td colspan=\"4\" class=\"muted\">No commits on this branch.</td></tr>".to_string()
    } else {
        commits
            .iter()
            .map(|c| {
                format!(
                    "<tr>\
                       <td><a href=\"/r/{owner}/{name}/commit/{oid}\"><code class=\"oid\">{short}</code></a></td>\
                       <td><span class=\"strong\">{subject}</span></td>\
                       <td>{author}</td>\
                       <td><span title=\"{abs}\">{rel}</span></td>\
                     </tr>",
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

    let opts = branches
        .iter()
        .map(|b| {
            let sel = if b == ref_name { " selected" } else { "" };
            format!("<option value=\"{v}\"{sel}>{v}</option>", v = esc(b), sel = sel)
        })
        .collect::<String>();

    // Keyset pager: "Newest" rewinds to page one; "Older" anchors after the last shown commit.
    let newest = if paged {
        format!(
            "<a class=\"btn btn-ghost btn-sm\" href=\"/r/{owner}/{name}/commits?ref={r}\">&larr; Newest</a>",
            owner = esc(&repo.owner_sub),
            name = esc(&repo.name),
            r = esc(ref_name),
        )
    } else {
        String::new()
    };
    let older = match (has_next, commits.last()) {
        (true, Some(last)) => format!(
            "<a class=\"btn btn-ghost btn-sm\" href=\"/r/{owner}/{name}/commits?ref={r}&amp;after={oid}\">Older &rarr;</a>",
            owner = esc(&repo.owner_sub),
            name = esc(&repo.name),
            r = esc(ref_name),
            oid = esc(&last.oid),
        ),
        _ => String::new(),
    };
    let pager = if newest.is_empty() && older.is_empty() {
        String::new()
    } else {
        format!("<div class=\"pager\">{newest}<span class=\"spacer\"></span>{older}</div>")
    };

    format!(
        r##"<section class="card">
  <div class="card__head">
    <h2>Commits</h2>
    <form class="inline-form compare-picker" method="get" action="/r/{owner}/{name}/commits">
      <span class="compare-picker__label">branch</span>
      <select name="ref" class="compare-picker__select">{opts}</select>
      <button class="btn btn-secondary btn-sm" type="submit">View</button>
    </form>
  </div>
  <div class="card__body">
    <table class="data">
      <thead><tr><th>Commit</th><th>Message</th><th>Author</th><th>When</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
    {pager}
  </div>
</section>"##,
        owner = esc(&repo.owner_sub),
        name = esc(&repo.name),
        opts = opts,
        rows = rows,
        pager = pager,
    )
}

// ===========================================================================
// GET /r/{owner}/{name}/commit/{sha} — one commit: metadata + stat + diff
// ===========================================================================

pub async fn detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, sha)): Path<(String, String, String)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    if !is_hex_oid(sha.trim()) {
        return Err(AppError::BadRequest("Invalid commit id.".to_string()));
    }
    let oid = state
        .git
        .resolve_commit(&repo.owner_sub, &repo.name, sha.trim())
        .await
        .ok_or_else(|| AppError::NotFound("No such commit.".to_string()))?;
    let detail = state
        .git
        .commit_detail(&repo.owner_sub, &repo.name, &oid)
        .await
        .ok_or_else(|| AppError::NotFound("No such commit.".to_string()))?;
    let stat = state.git.commit_stat(&repo.owner_sub, &repo.name, &oid).await;
    let patch = state
        .git
        .commit_patch(&repo.owner_sub, &repo.name, &oid)
        .await
        .unwrap_or_default();

    let header = header_with_counts(&state, &repo, "commits").await;
    let body = format!(
        "{header}{commit}",
        commit = render_commit(&repo, &detail, &stat, &patch),
    );
    Ok(html_ok(page(
        &format!("{owner}/{name} · {short}", short = short_oid(&oid)),
        Some(&who.email),
        &body,
    )))
}

/// The commit card (subject + metadata rows + full message) followed by the shared diff card.
fn render_commit(repo: &Repo, detail: &CommitDetail, stat: &str, patch: &str) -> String {
    let parents = if detail.parents.is_empty() {
        "<span class=\"muted\">none (root commit)</span>".to_string()
    } else {
        detail
            .parents
            .iter()
            .map(|p| {
                format!(
                    "<a href=\"/r/{owner}/{name}/commit/{oid}\"><code class=\"oid\">{short}</code></a>",
                    owner = esc(&repo.owner_sub),
                    name = esc(&repo.name),
                    oid = esc(p),
                    short = esc(&short_oid(p)),
                )
            })
            .collect::<Vec<_>>()
            .join(" ")
    };
    let stat_html = if stat.is_empty() {
        "<span class=\"muted\">no combined changes</span>".to_string()
    } else {
        esc(stat)
    };
    // Show the full message below the metadata only when it says more than the subject line.
    let message_block = if detail.message.trim() != detail.subject().trim() {
        format!(
            "<pre class=\"code-pre\"><code>{}</code></pre>",
            esc(&detail.message)
        )
    } else {
        String::new()
    };

    format!(
        r##"<div class="console__head">
  <h1 class="pr-title">{subject}</h1>
  <p class="sub">authored {when} by {author} &lt;{email}&gt;</p>
</div>
<section class="card">
  <div class="card__head"><h2>Commit</h2></div>
  <div class="card__body">
    <table class="data">
      <tbody>
        <tr><td><span class="strong">Commit</span></td><td><code class="oid">{oid}</code></td></tr>
        <tr><td><span class="strong">Author</span></td><td>{author} &lt;{email}&gt;</td></tr>
        <tr><td><span class="strong">Date</span></td><td>{when}</td></tr>
        <tr><td><span class="strong">Parents</span></td><td>{parents}</td></tr>
        <tr><td><span class="strong">Changes</span></td><td>{stat}</td></tr>
      </tbody>
    </table>
    {message_block}
  </div>
</section>
{diff}"##,
        subject = esc(detail.subject()),
        when = esc(&fmt_ts(detail.time)),
        author = esc(&detail.author_name),
        email = esc(&detail.author_email),
        oid = esc(&detail.oid),
        parents = parents,
        stat = stat_html,
        message_block = message_block,
        diff = crate::handlers::pulls::render_diff_card(patch),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_oid_validation() {
        assert!(is_hex_oid("deadbeef"));
        assert!(is_hex_oid(&"a".repeat(40)));
        assert!(!is_hex_oid("abc")); // too short
        assert!(!is_hex_oid(&"a".repeat(65))); // too long
        assert!(!is_hex_oid("--upload-pack=/x")); // never option-like
        assert!(!is_hex_oid("main")); // branch names are not hex
        assert!(!is_hex_oid("dead beef"));
    }
}
