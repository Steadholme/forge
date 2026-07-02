//! The branches + tags page (`GET /r/{owner}/{name}/branches`).
//!
//! One read-only page listing every local branch (head short-sha linking to the commit page, the
//! head commit's subject, its relative age, a `default` pill on the repo's default branch, and a
//! compare link into the existing PR compare picker) with the repo's tags below (annotated tags
//! show their tag-message subject; every tag links to the commit it points at).
//!
//! Branch names, tag names, commit subjects and tag messages are REMOTE input (they arrive over
//! `git push`), so every rendered field is HTML-escaped.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;

use crate::auth;
use crate::error::AppError;
use crate::gitops::{BranchInfo, TagInfo};
use crate::handlers::repos::{header_with_counts, load_visible_repo};
use crate::handlers::{esc, fmt_rel, fmt_ts, html_ok, page, short_oid};
use crate::model::Repo;
use crate::{now_secs, AppState};

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let repo = load_visible_repo(&state, &who, &owner, &name).await?;
    let header = header_with_counts(&state, &repo, "branches").await;

    let branches = state.git.branch_infos(&repo.owner_sub, &repo.name).await;
    let tags = state.git.tag_infos(&repo.owner_sub, &repo.name).await;

    let body = format!(
        "{header}{branches}{tags}",
        branches = render_branches(&repo, &branches),
        tags = render_tags(&repo, &tags),
    );
    Ok(html_ok(page(
        &format!("{owner}/{name} · Branches"),
        Some(&who.email),
        &body,
    )))
}

/// The branches card: name, default pill, head sha (link), subject, age, compare link.
fn render_branches(repo: &Repo, branches: &[BranchInfo]) -> String {
    let now = now_secs();
    let rows = if branches.is_empty() {
        "<tr><td colspan=\"5\" class=\"muted\">No branches yet — push a commit to create one.</td></tr>"
            .to_string()
    } else {
        branches
            .iter()
            .map(|b| {
                let default_pill = if b.name == repo.default_branch {
                    " <span class=\"pill pill-accent\">default</span>"
                } else {
                    ""
                };
                // Compare a topic branch into the default branch via the existing PR compare.
                let compare = if b.name == repo.default_branch {
                    String::new()
                } else {
                    format!(
                        "<a class=\"btn btn-ghost btn-sm\" href=\"/r/{owner}/{name}/compare?base={base}&amp;head={head}\">Compare</a>",
                        owner = esc(&repo.owner_sub),
                        name = esc(&repo.name),
                        base = esc(&repo.default_branch),
                        head = esc(&b.name),
                    )
                };
                format!(
                    "<tr>\
                       <td><a class=\"branch-badge\" href=\"/r/{owner}/{name}/commits?ref={bref}\">{bname}</a>{default_pill}</td>\
                       <td><a href=\"/r/{owner}/{name}/commit/{oid}\"><code class=\"oid\">{short}</code></a></td>\
                       <td>{subject}</td>\
                       <td><span title=\"{abs}\">{rel}</span></td>\
                       <td>{compare}</td>\
                     </tr>",
                    owner = esc(&repo.owner_sub),
                    name = esc(&repo.name),
                    bref = esc(&b.name),
                    bname = esc(&b.name),
                    default_pill = default_pill,
                    oid = esc(&b.oid),
                    short = esc(&short_oid(&b.oid)),
                    subject = esc(&b.subject),
                    abs = esc(&fmt_ts(b.time)),
                    rel = esc(&fmt_rel(now, b.time)),
                    compare = compare,
                )
            })
            .collect::<String>()
    };
    format!(
        r##"<section class="card">
  <div class="card__head"><h2>Branches <span class="tab__count">{n}</span></h2></div>
  <div class="card__body">
    <table class="data">
      <thead><tr><th>Branch</th><th>Head</th><th>Last commit</th><th>Updated</th><th></th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</section>"##,
        n = branches.len(),
        rows = rows,
    )
}

/// The tags card: name, target commit (link), the annotated tag message subject, age.
fn render_tags(repo: &Repo, tags: &[TagInfo]) -> String {
    let now = now_secs();
    let rows = if tags.is_empty() {
        "<tr><td colspan=\"4\" class=\"muted\">No tags.</td></tr>".to_string()
    } else {
        tags.iter()
            .map(|t| {
                let message = if t.message.is_empty() {
                    "<span class=\"muted\">&mdash;</span>".to_string()
                } else {
                    esc(&t.message)
                };
                format!(
                    "<tr>\
                       <td><span class=\"branch-badge\">{tname}</span></td>\
                       <td><a href=\"/r/{owner}/{name}/commit/{oid}\"><code class=\"oid\">{short}</code></a></td>\
                       <td>{message}</td>\
                       <td><span title=\"{abs}\">{rel}</span></td>\
                     </tr>",
                    tname = esc(&t.name),
                    owner = esc(&repo.owner_sub),
                    name = esc(&repo.name),
                    oid = esc(&t.oid),
                    short = esc(&short_oid(&t.oid)),
                    message = message,
                    abs = esc(&fmt_ts(t.time)),
                    rel = esc(&fmt_rel(now, t.time)),
                )
            })
            .collect::<String>()
    };
    format!(
        r##"<section class="card">
  <div class="card__head"><h2>Tags <span class="tab__count">{n}</span></h2></div>
  <div class="card__body">
    <table class="data">
      <thead><tr><th>Tag</th><th>Target</th><th>Message</th><th>Created</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</section>"##,
        n = tags.len(),
        rows = rows,
    )
}
