//! The SSO web console: repository list + repository detail + a CSRF-guarded delete-tag action.
//!
//! Mounted behind a Sluice `auth=sso` route at the subdomain root. The signed-in operator's email
//! comes from the gateway-injected `X-Auth-Email` (display only). The registry is a SHARED estate
//! resource — there is no per-user ownership — so any signed-in operator can browse every repo and
//! delete a tag (the one state-changing web action, double-submit CSRF protected). All
//! producer-supplied text (repo names, tags, media types, digests) is HTML-escaped on render.

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::auth::{self, Identity};
use crate::error::WebError;
use crate::handlers::{
    esc, fmt_ts, human_size, short_digest, userbox, APP_CSS, LAYERS_SVG, SHIELD_SVG,
};
use crate::model::{
    image_size, index_child_digests, index_platforms, is_manifest_list, ManifestRec, RepoSummary,
    TagDetail,
};
use crate::AppState;

const INDEX_HTML: &str = include_str!("../../templates/index.html");
const REPO_HTML: &str = include_str!("../../templates/repo.html");

// ---------------------------------------------------------------------------
// GET / — repository index
// ---------------------------------------------------------------------------

/// `GET /` — list every repository with its image/tag counts, total size and last-pushed time.
pub async fn index(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, WebError> {
    let who = auth::identity(&headers);
    let summaries = repo_summaries(&state).await?;
    let host = registry_host(&state.config.public_base);
    let html = render_index(&who, &summaries, &host);
    Ok(Html(html).into_response())
}

// ---------------------------------------------------------------------------
// GET /r/{*name} — repository detail
// ---------------------------------------------------------------------------

/// `GET /r/{name}` — a repository's tags, each with its manifest digest, media type, size and push
/// time, plus a delete control per tag.
pub async fn repo_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<Response, WebError> {
    let who = auth::identity(&headers);
    if !state.store.repo_exists(&name).await? {
        return Err(WebError::NotFound(format!(
            "No repository named \"{name}\" exists in this registry."
        )));
    }
    let details = tag_details(&state, &name).await?;
    let host = registry_host(&state.config.public_base);
    let csrf = auth::new_csrf_token();
    let html = render_repo(&who, &name, &details, &host, &csrf);
    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, auth::csrf_cookie(&csrf))],
        Html(html),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// POST /delete-tag — remove a tag (CSRF-guarded)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DeleteTagForm {
    #[serde(default)]
    pub repo: String,
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /delete-tag` — double-submit CSRF-checked tag removal, then 302 back to the repo page.
/// The manifest + blobs remain (untagged); reclaiming them is a DEFERRED GC sweep.
pub async fn delete_tag(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DeleteTagForm>,
) -> Result<Response, WebError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(WebError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    if form.repo.is_empty() || form.tag.is_empty() {
        return Err(WebError::BadRequest("Missing repository or tag.".to_string()));
    }
    let actor = auth::identity(&headers);
    let removed = state.store.delete_tag(&form.repo, &form.tag).await?;
    tracing::info!(repo = form.repo, tag = form.tag, removed, actor = actor.subject, "tag delete");
    Ok((
        StatusCode::FOUND,
        [(header::LOCATION, format!("/r/{}", form.repo))],
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// View assembly
// ---------------------------------------------------------------------------

async fn repo_summaries(state: &AppState) -> Result<Vec<RepoSummary>, WebError> {
    let mut out = Vec::new();
    for repo in state.store.list_repositories().await? {
        let manifests = state.store.manifests_for(&repo.name).await?;
        let tags = state.store.tags_for(&repo.name).await?;
        let mut total_size = 0i64;
        for t in &tags {
            total_size += resolved_size(&manifests, &t.manifest_digest);
        }
        let last_pushed = manifests
            .iter()
            .map(|m| m.created_at)
            .chain(tags.iter().map(|t| t.updated_at))
            .max()
            .unwrap_or(repo.created_at);
        out.push(RepoSummary {
            name: repo.name,
            manifest_count: manifests.len() as i64,
            tag_count: tags.len() as i64,
            total_size,
            last_pushed,
        });
    }
    // Most-recently-pushed first.
    out.sort_by(|a, b| b.last_pushed.cmp(&a.last_pushed).then_with(|| a.name.cmp(&b.name)));
    Ok(out)
}

async fn tag_details(state: &AppState, repo: &str) -> Result<Vec<TagDetail>, WebError> {
    let manifests = state.store.manifests_for(repo).await?;
    let mut out: Vec<TagDetail> = state
        .store
        .tags_for(repo)
        .await?
        .into_iter()
        .map(|t| {
            let m = manifests.iter().find(|m| m.digest == t.manifest_digest);
            let platforms = m
                .filter(|m| is_manifest_list(&m.media_type))
                .map(|m| index_platforms(&m.raw))
                .unwrap_or_default();
            TagDetail {
                tag: t.tag,
                manifest_digest: t.manifest_digest.clone(),
                media_type: m.map(|m| m.media_type.clone()).unwrap_or_default(),
                size: resolved_size(&manifests, &t.manifest_digest),
                platforms,
                updated_at: t.updated_at,
            }
        })
        .collect();
    out.sort_by(|a, b| b.updated_at.cmp(&a.updated_at).then_with(|| a.tag.cmp(&b.tag)));
    Ok(out)
}

/// The content size a tag's manifest represents. For a single-platform image it is `image_size`;
/// for a multi-arch index / manifest list it is the sum of its per-platform child image sizes
/// (resolved from the manifests already loaded for the repo), falling back to the index document's
/// own size when no children are present yet.
fn resolved_size(manifests: &[ManifestRec], digest: &str) -> i64 {
    let Some(m) = manifests.iter().find(|m| m.digest == digest) else {
        return 0;
    };
    if is_manifest_list(&m.media_type) {
        let mut total = 0i64;
        for child in index_child_digests(&m.raw) {
            if let Some(cm) = manifests.iter().find(|x| x.digest == child) {
                total += image_size(&cm.raw);
            }
        }
        if total > 0 {
            return total;
        }
    }
    image_size(&m.raw)
}

/// Strip the scheme from `PUBLIC_BASE_URL` to get the registry host used in `docker` commands.
fn registry_host(public_base: &str) -> String {
    public_base
        .trim_end_matches('/')
        .splitn(2, "://")
        .last()
        .unwrap_or(public_base)
        .to_string()
}

fn render_index(who: &Identity, repos: &[RepoSummary], host: &str) -> String {
    let count = match repos.len() {
        0 => "No repositories yet".to_string(),
        1 => "1 repository".to_string(),
        n => format!("{n} repositories"),
    };
    INDEX_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Registry", Some(&who.email)))
        .replace("{{HOST}}", &esc(host))
        .replace("{{COUNT}}", &esc(&count))
        .replace("{{ROWS}}", &render_repo_rows(repos, host))
}

fn render_repo_rows(repos: &[RepoSummary], host: &str) -> String {
    if repos.is_empty() {
        return format!(
            "<tr class=\"empty-row\"><td colspan=\"4\">\
               No images have been pushed yet. Authenticate and push one:<br>\
               <code>docker login {host}</code><br>\
               <code>docker tag alpine {host}/alpine:latest</code><br>\
               <code>docker push {host}/alpine:latest</code>\
             </td></tr>",
            host = esc(host),
        );
    }
    repos
        .iter()
        .map(|r| {
            format!(
                "<tr>\
                   <td class=\"repo-cell\"><a href=\"/r/{name_attr}\"><span class=\"repo-glyph\">{glyph}</span><span class=\"repo-name\">{name}</span></a></td>\
                   <td>{images}</td>\
                   <td>{tags}</td>\
                   <td class=\"num\">{size}</td>\
                   <td class=\"muted\">{date}</td>\
                 </tr>",
                name_attr = esc(&r.name),
                glyph = LAYERS_SVG,
                name = esc(&r.name),
                images = r.manifest_count,
                tags = r.tag_count,
                size = esc(&human_size(r.total_size)),
                date = esc(&fmt_ts(r.last_pushed)),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_repo(who: &Identity, name: &str, tags: &[TagDetail], host: &str, csrf: &str) -> String {
    let count = match tags.len() {
        0 => "No tags".to_string(),
        1 => "1 tag".to_string(),
        n => format!("{n} tags"),
    };
    let sample_tag = tags.first().map(|t| t.tag.as_str()).unwrap_or("latest");
    let pull_cmd = format!("docker pull {host}/{name}:{sample_tag}");
    REPO_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{LAYERS}}", LAYERS_SVG)
        .replace("{{USERBOX}}", &userbox("Registry", Some(&who.email)))
        .replace("{{NAME}}", &esc(name))
        .replace("{{COUNT}}", &esc(&count))
        .replace("{{PULL_CMD}}", &esc(&pull_cmd))
        .replace("{{TAG_ROWS}}", &render_tag_rows(name, tags, csrf))
}

/// A "multi-arch" badge listing the platforms of an index / manifest-list tag; empty for a
/// single-platform image. All platform labels come from the manifest and are HTML-escaped.
fn arch_badge(platforms: &[String]) -> String {
    if platforms.is_empty() {
        return String::new();
    }
    let list = platforms.iter().map(|p| esc(p)).collect::<Vec<_>>().join(", ");
    let label = match platforms.len() {
        1 => "multi-arch · 1 platform".to_string(),
        n => format!("multi-arch · {n} platforms"),
    };
    format!(
        " <span class=\"badge\" title=\"{list}\">{label}</span>",
        list = list,
        label = esc(&label),
    )
}

fn render_tag_rows(repo: &str, tags: &[TagDetail], csrf: &str) -> String {
    if tags.is_empty() {
        return "<tr class=\"empty-row\"><td colspan=\"5\">This repository has no tags.</td></tr>"
            .to_string();
    }
    tags
        .iter()
        .map(|t| {
            format!(
                "<tr>\
                   <td><span class=\"tag-pill\">{tag}</span></td>\
                   <td class=\"mono\" title=\"{digest_full}\">{digest_short}</td>\
                   <td class=\"muted\">{mtype}{arch}</td>\
                   <td class=\"num\">{size}</td>\
                   <td class=\"muted\">{date}</td>\
                   <td class=\"row-action\">\
                     <form method=\"post\" action=\"/delete-tag\" onsubmit=\"return confirm('Delete tag {tag_js}? The image stays until garbage-collected.');\">\
                       <input type=\"hidden\" name=\"repo\" value=\"{repo_attr}\">\
                       <input type=\"hidden\" name=\"tag\" value=\"{tag_attr}\">\
                       <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                       <button class=\"btn btn-danger btn-sm\" type=\"submit\">Delete</button>\
                     </form>\
                   </td>\
                 </tr>",
                tag = esc(&t.tag),
                digest_full = esc(&t.manifest_digest),
                digest_short = esc(&short_digest(&t.manifest_digest)),
                mtype = esc(&t.media_type),
                arch = arch_badge(&t.platforms),
                size = esc(&human_size(t.size)),
                date = esc(&fmt_ts(t.updated_at)),
                tag_js = esc(&t.tag),
                repo_attr = esc(repo),
                tag_attr = esc(&t.tag),
                csrf = esc(csrf),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}
