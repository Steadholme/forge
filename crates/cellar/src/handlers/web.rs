//! The SSO web console: repository list + repository detail + a CSRF-guarded delete-tag action.
//!
//! Mounted behind a Sluice `auth=sso` route at the subdomain root. The signed-in operator's email
//! comes from the gateway-injected `X-Auth-Email` (display only). The registry is a SHARED estate
//! resource — there is no per-user ownership — so any signed-in operator can browse every repo and
//! delete a tag (the one state-changing web action, double-submit CSRF protected). All
//! producer-supplied text (repo names, tags, media types, digests) is HTML-escaped on render.

use axum::extract::{Path, RawQuery, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::{Form, Json};
use serde::Deserialize;

use crate::auth::{self, Identity};
use crate::error::WebError;
use crate::handlers::{
    esc, fmt_ts, human_size, short_digest, time_ago, userbox, APP_JS, LAYERS_SVG, SHIELD_SVG,
};
use crate::model::{
    image_size, index_child_digests, index_entries, index_platforms, is_manifest_list,
    manifest_config, manifest_layers, Descriptor, IndexEntry, ManifestRec, RepoSummary, TagDetail,
};
use crate::names::reference_is_digest;
use crate::{now_secs, AppState};

const INDEX_HTML: &str = include_str!("../../templates/index.html");
const REPO_HTML: &str = include_str!("../../templates/repo.html");
const MANIFEST_HTML: &str = include_str!("../../templates/manifest.html");

// ---------------------------------------------------------------------------
// GET / — repository index
// ---------------------------------------------------------------------------

/// `GET /` — list every repository with its image/tag counts, total size and last-pushed time.
pub async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, WebError> {
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
    let stat = state.store.pull_stat(&name).await?;
    let pulls = pull_summary(
        stat.as_ref().map(|s| s.pulls).unwrap_or(0),
        stat.as_ref().map(|s| s.last_pulled_at).unwrap_or(0),
        now_secs(),
    );
    let host = registry_host(&state.config.public_base);
    let csrf = auth::new_csrf_token();
    let html = render_repo(&who, &name, &details, &host, &csrf, &pulls);
    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, auth::csrf_cookie(&csrf))],
        Html(html),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// GET /m/{*name}?ref={reference} — tag / manifest detail
// ---------------------------------------------------------------------------

/// `GET /m/{name}?ref={reference}` — the tag/manifest detail page: the manifest's media type,
/// its config + layers (with sizes) for an image manifest, or its per-platform child manifests for
/// a manifest list / image index, the full pull command, the manifest digest, and the tags that
/// point at it. `ref` is a tag OR a `sha256:` digest. Read-only; any signed-in operator may view it
/// (the registry is a shared estate resource — no per-user ownership). Every remote string
/// (name, reference, digest, media types, platforms) is HTML-escaped on render.
pub async fn manifest_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(raw_query): RawQuery,
) -> Result<Response, WebError> {
    let who = auth::identity(&headers);
    if !state.store.repo_exists(&name).await? {
        return Err(WebError::NotFound(format!(
            "No repository named \"{name}\" exists in this registry."
        )));
    }
    let reference = query_ref(raw_query.as_deref()).unwrap_or_default();
    let reference = reference.trim().to_string();
    if reference.is_empty() {
        return Err(WebError::BadRequest(
            "No image reference given. Open an image from its repository page.".to_string(),
        ));
    }
    // Resolve the reference to a manifest digest: a digest is used verbatim; a tag is looked up.
    let digest = if reference_is_digest(&reference) {
        reference.clone()
    } else {
        state
            .store
            .get_tag(&name, &reference)
            .await?
            .ok_or_else(|| {
                WebError::NotFound(format!("No tag \"{reference}\" in repository \"{name}\"."))
            })?
    };
    let manifest = state
        .store
        .get_manifest(&name, &digest)
        .await?
        .ok_or_else(|| {
            WebError::NotFound(format!("No manifest {digest} in repository \"{name}\"."))
        })?;

    let view = manifest_view(&state, &name, &reference, &manifest).await?;
    let host = registry_host(&state.config.public_base);
    let html = render_manifest(&who, &view, &host);
    Ok(Html(html).into_response())
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
    do_delete_tag(&state, &headers, &form).await?;
    Ok((
        StatusCode::FOUND,
        [(header::LOCATION, format!("/r/{}", form.repo))],
    )
        .into_response())
}

/// `POST /delete-tag.json` — JSON sibling of [`delete_tag`] backing the optimistic (no-reload) tag
/// removal on the repository page. Same double-submit CSRF, same audit; returns whether a tag was
/// removed. The form route above is unchanged for no-JS clients (progressive enhancement).
pub async fn delete_tag_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DeleteTagForm>,
) -> Result<Response, WebError> {
    let removed = do_delete_tag(&state, &headers, &form).await?;
    Ok(Json(serde_json::json!({ "ok": true, "removed": removed })).into_response())
}

/// Shared core for both tag-delete routes: CSRF-check, validate, remove the tag, audit. Returns
/// whether a tag was actually removed.
async fn do_delete_tag(
    state: &AppState,
    headers: &HeaderMap,
    form: &DeleteTagForm,
) -> Result<bool, WebError> {
    if !auth::verify_csrf(headers, &form.csrf_token) {
        return Err(WebError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    if form.repo.is_empty() || form.tag.is_empty() {
        return Err(WebError::BadRequest(
            "Missing repository or tag.".to_string(),
        ));
    }
    let actor = auth::identity(headers);
    let removed = state.store.delete_tag(&form.repo, &form.tag).await?;
    tracing::info!(
        repo = form.repo,
        tag = form.tag,
        removed,
        actor = actor.subject,
        "tag delete"
    );
    Ok(removed)
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
        let stat = state.store.pull_stat(&repo.name).await?;
        out.push(RepoSummary {
            name: repo.name,
            manifest_count: manifests.len() as i64,
            tag_count: tags.len() as i64,
            total_size,
            last_pushed,
            pulls: stat.as_ref().map(|s| s.pulls).unwrap_or(0),
            last_pulled_at: stat.as_ref().map(|s| s.last_pulled_at).unwrap_or(0),
        });
    }
    // Most-recently-pushed first.
    out.sort_by(|a, b| {
        b.last_pushed
            .cmp(&a.last_pushed)
            .then_with(|| a.name.cmp(&b.name))
    });
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
    out.sort_by(|a, b| {
        b.updated_at
            .cmp(&a.updated_at)
            .then_with(|| a.tag.cmp(&b.tag))
    });
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

/// The "N pulls · last pulled X ago" line for a repository (or "Never pulled"). Surfaced on the
/// repository list and the repository detail header.
fn pull_summary(pulls: i64, last_pulled_at: i64, now: i64) -> String {
    if pulls <= 0 {
        return "Never pulled".to_string();
    }
    format!(
        "{pulls} pull{s} · last pulled {ago}",
        s = if pulls == 1 { "" } else { "s" },
        ago = time_ago(last_pulled_at, now),
    )
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
        .replace("{{THEME}}", odyssey::html_theme_attr(who.theme))
        .replace("{{COLOR_SCHEME}}", odyssey::color_scheme_meta(who.theme))
        .replace(
            "{{JS}}",
            &format!("{}\n{}\n{}", odyssey::MOTION_JS, odyssey::WIRE_JS, APP_JS),
        )
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace(
            "{{USERBOX}}",
            &userbox("Registry", Some(&who.email), who.theme),
        )
        .replace("{{HOST}}", &esc(host))
        .replace("{{COUNT}}", &esc(&count))
        .replace("{{STATBAR}}", &render_index_statbar(repos))
        .replace("{{ROWS}}", &render_repo_rows(repos, host))
}

fn render_index_statbar(repos: &[RepoSummary]) -> String {
    let total_size: i64 = repos.iter().map(|r| r.total_size).sum();
    let total_pulls: i64 = repos.iter().map(|r| r.pulls).sum();
    format!(
        "<div class=\"cl-statbar stat-grid\">\
           <div class=\"stat\"><div class=\"stat__label\">Repositories</div><div class=\"stat__value\">{repos}</div></div>\
           <div class=\"stat\"><div class=\"stat__label\">Total size</div><div class=\"stat__value\">{size}</div></div>\
           <div class=\"stat\"><div class=\"stat__label\">Total pulls</div><div class=\"stat__value\">{pulls}</div></div>\
         </div>",
        repos = repos.len(),
        size = esc(&human_size(total_size)),
        pulls = total_pulls,
    )
}

fn render_repo_rows(repos: &[RepoSummary], host: &str) -> String {
    if repos.is_empty() {
        return format!(
            "<tr class=\"empty-row\"><td colspan=\"6\">\
               <div class=\"empty\">\
                 <svg class=\"empty__icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"m12.83 2.18 8 4A2 2 0 0 1 22 8v8a2 2 0 0 1-1.17 1.82l-8 4a2 2 0 0 1-1.66 0l-8-4A2 2 0 0 1 2 16V8a2 2 0 0 1 1.17-1.82l8-4a2 2 0 0 1 1.66 0Z\"/><path d=\"m7 5 10 5\"/></svg>\
                 <div class=\"empty__title\">No images pushed yet</div>\
                 <div class=\"empty__text\">Authenticate and push your first image over the Docker Registry V2 protocol.</div>\
                 <div class=\"cmd-strip\"><span class=\"cmd-label\">Login</span><code>docker login {host}</code><button class=\"btn btn-ghost btn-sm copy-btn\" type=\"button\" data-copy=\"docker login {host}\" aria-label=\"Copy docker login command\">Copy</button></div>\
               </div>\
             </td></tr>",
            host = esc(host),
        );
    }
    let now = now_secs();
    repos
        .iter()
        .map(|r| {
            let leaf = r.name.rsplit('/').next().unwrap_or(&r.name);
            let initial = leaf.chars().next().unwrap_or('#').to_uppercase().to_string();
            let name_html = render_repo_name(&r.name);
            let pushed_abs = fmt_ts(r.last_pushed);
            let pulls = pull_summary(r.pulls, r.last_pulled_at, now);
            format!(
                "<tr>\
                   <td class=\"repo-cell\"><a href=\"/r/{name_attr}\"><span class=\"letter-tile cl-repo-tile\" aria-hidden=\"true\">{initial}</span>{name}</a></td>\
                   <td class=\"num\" data-sort-value=\"{images}\">{images}</td>\
                   <td class=\"num\" data-sort-value=\"{tags}\"><span class=\"chip\"><span class=\"countpill\">{tags}</span> tags</span></td>\
                   <td class=\"num\" data-sort-value=\"{size_bytes}\"><span class=\"pill pill-size\">{size}</span></td>\
                   <td data-sort-value=\"{pushed}\"><span class=\"cl-when\" title=\"{date}\">{ago}<small>{date}</small></span></td>\
                   <td data-sort-value=\"{pulls_n}\"><span class=\"cl-pull\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M12 3v12\"/><path d=\"m7 10 5 5 5-5\"/><path d=\"M5 21h14\"/></svg><span>{pulls}</span></span></td>\
                 </tr>",
                name_attr = esc(&r.name),
                initial = esc(&initial),
                name = name_html,
                images = r.manifest_count,
                tags = r.tag_count,
                size_bytes = r.total_size,
                size = esc(&human_size(r.total_size)),
                pushed = r.last_pushed,
                ago = esc(&time_ago(r.last_pushed, now)),
                date = esc(&pushed_abs),
                pulls_n = r.pulls,
                pulls = esc(&pulls),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_repo_name(name: &str) -> String {
    if let Some((ns, leaf)) = name.rsplit_once('/') {
        format!(
            "<span class=\"repo-name cl-name-wrap\"><span class=\"cl-ns\">{ns}/</span><span class=\"cl-leaf\">{leaf}</span></span>",
            ns = esc(ns),
            leaf = esc(leaf),
        )
    } else {
        format!(
            "<span class=\"repo-name cl-name-wrap\"><span class=\"cl-leaf\">{leaf}</span></span>",
            leaf = esc(name),
        )
    }
}

fn render_repo(
    who: &Identity,
    name: &str,
    tags: &[TagDetail],
    host: &str,
    csrf: &str,
    pulls: &str,
) -> String {
    let count = match tags.len() {
        0 => "No tags".to_string(),
        1 => "1 tag".to_string(),
        n => format!("{n} tags"),
    };
    let sample_tag = tags.first().map(|t| t.tag.as_str()).unwrap_or("latest");
    let pull_cmd = format!("docker pull {host}/{name}:{sample_tag}");
    REPO_HTML
        .replace("{{THEME}}", odyssey::html_theme_attr(who.theme))
        .replace("{{COLOR_SCHEME}}", odyssey::color_scheme_meta(who.theme))
        .replace(
            "{{JS}}",
            &format!("{}\n{}\n{}", odyssey::MOTION_JS, odyssey::WIRE_JS, APP_JS),
        )
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{LAYERS}}", LAYERS_SVG)
        .replace(
            "{{USERBOX}}",
            &userbox("Registry", Some(&who.email), who.theme),
        )
        .replace("{{NAME}}", &esc(name))
        .replace("{{COUNT}}", &esc(&count))
        .replace("{{PULLS}}", &esc(pulls))
        .replace("{{PULL_CMD}}", &esc(&pull_cmd))
        .replace("{{TAG_ROWS}}", &render_tag_rows(name, tags, csrf))
}

/// A "multi-arch" badge listing the platforms of an index / manifest-list tag; empty for a
/// single-platform image. All platform labels come from the manifest and are HTML-escaped.
fn arch_badge(platforms: &[String]) -> String {
    if platforms.is_empty() {
        return String::new();
    }
    let list = platforms
        .iter()
        .map(|p| esc(p))
        .collect::<Vec<_>>()
        .join(", ");
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

// ---------------------------------------------------------------------------
// Manifest detail view assembly + rendering
// ---------------------------------------------------------------------------

/// The computed tag/manifest detail view (not stored).
struct ManifestView {
    name: String,
    /// What the operator asked for — a tag or a digest (drives the subtitle).
    reference: String,
    /// The resolved manifest digest.
    digest: String,
    media_type: String,
    created_at: i64,
    /// Aggregate content size (config + layers, or summed child image sizes for a list).
    size: i64,
    is_list: bool,
    /// The tags in this repo that point at this manifest digest.
    tags: Vec<String>,
    /// Image manifest only: the `config` descriptor.
    config: Option<Descriptor>,
    /// Image manifest only: the ordered `layers`.
    layers: Vec<Descriptor>,
    /// Manifest list only: each child entry paired with its resolved image size (falling back to
    /// the entry's own descriptor size when the child manifest is not stored yet).
    children: Vec<(IndexEntry, i64)>,
}

/// Assemble the [`ManifestView`] from the stored manifest plus the repo's other manifests (needed to
/// resolve child image sizes for a list) and tags (to list what points at this digest).
async fn manifest_view(
    state: &AppState,
    name: &str,
    reference: &str,
    manifest: &ManifestRec,
) -> Result<ManifestView, WebError> {
    let manifests = state.store.manifests_for(name).await?;
    let tags: Vec<String> = state
        .store
        .tags_for(name)
        .await?
        .into_iter()
        .filter(|t| t.manifest_digest == manifest.digest)
        .map(|t| t.tag)
        .collect();

    let is_list = is_manifest_list(&manifest.media_type);
    let (config, layers, children) = if is_list {
        let children = index_entries(&manifest.raw)
            .into_iter()
            .map(|e| {
                let resolved = manifests
                    .iter()
                    .find(|m| m.digest == e.digest)
                    .map(|m| image_size(&m.raw))
                    .unwrap_or(e.size);
                (e, resolved)
            })
            .collect();
        (None, Vec::new(), children)
    } else {
        (
            manifest_config(&manifest.raw),
            manifest_layers(&manifest.raw),
            Vec::new(),
        )
    };

    Ok(ManifestView {
        name: name.to_string(),
        reference: reference.to_string(),
        digest: manifest.digest.clone(),
        media_type: manifest.media_type.clone(),
        created_at: manifest.created_at,
        size: resolved_size(&manifests, &manifest.digest),
        is_list,
        tags,
        config,
        layers,
        children,
    })
}

fn render_manifest(who: &Identity, v: &ManifestView, host: &str) -> String {
    let subtitle = if reference_is_digest(&v.reference) {
        "Image manifest addressed by its content digest.".to_string()
    } else {
        format!("The image tagged \"{}\" in this repository.", v.reference)
    };
    let kind = if v.is_list {
        match v.children.len() {
            1 => "manifest list · 1 platform".to_string(),
            n => format!("manifest list · {n} platforms"),
        }
    } else {
        "image manifest".to_string()
    };
    let stats = render_manifest_stats(v, &kind);
    // The canonical, fully-qualified pull command is by digest.
    let pull_cmd = format!(
        "docker pull {host}/{name}@{digest}",
        name = v.name,
        digest = v.digest
    );
    MANIFEST_HTML
        .replace("{{THEME}}", odyssey::html_theme_attr(who.theme))
        .replace("{{COLOR_SCHEME}}", odyssey::color_scheme_meta(who.theme))
        .replace(
            "{{JS}}",
            &format!("{}\n{}\n{}", odyssey::MOTION_JS, odyssey::WIRE_JS, APP_JS),
        )
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{LAYERS}}", LAYERS_SVG)
        .replace(
            "{{USERBOX}}",
            &userbox("Registry", Some(&who.email), who.theme),
        )
        .replace("{{SUBTITLE}}", &esc(&subtitle))
        .replace("{{PULL_CMD}}", &esc(&pull_cmd))
        .replace("{{KIND}}", &esc(&kind))
        .replace("{{STATS}}", &stats)
        .replace("{{DIGEST}}", &esc(&v.digest))
        .replace("{{MEDIA_TYPE}}", &esc(&v.media_type))
        .replace("{{SIZE}}", &esc(&human_size(v.size)))
        .replace("{{TAGS}}", &render_tag_chips(&v.name, &v.tags))
        .replace("{{CONTENT}}", &render_manifest_content(v))
        // Replaced LAST: {{NAME}} appears in the title, the heading, and the back-link href, and
        // no injected value can contain the literal "{{NAME}}" (names carry no braces).
        .replace("{{NAME}}", &esc(&v.name))
}

fn render_manifest_stats(v: &ManifestView, kind: &str) -> String {
    let count_label = if v.is_list { "Platforms" } else { "Layers" };
    let count = if v.is_list {
        v.children.len()
    } else {
        v.layers.len()
    };
    format!(
        "<div class=\"stat-grid\">\
           <div class=\"stat\"><div class=\"stat__label\">Total size</div><div class=\"stat__value\">{size}</div></div>\
           <div class=\"stat\"><div class=\"stat__label\">{count_label}</div><div class=\"stat__value\">{count}</div></div>\
           <div class=\"stat\"><div class=\"stat__label\">Media type</div><div class=\"stat__meta\"><span class=\"chip chip--outline\">{kind}</span></div></div>\
           <div class=\"stat\"><div class=\"stat__label\">Pushed</div><div class=\"stat__meta\">{pushed}</div></div>\
         </div>",
        size = esc(&human_size(v.size)),
        count_label = count_label,
        count = count,
        kind = esc(kind),
        pushed = esc(&fmt_ts(v.created_at)),
    )
}

/// Tag chips linking back to the repository page (where the tag can be managed). "untagged" when a
/// manifest has no tags pointing at it (e.g. an index child pushed by digest).
fn render_tag_chips(repo: &str, tags: &[String]) -> String {
    if tags.is_empty() {
        return "<span class=\"muted\">untagged</span>".to_string();
    }
    tags.iter()
        .map(|t| {
            format!(
                "<a class=\"tag-pill\" href=\"/r/{repo}\">{tag}</a>",
                repo = esc(repo),
                tag = esc(t),
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn render_manifest_content(v: &ManifestView) -> String {
    if v.is_list {
        render_children(v)
    } else {
        render_layers(v)
    }
}

/// The config + layer stack of an image manifest.
fn render_layers(v: &ManifestView) -> String {
    let config = match &v.config {
        Some(c) => format!(
            "<div class=\"cl-config\">\
               <span class=\"chip chip--outline\">{mtype}</span>\
               <span class=\"cl-config__digest\" title=\"{dfull}\"><span>{dshort}</span><button class=\"btn btn-ghost btn-sm copy-btn\" type=\"button\" data-copy=\"{dfull}\" aria-label=\"Copy config digest\">Copy</button></span>\
               <span class=\"pill pill-size\">{size}</span>\
             </div>",
            mtype = esc(&c.media_type),
            dfull = esc(&c.digest),
            dshort = esc(&short_digest(&c.digest)),
            size = esc(&human_size(c.size)),
        ),
        None => "<div class=\"cl-config muted\">No config recorded for this manifest.</div>".to_string(),
    };
    let max_layer = v.layers.iter().map(|l| l.size).max().unwrap_or(0);
    let total_size = v.config.as_ref().map(|c| c.size).unwrap_or(0)
        + v.layers.iter().map(|l| l.size).sum::<i64>();
    let mut ribbon_parts = Vec::new();
    if let Some(c) = &v.config {
        ribbon_parts.push(format!(
            "<span class=\"cl-ribbon__seg\" style=\"width:{w}%\" title=\"{digest} · {size}\"></span>",
            w = size_percent(c.size, total_size),
            digest = esc(&short_digest(&c.digest)),
            size = esc(&human_size(c.size)),
        ));
    }
    ribbon_parts.extend(v.layers.iter().map(|l| {
        format!(
            "<span class=\"cl-ribbon__seg\" style=\"width:{w}%\" title=\"{digest} · {size}\"></span>",
            w = size_percent(l.size, total_size),
            digest = esc(&short_digest(&l.digest)),
            size = esc(&human_size(l.size)),
        )
    }));
    let ribbon = if ribbon_parts.is_empty() {
        String::new()
    } else {
        format!("<div class=\"cl-ribbon\">{}</div>", ribbon_parts.join(""))
    };
    let layer_rows = if v.layers.is_empty() {
        "<li class=\"cl-layer\"><span class=\"cl-layer__idx\">—</span><span class=\"muted\">This image has no layers.</span><span></span></li>".to_string()
    } else {
        v.layers
            .iter()
            .enumerate()
            .map(|(i, l)| {
                format!(
                    "<li class=\"cl-layer\">\
                       <span class=\"cl-layer__idx\">{n}</span>\
                       <span class=\"cl-layer__main\">\
                         <span class=\"cl-layer__bar\"><i style=\"--cl-frac:{frac}%\"></i></span>\
                         <span class=\"cl-layer__meta\"><span class=\"chip chip--outline\">{mtype}</span><span class=\"cl-layer__digest\" title=\"{dfull}\">{dshort}</span><button class=\"btn btn-ghost btn-sm copy-btn\" type=\"button\" data-copy=\"{dfull}\" aria-label=\"Copy layer digest\">Copy</button></span>\
                       </span>\
                       <span class=\"cl-layer__size\">{size}</span>\
                     </li>",
                    n = i + 1,
                    frac = size_percent(l.size, max_layer),
                    mtype = esc(&l.media_type),
                    dfull = esc(&l.digest),
                    dshort = esc(&short_digest(&l.digest)),
                    size = esc(&human_size(l.size)),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let layer_count = match v.layers.len() {
        1 => "1 layer".to_string(),
        n => format!("{n} layers"),
    };
    format!(
        "<div class=\"section-head\"><h2>Config</h2></div>\
         {config}\
         <div class=\"section-head\"><h2>Layers</h2><span class=\"count-badge\">{layer_count}</span></div>\
         <div class=\"cl-composition\">{ribbon}<ul class=\"cl-layers\" data-motion-list>{layer_rows}</ul></div>",
        config = config,
        layer_count = esc(&layer_count),
        ribbon = ribbon,
        layer_rows = layer_rows,
    )
}

/// The per-platform child manifests of a manifest list / image index. Each child digest links to
/// its own manifest detail page (linking a list to the image manifests it fans out to).
fn render_children(v: &ManifestView) -> String {
    let max_size = v.children.iter().map(|(_, size)| *size).max().unwrap_or(0);
    let rows = if v.children.is_empty() {
        "<div class=\"cl-platform muted\">This manifest list has no entries.</div>".to_string()
    } else {
        v.children
            .iter()
            .map(|(e, size)| {
                let platform = if e.platform.is_empty() {
                    "<span class=\"muted\">—</span>".to_string()
                } else {
                    format!("<span class=\"chip\">{}</span>", esc(&e.platform))
                };
                format!(
                    "<div class=\"cl-platform\">\
                       <div>{platform}</div>\
                       <div class=\"cl-platform__bar\"><i style=\"--cl-frac:{frac}%\"></i></div>\
                       <div class=\"muted\">{mtype}</div>\
                       <div class=\"num\">{size}</div>\
                       <div class=\"cl-platform__digest\"><a href=\"/m/{name}?ref={dref}\" title=\"{dfull}\">{dshort}</a><button class=\"btn btn-ghost btn-sm copy-btn\" type=\"button\" data-copy=\"{dfull}\" aria-label=\"Copy platform digest\">Copy</button></div>\
                     </div>",
                    platform = platform,
                    frac = size_percent(*size, max_size),
                    name = esc(&v.name),
                    dref = esc(&url_query_value(&e.digest)),
                    dfull = esc(&e.digest),
                    dshort = esc(&short_digest(&e.digest)),
                    mtype = esc(&e.media_type),
                    size = esc(&human_size(*size)),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let count = match v.children.len() {
        1 => "1 manifest".to_string(),
        n => format!("{n} manifests"),
    };
    format!(
        "<div class=\"section-head\"><h2>Platforms</h2><span class=\"count-badge\">{count}</span></div>\
         <div class=\"cl-composition\"><div class=\"cl-matrix\" data-motion-list>{rows}</div></div>",
        count = esc(&count),
        rows = rows,
    )
}

fn size_percent(part: i64, total: i64) -> String {
    if part <= 0 || total <= 0 {
        "0".to_string()
    } else {
        format!("{:.3}", (part as f64 / total as f64) * 100.0)
    }
}

/// Percent-encode a reference for use as a `?ref=` query value. Only a digest's `:` needs escaping;
/// tags are already URL-safe. Mirrors the encoding the registry tests use for the query string.
fn url_query_value(s: &str) -> String {
    s.replace(':', "%3A")
}

/// Extract the `ref` query parameter (percent-decoding a `%3A`-escaped digest colon), if present.
fn query_ref(raw: Option<&str>) -> Option<String> {
    for pair in raw?.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == "ref" {
            return Some(percent_decode(v));
        }
    }
    None
}

/// Minimal percent-decode of a query value (`%XX` -> byte). Leaves malformed escapes untouched.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hexval(b[i + 1]), hexval(b[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
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
                   <td><a class=\"tag-pill\" href=\"/m/{repo_attr}?ref={tag_ref}\">{tag}</a></td>\
                   <td class=\"mono\" title=\"{digest_full}\"><a href=\"/m/{repo_attr}?ref={digest_ref}\">{digest_short}</a></td>\
                   <td><span class=\"chip chip--outline\">{mtype}</span>{arch}</td>\
                   <td class=\"num\" data-sort-value=\"{size_bytes}\"><span class=\"pill pill-size\">{size}</span></td>\
                   <td class=\"muted\" data-sort-value=\"{updated}\">{date}</td>\
                   <td class=\"row-action\">\
                     <form method=\"post\" action=\"/delete-tag\" data-delete-row onsubmit=\"return confirm('Delete tag {tag_js}? The image stays until garbage-collected.');\">\
                       <input type=\"hidden\" name=\"repo\" value=\"{repo_attr}\">\
                       <input type=\"hidden\" name=\"tag\" value=\"{tag_attr}\">\
                       <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                       <button class=\"btn btn-danger btn-sm\" type=\"submit\">Delete</button>\
                     </form>\
                   </td>\
                 </tr>",
                tag = esc(&t.tag),
                tag_ref = esc(&url_query_value(&t.tag)),
                digest_full = esc(&t.manifest_digest),
                digest_ref = esc(&url_query_value(&t.manifest_digest)),
                digest_short = esc(&short_digest(&t.manifest_digest)),
                mtype = esc(&t.media_type),
                arch = arch_badge(&t.platforms),
                size_bytes = t.size,
                size = esc(&human_size(t.size)),
                updated = t.updated_at,
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
