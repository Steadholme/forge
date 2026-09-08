//! The `/admin` panel: repository + tag storage accounting and Garbage Collection.
//!
//! Gated by [`auth::require_admin`] — every route in the `/admin` subtree returns 403 for a
//! signed-in user who is not in `admins` / `infra-admins`; only admins see the panel.
//!
//! Storage accounting sums the on-disk bytes the registry keeps: each manifest's raw JSON plus the
//! content-addressed blob bytes (config + layers). Blobs are shared across repos (content-addressed
//! de-dup), so the TOTAL counts every unique blob once, while each per-repo row counts the blobs its
//! own manifests reference (a shared layer therefore shows in each repo that uses it).
//!
//! Garbage Collection (`POST /admin/gc`, double-submit CSRF protected) reclaims disk that grows
//! unbounded otherwise: starting from every tag, it walks the live set — the tagged manifests, the
//! child manifests of any tagged index, and the blobs those image manifests reference — then deletes
//! every manifest row and blob (metadata + bytes) that nothing live references, reporting the bytes
//! freed. All producer-supplied text (repo names, digests) is HTML-escaped on render.

use crate::handlers::APP_CSS_PATH;
use std::collections::{HashMap, HashSet};

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::auth::{self, Identity};
use crate::error::WebError;
use crate::handlers::{admin_tabs, esc, human_size, userbox, APP_JS, SHIELD_SVG};
use crate::model::{index_child_digests, is_manifest_list, manifest_blob_digests, ManifestRec};
use crate::AppState;

const ADMIN_HTML: &str = include_str!("../../templates/admin.html");

// ---------------------------------------------------------------------------
// GET /admin — storage accounting + GC control
// ---------------------------------------------------------------------------

/// `GET /admin` — the admin panel: per-repository + total storage bytes, and a garbage-collection
/// control showing the currently reclaimable bytes. Admin-only.
pub async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, WebError> {
    auth::require_admin(&headers)?;
    let who = auth::identity(&headers);
    let view = analyze(&state).await?.view();
    let csrf = auth::new_csrf_token();
    let html = render_admin(&who, &view, &csrf, "");
    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, auth::csrf_cookie(&csrf))],
        Html(html),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// POST /admin/gc — reclaim untagged/orphaned bytes (CSRF-guarded)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct GcForm {
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /admin/gc` — double-submit CSRF-checked garbage-collection sweep. Deletes every
/// unreferenced manifest + blob (metadata AND bytes), then re-renders the panel with a notice
/// reporting what was reclaimed. Admin-only.
pub async fn gc(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<GcForm>,
) -> Result<Response, WebError> {
    auth::require_admin(&headers)?;
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(WebError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let outcome = run_gc(&state).await?;
    tracing::warn!(
        actor = who.subject,
        manifests = outcome.manifests_deleted,
        blobs = outcome.blobs_deleted,
        bytes_freed = outcome.bytes_freed,
        "admin garbage collection"
    );

    // Re-analyze so the listing reflects the post-GC state.
    let view = analyze(&state).await?.view();
    let notice = gc_notice(&outcome);
    let csrf = auth::new_csrf_token();
    let html = render_admin(&who, &view, &csrf, &notice);
    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, auth::csrf_cookie(&csrf))],
        Html(html),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Reachability analysis (shared by the listing and the GC sweep)
// ---------------------------------------------------------------------------

/// A snapshot of the registry's metadata plus the computed LIVE sets (what a tag keeps alive), from
/// which both the storage listing and the GC orphan set are derived.
struct Analysis {
    /// `(repo, manifests, tag_count)` per repository.
    repos: Vec<(String, Vec<ManifestRec>, usize)>,
    /// All recorded blobs: digest -> size.
    blob_sizes: HashMap<String, i64>,
    /// Manifests reachable from a tag (a tagged manifest, or a child of a tagged index).
    live_manifests: HashSet<(String, String)>,
    /// Blob digests any live image manifest references.
    live_blobs: HashSet<String>,
}

/// Walk the registry: load every repo's manifests + tags, then mark the live manifest/blob sets by
/// following each tag (and the children of a tagged index).
async fn analyze(state: &AppState) -> Result<Analysis, WebError> {
    let mut repos: Vec<(String, Vec<ManifestRec>, usize)> = Vec::new();
    let mut live_manifests: HashSet<(String, String)> = HashSet::new();
    let mut live_blobs: HashSet<String> = HashSet::new();

    for repo in state.store.list_repositories().await? {
        let manifests = state.store.manifests_for(&repo.name).await?;
        let tags = state.store.tags_for(&repo.name).await?;

        // Depth-first from each tag target through any index children.
        let mut stack: Vec<String> = tags.iter().map(|t| t.manifest_digest.clone()).collect();
        while let Some(digest) = stack.pop() {
            if !live_manifests.insert((repo.name.clone(), digest.clone())) {
                continue; // already visited in this repo
            }
            if let Some(rec) = manifests.iter().find(|m| m.digest == digest) {
                if is_manifest_list(&rec.media_type) {
                    stack.extend(index_child_digests(&rec.raw));
                } else {
                    for bd in manifest_blob_digests(&rec.raw) {
                        live_blobs.insert(bd);
                    }
                }
            }
        }

        repos.push((repo.name, manifests, tags.len()));
    }

    let blob_sizes = state
        .store
        .list_blobs()
        .await?
        .into_iter()
        .map(|b| (b.digest, b.size))
        .collect();

    Ok(Analysis {
        repos,
        blob_sizes,
        live_manifests,
        live_blobs,
    })
}

impl Analysis {
    /// The manifests + blobs no tag keeps alive — what GC would (or did) reclaim.
    fn orphans(&self) -> Orphans {
        let mut manifests: Vec<(String, String, i64)> = Vec::new();
        for (repo, recs, _) in &self.repos {
            for rec in recs {
                if !self
                    .live_manifests
                    .contains(&(repo.clone(), rec.digest.clone()))
                {
                    manifests.push((repo.clone(), rec.digest.clone(), rec.size));
                }
            }
        }
        let blobs: Vec<(String, i64)> = self
            .blob_sizes
            .iter()
            .filter(|(d, _)| !self.live_blobs.contains(*d))
            .map(|(d, s)| (d.clone(), *s))
            .collect();
        Orphans { manifests, blobs }
    }

    /// The storage listing: per-repo rows + totals + the reclaimable estimate.
    fn view(&self) -> AdminView {
        let mut rows: Vec<RepoStorage> = Vec::new();
        for (repo, recs, tag_count) in &self.repos {
            let manifest_bytes: i64 = recs.iter().map(|m| m.size).sum();
            // Unique blob digests this repo's manifests reference.
            let mut seen: HashSet<String> = HashSet::new();
            let mut blob_bytes = 0i64;
            for rec in recs {
                for bd in manifest_blob_digests(&rec.raw) {
                    if let Some(sz) = self.blob_sizes.get(&bd) {
                        if seen.insert(bd) {
                            blob_bytes += sz;
                        }
                    }
                }
            }
            rows.push(RepoStorage {
                name: repo.clone(),
                image_count: recs.len() as i64,
                tag_count: *tag_count as i64,
                bytes: manifest_bytes + blob_bytes,
            });
        }
        rows.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.name.cmp(&b.name)));

        let total_manifest_bytes: i64 = self
            .repos
            .iter()
            .flat_map(|(_, recs, _)| recs.iter().map(|m| m.size))
            .sum();
        let total_blob_bytes: i64 = self.blob_sizes.values().sum();

        let orphans = self.orphans();
        let reclaimable_bytes: i64 = orphans.manifests.iter().map(|(_, _, s)| *s).sum::<i64>()
            + orphans.blobs.iter().map(|(_, s)| *s).sum::<i64>();

        AdminView {
            rows,
            total_bytes: total_manifest_bytes + total_blob_bytes,
            blob_count: self.blob_sizes.len() as i64,
            reclaimable_bytes,
            reclaimable_manifests: orphans.manifests.len() as i64,
            reclaimable_blobs: orphans.blobs.len() as i64,
        }
    }
}

struct Orphans {
    /// `(repo, digest, raw_size)` of each unreferenced manifest.
    manifests: Vec<(String, String, i64)>,
    /// `(digest, size)` of each unreferenced blob.
    blobs: Vec<(String, i64)>,
}

/// The outcome of a GC sweep.
pub(crate) struct GcOutcome {
    pub(crate) manifests_deleted: i64,
    pub(crate) blobs_deleted: i64,
    pub(crate) bytes_freed: i64,
}

/// Delete every unreferenced manifest + blob (metadata AND bytes), summing the bytes freed. Shared
/// by the GC panel and by retention "Apply" (which deletes tags, then reclaims the now-orphaned
/// content through this exact path).
pub(crate) async fn run_gc(state: &AppState) -> Result<GcOutcome, WebError> {
    let orphans = analyze(state).await?.orphans();

    let mut bytes_freed = 0i64;
    let mut manifests_deleted = 0i64;
    for (repo, digest, size) in &orphans.manifests {
        if state.store.delete_manifest(repo, digest).await? {
            bytes_freed += *size;
            manifests_deleted += 1;
        }
    }

    let mut blobs_deleted = 0i64;
    for (digest, size) in &orphans.blobs {
        let removed_meta = state.store.delete_blob(digest).await?;
        // Drop the bytes too (best-effort; absent bytes are fine).
        let removed_bytes = state
            .blobs
            .delete(digest)
            .await
            .map_err(|e| WebError::Internal(e.to_string()))?;
        if removed_meta || removed_bytes {
            bytes_freed += *size;
            blobs_deleted += 1;
        }
    }

    Ok(GcOutcome {
        manifests_deleted,
        blobs_deleted,
        bytes_freed,
    })
}

// ---------------------------------------------------------------------------
// View structs + rendering
// ---------------------------------------------------------------------------

/// One repository row on the admin storage table.
struct RepoStorage {
    name: String,
    image_count: i64,
    tag_count: i64,
    bytes: i64,
}

/// The computed admin panel view.
struct AdminView {
    rows: Vec<RepoStorage>,
    total_bytes: i64,
    blob_count: i64,
    reclaimable_bytes: i64,
    reclaimable_manifests: i64,
    reclaimable_blobs: i64,
}

fn gc_notice(o: &GcOutcome) -> String {
    let body = if o.manifests_deleted == 0 && o.blobs_deleted == 0 {
        "Garbage collection ran. Nothing to reclaim — no untagged manifests or orphaned blobs."
            .to_string()
    } else {
        format!(
            "Garbage collection reclaimed {freed} — deleted {m} manifest(s) and {b} blob(s).",
            freed = human_size(o.bytes_freed),
            m = o.manifests_deleted,
            b = o.blobs_deleted,
        )
    };
    format!("<div class=\"notice notice-ok\">{}</div>", esc(&body))
}

fn render_admin(who: &Identity, view: &AdminView, csrf: &str, notice: &str) -> String {
    let repo_count = match view.rows.len() {
        0 => "No repositories".to_string(),
        1 => "1 repository".to_string(),
        n => format!("{n} repositories"),
    };
    let reclaim_line = if view.reclaimable_manifests == 0 && view.reclaimable_blobs == 0 {
        "Nothing to reclaim — every stored byte is referenced by a tag.".to_string()
    } else {
        format!(
            "{bytes} reclaimable across {m} untagged manifest(s) and {b} orphaned blob(s).",
            bytes = human_size(view.reclaimable_bytes),
            m = view.reclaimable_manifests,
            b = view.reclaimable_blobs,
        )
    };
    ADMIN_HTML
        .replace("{{CSS_PATH}}", APP_CSS_PATH)
        .replace("{{THEME}}", odyssey::html_theme_attr(who.theme))
        .replace("{{COLOR_SCHEME}}", odyssey::color_scheme_meta(who.theme))
        .replace("{{JS}}", &format!("{}\n{}", odyssey::MOTION_JS, APP_JS))
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace(
            "{{USERBOX}}",
            &userbox("Admin", Some(&who.email), who.theme),
        )
        .replace("{{TABS}}", &admin_tabs("overview"))
        .replace("{{NOTICE}}", notice)
        .replace("{{SUMMARY}}", &render_summary(view))
        .replace("{{TOTAL_SIZE}}", &esc(&human_size(view.total_bytes)))
        .replace("{{BLOB_COUNT}}", &esc(&view.blob_count.to_string()))
        .replace("{{REPO_COUNT}}", &esc(&repo_count))
        .replace("{{RECLAIM_LINE}}", &esc(&reclaim_line))
        .replace("{{CSRF}}", &esc(csrf))
        .replace("{{ROWS}}", &render_rows(&view.rows))
}

fn render_summary(view: &AdminView) -> String {
    let repo_count = view.rows.len();
    let image_count: i64 = view.rows.iter().map(|r| r.image_count).sum();
    let reclaim_frac = if view.total_bytes <= 0 || view.reclaimable_bytes <= 0 {
        "0".to_string()
    } else {
        format!(
            "{:.3}",
            (view.reclaimable_bytes as f64 / view.total_bytes as f64) * 100.0
        )
    };
    format!(
        "<div class=\"cl-summary stat-grid\">\
           <div class=\"stat\"><div class=\"stat__label\">Repositories</div><div class=\"stat__value\">{repos}</div></div>\
           <div class=\"stat\"><div class=\"stat__label\">Images</div><div class=\"stat__value\">{images}</div></div>\
           <div class=\"stat\"><div class=\"stat__label\">On disk</div><div class=\"stat__value\">{total}</div></div>\
           <div class=\"stat cl-stat--reclaim\"><div class=\"stat__label\">Reclaimable</div><div class=\"stat__value stat__val--warn\">{reclaim}</div><div class=\"cl-quota\"><i style=\"--cl-frac:{reclaim_frac}%\"></i></div></div>\
         </div>",
        repos = repo_count,
        images = image_count,
        total = esc(&human_size(view.total_bytes)),
        reclaim = esc(&human_size(view.reclaimable_bytes)),
        reclaim_frac = reclaim_frac,
    )
}

fn render_rows(rows: &[RepoStorage]) -> String {
    if rows.is_empty() {
        return "<tr class=\"empty-row\"><td colspan=\"4\">No images have been pushed yet.</td></tr>"
            .to_string();
    }
    rows.iter()
        .map(|r| {
            format!(
                "<tr>\
                   <td class=\"repo-cell\"><a href=\"/r/{name_attr}\"><span class=\"repo-name\">{name}</span></a></td>\
                   <td class=\"num\" data-sort-value=\"{images}\">{images}</td>\
                   <td class=\"num\" data-sort-value=\"{tags}\">{tags}</td>\
                   <td class=\"num\" data-sort-value=\"{bytes}\">{size}</td>\
                 </tr>",
                name_attr = esc(&r.name),
                name = esc(&r.name),
                images = r.image_count,
                tags = r.tag_count,
                bytes = r.bytes,
                size = esc(&human_size(r.bytes)),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}
