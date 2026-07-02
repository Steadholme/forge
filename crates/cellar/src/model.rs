//! Core domain types mirroring the `cellar` database schema, plus the small view structs the web
//! UI renders.
//!
//! Storage layers:
//! - `repositories(name PK, created_at)` — one row per pushed repository.
//! - `manifests(id PK, repo, digest, media_type, raw, size, created_at, UNIQUE(repo,digest))` —
//!   the manifest JSON (`raw`) addressed by its sha256 `digest`; `media_type` is the stored
//!   `Content-Type` so a pull returns it verbatim. `id` is `"{repo}@{digest}"`.
//! - `tags(repo, tag, manifest_digest, updated_at, PRIMARY KEY(repo,tag))` — a mutable tag
//!   pointer to a manifest digest.
//! - `blobs(digest PK, size, created_at)` — content-addressed blob metadata; the bytes live on
//!   the `CELLAR_DATA` volume at `blobs/sha256/<hex>`.

// --------------------------------------------------------------------------------------
// Manifest media types.
//
// A registry stores two shapes of manifest under the SAME `/v2/{name}/manifests/{ref}` path,
// distinguished only by their `Content-Type`:
//   * an *image manifest* — one platform's config + layers, and
//   * a *manifest list / image index* — a multi-arch fan-out that points at several image
//     manifests by digest, each tagged with its `platform` (os/arch). `docker push` of a
//     multi-arch build sends the per-arch image manifests BY DIGEST first, then the index BY TAG;
//     `docker pull` on any arch fetches the index, picks its platform's child digest, and pulls
//     that image manifest. Both are stored verbatim (content-addressed by their sha256) and served
//     back with the stored media type — so the arch selection happens entirely on the client.
// --------------------------------------------------------------------------------------

/// Docker image manifest, schema 2 (single platform).
pub const MEDIA_DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
/// OCI image manifest (single platform).
pub const MEDIA_OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
/// Docker manifest list, schema 2 (multi-arch fan-out).
pub const MEDIA_DOCKER_MANIFEST_LIST: &str =
    "application/vnd.docker.distribution.manifest.list.v2+json";
/// OCI image index (multi-arch fan-out).
pub const MEDIA_OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";

/// True when `media_type` is a manifest type this registry accepts on a `PUT` (image manifest or
/// multi-arch index / manifest list).
pub fn is_manifest_media_type(media_type: &str) -> bool {
    matches!(
        media_type,
        MEDIA_DOCKER_MANIFEST | MEDIA_OCI_MANIFEST | MEDIA_DOCKER_MANIFEST_LIST | MEDIA_OCI_INDEX
    )
}

/// True when `media_type` is a multi-arch manifest list / image index (fans out to per-platform
/// image manifests) rather than a single-platform image manifest.
pub fn is_manifest_list(media_type: &str) -> bool {
    media_type == MEDIA_DOCKER_MANIFEST_LIST || media_type == MEDIA_OCI_INDEX
}

/// The `os/arch[/variant]` labels of the entries in a manifest list / image index `raw` JSON.
/// Attestation / unknown-platform entries (`architecture: "unknown"`) are skipped so only real
/// runnable platforms surface. Empty for a non-index document.
pub fn index_platforms(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
        if let Some(arr) = v.get("manifests").and_then(|m| m.as_array()) {
            for m in arr {
                let p = m.get("platform");
                let os = p.and_then(|p| p.get("os")).and_then(|s| s.as_str()).unwrap_or("");
                let arch = p
                    .and_then(|p| p.get("architecture"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("");
                if os == "unknown" || arch == "unknown" || (os.is_empty() && arch.is_empty()) {
                    continue;
                }
                let variant = p
                    .and_then(|p| p.get("variant"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("");
                if variant.is_empty() {
                    out.push(format!("{os}/{arch}"));
                } else {
                    out.push(format!("{os}/{arch}/{variant}"));
                }
            }
        }
    }
    out
}

/// The blob digests an IMAGE manifest references: its `config.digest` plus every `layers[].digest`.
/// These are the content-addressed blob bytes on the volume the manifest keeps alive. Empty for a
/// manifest list / image index (which references child manifests, not blobs) or a malformed
/// document. Used by garbage collection to compute the live blob set.
pub fn manifest_blob_digests(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
        if let Some(d) = v.get("config").and_then(|c| c.get("digest")).and_then(|s| s.as_str()) {
            out.push(d.to_string());
        }
        if let Some(layers) = v.get("layers").and_then(|l| l.as_array()) {
            for l in layers {
                if let Some(d) = l.get("digest").and_then(|s| s.as_str()) {
                    out.push(d.to_string());
                }
            }
        }
    }
    out
}

/// The child image-manifest digests referenced by a manifest list / image index `raw` JSON.
/// Empty for a non-index document.
pub fn index_child_digests(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
        if let Some(arr) = v.get("manifests").and_then(|m| m.as_array()) {
            for m in arr {
                if let Some(d) = m.get("digest").and_then(|s| s.as_str()) {
                    out.push(d.to_string());
                }
            }
        }
    }
    out
}

/// One content descriptor from an image manifest: the `config` object or a `layers[]` entry. The
/// `mediaType`/`digest`/`size` are carried IN the manifest JSON, so rendering the detail page needs
/// no blob lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub media_type: String,
    pub digest: String,
    pub size: i64,
}

/// The `config` descriptor of an IMAGE manifest, or `None` for an index / malformed document.
pub fn manifest_config(raw: &str) -> Option<Descriptor> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    descriptor_from(v.get("config")?)
}

/// The `layers[]` descriptors of an IMAGE manifest, in order. Empty for an index / malformed doc.
pub fn manifest_layers(raw: &str) -> Vec<Descriptor> {
    let mut out = Vec::new();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
        if let Some(arr) = v.get("layers").and_then(|l| l.as_array()) {
            for l in arr {
                if let Some(d) = descriptor_from(l) {
                    out.push(d);
                }
            }
        }
    }
    out
}

/// Parse a `{mediaType,digest,size}` descriptor object. Requires a `digest`; the `mediaType`/`size`
/// default to empty/0 when absent.
fn descriptor_from(v: &serde_json::Value) -> Option<Descriptor> {
    let digest = v.get("digest").and_then(|s| s.as_str())?;
    Some(Descriptor {
        media_type: v.get("mediaType").and_then(|s| s.as_str()).unwrap_or("").to_string(),
        digest: digest.to_string(),
        size: v.get("size").and_then(|s| s.as_i64()).unwrap_or(0),
    })
}

/// One child entry of a manifest list / image index: the referenced image-manifest `digest` plus
/// its declared `mediaType`, `size` and `os/arch[/variant]` platform (empty when absent/unknown).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexEntry {
    pub digest: String,
    pub media_type: String,
    pub size: i64,
    /// `os/arch[/variant]`, or empty when the entry carries no (or an unknown) platform.
    pub platform: String,
}

/// The child entries of a manifest list / image index `raw` JSON, in order. Empty for a
/// non-index / malformed document. Unlike [`index_platforms`], attestation / unknown-platform
/// entries are KEPT (with an empty `platform`) so the detail page reflects the document verbatim.
pub fn index_entries(raw: &str) -> Vec<IndexEntry> {
    let mut out = Vec::new();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
        if let Some(arr) = v.get("manifests").and_then(|m| m.as_array()) {
            for m in arr {
                let Some(digest) = m.get("digest").and_then(|s| s.as_str()) else {
                    continue;
                };
                let p = m.get("platform");
                let os = p.and_then(|p| p.get("os")).and_then(|s| s.as_str()).unwrap_or("");
                let arch = p
                    .and_then(|p| p.get("architecture"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("");
                let variant = p
                    .and_then(|p| p.get("variant"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("");
                let platform = if os == "unknown" || arch == "unknown" || (os.is_empty() && arch.is_empty()) {
                    String::new()
                } else if variant.is_empty() {
                    format!("{os}/{arch}")
                } else {
                    format!("{os}/{arch}/{variant}")
                };
                out.push(IndexEntry {
                    digest: digest.to_string(),
                    media_type: m.get("mediaType").and_then(|s| s.as_str()).unwrap_or("").to_string(),
                    size: m.get("size").and_then(|s| s.as_i64()).unwrap_or(0),
                    platform,
                });
            }
        }
    }
    out
}

/// One pushed repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repository {
    pub name: String,
    pub created_at: i64,
}

// --------------------------------------------------------------------------------------
// Harbor-style operator/consumer features: pull statistics, retention rules, robot accounts.
// --------------------------------------------------------------------------------------

/// Robot scope: pull-only, or push AND pull. Stored verbatim in `robot_accounts.scope`.
pub const ROBOT_SCOPE_PULL: &str = "pull";
pub const ROBOT_SCOPE_PUSHPULL: &str = "pushpull";

/// True when `scope` is a recognised robot scope string.
pub fn is_valid_robot_scope(scope: &str) -> bool {
    scope == ROBOT_SCOPE_PULL || scope == ROBOT_SCOPE_PUSHPULL
}

/// Match a repository name against a retention/robot `repo_pattern`: an exact name, or a
/// `prefix*` glob (only a single trailing `*` is significant). A bare `*` matches every repo.
pub fn repo_pattern_matches(pattern: &str, repo: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => repo.starts_with(prefix),
        None => repo == pattern,
    }
}

/// Per-repository pull statistics: how many real `/v2/` manifest GETs a repo has served, and when
/// the most recent one landed. Mirrors `pull_stats(repo PK, pulls, last_pulled_at)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PullStat {
    pub repo: String,
    pub pulls: i64,
    /// Epoch seconds of the most recent pull (0 = never, though a row only exists once pulled).
    pub last_pulled_at: i64,
}

/// A retention rule. Tags in a repo matching `repo_pattern` are KEPT when they are among the
/// newest `keep_last` tags OR were pushed within `keep_days` days (0 = ignore that dimension);
/// anything else is a deletion candidate. Mirrors
/// `retention_rules(id PK, repo_pattern, keep_last, keep_days, enabled)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionRule {
    pub id: String,
    pub repo_pattern: String,
    pub keep_last: i64,
    pub keep_days: i64,
    pub enabled: bool,
}

/// A robot account — an ADDITIONAL `/v2/` credential (alongside the human `CELLAR_USER`), scoped to
/// pull or pushpull on repos matching `repo_pattern`. The secret is shown once at mint time; only
/// its `token_hash` (sha256 hex) is stored. Mirrors `robot_accounts(id PK, name, token_hash, scope,
/// repo_pattern, enabled, created_at, last_used_at)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RobotAccount {
    pub id: String,
    /// The bare robot name; the `/v2/` Basic username is `robot$<name>`.
    pub name: String,
    /// sha256 hex of the minted token (never the token itself).
    pub token_hash: String,
    /// [`ROBOT_SCOPE_PULL`] or [`ROBOT_SCOPE_PUSHPULL`].
    pub scope: String,
    pub repo_pattern: String,
    pub enabled: bool,
    pub created_at: i64,
    /// Epoch seconds of the last authenticated use (0 = never used).
    pub last_used_at: i64,
}

impl RobotAccount {
    /// Whether this (enabled) robot is permitted to WRITE (push) to `repo`.
    pub fn may_push(&self, repo: &str) -> bool {
        self.enabled
            && self.scope == ROBOT_SCOPE_PUSHPULL
            && repo_pattern_matches(&self.repo_pattern, repo)
    }
}

/// A stored manifest (the JSON document a tag/digest resolves to).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestRec {
    /// `"{repo}@{digest}"` — primary key.
    pub id: String,
    pub repo: String,
    /// `sha256:<hex>` of `raw`.
    pub digest: String,
    /// Stored `Content-Type` (e.g. `application/vnd.oci.image.manifest.v1+json`).
    pub media_type: String,
    /// The verbatim manifest JSON bytes (UTF-8).
    pub raw: String,
    /// Length of `raw` in bytes.
    pub size: i64,
    pub created_at: i64,
}

impl ManifestRec {
    /// Compose the primary key from a repo + digest.
    pub fn make_id(repo: &str, digest: &str) -> String {
        format!("{repo}@{digest}")
    }
}

/// A mutable tag pointer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagRec {
    pub repo: String,
    pub tag: String,
    pub manifest_digest: String,
    pub updated_at: i64,
}

/// Content-addressed blob metadata (bytes on the volume).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobRec {
    pub digest: String,
    pub size: i64,
    pub created_at: i64,
}

// --------------------------------------------------------------------------------------
// View structs (computed for the SSO web UI; not stored).
// --------------------------------------------------------------------------------------

/// A repository row on the index page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoSummary {
    pub name: String,
    /// Number of distinct manifests (images) pushed.
    pub manifest_count: i64,
    /// Number of tags.
    pub tag_count: i64,
    /// Sum of per-tag image sizes (config + layers), bytes.
    pub total_size: i64,
    /// Most recent push time (max of manifest/tag timestamps), epoch seconds.
    pub last_pushed: i64,
    /// Total real `/v2/` manifest GETs this repo has served.
    pub pulls: i64,
    /// Epoch seconds of the most recent pull (0 = never pulled).
    pub last_pulled_at: i64,
}

/// A tag row on the repository detail page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagDetail {
    pub tag: String,
    pub manifest_digest: String,
    pub media_type: String,
    /// The image's content size (config + layers), bytes. For a multi-arch tag this is the sum of
    /// its per-platform image sizes.
    pub size: i64,
    /// `os/arch[/variant]` labels when the tag points at a multi-arch index / manifest list; empty
    /// for a single-platform image.
    pub platforms: Vec<String>,
    pub updated_at: i64,
}

/// Compute an image's on-disk size from its manifest JSON: `config.size` + sum of `layers[].size`.
/// Those sizes are carried IN the manifest, so no blob lookup is needed. Falls back to the raw
/// manifest length for documents without that shape (e.g. a manifest list / image index).
pub fn image_size(raw: &str) -> i64 {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
        let mut total: i64 = 0;
        if let Some(c) = v.get("config").and_then(|c| c.get("size")).and_then(|s| s.as_i64()) {
            total += c;
        }
        if let Some(layers) = v.get("layers").and_then(|l| l.as_array()) {
            for l in layers {
                if let Some(s) = l.get("size").and_then(|s| s.as_i64()) {
                    total += s;
                }
            }
        }
        if total > 0 {
            return total;
        }
    }
    raw.len() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_size_sums_config_and_layers() {
        let raw = r#"{"schemaVersion":2,"config":{"size":1000},"layers":[{"size":2000},{"size":500}]}"#;
        assert_eq!(image_size(raw), 3500);
    }

    #[test]
    fn image_size_falls_back_to_raw_len() {
        let raw = r#"{"schemaVersion":2,"manifests":[{"digest":"sha256:x"}]}"#;
        assert_eq!(image_size(raw), raw.len() as i64);
    }

    #[test]
    fn classifies_manifest_media_types() {
        assert!(is_manifest_media_type(MEDIA_OCI_MANIFEST));
        assert!(is_manifest_media_type(MEDIA_DOCKER_MANIFEST));
        assert!(is_manifest_media_type(MEDIA_OCI_INDEX));
        assert!(is_manifest_media_type(MEDIA_DOCKER_MANIFEST_LIST));
        assert!(!is_manifest_media_type("text/plain"));
        assert!(!is_manifest_media_type("application/octet-stream"));

        assert!(is_manifest_list(MEDIA_OCI_INDEX));
        assert!(is_manifest_list(MEDIA_DOCKER_MANIFEST_LIST));
        assert!(!is_manifest_list(MEDIA_OCI_MANIFEST));
    }

    #[test]
    fn parses_index_platforms_and_children() {
        let raw = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json",
            "manifests":[
              {"digest":"sha256:aaa","platform":{"os":"linux","architecture":"amd64"}},
              {"digest":"sha256:bbb","platform":{"os":"linux","architecture":"arm64","variant":"v8"}},
              {"digest":"sha256:ccc","platform":{"os":"unknown","architecture":"unknown"}}
            ]}"#;
        assert_eq!(index_platforms(raw), vec!["linux/amd64", "linux/arm64/v8"]);
        assert_eq!(
            index_child_digests(raw),
            vec!["sha256:aaa", "sha256:bbb", "sha256:ccc"]
        );

        // A single-platform image manifest has no children / platforms.
        let img = r#"{"schemaVersion":2,"config":{"size":1},"layers":[]}"#;
        assert!(index_platforms(img).is_empty());
        assert!(index_child_digests(img).is_empty());
    }

    #[test]
    fn parses_config_and_layers() {
        let raw = r#"{"schemaVersion":2,
            "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:cfg","size":1000},
            "layers":[
              {"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:l1","size":2000},
              {"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:l2","size":500}
            ]}"#;
        let config = manifest_config(raw).unwrap();
        assert_eq!(config.digest, "sha256:cfg");
        assert_eq!(config.size, 1000);
        assert_eq!(config.media_type, "application/vnd.oci.image.config.v1+json");
        let layers = manifest_layers(raw);
        assert_eq!(layers.len(), 2);
        assert_eq!(layers[0].digest, "sha256:l1");
        assert_eq!(layers[0].size, 2000);
        assert_eq!(layers[1].size, 500);

        // An index has no config / layers.
        let idx = r#"{"schemaVersion":2,"manifests":[{"digest":"sha256:x"}]}"#;
        assert!(manifest_config(idx).is_none());
        assert!(manifest_layers(idx).is_empty());
    }

    #[test]
    fn repo_pattern_exact_and_prefix() {
        // Exact match.
        assert!(repo_pattern_matches("library/app", "library/app"));
        assert!(!repo_pattern_matches("library/app", "library/app2"));
        assert!(!repo_pattern_matches("library/app", "library/ap"));
        // Prefix glob.
        assert!(repo_pattern_matches("library/*", "library/app"));
        assert!(repo_pattern_matches("library/*", "library/nested/app"));
        assert!(!repo_pattern_matches("library/*", "other/app"));
        // A bare `*` matches everything.
        assert!(repo_pattern_matches("*", "anything/at/all"));
    }

    #[test]
    fn robot_scope_and_push_gate() {
        assert!(is_valid_robot_scope(ROBOT_SCOPE_PULL));
        assert!(is_valid_robot_scope(ROBOT_SCOPE_PUSHPULL));
        assert!(!is_valid_robot_scope("admin"));

        let base = RobotAccount {
            id: "r1".into(),
            name: "ci".into(),
            token_hash: "h".into(),
            scope: ROBOT_SCOPE_PUSHPULL.into(),
            repo_pattern: "team/*".into(),
            enabled: true,
            created_at: 0,
            last_used_at: 0,
        };
        assert!(base.may_push("team/app"));
        assert!(!base.may_push("other/app")); // pattern miss
        let pull_only = RobotAccount { scope: ROBOT_SCOPE_PULL.into(), ..base.clone() };
        assert!(!pull_only.may_push("team/app")); // pull scope never pushes
        let disabled = RobotAccount { enabled: false, ..base.clone() };
        assert!(!disabled.may_push("team/app")); // disabled never pushes
    }

    #[test]
    fn parses_index_entries_with_platform_and_size() {
        let raw = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json",
            "manifests":[
              {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaa","size":11,"platform":{"os":"linux","architecture":"amd64"}},
              {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bbb","size":22,"platform":{"os":"linux","architecture":"arm64","variant":"v8"}},
              {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:ccc","size":33,"platform":{"os":"unknown","architecture":"unknown"}}
            ]}"#;
        let entries = index_entries(raw);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].platform, "linux/amd64");
        assert_eq!(entries[0].size, 11);
        assert_eq!(entries[1].platform, "linux/arm64/v8");
        // Unknown-platform child is kept but with an empty platform label.
        assert_eq!(entries[2].digest, "sha256:ccc");
        assert_eq!(entries[2].platform, "");

        // An image manifest yields no index entries.
        let img = r#"{"schemaVersion":2,"config":{"size":1},"layers":[]}"#;
        assert!(index_entries(img).is_empty());
    }
}
