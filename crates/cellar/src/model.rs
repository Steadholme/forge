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

/// One pushed repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repository {
    pub name: String,
    pub created_at: i64,
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
}
