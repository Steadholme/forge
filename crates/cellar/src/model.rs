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
    /// The image's content size (config + layers), bytes.
    pub size: i64,
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
}
