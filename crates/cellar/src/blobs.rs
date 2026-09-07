//! Blob byte storage + upload sessions.
//!
//! `BlobStore` is an async trait with two implementations, mirroring the metadata [`crate::store`]
//! seam so the DB-free test suite needs no volume:
//! - [`MemoryBlobStore`] — in-process maps; the default for dev + tests.
//! - [`FsBlobStore`] — bytes on the mounted `CELLAR_DATA` volume.
//!
//! Finalized blobs are CONTENT-ADDRESSED at `blobs/sha256/<hex>`: the filename IS the digest, so
//! identical layers across repos collapse to one file (free de-dup) and `finalize` can VERIFY the
//! accumulated bytes hash to the digest the client claimed. A push streams chunks into an upload
//! SESSION (`uploads/<uuid>`); `finalize` hashes it, checks it against the expected digest, then
//! atomically publishes it to its content address.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;
use tokio::io::AsyncWriteExt;

use crate::digest::sha256_digest;

/// Blob/upload failure surfaced to the handler layer.
#[derive(Debug, Error)]
pub enum BlobError {
    /// No such upload session (unknown/expired uuid).
    #[error("upload session not found")]
    UploadNotFound,
    /// The accumulated bytes did not hash to the digest the client claimed.
    #[error("digest mismatch: client said {expected}, computed {actual}")]
    DigestMismatch { expected: String, actual: String },
    /// Underlying I/O failure.
    #[error("blob io error: {0}")]
    Io(String),
}

/// Content store + upload sessions. Digests are full `sha256:<hex>` strings.
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Start an upload session, returning its opaque uuid.
    async fn create_upload(&self) -> Result<String, BlobError>;

    /// Append `data` to an open session; returns the new total byte length. `UploadNotFound` when
    /// the uuid is unknown.
    async fn append(&self, uuid: &str, data: &[u8]) -> Result<u64, BlobError>;

    /// Current byte length of an open session.
    async fn upload_len(&self, uuid: &str) -> Result<u64, BlobError>;

    /// Finalize a session: hash the accumulated bytes, verify they equal `expected_digest`, then
    /// atomically publish to the content address. Returns the blob size. The session is consumed.
    async fn finalize(&self, uuid: &str, expected_digest: &str) -> Result<u64, BlobError>;

    /// Discard an open session (best-effort; absent is OK).
    async fn cancel(&self, uuid: &str) -> Result<(), BlobError>;

    /// Store `bytes` directly at `digest` after verifying their hash (the monolithic
    /// `POST ...?digest=` path). Returns the size.
    async fn put_verified(&self, digest: &str, bytes: &[u8]) -> Result<u64, BlobError>;

    /// True when a finalized blob exists at `digest`.
    async fn exists(&self, digest: &str) -> Result<bool, BlobError>;

    /// Fetch a finalized blob's bytes, or `None` when absent.
    async fn get(&self, digest: &str) -> Result<Option<Vec<u8>>, BlobError>;

    /// Delete a finalized blob's bytes. Returns `true` when a blob was removed, `false` when it was
    /// already absent (idempotent). Used only by the garbage-collection sweep to reclaim disk from
    /// blobs no live manifest references.
    async fn delete(&self, digest: &str) -> Result<bool, BlobError>;
}

/// Verify `bytes` hash to `expected_digest` (sha256 only). Returns the computed digest on success
/// for callers that want to echo it; `DigestMismatch` otherwise.
fn verify(expected_digest: &str, bytes: &[u8]) -> Result<(), BlobError> {
    let actual = sha256_digest(bytes);
    if actual == expected_digest {
        Ok(())
    } else {
        Err(BlobError::DigestMismatch {
            expected: expected_digest.to_string(),
            actual,
        })
    }
}

/// Random 32-hex-char upload-session id (OS CSPRNG).
fn new_uuid() -> String {
    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    let mut s = String::with_capacity(32);
    for byte in b {
        s.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// Split a `sha256:<hex>` digest into `(algo, hex)` for filesystem layout.
fn split_digest(digest: &str) -> Option<(&str, &str)> {
    digest.split_once(':')
}

// --------------------------------------------------------------------------------------
// In-memory blob store (default; keeps the whole service volume-free for dev + tests).
// --------------------------------------------------------------------------------------

#[derive(Default)]
struct MemInner {
    uploads: HashMap<String, Vec<u8>>,
    blobs: HashMap<String, Vec<u8>>, // digest -> bytes
}

/// In-memory [`BlobStore`]. The `Mutex` critical sections are fully synchronous (no `.await` held
/// across the guard), so the std `Mutex` is correct here.
#[derive(Default)]
pub struct MemoryBlobStore {
    inner: Mutex<MemInner>,
}

impl MemoryBlobStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl BlobStore for MemoryBlobStore {
    async fn create_upload(&self) -> Result<String, BlobError> {
        let uuid = new_uuid();
        self.inner
            .lock()
            .expect("blob lock poisoned")
            .uploads
            .insert(uuid.clone(), Vec::new());
        Ok(uuid)
    }

    async fn append(&self, uuid: &str, data: &[u8]) -> Result<u64, BlobError> {
        let mut g = self.inner.lock().expect("blob lock poisoned");
        let buf = g.uploads.get_mut(uuid).ok_or(BlobError::UploadNotFound)?;
        buf.extend_from_slice(data);
        Ok(buf.len() as u64)
    }

    async fn upload_len(&self, uuid: &str) -> Result<u64, BlobError> {
        let g = self.inner.lock().expect("blob lock poisoned");
        g.uploads
            .get(uuid)
            .map(|b| b.len() as u64)
            .ok_or(BlobError::UploadNotFound)
    }

    async fn finalize(&self, uuid: &str, expected_digest: &str) -> Result<u64, BlobError> {
        let mut g = self.inner.lock().expect("blob lock poisoned");
        let bytes = g
            .uploads
            .get(uuid)
            .cloned()
            .ok_or(BlobError::UploadNotFound)?;
        verify(expected_digest, &bytes)?;
        let size = bytes.len() as u64;
        g.blobs.entry(expected_digest.to_string()).or_insert(bytes);
        g.uploads.remove(uuid);
        Ok(size)
    }

    async fn cancel(&self, uuid: &str) -> Result<(), BlobError> {
        self.inner
            .lock()
            .expect("blob lock poisoned")
            .uploads
            .remove(uuid);
        Ok(())
    }

    async fn put_verified(&self, digest: &str, bytes: &[u8]) -> Result<u64, BlobError> {
        verify(digest, bytes)?;
        let mut g = self.inner.lock().expect("blob lock poisoned");
        g.blobs
            .entry(digest.to_string())
            .or_insert_with(|| bytes.to_vec());
        Ok(bytes.len() as u64)
    }

    async fn exists(&self, digest: &str) -> Result<bool, BlobError> {
        Ok(self
            .inner
            .lock()
            .expect("blob lock poisoned")
            .blobs
            .contains_key(digest))
    }

    async fn get(&self, digest: &str) -> Result<Option<Vec<u8>>, BlobError> {
        Ok(self
            .inner
            .lock()
            .expect("blob lock poisoned")
            .blobs
            .get(digest)
            .cloned())
    }

    async fn delete(&self, digest: &str) -> Result<bool, BlobError> {
        Ok(self
            .inner
            .lock()
            .expect("blob lock poisoned")
            .blobs
            .remove(digest)
            .is_some())
    }
}

// --------------------------------------------------------------------------------------
// Filesystem blob store (content-addressed files on the CELLAR_DATA volume).
// --------------------------------------------------------------------------------------

/// Filesystem-backed [`BlobStore`]. Finalized blobs live at `<root>/blobs/<algo>/<hex>`;
/// in-progress uploads at `<root>/uploads/<uuid>`. Publishing is atomic (write then rename), so a
/// crash never leaves a torn blob at its content address.
pub struct FsBlobStore {
    blobs_dir: PathBuf,
    uploads_dir: PathBuf,
}

impl FsBlobStore {
    /// Open the store rooted at `data_dir`, creating `blobs/` and `uploads/` as needed.
    pub async fn open(data_dir: &str) -> Result<Self, BlobError> {
        let blobs_dir = PathBuf::from(data_dir).join("blobs");
        let uploads_dir = PathBuf::from(data_dir).join("uploads");
        tokio::fs::create_dir_all(&blobs_dir)
            .await
            .map_err(|e| BlobError::Io(format!("create {}: {e}", blobs_dir.display())))?;
        tokio::fs::create_dir_all(&uploads_dir)
            .await
            .map_err(|e| BlobError::Io(format!("create {}: {e}", uploads_dir.display())))?;
        Ok(Self {
            blobs_dir,
            uploads_dir,
        })
    }

    fn upload_path(&self, uuid: &str) -> PathBuf {
        self.uploads_dir.join(uuid)
    }

    /// `<blobs>/<algo>/<hex>` for a `sha256:<hex>` digest. Returns `None` for a malformed digest.
    fn blob_path(&self, digest: &str) -> Option<PathBuf> {
        let (algo, hex) = split_digest(digest)?;
        // Defend the filesystem against a crafted digest containing path separators.
        if algo.is_empty()
            || hex.is_empty()
            || algo.contains(['/', '\\', '.'])
            || hex.contains(['/', '\\', '.'])
        {
            return None;
        }
        Some(self.blobs_dir.join(algo).join(hex))
    }

    async fn read_upload(&self, uuid: &str) -> Result<Vec<u8>, BlobError> {
        match tokio::fs::read(self.upload_path(uuid)).await {
            Ok(b) => Ok(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(BlobError::UploadNotFound),
            Err(e) => Err(BlobError::Io(format!("read upload: {e}"))),
        }
    }

    /// Atomically publish `bytes` to the content address for `digest`.
    async fn publish(&self, digest: &str, bytes: &[u8]) -> Result<(), BlobError> {
        let final_path = self
            .blob_path(digest)
            .ok_or_else(|| BlobError::Io(format!("malformed digest {digest}")))?;
        if tokio::fs::try_exists(&final_path).await.unwrap_or(false) {
            return Ok(()); // idempotent: identical bytes already published
        }
        if let Some(parent) = final_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| BlobError::Io(format!("create blob dir: {e}")))?;
        }
        let tmp = self.blobs_dir.join(format!(
            ".tmp-publish-{}-{}",
            std::process::id(),
            new_uuid()
        ));
        tokio::fs::write(&tmp, bytes)
            .await
            .map_err(|e| BlobError::Io(format!("write temp blob: {e}")))?;
        match tokio::fs::rename(&tmp, &final_path).await {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                if tokio::fs::try_exists(&final_path).await.unwrap_or(false) {
                    Ok(()) // lost a publish race — fine, same bytes
                } else {
                    Err(BlobError::Io(format!("publish blob: {e}")))
                }
            }
        }
    }
}

#[async_trait]
impl BlobStore for FsBlobStore {
    async fn create_upload(&self) -> Result<String, BlobError> {
        let uuid = new_uuid();
        tokio::fs::write(self.upload_path(&uuid), b"")
            .await
            .map_err(|e| BlobError::Io(format!("create upload: {e}")))?;
        Ok(uuid)
    }

    async fn append(&self, uuid: &str, data: &[u8]) -> Result<u64, BlobError> {
        let path = self.upload_path(uuid);
        if !tokio::fs::try_exists(&path).await.unwrap_or(false) {
            return Err(BlobError::UploadNotFound);
        }
        let mut f = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .await
            .map_err(|e| BlobError::Io(format!("open upload: {e}")))?;
        f.write_all(data)
            .await
            .map_err(|e| BlobError::Io(format!("append upload: {e}")))?;
        f.flush()
            .await
            .map_err(|e| BlobError::Io(format!("flush upload: {e}")))?;
        let meta = tokio::fs::metadata(&path)
            .await
            .map_err(|e| BlobError::Io(format!("stat upload: {e}")))?;
        Ok(meta.len())
    }

    async fn upload_len(&self, uuid: &str) -> Result<u64, BlobError> {
        match tokio::fs::metadata(self.upload_path(uuid)).await {
            Ok(m) => Ok(m.len()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(BlobError::UploadNotFound),
            Err(e) => Err(BlobError::Io(format!("stat upload: {e}"))),
        }
    }

    async fn finalize(&self, uuid: &str, expected_digest: &str) -> Result<u64, BlobError> {
        let bytes = self.read_upload(uuid).await?;
        verify(expected_digest, &bytes)?;
        let size = bytes.len() as u64;
        self.publish(expected_digest, &bytes).await?;
        let _ = tokio::fs::remove_file(self.upload_path(uuid)).await;
        Ok(size)
    }

    async fn cancel(&self, uuid: &str) -> Result<(), BlobError> {
        let _ = tokio::fs::remove_file(self.upload_path(uuid)).await;
        Ok(())
    }

    async fn put_verified(&self, digest: &str, bytes: &[u8]) -> Result<u64, BlobError> {
        verify(digest, bytes)?;
        self.publish(digest, bytes).await?;
        Ok(bytes.len() as u64)
    }

    async fn exists(&self, digest: &str) -> Result<bool, BlobError> {
        match self.blob_path(digest) {
            Some(p) => Ok(tokio::fs::try_exists(&p).await.unwrap_or(false)),
            None => Ok(false),
        }
    }

    async fn get(&self, digest: &str) -> Result<Option<Vec<u8>>, BlobError> {
        let Some(p) = self.blob_path(digest) else {
            return Ok(None);
        };
        match tokio::fs::read(&p).await {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(BlobError::Io(format!("read blob: {e}"))),
        }
    }

    async fn delete(&self, digest: &str) -> Result<bool, BlobError> {
        let Some(p) = self.blob_path(digest) else {
            return Ok(false);
        };
        match tokio::fs::remove_file(&p).await {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(BlobError::Io(format!("delete blob: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::sha256_digest;

    async fn round_trip(store: &dyn BlobStore) {
        let payload = b"a tiny image layer";
        let digest = sha256_digest(payload);

        // Chunked upload: create -> append -> append -> finalize.
        let uuid = store.create_upload().await.unwrap();
        assert_eq!(store.append(&uuid, &payload[..5]).await.unwrap(), 5);
        assert_eq!(
            store.append(&uuid, &payload[5..]).await.unwrap(),
            payload.len() as u64
        );
        assert_eq!(store.upload_len(&uuid).await.unwrap(), payload.len() as u64);
        let size = store.finalize(&uuid, &digest).await.unwrap();
        assert_eq!(size, payload.len() as u64);

        assert!(store.exists(&digest).await.unwrap());
        assert_eq!(store.get(&digest).await.unwrap().unwrap(), payload);
        // Session consumed.
        assert!(matches!(
            store.upload_len(&uuid).await,
            Err(BlobError::UploadNotFound)
        ));
    }

    #[tokio::test]
    async fn memory_round_trip() {
        round_trip(&MemoryBlobStore::new()).await;
    }

    #[tokio::test]
    async fn fs_round_trip() {
        let dir = std::env::temp_dir().join(format!("cellar-test-{}", new_uuid()));
        let store = FsBlobStore::open(dir.to_str().unwrap()).await.unwrap();
        round_trip(&store).await;
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn digest_mismatch_is_rejected() {
        let store = MemoryBlobStore::new();
        let uuid = store.create_upload().await.unwrap();
        store.append(&uuid, b"the real bytes").await.unwrap();
        let wrong = sha256_digest(b"different bytes");
        assert!(matches!(
            store.finalize(&uuid, &wrong).await,
            Err(BlobError::DigestMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn monolithic_put_verified() {
        let store = MemoryBlobStore::new();
        let payload = b"config blob";
        let digest = sha256_digest(payload);
        assert_eq!(
            store.put_verified(&digest, payload).await.unwrap(),
            payload.len() as u64
        );
        assert!(store.exists(&digest).await.unwrap());
    }
}
