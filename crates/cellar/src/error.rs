//! Errors for the two surfaces.
//!
//! - [`RegError`] — the `/v2/` protocol layer. Rendered as the OCI Distribution error envelope
//!   `{"errors":[{"code","message","detail"}]}` with the spec's HTTP status + the
//!   `Docker-Distribution-Api-Version` header (and `WWW-Authenticate` on a 401). This is the shape
//!   the docker/oci clients parse.
//! - [`WebError`] — the SSO web UI. Rendered as the branded enterprise HTML error page (same
//!   app-bar + design tokens as the rest of the estate).

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use thiserror::Error;

use crate::auth::BASIC_REALM;

/// The `Docker-Distribution-Api-Version` header value advertised on every `/v2/` response.
pub const API_VERSION: &str = "registry/2.0";

/// A registry-protocol error mapped to its OCI `code` + HTTP status.
#[derive(Debug, Error)]
pub enum RegError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("denied: {0}")]
    Denied(String),
    #[error("name invalid: {0}")]
    NameInvalid(String),
    #[error("name unknown: {0}")]
    NameUnknown(String),
    #[error("blob unknown: {0}")]
    BlobUnknown(String),
    #[error("blob upload unknown: {0}")]
    BlobUploadUnknown(String),
    #[error("manifest unknown: {0}")]
    ManifestUnknown(String),
    #[error("manifest invalid: {0}")]
    ManifestInvalid(String),
    #[error("digest invalid: {0}")]
    DigestInvalid(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("not found")]
    NotFound,
    #[error("internal: {0}")]
    Internal(String),
}

impl RegError {
    /// `(status, oci_code, message)`.
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            RegError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "authentication required".to_string(),
            ),
            RegError::Denied(m) => (StatusCode::FORBIDDEN, "DENIED", m.clone()),
            RegError::NameInvalid(m) => (StatusCode::BAD_REQUEST, "NAME_INVALID", m.clone()),
            RegError::NameUnknown(m) => (StatusCode::NOT_FOUND, "NAME_UNKNOWN", m.clone()),
            RegError::BlobUnknown(m) => (StatusCode::NOT_FOUND, "BLOB_UNKNOWN", m.clone()),
            RegError::BlobUploadUnknown(m) => {
                (StatusCode::NOT_FOUND, "BLOB_UPLOAD_UNKNOWN", m.clone())
            }
            RegError::ManifestUnknown(m) => (StatusCode::NOT_FOUND, "MANIFEST_UNKNOWN", m.clone()),
            RegError::ManifestInvalid(m) => (StatusCode::BAD_REQUEST, "MANIFEST_INVALID", m.clone()),
            RegError::DigestInvalid(m) => (StatusCode::BAD_REQUEST, "DIGEST_INVALID", m.clone()),
            RegError::Unsupported(m) => (StatusCode::METHOD_NOT_ALLOWED, "UNSUPPORTED", m.clone()),
            RegError::NotFound => (StatusCode::NOT_FOUND, "NOT_FOUND", "not found".to_string()),
            RegError::Internal(m) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                m.clone(),
            ),
        }
    }
}

impl IntoResponse for RegError {
    fn into_response(self) -> Response {
        let (status, code, message) = self.parts();
        let body = serde_json::json!({
            "errors": [ { "code": code, "message": message, "detail": serde_json::Value::Null } ]
        })
        .to_string();

        let mut resp = (status, body).into_response();
        let h = resp.headers_mut();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        h.insert(
            "Docker-Distribution-Api-Version",
            HeaderValue::from_static(API_VERSION),
        );
        if status == StatusCode::UNAUTHORIZED {
            // The challenge the docker client needs in order to supply Basic credentials.
            if let Ok(v) = HeaderValue::from_str(&format!("Basic realm=\"{BASIC_REALM}\"")) {
                h.insert(header::WWW_AUTHENTICATE, v);
            }
        }
        resp
    }
}

impl From<crate::store::StoreError> for RegError {
    fn from(e: crate::store::StoreError) -> Self {
        RegError::Internal(e.to_string())
    }
}

impl From<crate::blobs::BlobError> for RegError {
    fn from(e: crate::blobs::BlobError) -> Self {
        use crate::blobs::BlobError;
        match e {
            BlobError::UploadNotFound => {
                RegError::BlobUploadUnknown("no such upload session".to_string())
            }
            BlobError::DigestMismatch { expected, actual } => RegError::DigestInvalid(format!(
                "provided digest {expected} did not match computed {actual}"
            )),
            BlobError::Io(m) => RegError::Internal(m),
        }
    }
}

// ---------------------------------------------------------------------------
// Web UI error (branded HTML page)
// ---------------------------------------------------------------------------

/// A web-UI error rendered as the branded enterprise error page.
#[derive(Debug, Error)]
pub enum WebError {
    #[error("bad_request: {0}")]
    BadRequest(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("not_found: {0}")]
    NotFound(String),
    #[error("server_error: {0}")]
    Internal(String),
}

impl WebError {
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            WebError::BadRequest(d) => (StatusCode::BAD_REQUEST, "Request rejected", d.clone()),
            WebError::Forbidden(d) => (StatusCode::FORBIDDEN, "Forbidden", d.clone()),
            WebError::NotFound(d) => (StatusCode::NOT_FOUND, "Not found", d.clone()),
            WebError::Internal(d) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                d.clone(),
            ),
        }
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        let (status, heading, message) = self.parts();
        crate::handlers::render_error(status, heading, &message, None).into_response()
    }
}

impl From<crate::store::StoreError> for WebError {
    fn from(e: crate::store::StoreError) -> Self {
        WebError::Internal(e.to_string())
    }
}
