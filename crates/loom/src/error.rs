//! Application errors, rendered as branded HTML pages.
//!
//! Loom's WEB surface is browser-facing, so a failure renders the enterprise error page (same
//! app-bar + design tokens) rather than a JSON envelope. The git smart-HTTP routes do NOT use
//! this type — they speak the git protocol and return protocol-appropriate status codes.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    /// Malformed/rejected request (e.g. CSRF mismatch, invalid repo name).
    #[error("bad_request: {0}")]
    BadRequest(String),

    /// Authenticated but not allowed (e.g. acting on another user's private repo).
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// No such repo / issue / page.
    #[error("not_found: {0}")]
    NotFound(String),

    /// Name collision (repo already exists).
    #[error("conflict: {0}")]
    Conflict(String),

    /// Unexpected internal failure (store or git I/O).
    #[error("server_error: {0}")]
    Internal(String),
}

impl AppError {
    /// Map to `(status, heading, message)` for the rendered error page.
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            AppError::BadRequest(d) => (StatusCode::BAD_REQUEST, "Request rejected", d.clone()),
            AppError::Forbidden(d) => (StatusCode::FORBIDDEN, "Not allowed", d.clone()),
            AppError::NotFound(d) => (StatusCode::NOT_FOUND, "Not found", d.clone()),
            AppError::Conflict(d) => (StatusCode::CONFLICT, "Already exists", d.clone()),
            AppError::Internal(d) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                d.clone(),
            ),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, heading, message) = self.parts();
        crate::handlers::render_error(status, heading, &message, None).into_response()
    }
}

/// Store failures collapse to a 500 server_error.
impl From<crate::store::StoreError> for AppError {
    fn from(e: crate::store::StoreError) -> Self {
        AppError::Internal(e.to_string())
    }
}
