//! Git smart-HTTP protocol (`/git/{owner}/{name}.git/...`) with Loom-enforced PAT auth.
//!
//! This subtree is `auth=public` at the Sluice gateway — `git` (and `docker`) cannot speak the
//! browser OIDC/cookie SSO — so Loom does its OWN HTTP Basic auth here against a Personal Access
//! Token (username = anything, password = the PAT, verified by SHA-256 against `pats.token_hash`):
//!
//! - PUSH (`git-receive-pack`): ALWAYS requires a valid PAT owned by the repo owner.
//! - FETCH (`git-upload-pack`) of a PUBLIC repo: allowed anonymously.
//! - FETCH of a PRIVATE repo: requires a valid PAT owned by the repo owner.
//!
//! Missing/invalid credentials get `401 WWW-Authenticate: Basic`; a valid token for the wrong
//! owner gets `403`. The protocol itself is served by invoking `git http-backend` as a CGI (see
//! [`crate::gitops::GitOps::http_backend`]), which produces correct
//! `info/refs?service=...` advertisement + `git-upload-pack`/`git-receive-pack` handling.

use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::{header, HeaderMap, Method, Response, StatusCode};
use axum::response::IntoResponse;

use crate::auth;
use crate::gitops::CgiOut;
use crate::model::Pat;
use crate::AppState;

/// Which git operation a request performs (drives the auth policy).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GitOp {
    /// `git-upload-pack` — clone / fetch / pull (read).
    Fetch,
    /// `git-receive-pack` — push (write).
    Push,
}

/// `GET|POST /git/{*path}` — the single smart-HTTP entry point.
pub async fn handle(
    State(state): State<AppState>,
    method: Method,
    Path(path): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> Response<axum::body::Body> {
    let query = query.unwrap_or_default();

    // Defensive: never let a traversal sequence reach the CGI PATH_INFO.
    if path.split('/').any(|seg| seg == "..") {
        return text_response(StatusCode::NOT_FOUND, "not found");
    }

    let Some((owner, name, op)) = classify(&path, &query) else {
        return text_response(StatusCode::NOT_FOUND, "not a git repository path");
    };

    // The repo must exist in metadata (this also fixes the on-disk path to a known repo).
    let repo = match state.store.get_repo(&owner, &name).await {
        Ok(Some(r)) => r,
        Ok(None) => return text_response(StatusCode::NOT_FOUND, "repository not found"),
        Err(e) => {
            tracing::error!(error = %e, "store error in smart-http");
            return text_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };

    // --- authorization ------------------------------------------------------
    let needs_auth = op == GitOp::Push || repo.is_private;
    let mut remote_user: Option<String> = None;
    if needs_auth {
        match resolve_pat(&state, &headers).await {
            Some(pat) if pat.owner_sub == repo.owner_sub => {
                remote_user = Some(pat.owner_sub.clone());
            }
            Some(_) => {
                // Valid token, but it does not own this repository.
                return text_response(
                    StatusCode::FORBIDDEN,
                    "this token cannot access this repository",
                );
            }
            None => return unauthorized(),
        }
    }
    if op == GitOp::Push
        && repo.protect_default_branch
        && method == Method::POST
        && body_touches_branch(&body, &repo.default_branch)
    {
        tracing::warn!(
            repo = repo.id,
            branch = repo.default_branch,
            "protected branch push blocked"
        );
        return text_response(
            StatusCode::FORBIDDEN,
            "direct push to the protected default branch is blocked; use web merge",
        );
    }

    // --- run git http-backend as a CGI -------------------------------------
    let path_info = format!("/{path}");
    let mut extra: Vec<(String, String)> = vec![("REQUEST_METHOD".into(), method.as_str().into())];
    if let Some(ct) = header_str(&headers, header::CONTENT_TYPE) {
        extra.push(("CONTENT_TYPE".into(), ct));
    }
    // Propagate protocol v2 negotiation (the `Git-Protocol` request header).
    if let Some(proto) = header_str(&headers, "git-protocol") {
        extra.push(("GIT_PROTOCOL".into(), proto));
    }
    // git http-backend inflates a gzip-compressed POST body when this is set.
    if let Some(enc) = header_str(&headers, header::CONTENT_ENCODING) {
        extra.push(("HTTP_CONTENT_ENCODING".into(), enc));
    }
    if let Some(user) = remote_user {
        extra.push(("REMOTE_USER".into(), user));
    }

    match state
        .git
        .http_backend(&path_info, &query, &extra, body.to_vec())
        .await
    {
        Ok(cgi) => cgi_to_response(cgi),
        Err(e) => {
            tracing::error!(error = %e, repo = repo.id, "git http-backend failed");
            text_response(StatusCode::INTERNAL_SERVER_ERROR, "git backend error")
        }
    }
}

/// Parse `{owner}/{name}.git/{rest...}` and decide whether the request reads or writes.
fn classify(path: &str, query: &str) -> Option<(String, String, GitOp)> {
    let segs: Vec<&str> = path.split('/').collect();
    if segs.len() < 2 || segs[0].is_empty() {
        return None;
    }
    let owner = segs[0].to_string();
    let name = segs[1].strip_suffix(".git")?.to_string();
    if name.is_empty() {
        return None;
    }
    let rest = &segs[2..];

    let op = if rest.len() == 2 && rest[0] == "info" && rest[1] == "refs" {
        // Advertisement: the requested service is in the query string.
        match service_param(query).as_deref() {
            Some("git-receive-pack") => GitOp::Push,
            _ => GitOp::Fetch,
        }
    } else {
        match rest.last().copied() {
            Some("git-receive-pack") => GitOp::Push,
            Some("git-upload-pack") => GitOp::Fetch,
            // Dumb-HTTP object/HEAD reads (rare; smart clients use the packs above).
            _ => GitOp::Fetch,
        }
    };
    Some((owner, name, op))
}

/// Extract `service=...` from a raw query string.
fn service_param(query: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        if k == "service" {
            Some(v.to_string())
        } else {
            None
        }
    })
}

/// Resolve the Basic-auth password to a stored PAT (by hash), if present and valid.
async fn resolve_pat(state: &AppState, headers: &HeaderMap) -> Option<Pat> {
    let (_user, password) = auth::parse_basic_auth(headers)?;
    if password.is_empty() {
        return None;
    }
    let hash = auth::hash_token(&password);
    state.store.find_pat_by_hash(&hash).await.ok().flatten()
}

/// Translate the parsed CGI output into an axum response, forwarding git's headers verbatim.
fn cgi_to_response(cgi: CgiOut) -> Response<axum::body::Body> {
    let status = StatusCode::from_u16(cgi.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = Response::builder().status(status);
    let mut saw_content_type = false;
    for (k, v) in &cgi.headers {
        if k.eq_ignore_ascii_case("content-type") {
            saw_content_type = true;
        }
        builder = builder.header(k, v);
    }
    if !saw_content_type {
        builder = builder.header(header::CONTENT_TYPE, "application/octet-stream");
    }
    builder
        .body(axum::body::Body::from(cgi.body))
        .unwrap_or_else(|_| text_response(StatusCode::INTERNAL_SERVER_ERROR, "bad response"))
}

/// `401` with the Basic challenge so `git` prompts for credentials and retries.
fn unauthorized() -> Response<axum::body::Body> {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"Loom\"")],
        "authentication required",
    )
        .into_response()
}

fn text_response(status: StatusCode, msg: &str) -> Response<axum::body::Body> {
    (status, msg.to_string()).into_response()
}

fn header_str(headers: &HeaderMap, name: impl axum::http::header::AsHeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

fn body_touches_branch(body: &[u8], branch: &str) -> bool {
    let needle = format!("refs/heads/{branch}");
    String::from_utf8_lossy(body).contains(&needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_info_refs_fetch_and_push() {
        let (o, n, op) = classify("alice/proj.git/info/refs", "service=git-upload-pack").unwrap();
        assert_eq!((o.as_str(), n.as_str()), ("alice", "proj"));
        assert_eq!(op, GitOp::Fetch);

        let (_, _, op) = classify("alice/proj.git/info/refs", "service=git-receive-pack").unwrap();
        assert_eq!(op, GitOp::Push);
    }

    #[test]
    fn classify_rpc_endpoints() {
        assert_eq!(
            classify("o/r.git/git-receive-pack", "").unwrap().2,
            GitOp::Push
        );
        assert_eq!(
            classify("o/r.git/git-upload-pack", "").unwrap().2,
            GitOp::Fetch
        );
    }

    #[test]
    fn classify_rejects_non_git() {
        assert!(classify("justone", "").is_none());
        assert!(classify("o/r/info/refs", "").is_none()); // name lacks .git
    }

    #[test]
    fn service_param_parses() {
        assert_eq!(
            service_param("service=git-upload-pack").as_deref(),
            Some("git-upload-pack")
        );
        assert_eq!(service_param("foo=bar").as_deref(), None);
    }

    #[test]
    fn protected_branch_detection_reads_pkt_text() {
        let body = b"0000000000000000000000000000000000000000 abc refs/heads/main\0 caps";
        assert!(body_touches_branch(body, "main"));
        assert!(!body_touches_branch(body, "feature"));
    }
}
