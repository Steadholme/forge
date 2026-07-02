//! The `/v2/` OCI Distribution / Docker Registry HTTP API V2.
//!
//! This is the CLI protocol surface: the gateway routes `registry.w33d.xyz/v2/` as `auth=public`,
//! and Cellar does its OWN HTTP Basic auth here (see [`crate::auth`]) — because `docker` does not
//! speak the browser OIDC/cookie SSO. Repository names may contain slashes, which axum's path
//! matcher cannot mix with fixed suffixes (`/blobs/{digest}`), so every `/v2/{*path}` request is
//! routed to one [`dispatch`] that parses the path itself and fans out to the per-endpoint logic.
//!
//! Endpoints: `GET /v2/` (version/auth probe); blob upload (`POST` init -> `PATCH` chunks -> `PUT`
//! finalize, or monolithic `POST ?digest=`); `HEAD`/`GET /v2/{name}/blobs/{digest}`; manifest
//! `PUT`/`GET`/`HEAD /v2/{name}/manifests/{reference}`; `GET /v2/{name}/tags/list`;
//! `GET /v2/_catalog`. Auth rule: writes (and the `GET /v2/` probe) REQUIRE valid Basic creds;
//! reads serve anonymously when no creds are sent (public pull) but reject WRONG creds.

use axum::body::{Body, Bytes};
use axum::extract::{Path, RawQuery, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::auth::{self, HEADER_SUBJECT};
use crate::digest::{is_valid_digest, sha256_digest};
use crate::error::{RegError, API_VERSION};
use crate::model::{is_manifest_media_type, ManifestRec, RobotAccount, MEDIA_OCI_MANIFEST};
use crate::names::{is_valid_name, is_valid_reference, reference_is_digest};
use crate::{now_secs, AppState};

/// Default manifest media type when a `PUT` omits `Content-Type` (rare — clients always send it).
const DEFAULT_MANIFEST_TYPE: &str = MEDIA_OCI_MANIFEST;

const H_CONTENT_DIGEST: &str = "docker-content-digest";
const H_UPLOAD_UUID: &str = "docker-upload-uuid";
const H_API_VERSION: &str = "docker-distribution-api-version";

// ---------------------------------------------------------------------------
// GET /v2/ — version check + auth probe (the docker login target)
// ---------------------------------------------------------------------------

/// `GET|HEAD /v2/` — 200 with the API-version header when authenticated; otherwise a 401 Basic
/// challenge. This is what `docker login` validates against, and what makes any client attach its
/// stored credentials before pushing. A valid ROBOT token authenticates here too (a robot
/// `docker login` succeeds).
pub async fn version_check(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match authenticate(&state, &headers).await {
        Principal::Human | Principal::Robot(_) => build(StatusCode::OK, vec![json_ct()], b"{}".to_vec()),
        _ => RegError::Unauthorized.into_response(),
    }
}

// ---------------------------------------------------------------------------
// Principal resolution — the human path PLUS the additional robot credential
// ---------------------------------------------------------------------------

/// Who is making a `/v2/` request, after checking credentials. Robots are an ADDITIONAL credential
/// layered on the unchanged human `CELLAR_USER` Basic path — a robot NEVER weakens it.
enum Principal {
    /// The configured human credentials, or auth disabled (dev). Full push/pull on every repo.
    Human,
    /// A verified, enabled robot account (its scope + repo_pattern gate writes).
    Robot(RobotAccount),
    /// No `Authorization` header — anonymous (public reads; challenged on writes).
    Anonymous,
    /// Credentials present but invalid (wrong human password, unknown/disabled robot).
    Bad,
}

/// Resolve the request's [`Principal`].
///
/// Order preserves the existing behaviour exactly: when auth is DISABLED everything is [`Human`];
/// otherwise the human `CELLAR_USER`/`CELLAR_PASSWORD` Basic check runs FIRST (unchanged). Only when
/// that does not match do we try the robot paths — `robot$<name>` Basic, or a `Bearer` token — so a
/// robot is purely additive. `last_used_at` is stamped whenever a robot token verifies.
async fn authenticate(state: &AppState, headers: &HeaderMap) -> Principal {
    // Auth disabled (empty CELLAR_USER, the dev default): every request is Human, exactly as before.
    if !state.config.auth_enabled() {
        return Principal::Human;
    }

    // Basic first — the human path is checked before any robot lookup.
    if let Some((user, pass)) = auth::basic_credentials(headers) {
        if auth::human_basic_ok(&user, &pass, &state.config) {
            return Principal::Human;
        }
        if let Some(name) = user.strip_prefix(auth::ROBOT_USER_PREFIX) {
            if let Some(robot) = verify_robot_secret(state, name, &pass).await {
                return Principal::Robot(robot);
            }
        }
        return Principal::Bad; // credentials present but neither human nor a valid robot
    }

    // Bearer — a robot token presented without a username.
    if let Some(token) = auth::bearer_token(headers) {
        if let Some(robot) = verify_robot_bearer(state, &token).await {
            return Principal::Robot(robot);
        }
        return Principal::Bad;
    }

    Principal::Anonymous
}

/// Verify a `robot$<name>` Basic secret against its stored hash; stamp `last_used_at` on success.
async fn verify_robot_secret(state: &AppState, name: &str, secret: &str) -> Option<RobotAccount> {
    let robot = state.store.get_robot_by_name(name).await.ok()??;
    if robot.enabled && auth::token_matches(secret, &robot.token_hash) {
        let _ = state.store.touch_robot(&robot.id, now_secs()).await;
        Some(robot)
    } else {
        None
    }
}

/// Verify a `Bearer` robot token by scanning enabled robots for a matching hash; stamp on success.
async fn verify_robot_bearer(state: &AppState, token: &str) -> Option<RobotAccount> {
    for robot in state.store.list_robots().await.ok()? {
        if robot.enabled && auth::token_matches(token, &robot.token_hash) {
            let _ = state.store.touch_robot(&robot.id, now_secs()).await;
            return Some(robot);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Catch-all dispatch for everything under /v2/
// ---------------------------------------------------------------------------

/// Parse `/v2/{*path}` + method, then route. Errors render as the OCI error envelope.
pub async fn dispatch(
    State(state): State<AppState>,
    method: Method,
    Path(path): Path<String>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let principal = authenticate(&state, &headers).await;
    let route = parse_route(&path);
    let query = parse_query(raw_query.as_deref().unwrap_or(""));
    match handle(&state, &method, route, &headers, &principal, &query, body).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

/// The parsed registry route (repository name reconstructed from the leading path components).
enum Route {
    Catalog,
    TagsList { name: String },
    UploadInit { name: String },
    UploadSession { name: String, uuid: String },
    Blob { name: String, digest: String },
    Manifest { name: String, reference: String },
    Unknown,
}

fn parse_route(path: &str) -> Route {
    let trimmed = path.trim_matches('/');
    let parts: Vec<&str> = if trimmed.is_empty() {
        Vec::new()
    } else {
        trimmed.split('/').collect()
    };
    let n = parts.len();

    if n == 1 && parts[0] == "_catalog" {
        return Route::Catalog;
    }
    if n >= 3 && parts[n - 2] == "tags" && parts[n - 1] == "list" {
        return Route::TagsList {
            name: parts[..n - 2].join("/"),
        };
    }
    // .../blobs/uploads  or  .../blobs/uploads/{uuid}
    for i in 0..n.saturating_sub(1) {
        if parts[i] == "blobs" && parts[i + 1] == "uploads" {
            let name = parts[..i].join("/");
            if name.is_empty() {
                return Route::Unknown;
            }
            return match n - (i + 2) {
                0 => Route::UploadInit { name },
                1 => Route::UploadSession {
                    name,
                    uuid: parts[i + 2].to_string(),
                },
                _ => Route::Unknown,
            };
        }
    }
    if n >= 3 && parts[n - 2] == "blobs" {
        let name = parts[..n - 2].join("/");
        if !name.is_empty() {
            return Route::Blob {
                name,
                digest: parts[n - 1].to_string(),
            };
        }
    }
    if n >= 3 && parts[n - 2] == "manifests" {
        let name = parts[..n - 2].join("/");
        if !name.is_empty() {
            return Route::Manifest {
                name,
                reference: parts[n - 1].to_string(),
            };
        }
    }
    Route::Unknown
}

async fn handle(
    state: &AppState,
    method: &Method,
    route: Route,
    headers: &HeaderMap,
    principal: &Principal,
    query: &Query,
    body: Bytes,
) -> Result<Response, RegError> {
    let now = now_secs();
    match route {
        // ---- GET /v2/_catalog --------------------------------------------
        Route::Catalog if method == Method::GET => {
            read_guard(principal)?;
            let names: Vec<String> = state
                .store
                .list_repositories()
                .await?
                .into_iter()
                .map(|r| r.name)
                .collect();
            json_ok(serde_json::json!({ "repositories": names }))
        }

        // ---- GET /v2/{name}/tags/list ------------------------------------
        Route::TagsList { name } if method == Method::GET => {
            read_guard(principal)?;
            valid_name(&name)?;
            if !state.store.repo_exists(&name).await? {
                return Err(RegError::NameUnknown(format!("repository {name} not found")));
            }
            let tags: Vec<String> = state
                .store
                .tags_for(&name)
                .await?
                .into_iter()
                .map(|t| t.tag)
                .collect();
            json_ok(serde_json::json!({ "name": name, "tags": tags }))
        }

        // ---- POST /v2/{name}/blobs/uploads/ ------------------------------
        Route::UploadInit { name } if method == Method::POST => {
            write_guard(principal, &name)?;
            valid_name(&name)?;
            state.store.ensure_repository(&name, now).await?;

            // Cross-repo mount: if the blob already exists globally, link it without re-upload.
            if let Some(mount) = &query.mount {
                if is_valid_digest(mount) && state.blobs.exists(mount).await? {
                    if let Some(size) = state.store.blob_size(mount).await? {
                        state.store.put_blob(mount, size, now).await?;
                    }
                    return created_blob(&name, mount);
                }
                // Not present locally — fall through to a normal session (client re-uploads).
            }

            // Monolithic upload: POST carrying ?digest= and the whole blob body.
            if let Some(digest) = &query.digest {
                if !is_valid_digest(digest) {
                    return Err(RegError::DigestInvalid(format!("invalid digest {digest}")));
                }
                let size = state.blobs.put_verified(digest, &body).await?;
                state.store.put_blob(digest, size as i64, now).await?;
                return created_blob(&name, digest);
            }

            let uuid = state.blobs.create_upload().await?;
            accepted_upload(&name, &uuid, 0)
        }

        // ---- PATCH /v2/{name}/blobs/uploads/{uuid} -----------------------
        Route::UploadSession { name, uuid } if method == Method::PATCH => {
            write_guard(principal, &name)?;
            valid_name(&name)?;
            let total = state.blobs.append(&uuid, &body).await?;
            accepted_upload(&name, &uuid, total)
        }

        // ---- PUT /v2/{name}/blobs/uploads/{uuid}?digest= -----------------
        Route::UploadSession { name, uuid } if method == Method::PUT => {
            write_guard(principal, &name)?;
            valid_name(&name)?;
            let digest = query
                .digest
                .clone()
                .ok_or_else(|| RegError::DigestInvalid("missing digest query parameter".into()))?;
            if !is_valid_digest(&digest) {
                return Err(RegError::DigestInvalid(format!("invalid digest {digest}")));
            }
            if !body.is_empty() {
                state.blobs.append(&uuid, &body).await?;
            }
            let size = state.blobs.finalize(&uuid, &digest).await?;
            state.store.put_blob(&digest, size as i64, now).await?;
            created_blob(&name, &digest)
        }

        // ---- GET /v2/{name}/blobs/uploads/{uuid} (status) ----------------
        Route::UploadSession { name, uuid } if method == Method::GET => {
            write_guard(principal, &name)?;
            valid_name(&name)?;
            let total = state.blobs.upload_len(&uuid).await?;
            let end = total.saturating_sub(1);
            Ok(build(
                StatusCode::NO_CONTENT,
                vec![
                    (header::RANGE, format!("0-{end}")),
                    (HeaderName::from_static(H_UPLOAD_UUID), uuid.clone()),
                    (header::LOCATION, format!("/v2/{name}/blobs/uploads/{uuid}")),
                ],
                Vec::new(),
            ))
        }

        // ---- DELETE /v2/{name}/blobs/uploads/{uuid} (cancel) -------------
        Route::UploadSession { name, uuid } if method == Method::DELETE => {
            write_guard(principal, &name)?;
            valid_name(&name)?;
            state.blobs.cancel(&uuid).await?;
            Ok(build(StatusCode::NO_CONTENT, vec![], Vec::new()))
        }

        // ---- HEAD/GET /v2/{name}/blobs/{digest} --------------------------
        Route::Blob { name, digest } if method == Method::HEAD || method == Method::GET => {
            read_guard(principal)?;
            valid_name(&name)?;
            if !is_valid_digest(&digest) {
                return Err(RegError::DigestInvalid(format!("invalid digest {digest}")));
            }
            let size = state
                .store
                .blob_size(&digest)
                .await?
                .ok_or_else(|| RegError::BlobUnknown(format!("blob {digest} unknown")))?;
            let common = vec![
                (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                (header::CONTENT_LENGTH, size.to_string()),
                (HeaderName::from_static(H_CONTENT_DIGEST), digest.clone()),
            ];
            if method == Method::HEAD {
                return Ok(build(StatusCode::OK, common, Vec::new()));
            }
            let bytes = state
                .blobs
                .get(&digest)
                .await?
                .ok_or_else(|| RegError::BlobUnknown(format!("blob {digest} unknown")))?;
            Ok(build(StatusCode::OK, common, bytes))
        }

        // ---- PUT /v2/{name}/manifests/{reference} ------------------------
        Route::Manifest { name, reference } if method == Method::PUT => {
            write_guard(principal, &name)?;
            valid_name(&name)?;
            if !is_valid_reference(&reference) {
                return Err(RegError::ManifestInvalid(format!(
                    "invalid reference {reference}"
                )));
            }
            let raw = String::from_utf8(body.to_vec())
                .map_err(|_| RegError::ManifestInvalid("manifest is not valid UTF-8".into()))?;
            let digest = sha256_digest(raw.as_bytes());
            let media_type = headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.split(';').next().unwrap_or(s).trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| DEFAULT_MANIFEST_TYPE.to_string());

            // Accept only real manifest media types: single-platform image manifests AND the
            // multi-arch manifest-list / image-index types (so `docker push` of a multi-arch build
            // stores its index verbatim and `docker pull` on any arch resolves it). Anything else
            // is not a manifest.
            if !is_manifest_media_type(&media_type) {
                return Err(RegError::ManifestInvalid(format!(
                    "unsupported manifest media type {media_type}"
                )));
            }

            // A push BY DIGEST must match the body's actual digest.
            if reference_is_digest(&reference) && reference != digest {
                return Err(RegError::DigestInvalid(format!(
                    "reference {reference} does not match manifest digest {digest}"
                )));
            }

            state.store.ensure_repository(&name, now).await?;
            let rec = ManifestRec {
                id: ManifestRec::make_id(&name, &digest),
                repo: name.clone(),
                digest: digest.clone(),
                media_type,
                size: raw.len() as i64,
                raw,
                created_at: now,
            };
            state.store.put_manifest(&rec).await?;
            if !reference_is_digest(&reference) {
                state.store.put_tag(&name, &reference, &digest, now).await?;
            }
            created_manifest(&name, &digest)
        }

        // ---- HEAD/GET /v2/{name}/manifests/{reference} -------------------
        Route::Manifest { name, reference } if method == Method::HEAD || method == Method::GET => {
            read_guard(principal)?;
            valid_name(&name)?;
            let digest = if reference_is_digest(&reference) {
                reference.clone()
            } else {
                state
                    .store
                    .get_tag(&name, &reference)
                    .await?
                    .ok_or_else(|| RegError::ManifestUnknown(format!("tag {reference} unknown")))?
            };
            let m = state
                .store
                .get_manifest(&name, &digest)
                .await?
                .ok_or_else(|| {
                    RegError::ManifestUnknown(format!("manifest {reference} unknown"))
                })?;
            let common = vec![
                (header::CONTENT_TYPE, m.media_type.clone()),
                (header::CONTENT_LENGTH, m.size.to_string()),
                (HeaderName::from_static(H_CONTENT_DIGEST), m.digest.clone()),
            ];
            if method == Method::HEAD {
                Ok(build(StatusCode::OK, common, Vec::new()))
            } else {
                // A real registry pull: count it. A HEAD existence-probe is a separate arm above
                // (never counted), and the SSO web console reads manifests via the store — NOT via
                // `/v2/` — so it never reaches here. The `is_registry_client` guard additionally
                // excludes any `/v2/` request that DID arrive with a gateway SSO identity.
                if is_registry_client(headers) {
                    state.store.increment_pull(&name, now).await?;
                }
                Ok(build(StatusCode::OK, common, m.raw.into_bytes()))
            }
        }

        // Blob/manifest DELETE over the protocol is OPTIONAL in the OCI spec and DEFERRED here
        // (tag removal is offered through the CSRF-guarded web UI instead).
        Route::Blob { .. } | Route::Manifest { .. } if method == Method::DELETE => {
            Err(RegError::Unsupported("delete is not supported".into()))
        }

        _ => Err(RegError::NotFound),
    }
}

// ---------------------------------------------------------------------------
// Auth guards
// ---------------------------------------------------------------------------

/// Writes (and uploads) require valid credentials AND, for a robot, push scope on the target repo.
/// A human (or auth-disabled dev) may write anything; a robot may write only when its scope is
/// `pushpull` and its `repo_pattern` matches `repo` — otherwise `403 DENIED` (authenticated but not
/// permitted, e.g. a pull-only token attempting a push). Anonymous / bad credentials get `401`.
fn write_guard(principal: &Principal, repo: &str) -> Result<(), RegError> {
    match principal {
        Principal::Human => Ok(()),
        Principal::Robot(r) if r.may_push(repo) => Ok(()),
        Principal::Robot(r) => Err(RegError::Denied(format!(
            "robot {} is not permitted to push to {repo}",
            r.name
        ))),
        Principal::Anonymous | Principal::Bad => Err(RegError::Unauthorized),
    }
}

/// Reads allow anonymous access (public pull) — a human, a robot (of any scope) and an anonymous
/// caller may all read — but WRONG credentials are still rejected.
fn read_guard(principal: &Principal) -> Result<(), RegError> {
    match principal {
        Principal::Bad => Err(RegError::Unauthorized),
        _ => Ok(()),
    }
}

/// True for a genuine registry-protocol client: a `/v2/` request WITHOUT a gateway SSO identity
/// (`X-Auth-Subject`). The SSO web console always carries that header; a docker/oci CLI never does.
/// Keeps the web console's own reads out of the pull counter (only real pulls count).
fn is_registry_client(headers: &HeaderMap) -> bool {
    headers.get(HEADER_SUBJECT).is_none()
}

fn valid_name(name: &str) -> Result<(), RegError> {
    if is_valid_name(name) {
        Ok(())
    } else {
        Err(RegError::NameInvalid(format!("invalid repository name {name}")))
    }
}

// ---------------------------------------------------------------------------
// Response builders
// ---------------------------------------------------------------------------

/// Build a response, always stamping the `Docker-Distribution-Api-Version` header.
fn build(status: StatusCode, extra: Vec<(HeaderName, String)>, body: Vec<u8>) -> Response {
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    h.insert(
        HeaderName::from_static(H_API_VERSION),
        HeaderValue::from_static(API_VERSION),
    );
    for (k, v) in extra {
        if let Ok(val) = HeaderValue::from_str(&v) {
            h.insert(k, val);
        }
    }
    resp
}

fn json_ct() -> (HeaderName, String) {
    (header::CONTENT_TYPE, "application/json; charset=utf-8".to_string())
}

fn json_ok(value: serde_json::Value) -> Result<Response, RegError> {
    Ok(build(StatusCode::OK, vec![json_ct()], value.to_string().into_bytes()))
}

/// `202 Accepted` for an open upload session.
fn accepted_upload(name: &str, uuid: &str, total: u64) -> Result<Response, RegError> {
    let end = total.saturating_sub(1);
    Ok(build(
        StatusCode::ACCEPTED,
        vec![
            (header::LOCATION, format!("/v2/{name}/blobs/uploads/{uuid}")),
            (HeaderName::from_static(H_UPLOAD_UUID), uuid.to_string()),
            (header::RANGE, format!("0-{end}")),
            (header::CONTENT_LENGTH, "0".to_string()),
        ],
        Vec::new(),
    ))
}

/// `201 Created` for a finalized blob.
fn created_blob(name: &str, digest: &str) -> Result<Response, RegError> {
    Ok(build(
        StatusCode::CREATED,
        vec![
            (header::LOCATION, format!("/v2/{name}/blobs/{digest}")),
            (HeaderName::from_static(H_CONTENT_DIGEST), digest.to_string()),
        ],
        Vec::new(),
    ))
}

/// `201 Created` for a stored manifest.
fn created_manifest(name: &str, digest: &str) -> Result<Response, RegError> {
    Ok(build(
        StatusCode::CREATED,
        vec![
            (header::LOCATION, format!("/v2/{name}/manifests/{digest}")),
            (HeaderName::from_static(H_CONTENT_DIGEST), digest.to_string()),
        ],
        Vec::new(),
    ))
}

// ---------------------------------------------------------------------------
// Query parsing (the `digest`/`mount`/`from` parameters, percent-decoded)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Query {
    digest: Option<String>,
    mount: Option<String>,
    #[allow(dead_code)]
    from: Option<String>,
}

fn parse_query(raw: &str) -> Query {
    let mut q = Query::default();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let val = percent_decode(v);
        match k {
            "digest" => q.digest = Some(val),
            "mount" => q.mount = Some(val),
            "from" => q.from = Some(val),
            _ => {}
        }
    }
    q
}

/// Percent-decode a query value (e.g. `sha256%3A...` -> `sha256:...`). Leaves any malformed `%`
/// escape untouched.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_blob_and_manifest_routes() {
        assert!(matches!(parse_route("library/alpine/blobs/sha256:abc"), Route::Blob { name, digest } if name=="library/alpine" && digest=="sha256:abc"));
        assert!(matches!(parse_route("alpine/manifests/latest"), Route::Manifest { name, reference } if name=="alpine" && reference=="latest"));
        assert!(matches!(parse_route("_catalog"), Route::Catalog));
        assert!(matches!(parse_route("alpine/tags/list"), Route::TagsList { name } if name=="alpine"));
    }

    #[test]
    fn parse_upload_routes() {
        assert!(matches!(parse_route("alpine/blobs/uploads"), Route::UploadInit { name } if name=="alpine"));
        assert!(matches!(parse_route("alpine/blobs/uploads/"), Route::UploadInit { name } if name=="alpine"));
        assert!(matches!(parse_route("team/app/blobs/uploads/abc-123"), Route::UploadSession { name, uuid } if name=="team/app" && uuid=="abc-123"));
    }

    #[test]
    fn query_percent_decodes_digest() {
        let q = parse_query("digest=sha256%3Aba78");
        assert_eq!(q.digest.as_deref(), Some("sha256:ba78"));
    }
}
