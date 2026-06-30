//! Gateway-injected identity (web UI) + double-submit CSRF + PAT/Basic auth (git CLI).
//!
//! Loom has TWO authentication surfaces, deliberately split at the Sluice gateway:
//!
//! - The WEB UI (`git.w33d.xyz/`) is `auth=sso`: the gateway runs the OIDC browser login against
//!   Keystone, STRIPS any inbound `X-Auth-*`, and injects the verified `X-Auth-Subject` /
//!   `X-Auth-Email`. Loom is internal-only, so it TRUSTS those headers as the authenticated user.
//!   State-changing POSTs additionally carry a double-submit CSRF token.
//!
//! - The git SMART-HTTP protocol (`git.w33d.xyz/git/...`) is `auth=public` at the gateway —
//!   `git`/`docker` cannot speak the browser OIDC/cookie SSO — so Loom does its OWN HTTP Basic
//!   auth there against a Personal Access Token (username = anything, password = the PAT). The
//!   token is verified by SHA-256 against `pats.token_hash`; only the hash is ever stored.

use axum::http::{header, HeaderMap};
use sha2::{Digest, Sha256};

use crate::random_alnum;

pub const HEADER_SUBJECT: &str = "x-auth-subject";
pub const HEADER_EMAIL: &str = "x-auth-email";

/// Dev/test fallback identity used ONLY when no gateway headers are present (local `cargo run`
/// or the DB-free test suite). In production every request arrives with `X-Auth-*` injected.
pub const DEV_SUBJECT: &str = "dev-user";
pub const DEV_EMAIL: &str = "dev@loom.local";

/// Double-submit CSRF cookie. `__Host-` prefix => Secure + Path=/ + no Domain, so the browser
/// only ever returns it over TLS to this exact host.
pub const CSRF_COOKIE: &str = "__Host-csrf";
/// CSRF cookie lifetime, seconds.
const CSRF_TTL: u64 = 3600;
/// CSRF token length (characters from the 62-symbol alphabet ~= 238 bits).
const CSRF_LEN: usize = 40;

/// Personal-access-token secret length (62-symbol alphabet). Shown once, then only its hash is
/// kept. Rendered with a recognizable prefix so it is greppable in client configs.
const PAT_SECRET_LEN: usize = 40;
/// Human-recognizable prefix on a freshly minted PAT secret.
pub const PAT_PREFIX: &str = "loom_pat_";

/// The authenticated user. Subject is the ownership key; email is display-only.
#[derive(Clone, Debug)]
pub struct Identity {
    pub subject: String,
    pub email: String,
}

/// Resolve the current user from the gateway-injected headers, falling back to the dev identity
/// when none are present (so the service still runs DB-free locally and in tests).
pub fn identity(headers: &HeaderMap) -> Identity {
    Identity {
        subject: header_value(headers, HEADER_SUBJECT).unwrap_or_else(|| DEV_SUBJECT.to_string()),
        email: header_value(headers, HEADER_EMAIL).unwrap_or_else(|| DEV_EMAIL.to_string()),
    }
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

// ---------------------------------------------------------------------------
// Personal access tokens
// ---------------------------------------------------------------------------

/// Mint a fresh PAT secret (the value shown ONCE to the user). Only its [`hash_token`] is stored.
pub fn new_pat_secret() -> String {
    format!("{PAT_PREFIX}{}", random_alnum(PAT_SECRET_LEN))
}

/// Lowercase hex SHA-256 of a token secret — the value persisted in `pats.token_hash` and the
/// lookup key used when verifying a Basic-auth password on the `/git/` routes.
pub fn hash_token(secret: &str) -> String {
    let mut h = Sha256::new();
    h.update(secret.as_bytes());
    hex::encode(h.finalize())
}

/// Parse the password from an HTTP Basic `Authorization` header. The git client sends
/// `Basic base64(username:password)`; for a PAT the username is ignored and the password is the
/// token. Returns the decoded `(username, password)` on success.
pub fn parse_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    use base64::Engine;
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = raw.strip_prefix("Basic ").or_else(|| raw.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (user, pass) = text.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

// ---------------------------------------------------------------------------
// CSRF (double-submit)
// ---------------------------------------------------------------------------

/// Mint a fresh CSRF token (same value goes in the cookie and the form field).
pub fn new_csrf_token() -> String {
    random_alnum(CSRF_LEN)
}

/// `Set-Cookie` value for the (JS-readable) CSRF cookie.
pub fn csrf_cookie(value: &str) -> String {
    format!("{CSRF_COOKIE}={value}; Path=/; Secure; SameSite=Lax; Max-Age={CSRF_TTL}")
}

/// Double-submit check: the `submitted` form token must equal the `__Host-csrf` cookie.
pub fn verify_csrf(headers: &HeaderMap, submitted: &str) -> bool {
    match get_cookie(headers, CSRF_COOKIE) {
        Some(cookie) if !cookie.is_empty() => ct_eq(cookie.as_bytes(), submitted.as_bytes()),
        _ => false,
    }
}

/// Read a single cookie value from the request's `Cookie` header(s).
pub fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for hv in headers.get_all(header::COOKIE).iter() {
        let Ok(raw) = hv.to_str() else { continue };
        for pair in raw.split(';') {
            let pair = pair.trim();
            if let Some((k, v)) = pair.split_once('=') {
                if k.trim() == name {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

/// Length-checked constant-time byte comparison (no early return on the first differing byte).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn identity_falls_back_to_dev() {
        let id = identity(&HeaderMap::new());
        assert_eq!(id.subject, DEV_SUBJECT);
        assert_eq!(id.email, DEV_EMAIL);
    }

    #[test]
    fn identity_reads_gateway_headers() {
        let mut h = HeaderMap::new();
        h.insert(HEADER_SUBJECT, HeaderValue::from_static("u_admin"));
        h.insert(HEADER_EMAIL, HeaderValue::from_static("a@w33d.xyz"));
        let id = identity(&h);
        assert_eq!(id.subject, "u_admin");
        assert_eq!(id.email, "a@w33d.xyz");
    }

    #[test]
    fn pat_hash_is_stable_and_prefixed() {
        let secret = new_pat_secret();
        assert!(secret.starts_with(PAT_PREFIX));
        assert_eq!(hash_token(&secret), hash_token(&secret));
        assert_ne!(hash_token(&secret), hash_token("loom_pat_other"));
        // Known vector: sha256("") well-known digest.
        assert_eq!(
            hash_token(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn basic_auth_parses_user_and_pat() {
        use base64::Engine;
        let token = "loom_pat_abc123";
        let raw = base64::engine::general_purpose::STANDARD.encode(format!("git:{token}"));
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, format!("Basic {raw}").parse().unwrap());
        let (user, pass) = parse_basic_auth(&h).unwrap();
        assert_eq!(user, "git");
        assert_eq!(pass, token);
        assert!(parse_basic_auth(&HeaderMap::new()).is_none());
    }

    #[test]
    fn csrf_double_submit() {
        let token = new_csrf_token();
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, format!("{CSRF_COOKIE}={token}").parse().unwrap());
        assert!(verify_csrf(&h, &token));
        assert!(!verify_csrf(&h, "not-the-token"));
        assert!(!verify_csrf(&HeaderMap::new(), &token));
    }
}
