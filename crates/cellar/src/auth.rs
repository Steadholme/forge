//! Two distinct auth surfaces — the registry's defining constraint.
//!
//! 1. **`/v2/` protocol (HTTP Basic).** `docker` / `git`-style CLIs do NOT speak the browser
//!    OIDC/cookie SSO, so the gateway routes `registry.w33d.xyz/v2/` as `auth=public` and Cellar
//!    does its OWN auth: HTTP Basic against `CELLAR_USER`/`CELLAR_PASSWORD` (constant-time). A
//!    missing/invalid credential on a write (or the `docker login` probe) gets
//!    `401 WWW-Authenticate: Basic`, which is exactly what makes the docker client supply creds.
//!    When `CELLAR_USER` is empty (dev), auth is DISABLED so the DB-free path needs no secret.
//!
//! 2. **Web UI (gateway SSO).** `registry.w33d.xyz/` is `auth=sso`: the gateway runs the OIDC
//!    login, STRIPS inbound `X-Auth-*`, and injects the verified `X-Auth-Subject`/`X-Auth-Email`.
//!    Cellar is internal-only, so it TRUSTS those headers (no login of its own). State-changing
//!    web POSTs (delete a tag) carry a double-submit CSRF token.

use axum::http::{header, HeaderMap};

use crate::config::Config;
use crate::random_alnum;

// ---------------------------------------------------------------------------
// /v2/ HTTP Basic auth
// ---------------------------------------------------------------------------

/// The `WWW-Authenticate` realm advertised on a 401 challenge.
pub const BASIC_REALM: &str = "Cellar Registry";

/// Outcome of checking the `Authorization: Basic` header against the configured credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cred {
    /// Valid credentials (or auth disabled in dev) — the request is authenticated.
    Ok,
    /// No `Authorization` header — anonymous (allowed on public read paths; challenged on writes).
    None,
    /// An `Authorization` header was present but the credentials were wrong.
    Bad,
}

/// Check the request's HTTP Basic credentials against `cfg`. When auth is disabled (empty
/// `CELLAR_USER`) every request is [`Cred::Ok`].
pub fn check_basic(headers: &HeaderMap, cfg: &Config) -> Cred {
    if !cfg.auth_enabled() {
        return Cred::Ok;
    }
    match basic_credentials(headers) {
        None => Cred::None,
        Some((user, pass)) => {
            // Constant-time over BOTH fields so neither a username nor a password length/content
            // leaks via timing.
            let ok = ct_eq(user.as_bytes(), cfg.user.as_bytes())
                & ct_eq(pass.as_bytes(), cfg.password.as_bytes());
            if ok {
                Cred::Ok
            } else {
                Cred::Bad
            }
        }
    }
}

/// Parse `Authorization: Basic base64(user:password)` into `(user, password)`.
pub fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = raw.strip_prefix("Basic ").or_else(|| raw.strip_prefix("basic "))?;
    let decoded = b64_decode(b64.trim())?;
    let text = String::from_utf8(decoded).ok()?;
    let (user, pass) = text.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// Minimal standard-alphabet base64 decoder (no padding requirement). Returns `None` on any
/// invalid symbol. Kept local to avoid a dependency for ~30 lines.
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c == b'=' {
            break;
        }
        let v = val(c)?;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Length-checked constant-time byte comparison (no early return on the first differing byte).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Web UI gateway identity
// ---------------------------------------------------------------------------

pub const HEADER_SUBJECT: &str = "x-auth-subject";
pub const HEADER_EMAIL: &str = "x-auth-email";

/// Dev/test fallback identity used ONLY when no gateway headers are present (local `cargo run` or
/// the DB-free test suite). In production every SSO request arrives with `X-Auth-*` injected.
pub const DEV_SUBJECT: &str = "dev-user";
pub const DEV_EMAIL: &str = "dev@cellar.local";

/// The signed-in operator (web UI only). Subject is the identity key; email is display-only.
#[derive(Clone, Debug)]
pub struct Identity {
    pub subject: String,
    pub email: String,
}

/// Resolve the current operator from the gateway-injected headers, falling back to the dev
/// identity when none are present.
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
// Gateway identity signature (X-Auth-Sig) verification
// ---------------------------------------------------------------------------

use std::sync::OnceLock;

pub const HEADER_GROUPS: &str = "x-auth-groups";
/// HMAC binding the injected identity to a 1-minute window (set by Sluice when GATEWAY_HMAC_KEY
/// is configured). See [`gateway_identity_ok`].
pub const HEADER_SIG: &str = "x-auth-sig";

/// The shared gateway HMAC key, read once from `GATEWAY_HMAC_KEY`. Empty (unset) disables
/// verification — the pre-signature behavior, fully backward compatible.
fn gateway_key() -> &'static str {
    static KEY: OnceLock<String> = OnceLock::new();
    KEY.get_or_init(|| std::env::var("GATEWAY_HMAC_KEY").unwrap_or_default())
        .as_str()
}

/// Verify the gateway-injected identity is authentic. When `GATEWAY_HMAC_KEY` is set AND an
/// identity (`X-Auth-Subject`) is present, a valid `X-Auth-Sig` — HMAC-SHA256 over
/// `subject "\n" groups "\n" minute` for the current OR previous minute — is REQUIRED; a rogue
/// peer that POSTs `X-Auth-Subject` directly (bypassing Sluice) cannot forge it. Returns:
/// - `true` when the key is unset (verification off), or no identity header is present
///   (public/dev path), or the signature is valid;
/// - `false` when an identity is present but the signature is missing or invalid (=> 401).
pub fn gateway_identity_ok(headers: &HeaderMap) -> bool {
    let key = gateway_key();
    if key.is_empty() {
        return true;
    }
    let Some(subject) = header_value(headers, HEADER_SUBJECT) else {
        return true; // no injected identity to verify (public route / local dev)
    };
    let groups = header_value(headers, HEADER_GROUPS).unwrap_or_default();
    let Some(sig) = header_value(headers, HEADER_SIG) else {
        return false; // identity present but unsigned — reject
    };
    let win = now_unix() / 60;
    // Accept the current and previous minute (clock skew + minute-boundary tolerance).
    [win, win - 1]
        .iter()
        .any(|&w| ct_eq(sig.as_bytes(), sign_identity(key, &subject, &groups, w).as_bytes()))
}

/// Recompute the gateway signature — byte-identical to Sluice's `auth.SignIdentity` (Go).
fn sign_identity(key: &str, subject: &str, groups: &str, window: i64) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key len");
    mac.update(subject.as_bytes());
    mac.update(b"\n");
    mac.update(groups.as_bytes());
    mac.update(b"\n");
    mac.update(window.to_string().as_bytes());
    to_hex(&mac.finalize().into_bytes())
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// CSRF (double-submit) for web POSTs
// ---------------------------------------------------------------------------

/// Double-submit CSRF cookie. `__Host-` prefix => Secure + Path=/ + no Domain.
pub const CSRF_COOKIE: &str = "__Host-csrf";
const CSRF_TTL: u64 = 3600;
const CSRF_LEN: usize = 40;

/// Mint a fresh CSRF token (the same value goes in the cookie and the form field).
pub fn new_csrf_token() -> String {
    random_alnum(CSRF_LEN)
}

/// `Set-Cookie` value for the CSRF cookie.
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn cfg_with_auth() -> Config {
        let mut c = Config::dev();
        c.user = "robot".to_string();
        c.password = "s3cret".to_string();
        c
    }

    #[test]
    fn base64_decodes_basic_pair() {
        // base64("robot:s3cret")
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic cm9ib3Q6czNjcmV0"),
        );
        assert_eq!(
            basic_credentials(&h),
            Some(("robot".to_string(), "s3cret".to_string()))
        );
    }

    #[test]
    fn check_basic_states() {
        let cfg = cfg_with_auth();
        assert_eq!(check_basic(&HeaderMap::new(), &cfg), Cred::None);

        let mut good = HeaderMap::new();
        good.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic cm9ib3Q6czNjcmV0"));
        assert_eq!(check_basic(&good, &cfg), Cred::Ok);

        let mut bad = HeaderMap::new();
        // base64("robot:wrong")
        bad.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic cm9ib3Q6d3Jvbmc="));
        assert_eq!(check_basic(&bad, &cfg), Cred::Bad);
    }

    #[test]
    fn auth_disabled_is_always_ok() {
        let cfg = Config::dev(); // empty user
        assert_eq!(check_basic(&HeaderMap::new(), &cfg), Cred::Ok);
    }

    #[test]
    fn csrf_double_submit() {
        let token = new_csrf_token();
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, format!("{CSRF_COOKIE}={token}").parse().unwrap());
        assert!(verify_csrf(&h, &token));
        assert!(!verify_csrf(&h, "nope"));
    }

    #[test]
    fn sign_identity_matches_go_vector() {
        // MUST equal sluice/internal/auth/sig_test.go — the cross-language contract.
        assert_eq!(
            sign_identity("test-key", "usr_alice", "admins,devs", 1),
            "ddc77236dcfb03dd9f462f7c84e1b25e58f5fc380997695a689e6c3ac4bb3777"
        );
        assert_eq!(
            sign_identity("test-key", "usr_bob", "", 2),
            "930f82fb1224e69c9c5bc46e545c3b108b1eeb6c9078c7a33fc24f30c595f658"
        );
    }

    #[test]
    fn gateway_ok_when_key_unset() {
        // No GATEWAY_HMAC_KEY in the test env => verification disabled => always ok.
        let mut h = HeaderMap::new();
        h.insert(HEADER_SUBJECT, HeaderValue::from_static("user-42"));
        assert!(gateway_identity_ok(&h));
    }
}
