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
pub const HEADER_GROUPS: &str = "x-auth-groups";
/// HMAC binding the injected identity to a 1-minute window (set by Sluice when GATEWAY_HMAC_KEY
/// is configured). See [`gateway_identity_ok`].
pub const HEADER_SIG: &str = "x-auth-sig";

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
    /// Display-only colour theme, resolved from the __Secure-theme cookie.
    pub theme: &'static str,
}

/// Resolve the current user from the gateway-injected headers, falling back to the dev identity
/// when none are present (so the service still runs DB-free locally and in tests).
pub fn identity(headers: &HeaderMap) -> Identity {
    Identity {
        subject: header_value(headers, HEADER_SUBJECT).unwrap_or_else(|| DEV_SUBJECT.to_string()),
        email: header_value(headers, HEADER_EMAIL).unwrap_or_else(|| DEV_EMAIL.to_string()),
        theme: odyssey::resolve_theme(headers.get(header::COOKIE).and_then(|v| v.to_str().ok())),
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
// Group-based authorization (X-Auth-Groups)
// ---------------------------------------------------------------------------

/// The two GLOBAL admin groups that ALWAYS grant estate-admin authority, in EVERY crate. Kept as
/// the immutable default seed for [`admin_groups`] — never removed, so anything an `admins` /
/// `infra-admins` member can do today keeps working unchanged.
pub const ADMIN_GROUPS: &[&str] = &["admins", "infra-admins"];

/// Default PRODUCT-scoped operator group for Loom (git hosting). Overridable via `LOOM_ADMIN_GROUP`.
pub const PRODUCT_ADMIN_GROUP: &str = "git-admins";

/// DELEGATED ADMIN — the effective admin set is the two globals PLUS one product-scoped operator
/// group, so Loom administration (the issue-moderation gate, etc.) can be handed to a scoped
/// operator via Census WITHOUT granting global `admins`. The product group is read ONCE from
/// `LOOM_ADMIN_GROUP` (default [`PRODUCT_ADMIN_GROUP`] = `"git-admins"`); the two globals are always
/// present, so this is purely ADDITIVE — behaviour is identical until someone is put in the new
/// group. See [`is_admin`].
pub fn admin_groups() -> &'static [String] {
    static GROUPS: OnceLock<Vec<String>> = OnceLock::new();
    GROUPS.get_or_init(|| {
        let product = std::env::var("LOOM_ADMIN_GROUP")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| PRODUCT_ADMIN_GROUP.to_string());
        let mut groups: Vec<String> = ADMIN_GROUPS.iter().map(|s| s.to_string()).collect();
        if !groups.iter().any(|g| g == &product) {
            groups.push(product);
        }
        groups
    })
}

/// The signed-in user's groups, parsed from the comma-separated `X-Auth-Groups` header (injected
/// AND HMAC-verified by the gateway, so it is trustworthy). Empty when absent/blank.
pub fn author_groups(headers: &HeaderMap) -> Vec<String> {
    header_value(headers, HEADER_GROUPS)
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Whether the signed-in user belongs to `group` (exact match against `X-Auth-Groups`).
pub fn has_group(headers: &HeaderMap, group: &str) -> bool {
    author_groups(headers).iter().any(|g| g == group)
}

/// Whether the signed-in user is in ANY [`admin_groups`] entry (the two globals + the product group).
pub fn is_admin(headers: &HeaderMap) -> bool {
    let groups = author_groups(headers);
    admin_groups().iter().any(|a| groups.iter().any(|g| g == a))
}

// ---------------------------------------------------------------------------
// Gateway identity signature (X-Auth-Sig) verification
// ---------------------------------------------------------------------------

use std::sync::OnceLock;

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
    [win, win - 1].iter().any(|&w| {
        ct_eq(
            sig.as_bytes(),
            sign_identity(key, &subject, &groups, w).as_bytes(),
        )
    })
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
    let b64 = raw
        .strip_prefix("Basic ")
        .or_else(|| raw.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (user, pass) = text.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// Parse `Authorization: Bearer <token>` into the bare token.
pub fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let tok = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))?;
    let tok = tok.trim();
    if tok.is_empty() {
        None
    } else {
        Some(tok.to_string())
    }
}

/// Constant-time check for a configured Bearer token. Empty expected tokens are never accepted.
pub fn bearer_token_ok(headers: &HeaderMap, expected: &str) -> bool {
    if expected.is_empty() {
        return false;
    }
    bearer_token(headers)
        .map(|token| ct_eq(token.as_bytes(), expected.as_bytes()))
        .unwrap_or(false)
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
        h.insert(HEADER_SUBJECT, HeaderValue::from_static("u_admin"));
        assert!(gateway_identity_ok(&h));
    }

    #[test]
    fn admin_group_membership() {
        // No X-Auth-Groups -> not an admin.
        assert!(!is_admin(&HeaderMap::new()));

        // A non-admin group -> not an admin.
        let mut other = HeaderMap::new();
        other.insert(HEADER_GROUPS, HeaderValue::from_static("readers,writers"));
        assert!(!is_admin(&other));
        assert!(has_group(&other, "readers"));

        // An admin group (whitespace-tolerant) -> admin.
        let mut admins = HeaderMap::new();
        admins.insert(HEADER_GROUPS, HeaderValue::from_static("dev, admins ,x"));
        assert!(is_admin(&admins));
        assert!(has_group(&admins, "admins"));

        let mut infra = HeaderMap::new();
        infra.insert(HEADER_GROUPS, HeaderValue::from_static("infra-admins"));
        assert!(is_admin(&infra));

        // Delegated admin: the product-scoped operator group (default "git-admins") is ALSO
        // accepted, WITHOUT belonging to either global admin group.
        let mut product = HeaderMap::new();
        product.insert(HEADER_GROUPS, HeaderValue::from_static("git-admins"));
        assert!(is_admin(&product));
        // The resolved set is exactly the two globals plus the product group.
        assert_eq!(admin_groups(), ["admins", "infra-admins", "git-admins"]);
        // A random unrelated group is still refused (403 at the gate).
        let mut random = HeaderMap::new();
        random.insert(HEADER_GROUPS, HeaderValue::from_static("random-group"));
        assert!(!is_admin(&random));
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
        h.insert(
            header::AUTHORIZATION,
            format!("Basic {raw}").parse().unwrap(),
        );
        let (user, pass) = parse_basic_auth(&h).unwrap();
        assert_eq!(user, "git");
        assert_eq!(pass, token);
        assert!(parse_basic_auth(&HeaderMap::new()).is_none());
    }

    #[test]
    fn bearer_auth_parses_and_checks_token() {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer status-secret"),
        );
        assert_eq!(bearer_token(&h).as_deref(), Some("status-secret"));
        assert!(bearer_token_ok(&h, "status-secret"));
        assert!(!bearer_token_ok(&h, "wrong"));
        assert!(!bearer_token_ok(&h, ""));
        assert!(bearer_token(&HeaderMap::new()).is_none());
    }

    #[test]
    fn csrf_double_submit() {
        let token = new_csrf_token();
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            format!("{CSRF_COOKIE}={token}").parse().unwrap(),
        );
        assert!(verify_csrf(&h, &token));
        assert!(!verify_csrf(&h, "not-the-token"));
        assert!(!verify_csrf(&HeaderMap::new(), &token));
    }
}
