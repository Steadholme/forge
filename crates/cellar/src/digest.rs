//! Content-address digests.
//!
//! A blob's (or manifest's) digest is `sha256:<64 lowercase hex>` — the SHA-256 of its bytes.
//! This is the registry's content-address: the digest IS the storage key, so writes are
//! idempotent and de-duped, and a finalize can VERIFY the bytes match the digest the client
//! claimed (integrity, not just naming). Only the `sha256` algorithm is computed here; a
//! well-formed `sha512:` reference is still ACCEPTED on read paths (lookup by string) but never
//! produced.

use sha2::{Digest, Sha256};

/// Lowercase-hex SHA-256 of `bytes` (no algorithm prefix).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let out = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in out.iter() {
        // Two lowercase hex nibbles per byte.
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// Full digest string `sha256:<hex>` for `bytes`.
pub fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

/// True when `d` is a syntactically valid `<algo>:<hex>` digest (lowercase hex of the right
/// length for the algorithm). Accepts `sha256` (64) and `sha512` (128).
pub fn is_valid_digest(d: &str) -> bool {
    match d.split_once(':') {
        Some(("sha256", hex)) => hex.len() == 64 && is_lower_hex(hex),
        Some(("sha512", hex)) => hex.len() == 128 && is_lower_hex(hex),
        _ => false,
    }
}

fn is_lower_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_sha256_vectors() {
        // SHA-256("") and SHA-256("abc") — standard NIST vectors.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_digest(b"abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn digest_validation() {
        assert!(is_valid_digest(&sha256_digest(b"hello")));
        assert!(is_valid_digest(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        ));
        assert!(!is_valid_digest("sha256:TOOSHORT"));
        assert!(!is_valid_digest("sha256:ABC")); // uppercase rejected
        assert!(!is_valid_digest("md5:abc"));
        assert!(!is_valid_digest("no-colon"));
    }
}
