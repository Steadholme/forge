//! Repository-name and reference (tag/digest) validation per the OCI Distribution spec.
//!
//! A repository `name` is one-or-more slash-separated path components, each
//! `[a-z0-9]+(?:[._-][a-z0-9]+)*` (lowercase only), total length <= 255. A `reference` is either a
//! `tag` (`[A-Za-z0-9_][A-Za-z0-9._-]{0,127}`) or a digest (`<algo>:<hex>`). Validating these at
//! the edge keeps malformed/abusive names (path traversal, uppercase, control chars) out of the
//! store and off the blob volume.

use crate::digest::is_valid_digest;

/// Maximum total length of a repository name (OCI spec).
const MAX_NAME_LEN: usize = 255;
/// Maximum length of a tag (OCI spec).
const MAX_TAG_LEN: usize = 128;

/// True when `name` is a valid repository name (lowercase, slash-separated components).
pub fn is_valid_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return false;
    }
    name.split('/').all(is_valid_component)
}

/// One path component: starts and ends with `[a-z0-9]`, with single `.`/`_`/`-` separators
/// between alphanumeric runs. (Docker permits `__` / `--`; we allow repeated `_`/`-` but never a
/// leading/trailing/repeated `.`, which is the path-traversal risk.)
fn is_valid_component(c: &str) -> bool {
    let b = c.as_bytes();
    if b.is_empty() {
        return false;
    }
    if !is_alnum(b[0]) || !is_alnum(b[b.len() - 1]) {
        return false;
    }
    let mut prev_dot = false;
    for &ch in b {
        let alnum = is_alnum(ch);
        let sep = matches!(ch, b'.' | b'_' | b'-');
        if !alnum && !sep {
            return false;
        }
        // No consecutive dots (`..`) and no dot adjacent to another separator.
        if ch == b'.' && prev_dot {
            return false;
        }
        prev_dot = ch == b'.';
    }
    true
}

fn is_alnum(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

/// True when `t` is a valid tag.
pub fn is_valid_tag(t: &str) -> bool {
    let b = t.as_bytes();
    if b.is_empty() || b.len() > MAX_TAG_LEN {
        return false;
    }
    let first = b[0];
    if !(first.is_ascii_alphanumeric() || first == b'_') {
        return false;
    }
    b.iter()
        .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

/// A reference is either a digest (`sha256:...`) or a tag.
pub fn is_valid_reference(r: &str) -> bool {
    is_valid_digest(r) || is_valid_tag(r)
}

/// True when the reference is a digest (vs a tag).
pub fn reference_is_digest(r: &str) -> bool {
    is_valid_digest(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names() {
        assert!(is_valid_name("alpine"));
        assert!(is_valid_name("library/alpine"));
        assert!(is_valid_name("team/sub/project"));
        assert!(is_valid_name("my-app.v2"));
        assert!(is_valid_name("a_b-c.d"));
    }

    #[test]
    fn invalid_names() {
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("Alpine")); // uppercase
        assert!(!is_valid_name("/leading"));
        assert!(!is_valid_name("trailing/"));
        assert!(!is_valid_name("a//b")); // empty component
        assert!(!is_valid_name("../etc")); // traversal
        assert!(!is_valid_name(".hidden"));
        assert!(!is_valid_name("has space"));
    }

    #[test]
    fn tags_and_refs() {
        assert!(is_valid_tag("latest"));
        assert!(is_valid_tag("v1.2.3"));
        assert!(is_valid_tag("_underscore_start"));
        assert!(!is_valid_tag(".dotstart"));
        assert!(!is_valid_tag("has space"));
        assert!(is_valid_reference("latest"));
        assert!(is_valid_reference(
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        ));
        assert!(reference_is_digest(
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        ));
        assert!(!reference_is_digest("latest"));
    }
}
