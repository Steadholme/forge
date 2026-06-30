//! Core domain types: a repository, an issue, and a personal access token.
//!
//! One flat record per the agreed schema (db `loom`). Identity (`owner_sub` / `author_sub`)
//! always comes from the Sluice-injected `X-Auth-*` headers, never from client input.

/// A git repository. Field order/types mirror the `repos` table exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repo {
    /// Random opaque id (primary key; also the foreign key from issues).
    pub id: String,
    /// Owner subject from `X-Auth-Subject` (ownership key; first path segment on disk + URL).
    pub owner_sub: String,
    /// Repository name (validated; second path segment, `{name}.git` on disk).
    pub name: String,
    /// Free-text description (may be empty).
    pub description: String,
    /// Private repos are owner-only in the UI and require a PAT to clone over git.
    pub is_private: bool,
    /// Default branch name (HEAD), e.g. `main`.
    pub default_branch: String,
    /// Creation time, epoch seconds.
    pub created_at: i64,
}

/// An issue on a repository. Field order/types mirror the `issues` table exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issue {
    /// Random opaque id (primary key).
    pub id: String,
    /// Owning repository id.
    pub repo_id: String,
    /// Per-repo sequential issue number (1-based; display key).
    pub number: i64,
    /// Issue title.
    pub title: String,
    /// Issue body (markdown rendered as escaped text).
    pub body: String,
    /// Author subject from `X-Auth-Subject`.
    pub author_sub: String,
    /// `open` or `closed`.
    pub state: String,
    /// Creation time, epoch seconds.
    pub created_at: i64,
}

impl Issue {
    /// True when the issue is open.
    pub fn is_open(&self) -> bool {
        self.state == "open"
    }
}

/// A personal access token. Only the SHA-256 hash is stored; the secret is shown once at mint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pat {
    /// Random opaque id (primary key; revoke key).
    pub id: String,
    /// Owner subject from `X-Auth-Subject`.
    pub owner_sub: String,
    /// Human label for the token.
    pub name: String,
    /// Lowercase hex SHA-256 of the token secret (never the secret itself).
    pub token_hash: String,
    /// Creation time, epoch seconds.
    pub created_at: i64,
}

/// Validate a repository name. Allows a conservative, path-safe, URL-safe charset so the name is
/// safe to use as the on-disk directory (`{name}.git`) and the URL segment, with NO traversal.
/// Returns a user-facing reason on rejection.
pub fn validate_repo_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("Repository name cannot be empty.");
    }
    if name.len() > 64 {
        return Err("Repository name is too long (64 characters maximum).");
    }
    if name.starts_with('.') || name.starts_with('-') {
        return Err("Repository name cannot start with '.' or '-'.");
    }
    if name.ends_with(".git") {
        return Err("Do not include the '.git' suffix in the name.");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err("Repository name may only contain letters, digits, '-', '_' and '.'.");
    }
    Ok(())
}

/// Validate that a subject is path/URL safe before it is used as an on-disk owner directory.
/// Subjects come from the trusted gateway (`u_admin` shape), but we still refuse anything that
/// could escape the repos root.
pub fn validate_owner_sub(sub: &str) -> Result<(), &'static str> {
    if sub.is_empty() || sub.len() > 128 {
        return Err("invalid owner");
    }
    if sub.starts_with('.') {
        return Err("invalid owner");
    }
    if !sub
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'))
    {
        return Err("invalid owner");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_name_rules() {
        assert!(validate_repo_name("my-repo_1.2").is_ok());
        assert!(validate_repo_name("").is_err());
        assert!(validate_repo_name(".hidden").is_err());
        assert!(validate_repo_name("-lead").is_err());
        assert!(validate_repo_name("has space").is_err());
        assert!(validate_repo_name("../escape").is_err());
        assert!(validate_repo_name("repo.git").is_err());
        assert!(validate_repo_name("a/b").is_err());
    }

    #[test]
    fn owner_sub_rules() {
        assert!(validate_owner_sub("u_admin").is_ok());
        assert!(validate_owner_sub("user@w33d.xyz").is_ok());
        assert!(validate_owner_sub("../x").is_err());
        assert!(validate_owner_sub("a/b").is_err());
        assert!(validate_owner_sub("").is_err());
    }
}
