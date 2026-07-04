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
    /// Legacy compatibility flag for repositories that required one PR approval before the
    /// numeric approval setting existed.
    pub require_approval: bool,
    /// Number of latest approving reviewers required before web merge. Zero means no approval gate.
    pub required_approvals: i64,
    /// Whether matching CODEOWNERS groups must approve before web merge.
    pub require_code_owner_reviews: bool,
    /// Whether direct smart-HTTP pushes to the default branch are blocked.
    pub protect_default_branch: bool,
    /// Parent repo id when this repo is a fork; empty for original repositories.
    pub forked_from_id: String,
    /// Creation time, epoch seconds.
    pub created_at: i64,
}

/// A user granted explicit access to one repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoCollaborator {
    /// Random opaque id (primary key).
    pub id: String,
    /// Owning repository id.
    pub repo_id: String,
    /// Collaborator subject from `X-Auth-Subject`.
    pub user_sub: String,
    /// One of `read`, `write`, or `admin`.
    pub role: String,
    /// Creation time, epoch seconds.
    pub created_at: i64,
}

pub const REPO_ROLE_READ: &str = "read";
pub const REPO_ROLE_WRITE: &str = "write";
pub const REPO_ROLE_ADMIN: &str = "admin";

pub fn normalize_repo_role(raw: &str) -> Option<&'static str> {
    match raw.trim() {
        REPO_ROLE_READ => Some(REPO_ROLE_READ),
        REPO_ROLE_WRITE => Some(REPO_ROLE_WRITE),
        REPO_ROLE_ADMIN => Some(REPO_ROLE_ADMIN),
        _ => None,
    }
}

pub fn repo_role_rank(role: &str) -> i64 {
    match role {
        REPO_ROLE_ADMIN => 3,
        REPO_ROLE_WRITE => 2,
        REPO_ROLE_READ => 1,
        _ => 0,
    }
}

/// A release attached to one repository tag. Field order/types mirror the `releases` table exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    /// Random opaque id (primary key).
    pub id: String,
    /// Owning repository id.
    pub repo_id: String,
    /// Git tag name this release describes.
    pub tag_name: String,
    /// Commit OID the tag pointed at when the release was created/updated.
    pub target_commit: String,
    /// Release title.
    pub title: String,
    /// Release notes in Markdown.
    pub body_md: String,
    /// Whether this is marked as a pre-release.
    pub is_prerelease: bool,
    /// Draft releases are visible only to writers.
    pub is_draft: bool,
    /// Creator subject from `X-Auth-Subject`.
    pub created_by: String,
    /// Creation time, epoch seconds.
    pub created_at: i64,
    /// Publish time, epoch seconds; `0` while the release remains a draft.
    pub published_at: i64,
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
    /// Optional assignee subject. Empty means unassigned.
    pub assignee_sub: String,
    /// Optional milestone id. Empty means no milestone.
    pub milestone_id: String,
    /// `open` or `closed`.
    pub state: String,
    /// Creation time, epoch seconds.
    pub created_at: i64,
    /// Last-activity time, epoch seconds (state change or a new comment). Equals `created_at` at
    /// open time.
    pub updated_at: i64,
}

impl Issue {
    /// True when the issue is open.
    pub fn is_open(&self) -> bool {
        self.state == "open"
    }
}

/// A comment on an issue. Field order/types mirror the `issue_comments` table exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssueComment {
    /// Random opaque id (primary key).
    pub id: String,
    /// Owning issue id (foreign key into `issues.id`).
    pub issue_id: String,
    /// Author subject from `X-Auth-Subject`.
    pub author_sub: String,
    /// Comment body (markdown rendered as sanitised HTML).
    pub body: String,
    /// Creation time, epoch seconds.
    pub created_at: i64,
}

/// One emoji reaction on an issue, pull request, or comment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reaction {
    /// Random opaque id (primary key).
    pub id: String,
    /// Target kind: `issue`, `pull`, or `comment`.
    pub target_type: String,
    /// Target row id from the matching table.
    pub target_id: String,
    /// Reacting user subject from `X-Auth-Subject`.
    pub user_sub: String,
    /// Whitelisted emoji glyph.
    pub emoji: String,
    /// Creation time, epoch seconds.
    pub created_at: i64,
}

/// Aggregated reaction count for one emoji plus whether the current viewer selected it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReactionSummary {
    pub emoji: String,
    pub count: i64,
    pub viewer_selected: bool,
}

/// A pull request: a request to merge the `head` branch into the `base` branch of one repository.
/// Field order/types mirror the `pulls` table exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pull {
    /// Random opaque id (primary key).
    pub id: String,
    /// Owning repository id.
    pub repo_id: String,
    /// Per-repo sequential PR number (1-based; display key), independent of issue numbers.
    pub number: i64,
    /// PR title.
    pub title: String,
    /// PR description (markdown rendered as sanitised HTML).
    pub body: String,
    /// Base branch — the branch the changes merge INTO (e.g. `main`).
    pub base: String,
    /// Head branch — the branch that CARRIES the changes.
    pub head: String,
    /// Author subject from `X-Auth-Subject`.
    pub author_sub: String,
    /// Optional assignee subject. Empty means unassigned.
    pub assignee_sub: String,
    /// Optional requested reviewer subject. Empty means no requested reviewer.
    pub reviewer_sub: String,
    /// Optional milestone id. Empty means no milestone.
    pub milestone_id: String,
    /// Whether this pull request is a draft and cannot be merged yet.
    pub is_draft: bool,
    /// `open`, `merged`, or `closed`.
    pub state: String,
    /// Creation time, epoch seconds.
    pub created_at: i64,
    /// Merge time, epoch seconds; `0` while the PR has never been merged.
    pub merged_at: i64,
}

impl Pull {
    /// True when the PR is still open (neither merged nor closed).
    pub fn is_open(&self) -> bool {
        self.state == "open"
    }
    /// True when the PR has been merged.
    pub fn is_merged(&self) -> bool {
        self.state == "merged"
    }
}

/// Per-user viewed state for one file in a pull-request diff.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrFileViewed {
    /// Owning pull request id.
    pub pr_id: String,
    /// Viewer subject from `X-Auth-Subject`.
    pub user_sub: String,
    /// File path in the diff.
    pub file_path: String,
    /// Whether this user has marked the file viewed.
    pub viewed: bool,
    /// Last update time, epoch seconds.
    pub updated_at: i64,
}

/// Resolve state for one pull-request inline comment thread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrThreadResolved {
    /// Owning pull request id.
    pub pr_id: String,
    /// Stable thread key, currently the inline anchor as `path:line`.
    pub thread_key: String,
    /// Whether the thread is resolved.
    pub resolved: bool,
    /// Subject that last changed the resolved state.
    pub resolved_by: String,
    /// Last resolved-state change time, epoch seconds.
    pub resolved_at: i64,
}

/// A repo-scoped label assignable to issues and pull requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Label {
    /// Random opaque id (primary key).
    pub id: String,
    /// Owning repository id.
    pub repo_id: String,
    /// Display name, unique per repo.
    pub name: String,
    /// Six-digit hex color, without a leading '#'.
    pub color: String,
    /// Creation time, epoch seconds.
    pub created_at: i64,
}

/// A repo-scoped milestone assignable to issues and pull requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Milestone {
    /// Random opaque id (primary key).
    pub id: String,
    /// Owning repository id.
    pub repo_id: String,
    /// Display title, unique per repo.
    pub title: String,
    /// Optional due date as YYYY-MM-DD text. Empty means no due date.
    pub due: String,
    /// `open` or `closed`.
    pub state: String,
    /// Creation time, epoch seconds.
    pub created_at: i64,
}

impl Milestone {
    /// True when the milestone is open.
    pub fn is_open(&self) -> bool {
        self.state == "open"
    }
}

/// A repo-scoped outbound webhook subscription.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Webhook {
    /// Random opaque id (primary key).
    pub id: String,
    /// Owning repository id.
    pub repo_id: String,
    /// Destination URL. Only `http` and `https` schemes are accepted by the handler layer.
    pub url: String,
    /// Shared secret used for the HMAC-SHA256 delivery signature.
    pub secret: String,
    /// Comma-separated event names, e.g. `push,pull_request,issues`.
    pub events: String,
    /// Whether this webhook should receive deliveries.
    pub active: bool,
    /// Creation time, epoch seconds.
    pub created_at: i64,
}

/// SiteFlow deployment metadata for one repository. Field order/types mirror `repo_deploy`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoDeploy {
    /// Random opaque id (primary key).
    pub id: String,
    /// Owning repository id. Unique; one deployment config per repository.
    pub repo_id: String,
    /// SiteFlow project slug, derived from owner/name for display and createProject idempotency.
    pub siteflow_slug: String,
    /// SiteFlow project id returned by `POST /api/projects`. This is not the slug.
    pub siteflow_project_id: String,
    /// Deploy hook token. Stored for server-side trigger only; never rendered.
    pub deploy_hook_token: String,
    /// Deploy hook URL. Stored for diagnostics/server use only; never rendered.
    pub deploy_hook_url: String,
    /// Branch used for production deploys.
    pub production_branch: String,
    /// Static build output directory sent to SiteFlow.
    pub output_directory: String,
    /// SiteFlow framework. Currently only `static`.
    pub framework: String,
    /// Whether pushes to the production branch should trigger deployment.
    pub auto_deploy: bool,
    /// Last SiteFlow build job id returned by a trigger.
    pub last_build_job_id: String,
    /// Placeholder preview URL on the SiteFlow base domain.
    pub preview_url: String,
    /// Last commit SHA submitted to SiteFlow.
    pub last_deployed_sha: String,
    /// Creation time, epoch seconds.
    pub created_at: i64,
    /// Last update time, epoch seconds.
    pub updated_at: i64,
}

/// A pull-request review verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PullReview {
    /// Random opaque id (primary key).
    pub id: String,
    /// Owning pull request id.
    pub pull_id: String,
    /// Reviewer subject from `X-Auth-Subject`.
    pub reviewer_sub: String,
    /// `comment`, `approve`, or `request_changes`.
    pub verdict: String,
    /// Optional review body.
    pub body: String,
    /// Creation time, epoch seconds.
    pub created_at: i64,
}

/// An inline pull-request review comment anchored to a file path and new-file line number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PullReviewComment {
    /// Random opaque id (primary key).
    pub id: String,
    /// Owning pull request id.
    pub pull_id: String,
    /// Optional review id this comment belongs to. Empty means a standalone inline comment.
    pub review_id: String,
    /// File path in the diff.
    pub path: String,
    /// New-file line number in the diff. `0` means no exact line.
    pub line: i64,
    /// Author subject from `X-Auth-Subject`.
    pub author_sub: String,
    /// Comment body.
    pub body: String,
    /// Pending comments are visible only to their author until the review is finished.
    pub pending: bool,
    /// Head commit when the line anchor was created. Empty for legacy comments without anchor data.
    pub anchor_head_oid: String,
    /// Original text of the anchored head line, without its line ending.
    pub anchor_text: String,
    /// Whether a suggestion block in this comment has already been applied.
    pub applied: bool,
    /// Creation time, epoch seconds.
    pub created_at: i64,
}

/// Latest CI/check status for one `(repo, commit_sha, context)` tuple.
/// Field order/types mirror the `commit_statuses` table exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitStatus {
    /// Random opaque id (primary key).
    pub id: String,
    /// Owning repository id.
    pub repo_id: String,
    /// Full resolved commit object id.
    pub commit_sha: String,
    /// `pending`, `success`, `failure`, or `error`.
    pub state: String,
    /// Status/check context, e.g. `ci/anvil`, `build`, `test`.
    pub context: String,
    /// Optional short human-readable summary. Empty means none.
    pub description: String,
    /// Optional URL for the CI/check run. Empty means none.
    pub target_url: String,
    /// First creation time, epoch seconds.
    pub created_at: i64,
    /// Last update time, epoch seconds.
    pub updated_at: i64,
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

/// Validate a label name. Labels are plain display text, but bounded so list rows stay compact.
pub fn validate_label_name(name: &str) -> Result<(), &'static str> {
    if name.trim().is_empty() {
        return Err("Label name cannot be empty.");
    }
    if name.chars().count() > 40 {
        return Err("Label name is too long (40 characters maximum).");
    }
    Ok(())
}

/// Validate a label color as six ASCII hex digits, stored without a leading '#'.
pub fn validate_label_color(color: &str) -> Result<(), &'static str> {
    let c = color.trim().trim_start_matches('#');
    if c.len() != 6 || !c.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("Label color must be a six-digit hex value.");
    }
    Ok(())
}

/// Validate a milestone title.
pub fn validate_milestone_title(title: &str) -> Result<(), &'static str> {
    if title.trim().is_empty() {
        return Err("Milestone title cannot be empty.");
    }
    if title.chars().count() > 120 {
        return Err("Milestone title is too long (120 characters maximum).");
    }
    Ok(())
}

/// Validate an optional YYYY-MM-DD due-date string.
pub fn validate_milestone_due(due: &str) -> Result<(), &'static str> {
    let due = due.trim();
    if due.is_empty() {
        return Ok(());
    }
    let bytes = due.as_bytes();
    let ok = bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit());
    if ok {
        Ok(())
    } else {
        Err("Milestone due date must be YYYY-MM-DD.")
    }
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
