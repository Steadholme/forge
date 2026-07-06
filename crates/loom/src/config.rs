//! Server configuration, env-driven with working dev defaults.
//!
//! Every value keeps its dev default when the corresponding env var is unset/empty, so the
//! in-memory dev path boots with NO configuration and NO database — exactly like
//! keystone/cairn/pastefire. Production overrides each via the environment.

/// Default listen address (all interfaces, internal-only port 9030).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9030";

/// Default on-disk root for the bare repositories + working state (`LOOM_DATA`). Bare repos
/// live under `<LOOM_DATA>/repos/{owner}/{name}.git`.
pub const DEFAULT_LOOM_DATA: &str = "/data";

/// Default public base URL, used to render the `git clone` URL on the repo page.
pub const DEFAULT_PUBLIC_BASE_URL: &str = "https://git.w33d.xyz";

/// Default clone base URL passed to SiteFlow project repository metadata.
pub const DEFAULT_SITEFLOW_LOOM_CLONE_BASE_URL: &str = "https://git.w33d.xyz/git";

/// Default placeholder domain for SiteFlow preview URLs. This must not be under `w33d.xyz`.
pub const DEFAULT_SITEFLOW_BASE_DOMAIN: &str = "sites.holdfast.internal";

/// Default cistern provisioning endpoint (`CISTERN_PROVISION_URL`); internal service address.
pub const DEFAULT_CISTERN_PROVISION_URL: &str = "http://cistern:9370/provision";

/// Default path to the `git http-backend` CGI (Debian `git` package location).
pub const DEFAULT_GIT_HTTP_BACKEND: &str = "/usr/lib/git-core/git-http-backend";

/// Default `git` binary (resolved on PATH).
pub const DEFAULT_GIT_BIN: &str = "git";

/// How many repos the home listing shows.
pub const REPO_LIST_LIMIT: usize = 200;

/// How many commits the repo page shows.
pub const COMMIT_LIMIT: usize = 30;

/// Hard cap (bytes) on a blob rendered inline in the file view; larger files show a notice.
pub const MAX_BLOB_RENDER_BYTES: usize = 512 * 1024;

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen address (`BIND_ADDR`).
    pub bind_addr: String,
    /// On-disk data root (`LOOM_DATA`); bare repos live under `<data>/repos/...`.
    pub data_dir: String,
    /// Public base URL (`PUBLIC_BASE_URL`) for the rendered clone URL.
    pub public_base_url: String,
    /// `git http-backend` CGI path (`GIT_HTTP_BACKEND`).
    pub git_http_backend: String,
    /// `git` binary (`GIT_BIN`).
    pub git_bin: String,
    /// Bearer token accepted by the internal commit-status write API (`LOOM_STATUS_TOKEN`).
    pub status_token: String,
    /// Internal SiteFlow control-plane URL (`SITEFLOW_CTRL_URL`). Empty disables outbound calls.
    pub siteflow_base_url: String,
    /// Bearer token for Loom -> SiteFlow machine calls (`SITEFLOW_API_TOKEN`).
    pub siteflow_api_token: String,
    /// Clone URL base passed to SiteFlow (`SITEFLOW_LOOM_CLONE_BASE_URL`).
    pub siteflow_clone_base_url: String,
    /// Base domain used to render placeholder preview URLs (`SITEFLOW_BASE_DOMAIN`).
    pub siteflow_base_domain: String,
    /// Default auto-deploy setting for newly saved deploy configs.
    pub auto_deploy_default: bool,
    /// Cistern provisioning endpoint (`CISTERN_PROVISION_URL`) called to lazily open a database
    /// for a repo on first deploy. Defaults to the internal service address.
    pub cistern_provision_url: String,
    /// Bearer token for Loom -> cistern provisioning calls (`CISTERN_PROVISION_TOKEN`). Empty
    /// disables lazy database provisioning (no outbound call is made).
    pub cistern_provision_token: String,
    /// Global estate webhook sink (`ESTATE_WEBHOOK_URL`) for internal bridge delivery.
    pub estate_webhook_url: Option<String>,
    /// Shared secret for signing estate webhook deliveries (`ESTATE_WEBHOOK_SECRET`).
    pub estate_webhook_secret: Option<String>,
}

impl Config {
    /// Default development configuration (in-memory store, data under the OS temp dir).
    pub fn dev() -> Self {
        Config {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            data_dir: DEFAULT_LOOM_DATA.to_string(),
            public_base_url: DEFAULT_PUBLIC_BASE_URL.to_string(),
            git_http_backend: DEFAULT_GIT_HTTP_BACKEND.to_string(),
            git_bin: DEFAULT_GIT_BIN.to_string(),
            status_token: String::new(),
            siteflow_base_url: String::new(),
            siteflow_api_token: String::new(),
            siteflow_clone_base_url: DEFAULT_SITEFLOW_LOOM_CLONE_BASE_URL.to_string(),
            siteflow_base_domain: DEFAULT_SITEFLOW_BASE_DOMAIN.to_string(),
            auto_deploy_default: false,
            cistern_provision_url: DEFAULT_CISTERN_PROVISION_URL.to_string(),
            cistern_provision_token: String::new(),
            estate_webhook_url: None,
            estate_webhook_secret: None,
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    pub fn from_env() -> Self {
        let mut config = Config::dev();
        if let Some(v) = env_nonempty("BIND_ADDR") {
            config.bind_addr = v;
        }
        if let Some(v) = env_nonempty("LOOM_DATA") {
            config.data_dir = v;
        }
        if let Some(v) = env_nonempty("PUBLIC_BASE_URL") {
            config.public_base_url = v;
        }
        if let Some(v) = env_nonempty("GIT_HTTP_BACKEND") {
            config.git_http_backend = v;
        }
        if let Some(v) = env_nonempty("GIT_BIN") {
            config.git_bin = v;
        }
        if let Some(v) = env_nonempty("LOOM_STATUS_TOKEN") {
            config.status_token = v;
        }
        if let Some(v) = env_nonempty("SITEFLOW_CTRL_URL") {
            config.siteflow_base_url = v;
        }
        if let Some(v) = env_nonempty("SITEFLOW_API_TOKEN") {
            config.siteflow_api_token = v;
        }
        if let Some(v) = env_nonempty("SITEFLOW_LOOM_CLONE_BASE_URL") {
            config.siteflow_clone_base_url = v;
        }
        if let Some(v) = env_nonempty("SITEFLOW_BASE_DOMAIN") {
            config.siteflow_base_domain = v;
        }
        if let Some(v) = env_nonempty("SITEFLOW_AUTO_DEPLOY_DEFAULT") {
            config.auto_deploy_default = parse_bool(&v);
        }
        if let Some(v) = env_nonempty("CISTERN_PROVISION_URL") {
            config.cistern_provision_url = v;
        }
        if let Some(v) = env_nonempty("CISTERN_PROVISION_TOKEN") {
            config.cistern_provision_token = v;
        }
        if let Some(v) = env_nonempty("ESTATE_WEBHOOK_URL") {
            config.estate_webhook_url = Some(v);
        }
        if let Some(v) = env_nonempty("ESTATE_WEBHOOK_SECRET") {
            config.estate_webhook_secret = Some(v);
        }
        config
    }

    /// Filesystem root holding the bare repositories (`<data>/repos`). This is the
    /// `GIT_PROJECT_ROOT` handed to `git http-backend`.
    pub fn repos_root(&self) -> String {
        format!("{}/repos", self.data_dir.trim_end_matches('/'))
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::dev()
    }
}

/// Read an env var, returning `None` when unset OR empty (empty never clobbers a default).
fn env_nonempty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

fn parse_bool(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}
