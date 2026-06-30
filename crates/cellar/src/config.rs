//! Server configuration, env-driven with working dev defaults.
//!
//! Every value keeps its dev default when the corresponding env var is unset/empty, so the
//! in-memory dev path boots with NO configuration, NO database and NO blob volume — exactly like
//! the rest of the estate. Production overrides each via the environment.

/// Default listen address (all interfaces, internal-only port 9040).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9040";

/// Default root directory of the content-addressed blob volume (`CELLAR_DATA`). Finalized blobs
/// live at `<data>/blobs/sha256/<hex>`; in-progress uploads at `<data>/uploads/<uuid>`.
pub const DEFAULT_DATA_DIR: &str = "/data";

/// Default public base URL, used in the `WWW-Authenticate` realm hint and for display.
pub const DEFAULT_PUBLIC_BASE: &str = "https://registry.w33d.xyz";

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen address (`BIND_ADDR`).
    pub bind_addr: String,
    /// Root directory of the content-addressed blob volume (`CELLAR_DATA`).
    pub data_dir: String,
    /// `/v2/` HTTP Basic auth username (`CELLAR_USER`). EMPTY disables auth entirely (the dev
    /// default), so `cargo run` and the DB-free test suite push/pull WITHOUT credentials. In
    /// production this is set, and pushes (plus the `docker login` probe) then require Basic auth.
    pub user: String,
    /// `/v2/` HTTP Basic auth password (`CELLAR_PASSWORD`).
    pub password: String,
    /// Public base URL (`PUBLIC_BASE_URL`).
    pub public_base: String,
}

impl Config {
    /// Default development configuration (in-memory store + in-memory blobs, NO auth).
    pub fn dev() -> Self {
        Config {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            data_dir: DEFAULT_DATA_DIR.to_string(),
            user: String::new(),
            password: String::new(),
            public_base: DEFAULT_PUBLIC_BASE.to_string(),
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    pub fn from_env() -> Self {
        let mut config = Config::dev();
        if let Some(v) = env_nonempty("BIND_ADDR") {
            config.bind_addr = v;
        }
        if let Some(v) = env_nonempty("CELLAR_DATA") {
            config.data_dir = v;
        }
        // user/password may legitimately be set to enable auth; empty leaves auth disabled.
        config.user = std::env::var("CELLAR_USER").unwrap_or_default();
        config.password = std::env::var("CELLAR_PASSWORD").unwrap_or_default();
        if let Some(v) = env_nonempty("PUBLIC_BASE_URL") {
            config.public_base = v.trim_end_matches('/').to_string();
        }
        config
    }

    /// True when `/v2/` Basic auth is enforced (a username is configured).
    pub fn auth_enabled(&self) -> bool {
        !self.user.is_empty()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_disables_auth() {
        let c = Config::dev();
        assert!(!c.auth_enabled());
        assert_eq!(c.bind_addr, DEFAULT_BIND_ADDR);
    }
}
