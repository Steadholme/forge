//! Server configuration, env-driven with working dev defaults.
//!
//! Every value keeps its dev default when the corresponding env var is unset/empty, so the
//! in-memory dev path boots with NO configuration and NO database — exactly like
//! inkwell/cortex/portal. Production overrides each via the environment.

/// Default listen address (all interfaces, internal-only port 9250).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9250";

/// Default INTERNAL Beacon base URL; the live-status fetch hits `<url>/api/status`.
pub const DEFAULT_BEACON_URL: &str = "http://beacon:8400";

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen address (`BIND_ADDR`).
    pub bind_addr: String,
    /// INTERNAL Beacon base URL (`BEACON_URL`); live status comes from `<url>/api/status`.
    pub beacon_url: String,
}

impl Config {
    /// Default development configuration (in-memory friendly, no database).
    pub fn dev() -> Self {
        Config {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            beacon_url: DEFAULT_BEACON_URL.to_string(),
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    pub fn from_env() -> Self {
        let mut config = Config::dev();
        if let Some(v) = env_nonempty("BIND_ADDR") {
            config.bind_addr = v;
        }
        if let Some(v) = env_nonempty("BEACON_URL") {
            config.beacon_url = v.trim_end_matches('/').to_string();
        }
        config
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::dev()
    }
}

/// Read an env var, returning `None` when unset OR empty (empty never clobbers a default).
pub fn env_nonempty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => None,
    }
}
