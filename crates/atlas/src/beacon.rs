//! Beacon client: fetch the live component-status snapshot.
//!
//! The catalog maps each service to a status pill, and the summary shows a "systems online" count.
//! Both come from Beacon's machine-readable snapshot at `<BEACON_URL>/api/status` (the same JSON
//! Beacon's public status page is built from). Beacon is open internally, so no auth is sent.
//!
//! RESILIENCE IS THE CONTRACT: every failure (DNS, connect, timeout, non-200, bad JSON) collapses
//! to an EMPTY snapshot (`reached == false`). The catalog then degrades every status to
//! "unavailable" and the count to "—", so a down or slow Beacon NEVER errors the dashboard.

use std::collections::HashMap;
use std::time::Duration;

use serde::Deserialize;

use crate::http;

/// Per-fetch budget. Beacon is in-network; keep it short so a stalled connection can never tie a
/// page load up for long.
const FETCH_TIMEOUT: Duration = Duration::from_secs(2);

/// The slice of Beacon's `/api/status` JSON we need: each component's name + status.
#[derive(Debug, Deserialize)]
struct BeaconStatus {
    #[serde(default)]
    components: Vec<BeaconComponent>,
}

#[derive(Debug, Deserialize)]
struct BeaconComponent {
    name: String,
    status: String,
}

/// A parsed Beacon snapshot: per-component statuses plus the operational rollup the "systems
/// online" metric reads. An empty snapshot (`reached == false`) means Beacon was unreachable.
#[derive(Clone, Debug, Default)]
pub struct Statuses {
    /// Lower-cased component name -> status token (`operational` | `degraded` | `down`).
    pub by_name: HashMap<String, String>,
    /// Count of components reporting `operational`.
    pub up: usize,
    /// Total components Beacon reported.
    pub total: usize,
    /// Whether Beacon answered with parseable JSON at all (drives "—" vs a real count).
    pub reached: bool,
}

impl Statuses {
    /// Best-effort status for a service, trying each `candidate` name (case-insensitively) against
    /// the components Beacon reported. Returns `"unavailable"` when Beacon was unreachable, or
    /// `"unknown"` when it answered but reported no matching component.
    pub fn status_for(&self, candidates: &[&str]) -> String {
        if !self.reached {
            return "unavailable".to_string();
        }
        for c in candidates {
            let key = c.trim().to_ascii_lowercase();
            if key.is_empty() {
                continue;
            }
            if let Some(s) = self.by_name.get(&key) {
                return s.clone();
            }
        }
        "unknown".to_string()
    }
}

/// Fetch Beacon's component statuses. On ANY failure returns the default (empty, not reached)
/// snapshot — never errors.
pub async fn fetch(beacon_url: &str) -> Statuses {
    let url = format!("{}/api/status", beacon_url.trim_end_matches('/'));
    match http::fetch_text(&url, FETCH_TIMEOUT).await {
        Some(body) => parse_statuses(&body),
        None => Statuses::default(),
    }
}

/// Parse Beacon's `/api/status` JSON body into a [`Statuses`] snapshot. Invalid/foreign JSON yields
/// the default (not-reached) snapshot so the caller renders "unavailable".
pub fn parse_statuses(body: &str) -> Statuses {
    match serde_json::from_str::<BeaconStatus>(body) {
        Ok(snap) => {
            let total = snap.components.len();
            let up = snap
                .components
                .iter()
                .filter(|c| c.status == "operational")
                .count();
            let by_name = snap
                .components
                .into_iter()
                .map(|c| (c.name.to_ascii_lowercase(), c.status))
                .collect();
            Statuses {
                by_name,
                up,
                total,
                reached: true,
            }
        }
        Err(_) => Statuses::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_for_matches_any_candidate_case_insensitively() {
        let body = r#"{
            "overall":"degraded",
            "components":[
                {"name":"Identity","kind":"tcp","status":"operational"},
                {"name":"Gateway","kind":"http","status":"degraded"}
            ]
        }"#;
        let s = parse_statuses(body);
        assert!(s.reached);
        assert_eq!(s.status_for(&["identity"]), "operational");
        assert_eq!(s.status_for(&["GATEWAY"]), "degraded");
        assert_eq!(s.status_for(&["nope", "Identity"]), "operational");
        assert_eq!(s.status_for(&["nope"]), "unknown");
        assert_eq!(s.total, 2);
        assert_eq!(s.up, 1);
    }

    #[test]
    fn status_for_on_unreached_is_unavailable() {
        let s = parse_statuses("not json at all");
        assert!(!s.reached);
        assert_eq!(s.status_for(&["identity"]), "unavailable");
        assert_eq!(s.total, 0);
    }
}
