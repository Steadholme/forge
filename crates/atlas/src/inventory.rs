//! The estate inventory: assemble the gateway routes + operator annotations + live Beacon status
//! into the grouped, ranked catalog the dashboard, the topology graph, and the JSON API all render.
//!
//! The unit of the catalog is the **upstream service** (the container behind one or more public
//! routes), keyed by the upstream authority's host (`http://inkwell:8700` -> `inkwell`). Multiple
//! routes can map to one service (e.g. `drive.w33d.xyz/` and `drive.w33d.xyz/s/` both front
//! `aperture`); they collapse into one entry. The whole module is pure (no I/O): the handlers fetch
//! the three inputs and call [`build`], so it is trivially unit-testable.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::beacon::Statuses;
use crate::routes_src::Route;
use crate::store::Service;

/// One public route as presented in the catalog (effective auth resolved, public URL derived).
#[derive(Clone, Debug, Serialize)]
pub struct RouteView {
    pub name: String,
    pub host: String,
    pub path_prefix: String,
    pub public_url: String,
    /// Effective auth mode: `sso` | `public` | `bearer` (derived from `auth`/`protected`).
    pub auth: String,
    pub waf: bool,
}

/// One discovered service, with its routes, a representative auth/status, and any operator metadata.
#[derive(Clone, Debug, Serialize)]
pub struct ServiceEntry {
    /// Upstream service key (e.g. `inkwell`).
    pub key: String,
    /// Operator display name, falling back to `key` when unannotated.
    pub display_name: String,
    pub owner: String,
    pub tier: String,
    pub notes: String,
    /// All public routes that front this service, sorted by host then path.
    pub routes: Vec<RouteView>,
    /// Distinct effective auth modes across this service's routes (e.g. `["sso","public"]`).
    pub auth_modes: Vec<String>,
    /// Representative auth mode used to classify the topology edge (the root `/` route's, else first).
    pub primary_auth: String,
    /// True when any route fronting this service has the inline WAF engaged.
    pub waf_any: bool,
    /// Live status token: `operational` | `degraded` | `down` | `unknown` | `unavailable`.
    pub status: String,
    /// True when an operator annotation exists for this key (any non-empty metadata field).
    pub annotated: bool,
    pub updated_at: i64,
}

/// The assembled inventory: every discovered service plus the headline summary counts.
#[derive(Clone, Debug, Serialize)]
pub struct Inventory {
    pub services: Vec<ServiceEntry>,
    pub services_total: usize,
    pub routes_total: usize,
    pub public_count: usize,
    pub sso_count: usize,
    pub bearer_count: usize,
    /// False when the route table could not be read (the dashboard shows a degrade banner).
    pub routes_available: bool,
    /// False when Beacon was unreachable (every status falls back to `unavailable`).
    pub beacon_reached: bool,
    /// Beacon "systems online" rollup (`up` of `total`); both 0 when Beacon was unreachable.
    pub beacon_up: usize,
    pub beacon_total: usize,
}

/// Derive a route's effective auth mode. An explicit `auth` wins; otherwise fall back to the legacy
/// `protected` flag (`true` -> `sso`, `false` -> `public`).
pub fn effective_auth(r: &Route) -> String {
    let a = r.auth.trim().to_ascii_lowercase();
    if !a.is_empty() {
        return a;
    }
    if r.protected {
        "sso".to_string()
    } else {
        "public".to_string()
    }
}

/// Derive the upstream service key from an upstream URL: the authority's host component, dropping
/// the scheme, any path, and the port (`http://inkwell:8700/x` -> `inkwell`).
pub fn service_key(upstream: &str) -> String {
    let rest = upstream.split("://").nth(1).unwrap_or(upstream);
    let authority = rest.split('/').next().unwrap_or(rest);
    let host = authority
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(authority)
        .trim();
    if host.is_empty() {
        upstream.trim().to_string()
    } else {
        host.to_string()
    }
}

/// Build the public URL for a route: `https://{host}{path_prefix}`. An empty host (a host-agnostic
/// route) renders just the path prefix.
pub fn public_url(host: &str, path_prefix: &str) -> String {
    if host.is_empty() {
        path_prefix.to_string()
    } else {
        format!("https://{host}{path_prefix}")
    }
}

/// Stable presentation category for an auth mode.
///
/// The inventory authority keeps the original auth token. Renderers consume this bounded slug so
/// an unknown token can never become a CSS value or a `data-*` attribute.
pub fn auth_slug(auth: &str) -> &'static str {
    match auth {
        "sso" => "sso",
        "public" => "public",
        "bearer" => "bearer",
        _ => "other",
    }
}

/// Assemble the inventory from the three inputs. `routes_ok == false` means the route table read
/// failed — `routes` is then empty and `routes_available` is reported false so the UI degrades.
pub fn build(
    routes: Vec<Route>,
    routes_ok: bool,
    annotations: &[Service],
    beacon: &Statuses,
) -> Inventory {
    // Headline route counts (over every route, before grouping).
    let routes_total = routes.len();
    let mut public_count = 0;
    let mut sso_count = 0;
    let mut bearer_count = 0;
    for r in &routes {
        match effective_auth(r).as_str() {
            "public" => public_count += 1,
            "sso" => sso_count += 1,
            "bearer" => bearer_count += 1,
            _ => {}
        }
    }

    // Group routes by upstream service key (BTreeMap keeps the output stably alphabetized).
    let mut grouped: BTreeMap<String, Vec<Route>> = BTreeMap::new();
    for r in routes {
        grouped.entry(service_key(&r.upstream)).or_default().push(r);
    }

    let mut services = Vec::with_capacity(grouped.len());
    for (key, mut group) in grouped {
        // Routes within a service: stable by host then (descending length) path, so a longer,
        // more-specific prefix lists first — matching how the gateway resolves them.
        group.sort_by(|a, b| {
            a.host
                .cmp(&b.host)
                .then_with(|| b.path_prefix.len().cmp(&a.path_prefix.len()))
                .then_with(|| a.path_prefix.cmp(&b.path_prefix))
        });

        let mut auth_modes: Vec<String> = Vec::new();
        let mut waf_any = false;
        let mut hosts: Vec<String> = Vec::new();
        let route_views: Vec<RouteView> = group
            .iter()
            .map(|r| {
                let auth = effective_auth(r);
                if !auth_modes.contains(&auth) {
                    auth_modes.push(auth.clone());
                }
                if r.waf {
                    waf_any = true;
                }
                if !r.host.is_empty() && !hosts.contains(&r.host) {
                    hosts.push(r.host.clone());
                }
                RouteView {
                    name: r.name.clone(),
                    host: r.host.clone(),
                    path_prefix: r.path_prefix.clone(),
                    public_url: public_url(&r.host, &r.path_prefix),
                    auth,
                    waf: r.waf,
                }
            })
            .collect();

        // Representative auth: the root `/` route's mode (what a browser hits first), else the first.
        let primary_auth = group
            .iter()
            .find(|r| r.path_prefix == "/")
            .map(effective_auth)
            .or_else(|| group.first().map(effective_auth))
            .unwrap_or_default();

        let annotation = annotations.iter().find(|s| s.key == key);
        let display_name = annotation
            .map(|a| a.display_name.clone())
            .filter(|d| !d.trim().is_empty())
            .unwrap_or_else(|| key.clone());
        let annotated = annotation
            .map(|a| {
                !a.display_name.trim().is_empty()
                    || !a.owner.trim().is_empty()
                    || !a.tier.trim().is_empty()
                    || !a.notes.trim().is_empty()
            })
            .unwrap_or(false);

        // Best-effort live status: try the operator display name, the key, and each host's first
        // label against Beacon's component names. Unreachable Beacon -> "unavailable".
        let mut candidates: Vec<&str> = vec![display_name.as_str(), key.as_str()];
        for h in &hosts {
            if let Some(label) = h.split('.').next() {
                candidates.push(label);
            }
        }
        let status = beacon.status_for(&candidates);

        services.push(ServiceEntry {
            key: key.clone(),
            display_name,
            owner: annotation.map(|a| a.owner.clone()).unwrap_or_default(),
            tier: annotation.map(|a| a.tier.clone()).unwrap_or_default(),
            notes: annotation.map(|a| a.notes.clone()).unwrap_or_default(),
            routes: route_views,
            auth_modes,
            primary_auth,
            waf_any,
            status,
            annotated,
            updated_at: annotation.map(|a| a.updated_at).unwrap_or(0),
        });
    }

    let services_total = services.len();
    Inventory {
        services,
        services_total,
        routes_total,
        public_count,
        sso_count,
        bearer_count,
        routes_available: routes_ok,
        beacon_reached: beacon.reached,
        beacon_up: beacon.up,
        beacon_total: beacon.total,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(name: &str, host: &str, path: &str, upstream: &str, auth: &str, waf: bool) -> Route {
        Route {
            name: name.to_string(),
            host: host.to_string(),
            path_prefix: path.to_string(),
            upstream: upstream.to_string(),
            protected: auth != "public",
            auth: auth.to_string(),
            waf,
        }
    }

    #[test]
    fn service_key_strips_scheme_port_path() {
        assert_eq!(service_key("http://inkwell:8700"), "inkwell");
        assert_eq!(service_key("https://keystone:8443/x"), "keystone");
        assert_eq!(service_key("http://whoami:80"), "whoami");
        assert_eq!(service_key("cellar:9040"), "cellar");
    }

    #[test]
    fn effective_auth_falls_back_to_protected() {
        // Empty auth + protected=false -> public.
        let mut r = Route {
            name: "x".into(),
            host: "h".into(),
            path_prefix: "/".into(),
            upstream: "http://u:1".into(),
            protected: false,
            auth: String::new(),
            waf: false,
        };
        assert_eq!(effective_auth(&r), "public");
        // Empty auth + protected=true -> sso (legacy flag).
        r.protected = true;
        assert_eq!(effective_auth(&r), "sso");
        // Explicit auth always wins over the protected flag.
        r.auth = "bearer".to_string();
        assert_eq!(effective_auth(&r), "bearer");
    }

    #[test]
    fn build_groups_routes_by_upstream_and_counts() {
        let routes = vec![
            route(
                "drive-share",
                "drive.w33d.xyz",
                "/s/",
                "http://aperture:8900",
                "public",
                false,
            ),
            route(
                "drive-root",
                "drive.w33d.xyz",
                "/",
                "http://aperture:8900",
                "sso",
                false,
            ),
            route(
                "blog",
                "blog.w33d.xyz",
                "/",
                "http://inkwell:8700",
                "sso",
                false,
            ),
            route(
                "id-api",
                "id.w33d.xyz",
                "/api",
                "http://whoami:80",
                "bearer",
                false,
            ),
        ];
        let inv = build(routes, true, &[], &Statuses::default());
        assert_eq!(inv.routes_total, 4);
        // aperture (2 routes -> 1 service), inkwell, whoami => 3 services.
        assert_eq!(inv.services_total, 3);
        assert_eq!(inv.public_count, 1);
        assert_eq!(inv.sso_count, 2);
        assert_eq!(inv.bearer_count, 1);

        let aperture = inv.services.iter().find(|s| s.key == "aperture").unwrap();
        assert_eq!(aperture.routes.len(), 2);
        // root route's auth is the primary (edge color).
        assert_eq!(aperture.primary_auth, "sso");
        assert!(aperture.auth_modes.contains(&"public".to_string()));
        assert!(aperture.auth_modes.contains(&"sso".to_string()));
        // Beacon unreachable -> unavailable.
        assert_eq!(aperture.status, "unavailable");
    }

    #[test]
    fn build_layers_annotation_and_display_name() {
        let routes = vec![route(
            "blog",
            "blog.w33d.xyz",
            "/",
            "http://inkwell:8700",
            "sso",
            false,
        )];
        let ann = Service {
            key: "inkwell".to_string(),
            display_name: "Inkwell Blog".to_string(),
            owner: "platform".to_string(),
            tier: "content".to_string(),
            notes: "personal CMS".to_string(),
            updated_at: 42,
        };
        let inv = build(
            routes,
            true,
            std::slice::from_ref(&ann),
            &Statuses::default(),
        );
        let s = &inv.services[0];
        assert_eq!(s.display_name, "Inkwell Blog");
        assert!(s.annotated);
        assert_eq!(s.owner, "platform");
        assert_eq!(s.updated_at, 42);
    }

    #[test]
    fn build_degrades_when_routes_unavailable() {
        let inv = build(Vec::new(), false, &[], &Statuses::default());
        assert!(!inv.routes_available);
        assert_eq!(inv.services_total, 0);
    }

    #[test]
    fn public_url_includes_host_and_prefix() {
        assert_eq!(
            public_url("drive.w33d.xyz", "/s/"),
            "https://drive.w33d.xyz/s/"
        );
        assert_eq!(public_url("", "/x"), "/x");
    }

    #[test]
    fn auth_slug_normalizes_to_four_buckets() {
        assert_eq!(auth_slug("sso"), "sso");
        assert_eq!(auth_slug("public"), "public");
        assert_eq!(auth_slug("bearer"), "bearer");
        assert_eq!(auth_slug(""), "other");
        assert_eq!(auth_slug("mtls"), "other");
        assert_eq!(auth_slug("<x>"), "other");
    }
}
