# Atlas — infrastructure catalog & topology map

Atlas is the IaC/portal **capstone** of the Steadholme estate: a single _"what is in my
estate"_ catalog and dependency view, built over the gateway's route table and live
component status. Rust + axum, rustls (no OpenSSL), sqlx runtime queries (no compile-time
macros, no database needed to build). Boots zero-config on the in-memory defaults.

## What it does

- **Discovers** every public service by reading Sluice's `routes` table **READ-ONLY** via
  `ATLAS_ROUTES_DSN` (the shared `holdfast` DB). Routes are grouped by upstream service.
- **Overlays** live component status from Beacon (`GET http://beacon:8400/api/status`, open
  internally). A down source degrades to _Unavailable_ — it never errors the page.
- **Lets an operator annotate** each service (display name / owner / tier / free-text notes),
  stored in Atlas's OWN `atlas` database (`services` table).

## Endpoints (served at the subdomain ROOT — Sluice forwards the path unmodified)

| Method | Path               | Auth      | Description |
|--------|--------------------|-----------|-------------|
| GET    | `/healthz`         | none      | Liveness (container HEALTHCHECK) |
| GET    | `/`                | sso       | The catalog: hosts grouped by upstream service + status + notes + summary |
| GET    | `/service/{key}`   | sso       | One service's routes + the annotation edit form |
| POST   | `/api/annotate`    | sso, CSRF | Save operator metadata for a service key (audited) |
| GET    | `/graph`           | sso       | Inline-SVG topology: gateway → each upstream, colored by auth mode |
| GET    | `/api/inventory`   | sso       | The full assembled inventory as JSON |

Atlas is **internal-only** behind Sluice `auth=sso`: it does no login, trusts the
gateway-injected `X-Auth-Subject` / `X-Auth-Email` / `X-Auth-Scope`, and 401s every
non-health endpoint without an identity. State-changing POSTs are double-submit CSRF
protected (`__Host-csrf`).

## Configuration

| Env | Default | Meaning |
|-----|---------|---------|
| `BIND_ADDR` | `0.0.0.0:9250` | Listen address |
| `ATLAS_STORE` | `memory` | Annotation store: `memory` or `postgres` |
| `DATABASE_URL` | — | Required for `ATLAS_STORE=postgres` (the `atlas` db) |
| `ATLAS_ROUTES_DSN` | — | READ-ONLY DSN to the shared `holdfast` DB (the `routes` table). Unset → built-in demo seed |
| `BEACON_URL` | `http://beacon:8400` | Beacon base URL (`/api/status`) |
| `AUDIT_ENABLED` | `false` | Enable the non-blocking Watchtower audit emitter |
| `WATCHTOWER_URL` | — | `http://watchtower:8500` |
| `AUDIT_INGEST_TOKEN` | — | Bearer token for Watchtower ingest |

Notable events emit `atlas.annotate` to Watchtower via a non-blocking bounded queue —
a down Watchtower never blocks a request.

## Build & test

```
CARGO_BUILD_JOBS=2 cargo check --all-targets
cargo test
```
