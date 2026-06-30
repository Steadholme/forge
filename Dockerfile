# syntax=docker/dockerfile:1
#
# Multi-stage build for Forge (git/registry/atlas vhost demux over three vendored library crates).
#   - builder: rust:1.96-slim (Debian trixie).
#   - runtime: debian:trixie-slim (matching glibc), non-root, ca-certificates + git.
#
# The three surfaces embed their templates + static CSS via include_str! at COMPILE time, so the
# runtime image carries only the single statically-templated binary — no assets to ship. sqlx uses
# rustls (ring) and all digests/PAT hashing are pure-Rust (sha2); Atlas's audit emitter is a raw
# TCP HTTP/1.1 writer — so the binary depends only on glibc, NO OpenSSL in either stage.
#
# The runtime DOES install `git`: Loom shells out to `git` for bare-repo management/browsing and
# serves clone/pull/push by invoking `git http-backend` as a CGI (shipped by the `git` package).
# ca-certificates is kept because Atlas's audit emitter posts to Watchtower. The HEALTHCHECK uses
# the built-in `forge healthcheck` subcommand, so the image needs no curl.

FROM rust:1.96-slim AS builder
WORKDIR /build

# Bring the whole self-contained crate (the binary + the three vendored surface crates under
# crates/) and build the release binary. The surfaces' static/ + templates/ are needed at build
# time for their include_str! embeds (they ship inside crates/).
COPY Cargo.toml ./
COPY src ./src
COPY crates ./crates
RUN cargo build --release --bin forge \
    && strip target/release/forge

FROM debian:trixie-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user (no shell, no home writes needed).
RUN useradd --system --uid 10001 --user-group --no-create-home forge
COPY --from=builder /build/target/release/forge /usr/local/bin/forge

# Loom (bare repos) and Cellar (content-addressed blobs) each own a SEPARATE on-disk data volume.
# Pre-create both owned by uid 10001 so fresh named/anonymous volumes inherit writable ownership.
RUN mkdir -p /data/loom /data/cellar && chown -R forge:forge /data
VOLUME ["/data/loom", "/data/cellar"]

USER forge
# Default in-container config; overridable at runtime. LOOM_DATA and CELLAR_DATA are DISTINCT paths
# (separate volumes) — they must never share a root.
ENV BIND_ADDR=0.0.0.0:9030 \
    LOOM_DATA=/data/loom \
    CELLAR_DATA=/data/cellar \
    GIT_HTTP_BACKEND=/usr/lib/git-core/git-http-backend
EXPOSE 9030

# Dependency-free liveness probe -> GET /healthz on the loopback, exit 0/1.
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["forge", "healthcheck"]

CMD ["forge"]
