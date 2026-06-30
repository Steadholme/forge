# syntax=docker/dockerfile:1
#
# Multi-stage build for Loom (self-hosted git forge).
#   - builder: rust:1.96-slim (Debian trixie).
#   - runtime: debian:trixie-slim (matching glibc), non-root, ca-certificates + git.
#
# Loom links NO OpenSSL: sqlx uses `rustls` and PAT hashing is RustCrypto (sha2), so the binary
# depends only on glibc. The runtime DOES install `git` — Loom shells out to `git` for bare-repo
# management + browsing, and serves clone/pull/push by invoking `git http-backend` as a CGI
# (`/usr/lib/git-core/git-http-backend`, shipped by the `git` package). The container HEALTHCHECK
# uses the built-in `loom healthcheck` subcommand, so the image needs no curl.

FROM rust:1.96-slim AS builder
WORKDIR /build

# Cache the dependency graph first: build a throwaway lib/bin against the real manifest so
# `cargo build` only recompiles our crate when src/ changes, not the whole tree.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && echo '' > src/lib.rs \
    && cargo build --release --bin loom \
    && rm -rf src

# Now build the real binary. static/ + templates/ are include_str!'d into the binary, so they
# must be present at compile time.
COPY src ./src
COPY static ./static
COPY templates ./templates
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --bin loom \
    && strip target/release/loom

FROM debian:trixie-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user (no shell, no home writes needed).
RUN useradd --system --uid 10001 --user-group --no-create-home loom
COPY --from=builder /build/target/release/loom /usr/local/bin/loom

# Bare-repository root. Pre-creating it owned by uid 10001 means a FRESH named/anonymous volume
# mounted here inherits writable ownership (Docker seeds the volume from the image path).
RUN mkdir -p /data && chown loom:loom /data
VOLUME ["/data"]

USER loom
# Default in-container config; overridable at runtime.
ENV BIND_ADDR=0.0.0.0:9030 \
    LOOM_DATA=/data \
    GIT_HTTP_BACKEND=/usr/lib/git-core/git-http-backend
EXPOSE 9030

# Dependency-free liveness probe -> GET /healthz on the loopback, exit 0/1.
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["loom", "healthcheck"]

ENTRYPOINT ["loom"]
