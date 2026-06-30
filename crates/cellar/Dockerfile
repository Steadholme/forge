# syntax=docker/dockerfile:1
#
# Multi-stage build for Cellar (OCI container registry).
#   - builder: rust:1.96-slim (Debian trixie).
#   - runtime: debian:trixie-slim (matching glibc), non-root, ca-certificates.
#
# Cellar links NO OpenSSL: sqlx uses `rustls` (ring) and digests use the pure-Rust `sha2`, so the
# binary depends only on glibc — no libssl in either stage. The container HEALTHCHECK uses the
# built-in `cellar healthcheck` subcommand, so no extra HTTP tool is needed in the image. Blob
# BYTES are content-addressed on the mounted CELLAR_DATA volume (/data), owned by the non-root
# runtime user.

FROM rust:1.96-slim AS builder
WORKDIR /build

# Cache the dependency graph first: build a throwaway lib/bin against the real manifest so
# `cargo build` only recompiles our crate when src/ changes, not the whole tree.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && echo '' > src/lib.rs \
    && cargo build --release --bin cellar \
    && rm -rf src

# Now build the real binary. static/ + templates/ are include_str!'d into the binary, so they
# must be present at compile time.
COPY src ./src
COPY static ./static
COPY templates ./templates
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --bin cellar \
    && strip target/release/cellar

FROM debian:trixie-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user (no shell, no home writes needed).
RUN useradd --system --uid 10001 --user-group --no-create-home cellar \
    && mkdir -p /data \
    && chown -R cellar:cellar /data
COPY --from=builder /build/target/release/cellar /usr/local/bin/cellar

USER cellar
# Default in-container bind + blob volume; overridable at runtime.
ENV BIND_ADDR=0.0.0.0:9040 \
    CELLAR_DATA=/data
EXPOSE 9040
VOLUME ["/data"]

# Dependency-free liveness probe -> GET /healthz on the loopback, exit 0/1.
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["cellar", "healthcheck"]

ENTRYPOINT ["cellar"]
