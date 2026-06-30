# syntax=docker/dockerfile:1
#
# Multi-stage build for Atlas (infrastructure catalog & topology map).
#   - builder: rust:1.96-slim (Debian trixie).
#   - runtime: debian:trixie-slim (matching glibc), non-root, ca-certificates.
#
# Like inkwell/cortex, Atlas links NO OpenSSL: sqlx uses `rustls`, and the Beacon/Watchtower hops
# are plaintext HTTP over raw TCP, so the binary depends only on glibc — no libssl in either stage.
# The container HEALTHCHECK uses the built-in `atlas healthcheck` subcommand, so no extra HTTP tool
# is needed in the image.

FROM rust:1.96-slim AS builder
WORKDIR /build

# Cache the dependency graph first: build a throwaway lib/bin against the real manifest so
# `cargo build` only recompiles our crate when src/ changes, not the whole tree.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && echo '' > src/lib.rs \
    && cargo build --release --bin atlas \
    && rm -rf src

# Now build the real binary. static/ + templates/ are include_str!'d into the binary, so they
# must be present at compile time.
COPY src ./src
COPY static ./static
COPY templates ./templates
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --bin atlas \
    && strip target/release/atlas

FROM debian:trixie-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user (no shell, no home writes needed).
RUN useradd --system --uid 10001 --user-group --no-create-home atlas
COPY --from=builder /build/target/release/atlas /usr/local/bin/atlas

USER atlas
# Default in-container bind; overridable at runtime.
ENV BIND_ADDR=0.0.0.0:9250
EXPOSE 9250

# Dependency-free liveness probe -> GET /healthz on the loopback, exit 0/1.
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["atlas", "healthcheck"]

ENTRYPOINT ["atlas"]
