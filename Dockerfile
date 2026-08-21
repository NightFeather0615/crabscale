# syntax=docker/dockerfile:1
# Multi-stage deployment image for crabscale-server (M4-03, #26).
#
#   stage builder: full Rust toolchain + C compiler (for bundled SQLite)
#   stage runtime: minimal Debian slim, NO compiler, runs as non-root
#
# Build:
#   docker build -t crabscale:latest .
#
# The final stage is intentionally free of build tooling and runs as the
# `crabscale` user so a compromised server process has no compiler to leverage.

FROM rust:1-slim AS builder
WORKDIR /app

# Compile-time-only dependencies: a C compiler (bundled SQLite) and headers.
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first so dependency layers cache across source edits.
COPY Cargo.toml Cargo.lock ./
COPY crabscale-proto/Cargo.toml crabscale-proto/
COPY crabscale-transport/Cargo.toml crabscale-transport/
COPY crabscale-control/Cargo.toml crabscale-control/
COPY crabscale-policy/Cargo.toml crabscale-policy/
COPY crabscale-derp/Cargo.toml crabscale-derp/
COPY crabscale-server/Cargo.toml crabscale-server/
COPY crabscale-cli/Cargo.toml crabscale-cli/
COPY crabscale-harness/Cargo.toml crabscale-harness/
COPY crabscale-fuzz/Cargo.toml crabscale-fuzz/

# Copy the rest of the source and build the server binary in release mode.
COPY . .
RUN cargo build --release -p crabscale-server

FROM debian:bookworm-slim AS runtime
# No compiler, no build tools: only the runtime libraries baked into the
# statically-linked Rust binary are present.
RUN groupadd -r crabscale \
    && useradd -r -g crabscale -m -d /var/lib/crabscale crabscale \
    && mkdir -p /var/lib/crabscale/data \
    && chown -R crabscale:crabscale /var/lib/crabscale

WORKDIR /var/lib/crabscale

COPY --from=builder /app/target/release/crabscale-server /usr/local/bin/crabscale-server

RUN chmod 755 /usr/local/bin/crabscale-server

# Non-root user: the container must not be able to install software.
USER crabscale

# Persistent state: machine key file + SQLite database live here.
VOLUME ["/var/lib/crabscale/data"]

EXPOSE 8080 8443 80 3478/udp

ENTRYPOINT ["crabscale-server"]
CMD ["--listen", "0.0.0.0:8080"]
