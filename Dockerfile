#
# Hedge – AI Guard Proxy as a container image.
#
#   docker build -t hedge:0.1.0 .
#
# Both architectures at once, pushed to your registry:
#
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -t registry.example.com/hedge:0.1.0 --push .
#
# The image runs as a non-root user (uid 10001), reads its config from
# /etc/hedge/hedge.toml and keeps everything that must survive a restart
# (witness, signing key, control token) under /var/lib/hedge – mount a volume
# there. See docs/operations.md. `hedge deploy compose` writes the Compose
# directory that runs this image together with Presidio.

# ---- build ----
FROM rust:1-slim-bookworm AS build

# aws-lc (the TLS library behind rustls) needs a C toolchain; cmake is its
# fallback on targets without a prepared build.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential cmake \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# The templates for `hedge deploy compose` and the files of the Presidio
# image are compiled into the binary (include_str!).
COPY deploy ./deploy

# The cache mounts keep the crate registry and the build directory between
# builds (BuildKit, the default builder since Docker 23); the binary is
# copied out because a cache mount is not part of the image.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
 && cp target/release/hedge /usr/local/bin/hedge

# ---- run ----
FROM debian:bookworm-slim

# ca-certificates: Hedge verifies api.anthropic.com against the system trust
# store. A company CA (TLS inspection) goes into the same store – see
# docs/operations.md, "Corporate proxy and CA".
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --user-group \
      --home-dir /var/lib/hedge --shell /usr/sbin/nologin hedge \
 && install -d -o root  -g hedge -m 0750 /etc/hedge \
 && install -d -o hedge -g hedge -m 0750 /var/lib/hedge

COPY --from=build /usr/local/bin/hedge /usr/local/bin/hedge
COPY --chmod=0755 deploy/docker/entrypoint.sh /usr/local/bin/hedge-entrypoint
# A config to start with: observe mode, all addresses, client token required
# only once you add clients. Mount your own over /etc/hedge.
COPY --chown=root:hedge --chmod=0640 deploy/docker/hedge.toml /etc/hedge/hedge.toml

ENV HEDGE_CONFIG=/etc/hedge/hedge.toml \
    HOME=/var/lib/hedge

USER 10001:10001
WORKDIR /var/lib/hedge
VOLUME /var/lib/hedge

# 18765: the proxy (agents). 18766: the control API (admins).
EXPOSE 18765 18766

# `hedge ready` asks /ready: unhealthy while the witness cannot be written,
# while hedge is shutting down, or – with on_unavailable = "block" in force –
# while Presidio is not ready yet.
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
  CMD ["hedge", "ready"]

LABEL org.opencontainers.image.title="hedge" \
      org.opencontainers.image.description="AI guard proxy for coding agents" \
      org.opencontainers.image.source="https://github.com/munichbughunter/hedge" \
      org.opencontainers.image.licenses="MIT"

ENTRYPOINT ["hedge-entrypoint"]
CMD ["run"]
