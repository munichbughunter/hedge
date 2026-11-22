# Hedge als Container-Image (für den zentralen Betrieb).
#
#   docker build -t ghcr.io/munichbughunter/hedge:<version> .
#
# Das Compose-Verzeichnis dazu schreibt `hedge deploy compose`.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# Vorlagen und Deploy-Dateien stecken im Binary (include_str!).
COPY deploy ./deploy
RUN cargo build --release --locked

FROM debian:bookworm-slim
# CA-Zertifikate: Hedge prüft die Upstreams gegen den Trust Store des Systems.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --home-dir /var/lib/hedge hedge
COPY --from=build /src/target/release/hedge /usr/local/bin/hedge

USER 10001
ENV HOME=/var/lib/hedge \
    HEDGE_CONFIG=/etc/hedge/hedge.toml
VOLUME /var/lib/hedge
EXPOSE 18765

# `hedge ready` fragt /ready: 0, wenn Hedge Anfragen so bedient, wie die
# Config es verlangt (bei on_unavailable = "block" also erst mit Presidio).
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD ["hedge", "ready"]

LABEL org.opencontainers.image.title="hedge" \
      org.opencontainers.image.description="AI guard proxy for coding agents" \
      org.opencontainers.image.source="https://github.com/munichbughunter/hedge" \
      org.opencontainers.image.licenses="MIT"

# Schlüssel und Steuer-Token entstehen beim ersten Start im Volume; die
# Config kommt von außen.
CMD ["sh", "-c", "hedge init --keys-only --dir /var/lib/hedge && exec hedge run"]
