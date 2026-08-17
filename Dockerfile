# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.88
FROM rust:${RUST_VERSION}-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY api api
COPY assets assets
COPY config config
COPY migrations migrations
COPY priv priv
COPY src src
COPY templates templates
RUN --mount=type=cache,id=robine-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=robine-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=robine-target,target=/app/target \
    cargo build --locked --release \
      --bin robine-id \
      --bin rotate_keys \
      --bin validate_config \
      --bin config_preview \
      --bin config_apply \
      --bin config_effective \
    && mkdir -p /out \
    && cp \
      target/release/robine-id \
      target/release/rotate_keys \
      target/release/validate_config \
      target/release/config_preview \
      target/release/config_apply \
      target/release/config_effective \
      /out/

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --uid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin robine-id

WORKDIR /app
COPY --from=builder /out/ /usr/local/bin/
COPY --from=builder /app/config /app/config

USER robine-id

ENV HOST=0.0.0.0 \
    PORT=4001 \
    ROBINE_ID_CONFIG=/app/config/robine_id.json \
    ROBINE_ID_APPLICATIONS_DIR=/app/config/applications

EXPOSE 4001

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl --fail --silent --show-error http://127.0.0.1:4001/health/ready >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/robine-id"]
