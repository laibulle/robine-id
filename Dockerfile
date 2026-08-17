# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.88
FROM rust:${RUST_VERSION}-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY api api
COPY assets assets
COPY config config
COPY deploy/config deploy/config
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
      --bin prune_keys \
      --bin validate_config \
      --bin config_preview \
      --bin config_apply \
      --bin config_effective \
      --bin robine-id-healthcheck \
      --bin reencrypt_keys \
      --bin generate_encryption_secret \
      --bin generate_recovery_codes \
      --bin generate_user_password \
      --bin generate_totp_secret \
    && mkdir -p /out \
    && cp \
      target/release/robine-id \
      target/release/rotate_keys \
      target/release/prune_keys \
      target/release/validate_config \
      target/release/config_preview \
      target/release/config_apply \
      target/release/config_effective \
      target/release/robine-id-healthcheck \
      target/release/reencrypt_keys \
      target/release/generate_encryption_secret \
      target/release/generate_recovery_codes \
      target/release/generate_user_password \
      target/release/generate_totp_secret \
      /out/

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --uid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin robine-id

WORKDIR /app
COPY --from=builder /out/ /usr/local/bin/
COPY --from=builder /app/deploy/config /app/config

USER robine-id

ENV HOST=0.0.0.0 \
    PORT=4001 \
    ROBINE_ID_CONFIG=/app/config/robine_id.json \
    ROBINE_ID_APPLICATIONS_DIR=/app/config/applications

EXPOSE 4001

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/usr/local/bin/robine-id-healthcheck"]

STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/robine-id"]
