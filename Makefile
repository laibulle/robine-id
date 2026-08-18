SHELL := /bin/sh

APP_NAME := robine-id
DOCKERHUB_USER ?= laibulle
VERSION ?= $(shell sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)
IMAGE ?= $(DOCKERHUB_USER)/$(APP_NAME)
PLATFORM ?= linux/amd64
DATABASE_URL ?= postgres://robine_id:robine_id_dev@127.0.0.1:54329/robine_id
KEY_ENCRYPTION_SECRET ?= development-only-key-encryption-secret-change-me
OAUTH2_PROXY_DEVELOPMENT_CLIENT_SECRET ?= oauth2-proxy-development-only-secret

VERSION_TAG := $(IMAGE):$(VERSION)
LATEST_TAG := $(IMAGE):latest

.DEFAULT_GOAL := help

.PHONY: help dev dev-container dev-db dev-down rp-smoke deployment-rp-smoke deployment-restore-check compose-validate config-validate config-preview config-apply config-effective doctor deployment-secrets deployment-secret-files encryption-secret metrics-token user-password totp-secret recovery-codes rust-preflight rust-integration release-smoke keys-rotate keys-prune keys-reencrypt check-variables preflight build login push publish

help:
	@echo "Robine ID development and container targets"
	@echo ""
	@echo "  make dev        Start PostgreSQL and run the Rust development server"
	@echo "  make dev-container  Build and run Rust and private PostgreSQL in Docker"
	@echo "  make dev-db     Start PostgreSQL on the loopback development port"
	@echo "  make dev-down   Stop the development PostgreSQL container"
	@echo "  make compose-validate Validate development and release Compose models"
	@echo "  make config-validate  Validate the effective Rust configuration"
	@echo "  make config-preview [CONFIG=path]  Preview Rust configuration reconciliation"
	@echo "  make config-apply [CONFIG=path]    Validate and atomically apply in the command runtime"
	@echo "  make config-effective Print the redacted effective Rust configuration"
	@echo "  make doctor     Inspect configuration, database, migrations, and signing keys read-only"
	@echo "  make deployment-secrets  Generate independent release database/encryption secrets"
	@echo "  make deployment-secret-files [SECRET_DIRECTORY=deploy/secrets]  Create protected secret files once"
	@echo "  make encryption-secret  Generate one production key-encryption secret"
	@echo "  make metrics-token  Generate one production metrics Bearer token"
	@echo "  make user-password [BCRYPT_COST=12]  Generate one initial password and hash"
	@echo "  make totp-secret  Generate one canonical 160-bit TOTP secret"
	@echo "  make recovery-codes [COUNT=10]  Generate one MFA recovery-code set"
	@echo "  make rust-preflight   Run Rust formatting, lint, tests, and configuration validation"
	@echo "  make rust-integration Run PostgreSQL-backed Rust integration tests"
	@echo "  make release-smoke    Test production OIDC, multi-instance state, and PostgreSQL restore"
	@echo "  make rp-smoke         Test a real OAuth2 Proxy relying party against the dev containers"
	@echo "  make deployment-rp-smoke  Test OAuth2 Proxy through the public release proxy"
	@echo "  make deployment-restore-check  Restore-test the running release database in isolation"
	@echo "  make keys-rotate ROTATION_ID=<id> [ISSUER=default]"
	@echo "  make keys-prune   Remove retained keys whose safe verification window elapsed"
	@echo "  make keys-reencrypt NEW_KEY_ENCRYPTION_SECRET=<secret>  Re-encrypt signing keys"
	@echo "  make build      Build $(VERSION_TAG) and $(LATEST_TAG)"
	@echo "  make login      Authenticate with Docker Hub"
	@echo "  make push       Push the already-built version and latest tags"
	@echo "  make publish    Run preflight, build, and push"
	@echo ""
	@echo "Overrides: HOST, PORT, SECRET_DIRECTORY, DOCKERHUB_USER, IMAGE, VERSION, PLATFORM"

dev: dev-db
	DATABASE_URL="$(DATABASE_URL)" KEY_ENCRYPTION_SECRET="$(KEY_ENCRYPTION_SECRET)" \
		OAUTH2_PROXY_DEVELOPMENT_CLIENT_SECRET="$(OAUTH2_PROXY_DEVELOPMENT_CLIENT_SECRET)" \
		cargo run --bin robine-id

dev-container:
	@if docker info >/dev/null 2>&1; then \
		docker compose -f compose.dev.yml --profile runtime up --detach --build --wait; \
	else \
		sg docker -c "docker compose -f compose.dev.yml --profile runtime up --detach --build --wait"; \
	fi

dev-db:
	@if docker info >/dev/null 2>&1; then \
		docker compose -f compose.dev.yml -f compose.dev.host.yml up --detach --wait; \
	else \
		sg docker -c "docker compose -f compose.dev.yml -f compose.dev.host.yml up --detach --wait"; \
	fi

dev-down:
	@if docker info >/dev/null 2>&1; then \
		docker compose -f compose.dev.yml --profile runtime down; \
	else \
		sg docker -c "docker compose -f compose.dev.yml --profile runtime down"; \
	fi

rp-smoke:
	./scripts/smoke-oauth2-proxy.sh

DEPLOYMENT_URL ?= https://id.base59.dev
DEPLOYMENT_RP_CLIENT_ID ?= oauth2-proxy
DEPLOYMENT_IDENTIFIER ?= guillaume.bailleul@gmail.com
DEPLOYMENT_RP_SECRET_FILE ?= deploy/secrets/oauth2_proxy_client_secret
DEPLOYMENT_CREDENTIALS_FILE ?= deploy/secrets/initial_admin_credentials
deployment-rp-smoke:
	ROBINE_ID_URL="$(DEPLOYMENT_URL)" \
		OAUTH2_PROXY_CLIENT_ID="$(DEPLOYMENT_RP_CLIENT_ID)" \
		OAUTH2_PROXY_CLIENT_SECRET_FILE="$(DEPLOYMENT_RP_SECRET_FILE)" \
		ROBINE_ID_IDENTIFIER="$(DEPLOYMENT_IDENTIFIER)" \
		ROBINE_ID_GENERATED_CREDENTIALS_FILE="$(DEPLOYMENT_CREDENTIALS_FILE)" \
		./scripts/smoke-oauth2-proxy.sh

deployment-restore-check:
	./scripts/verify-deployment-backup.sh

compose-validate:
	docker compose --profile runtime -f compose.dev.yml config --quiet
	docker compose --profile runtime -f compose.dev.yml -f compose.dev.host.yml config --quiet
	ROBINE_ID_ENV_FILE=.env.release.example docker compose -f compose.release.yml config --quiet
	ROBINE_ID_ENV_FILE=.env.release.files.example docker compose --env-file .env.release.files.example -f compose.release.yml -f compose.release.secrets.yml config --quiet
	ROBINE_ID_ENV_FILE=.env.release.files.example docker compose --env-file .env.release.files.example -f compose.release.yml -f compose.release.secrets.yml -f compose.release.secrets-rotation.yml config --quiet

config-validate:
	cargo run --bin validate_config

config-preview:
	cargo run --bin config_preview -- $(CONFIG)

config-apply:
	cargo run --bin config_apply -- $(CONFIG)

config-effective:
	cargo run --bin config_effective

doctor: dev-db
	DATABASE_URL="$(DATABASE_URL)" KEY_ENCRYPTION_SECRET="$(KEY_ENCRYPTION_SECRET)" \
		cargo run --bin robine-id-doctor

deployment-secrets:
	cargo run --bin generate_deployment_secrets

SECRET_DIRECTORY ?= deploy/secrets
deployment-secret-files:
	cargo run --bin generate_deployment_secrets -- --directory "$(SECRET_DIRECTORY)"

encryption-secret:
	cargo run --bin generate_encryption_secret

metrics-token:
	cargo run --bin generate_metrics_bearer_token

BCRYPT_COST ?= 12
user-password:
	cargo run --bin generate_user_password -- "$(BCRYPT_COST)"

totp-secret:
	cargo run --bin generate_totp_secret

COUNT ?= 10
recovery-codes:
	cargo run --bin generate_recovery_codes -- "$(COUNT)"

rust-preflight: config-validate
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings
	cargo test --all-targets

rust-integration: dev-db
	DATABASE_URL="$(DATABASE_URL)" KEY_ENCRYPTION_SECRET="$(KEY_ENCRYPTION_SECRET)" \
		cargo test --test postgres -- --ignored --test-threads=1

release-smoke:
	sh scripts/smoke-release.sh

ISSUER ?= default
keys-rotate: dev-db
	@test -n "$(ROTATION_ID)" || (echo "ROTATION_ID is required" >&2; exit 1)
	DATABASE_URL="$(DATABASE_URL)" KEY_ENCRYPTION_SECRET="$(KEY_ENCRYPTION_SECRET)" \
		cargo run --bin rotate_keys -- "$(ISSUER)" "$(ROTATION_ID)"

keys-prune: dev-db
	DATABASE_URL="$(DATABASE_URL)" KEY_ENCRYPTION_SECRET="$(KEY_ENCRYPTION_SECRET)" \
		cargo run --bin prune_keys

keys-reencrypt: dev-db
	@test -n "$(NEW_KEY_ENCRYPTION_SECRET)" || (echo "NEW_KEY_ENCRYPTION_SECRET is required" >&2; exit 1)
	@DATABASE_URL="$(DATABASE_URL)" \
		KEY_ENCRYPTION_SECRET="$(NEW_KEY_ENCRYPTION_SECRET)" \
		KEY_ENCRYPTION_SECRET_PREVIOUS="$(KEY_ENCRYPTION_SECRET)" \
		cargo run --bin reencrypt_keys

check-variables:
	@test -n "$(DOCKERHUB_USER)" || (echo "DOCKERHUB_USER is required" >&2; exit 1)
	@test -n "$(VERSION)" || (echo "VERSION could not be read from Cargo.toml" >&2; exit 1)

preflight: check-variables compose-validate rust-preflight
	ROBINE_ID_CONFIG="$(CURDIR)/deploy/image-config/robine_id.json" \
		ROBINE_ID_APPLICATIONS_DIR="$(CURDIR)/deploy/image-config/applications" \
		cargo run --bin validate_config
	ROBINE_ID_CONFIG="$(CURDIR)/deploy/config/robine_id.json" \
		ROBINE_ID_APPLICATIONS_DIR="$(CURDIR)/deploy/config/applications" \
		cargo run --bin validate_config

build: check-variables
	@if docker info >/dev/null 2>&1; then \
		docker build --platform "$(PLATFORM)" --tag "$(VERSION_TAG)" --tag "$(LATEST_TAG)" .; \
	else \
		sg docker -c 'docker build --platform "$(PLATFORM)" --tag "$(VERSION_TAG)" --tag "$(LATEST_TAG)" .'; \
	fi

login:
	docker login --username "$(DOCKERHUB_USER)"

push: check-variables
	docker push "$(VERSION_TAG)"
	docker push "$(LATEST_TAG)"

publish: preflight release-smoke build push
