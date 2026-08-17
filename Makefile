SHELL := /bin/sh

APP_NAME := robine-id
DOCKERHUB_USER ?= laibulle
VERSION ?= $(shell sed -n 's/.*version: "\([^"]*\)".*/\1/p' mix.exs | head -n 1)
IMAGE ?= $(DOCKERHUB_USER)/$(APP_NAME)
PLATFORM ?= linux/amd64
DATABASE_URL ?= postgres://robine_id:robine_id_dev@127.0.0.1:54329/robine_id
KEY_ENCRYPTION_SECRET ?= development-only-key-encryption-secret-change-me

VERSION_TAG := $(IMAGE):$(VERSION)
LATEST_TAG := $(IMAGE):latest

.DEFAULT_GOAL := help

.PHONY: help dev dev-container dev-db dev-down config-validate config-preview config-effective rust-preflight rust-integration keys-rotate check-variables preflight build login push publish

help:
	@echo "Robine ID development and container targets"
	@echo ""
	@echo "  make dev        Start PostgreSQL and run the Rust development server"
	@echo "  make dev-container  Build and run the Rust server entirely in Docker"
	@echo "  make dev-db     Start the development PostgreSQL container"
	@echo "  make dev-down   Stop the development PostgreSQL container"
	@echo "  make config-validate  Validate the effective Rust configuration"
	@echo "  make config-preview [CONFIG=path]  Preview Rust configuration reconciliation"
	@echo "  make config-effective Print the redacted effective Rust configuration"
	@echo "  make rust-preflight   Run Rust formatting, lint, tests, and configuration validation"
	@echo "  make rust-integration Run PostgreSQL-backed Rust integration tests"
	@echo "  make keys-rotate ROTATION_ID=<id> [ISSUER=default]"
	@echo "  make build      Build $(VERSION_TAG) and $(LATEST_TAG)"
	@echo "  make login      Authenticate with Docker Hub"
	@echo "  make push       Push the already-built version and latest tags"
	@echo "  make publish    Run preflight, build, and push"
	@echo ""
	@echo "Overrides: HOST, PORT, DOCKERHUB_USER, IMAGE, VERSION, PLATFORM"

dev: dev-db
	DATABASE_URL="$(DATABASE_URL)" KEY_ENCRYPTION_SECRET="$(KEY_ENCRYPTION_SECRET)" \
		cargo run --bin robine-id

dev-container:
	@if docker info >/dev/null 2>&1; then \
		docker compose -f compose.dev.yml --profile runtime up --detach --build --wait; \
	else \
		sg docker -c "docker compose -f compose.dev.yml --profile runtime up --detach --build --wait"; \
	fi

dev-db:
	@if docker info >/dev/null 2>&1; then \
		docker compose -f compose.dev.yml up --detach --wait; \
	else \
		sg docker -c "docker compose -f compose.dev.yml up --detach --wait"; \
	fi

dev-down:
	@if docker info >/dev/null 2>&1; then \
		docker compose -f compose.dev.yml down; \
	else \
		sg docker -c "docker compose -f compose.dev.yml down"; \
	fi

config-validate:
	cargo run --bin validate_config

config-preview:
	cargo run --bin config_preview -- $(CONFIG)

config-effective:
	cargo run --bin config_effective

rust-preflight: config-validate
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings
	cargo test --all-targets

rust-integration: dev-db
	DATABASE_URL="$(DATABASE_URL)" KEY_ENCRYPTION_SECRET="$(KEY_ENCRYPTION_SECRET)" \
		cargo test --test postgres -- --ignored --test-threads=1

ISSUER ?= default
keys-rotate: dev-db
	@test -n "$(ROTATION_ID)" || (echo "ROTATION_ID is required" >&2; exit 1)
	DATABASE_URL="$(DATABASE_URL)" KEY_ENCRYPTION_SECRET="$(KEY_ENCRYPTION_SECRET)" \
		cargo run --bin rotate_keys -- "$(ISSUER)" "$(ROTATION_ID)"

check-variables:
	@test -n "$(DOCKERHUB_USER)" || (echo "DOCKERHUB_USER is required" >&2; exit 1)
	@test -n "$(VERSION)" || (echo "VERSION could not be read from mix.exs" >&2; exit 1)

preflight: check-variables
	mix precommit
	ROBINE_ID_APPLICATIONS_DIR="$(CURDIR)/deploy/config/applications" \
		mix robine_id.config.validate deploy/config/robine_id.json

build: check-variables
	docker build \
		--platform "$(PLATFORM)" \
		--tag "$(VERSION_TAG)" \
		--tag "$(LATEST_TAG)" \
		.

login:
	docker login --username "$(DOCKERHUB_USER)"

push: check-variables
	docker push "$(VERSION_TAG)"
	docker push "$(LATEST_TAG)"

publish: preflight build push
