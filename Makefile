SHELL := /bin/sh

APP_NAME := robine-id
DOCKERHUB_USER ?= laibulle
VERSION ?= $(shell cat VERSION)
IMAGE ?= $(DOCKERHUB_USER)/$(APP_NAME)
PLATFORM ?= linux/amd64
DEV_PORT ?= 4001
DEV_APP_PORT ?= 4002
DEV_STATE_ROOT ?= .dev/state
AIR_VERSION ?= v1.67.3

VERSION_TAG := $(IMAGE):$(VERSION)
LATEST_TAG := $(IMAGE):latest

.DEFAULT_GOAL := help
.PHONY: help dev fmt lint test coverage check preflight build login push publish

help:
	@echo "Robine ID targets"
	@echo "  make dev        Run with automatic rebuild and browser reload on port $(DEV_PORT)"
	@echo "  make check      Format, vet, test, and enforce 80% coverage"
	@echo "  make build      Build $(VERSION_TAG) and $(LATEST_TAG)"
	@echo "  make publish    Check, build, and push both image tags"

dev:
	@public_port="$${PORT:-$(DEV_PORT)}"; \
	PORT="$(DEV_APP_PORT)" \
	SECRET_KEY_BASE="$${SECRET_KEY_BASE:-robine-id-development-only-secret-key-do-not-use-in-production}" \
	ROBINE_ID_SECURE_COOKIES="$${ROBINE_ID_SECURE_COOKIES:-false}" \
	ROBINE_ID_STATE_ROOT="$${ROBINE_ID_STATE_ROOT:-$(DEV_STATE_ROOT)}" \
	ROBINE_ID_ENV=development \
	go run github.com/air-verse/air@$(AIR_VERSION) -c .air.toml \
		-proxy.enabled=true \
		-proxy.proxy_port="$$public_port" \
		-proxy.app_port="$(DEV_APP_PORT)"

fmt:
	@test -z "$$(gofmt -l cmd internal)" || (gofmt -d cmd internal; exit 1)

lint:
	go vet ./...

test:
	go test -race ./...

coverage:
	./scripts/check-coverage.sh

check: fmt lint test coverage

preflight: check
	@test -n "$(DOCKERHUB_USER)"
	@test -n "$(VERSION)"

build:
	docker build --platform "$(PLATFORM)" --tag "$(VERSION_TAG)" --tag "$(LATEST_TAG)" .

login:
	docker login --username "$(DOCKERHUB_USER)"

push:
	docker push "$(VERSION_TAG)"
	docker push "$(LATEST_TAG)"

publish: preflight build push
