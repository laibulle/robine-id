SHELL := /bin/sh

APP_NAME := robine-id
DOCKERHUB_USER ?= laibulle
VERSION ?= $(shell sed -n 's/.*version: "\([^"]*\)".*/\1/p' mix.exs | head -n 1)
IMAGE ?= $(DOCKERHUB_USER)/$(APP_NAME)
PLATFORM ?= linux/amd64

VERSION_TAG := $(IMAGE):$(VERSION)
LATEST_TAG := $(IMAGE):latest

.DEFAULT_GOAL := help

.PHONY: help dev check-variables preflight build login push publish

help:
	@echo "Robine ID development and container targets"
	@echo ""
	@echo "  make dev        Run the Rust development server"
	@echo "  make build      Build $(VERSION_TAG) and $(LATEST_TAG)"
	@echo "  make login      Authenticate with Docker Hub"
	@echo "  make push       Push the already-built version and latest tags"
	@echo "  make publish    Run preflight, build, and push"
	@echo ""
	@echo "Overrides: HOST, PORT, DOCKERHUB_USER, IMAGE, VERSION, PLATFORM"

dev:
	cargo run --bin robine-id

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
