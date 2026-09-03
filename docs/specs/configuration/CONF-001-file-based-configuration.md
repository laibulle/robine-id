# CONF-001 — File-Based Configuration

## Status

MVP target

## Summary

Robine ID is fully configurable through versionable files, with environment-specific values supplied without editing application code.

## Requirements

- Configuration files MUST cover issuers, relying applications, scopes, claims, authentication methods, UI branding, token policy, storage, telemetry, and operational settings.
- The supported file format and schema version MUST be explicit in every root configuration document.
- Configuration MAY reference environment variables using typed references; resolved secret values MUST not be written back to files or logs.
- Defaults MUST be deterministic. Checked-in users, HTTP loopback URLs, and development secrets MUST be labeled development-only and replaced for production.
- Unknown fields, invalid types, missing required values, duplicate identifiers, and incompatible options MUST fail validation.
- Relative file references MUST resolve from the file that declares them.
- Configuration precedence MUST be deterministic and documented.
- The effective non-secret configuration MUST be inspectable through a CLI command or protected diagnostic interface.

## Document Model

The root is a JSON object with `schema_version: 1`. Supported sections are `issuers`, `users`, `claims`, `branding`, `reconciliation`, `authentication`, `storage`, and `telemetry`. Unknown fields at all validated levels are errors. A legacy root `clients` list MAY be composed for compatibility but new applications MUST use individual documents.

- `issuers` requires unique string `id` and absolute `url`; optional fields are `scopes`, `token_policy`, `claim_mappings`, and `branding`.
- `applications/*.json` contains one `oidc_application` document per relying application and follows APPL-001 after composition.
- `users` follows IDEN-001.
- `claims` maps an OIDC claim to a source field and required scope.
- `branding` follows UX-002.
- `reconciliation.deletion_policy` is one of `disable`, `retain`, or `delete`.
- `authentication.methods` supports only `password`; session and rate-limit values are positive integers.
- `storage` configures database path, pool size, and signing-key path.
- `telemetry.log_level` is one of `debug`, `info`, `warning`, or `error`.

Issuer token-policy fields are positive integer seconds no greater than 86,400. They include authorization-code, ID-token, and access-token lifetimes plus clock skew.

## Loading and Paths

`ROBINE_ID_CONFIG` selects an absolute local root document as a convenience. Otherwise `ROBINE_ID_BLOB_STORE`, `ROBINE_ID_STORAGE_ROOT`, and `ROBINE_ID_CONFIG_KEY` select the configuration backend and object. Application documents are loaded from `ROBINE_ID_APPLICATIONS_PREFIX`. Durable keys and account overrides use the independently selectable state blob backend. A missing, unreadable, syntactically invalid, or semantically invalid startup revision MUST prevent readiness and application startup rather than activate partial defaults.

Each application document MUST be a JSON object containing `schema_version: 1`, `kind: "oidc_application"`, a stable non-empty `id`, and the fields defined by APPL-001. Files without a `.json` suffix are ignored. Application files are composed in lexicographic filename order and duplicate identifiers invalidate the complete revision.

## Commands

- Server startup validates the complete root and application revision before accepting traffic.
- The active configuration is checked at the configured reload interval.
- An invalid update leaves the last valid revision active.
- `/health/ready` exposes only the active non-secret revision fingerprint.

Effective output MUST redact passwords, hashes, secret references, tokens, and private key material.

## Acceptance Criteria

- A fresh Robine ID instance can be fully initialized from configuration files plus referenced secrets.
- The same inputs produce the same effective configuration on separate instances.
- Validation errors identify the file, path, and reason without displaying secret values.
- An unsupported schema version or unknown field prevents activation.
- HTTP issuer and redirect URLs are accepted only for loopback development hosts; other origins require HTTPS.

## Configuration Precedence

Branding resolution is `built-in safe defaults < global branding < issuer branding < client branding`. Other resources do not merge across layers: the active revision is the complete desired state.
