# CONF-001 — Declarative Configuration

## Status

MVP target

## Summary

Robine ID is configured through versionable JSON documents, with an inline JSON transport for
filesystem-independent runtimes and environment variables for deployment-specific infrastructure
and secrets.

## Requirements

- Configuration documents MUST cover issuers, relying applications, scopes, claims, authentication methods, UI branding, token policy, telemetry, and reconciliation settings.
- PostgreSQL connectivity and signing-key encryption MUST be supplied through deployment environment variables rather than committed configuration documents.
- The supported file format and schema version MUST be explicit in every root configuration document.
- Configuration MAY reference environment variables using typed references; resolved secret values MUST not be written back to files or logs.
- Defaults MUST be deterministic. Checked-in users, HTTP loopback URLs, and development secrets MUST be labeled development-only and replaced for production.
- Unknown fields, invalid types, missing required values, duplicate identifiers, and incompatible options MUST fail validation.
- Inline application serialization, semantic fingerprint serialization, and effective redaction
  MUST propagate or safely represent failure without panicking or exposing unredacted configuration.
- Resource collections, identifiers, URLs, locale/message maps, session policies, and rate-limit
  policies MUST remain within documented safe bounds so trusted configuration cannot create
  unbounded request or persistence behavior.
- Relative file references MUST resolve from the file that declares them.
- Configuration precedence MUST be deterministic and documented.
- The effective non-secret configuration MUST be inspectable through a CLI command or protected diagnostic interface.

## Document Model

The root is a JSON object with `schema_version: 1`. Supported sections are `issuers`, `users`,
`claims`, `authorization_detail_types`, `branding`, `reconciliation`, `authentication`, and `telemetry`. A `storage` object is
accepted only as legacy Phoenix compatibility metadata and does not configure Rust persistence.
Unknown fields at all validated levels are errors. A legacy root `clients` list MAY be composed for
compatibility but new applications MUST use individual documents.

- `issuers` requires unique string `id` and absolute `url`; optional `enabled` defaults to `true`,
  while `false` retains the validated tenant declaration but removes it from routing, WebFinger,
  default-page selection, and automatic key rotation. Other optional fields are `scopes`,
  `token_policy`, `claim_mappings`, and `branding`.
- `applications/*.json` contains one `oidc_application` document per relying application and
  follows APPL-001 after composition; optional `enabled` defaults to `true`, while `false` retains
  the validated declaration but excludes it from active client resolution. Optional `issuer_ids`
  is a unique list of configured tenant identifiers; omitted or empty means all active issuers.
- `users` follows IDEN-001; optional `enabled` defaults to `true`, while `false` keeps the record
  configured but excludes it from every active identity lookup. Optional `issuer_ids` is a unique
  list of configured tenant identifiers; omitted or empty means all active issuers. Login
  identifiers may repeat only across disjoint non-empty issuer sets.
- `claims` maps an OIDC claim to a source field and required scope.
- `authorization_detail_types` registers bounded RFC 9396 type identifiers, display names, allowed
  fields, and the required-field subset. Applications opt in with `authorization_details_types`.
- `branding` follows UX-002.
- `reconciliation.deletion_policy` is one of `disable`, `retain`, or `delete`.
- `authentication.methods` requires `password` and may additionally contain `totp` once; session
  and rate-limit values are positive integers. A per-user TOTP factor uses only a strict environment
  `totp_secret_reference` and requires the global method to be enabled.
- `storage` is optional legacy compatibility metadata; the Rust runtime persists all mutable state and encrypted signing keys in PostgreSQL.
- `telemetry.log_level` is one of `debug`, `info`, `warning`, or `error`.

Issuer token-policy fields include authorization-code, ID-token, and access-token lifetimes plus
clock skew between 1 and 86,400 seconds, and a refresh-token lifetime between 60 and 31,536,000
seconds. `access_token_format` accepts `opaque` (the default) or `jwt` as defined by OAUTH-007.
`pushed_authorization_request_lifetime` defaults to 90 seconds and accepts 10 through 600;
its creation limit defaults to 120 requests per 60-second window and uses bounded
`pushed_authorization_request_limit` and `pushed_authorization_request_window` fields.
Optional `signing_key_rotation_interval` enables automatic rollover from 3,600 through
31,536,000 seconds; omitting it keeps rotation operator-driven. `dpop_nonce_required` defaults to
`false`; when enabled, `dpop_nonce_lifetime` controls the recent server-nonce window from 30 through
3,600 seconds and defaults to 300. `browser_authorization_lifetime` defaults to 600 seconds and
accepts 60 through 3,600; it bounds opaque server-side login continuations.
`device_code_lifetime` defaults to 600 seconds and accepts 300 through 1,800;
`device_poll_interval` defaults to five seconds and accepts 5 through 60. Server-directed
`slow_down` responses may increase the stored interval up to 300 seconds for one authorization.
`require_pushed_authorization_requests` defaults to `false` in issuer token policy and application
documents. The issuer value is global; the application value targets only that authorization-code
client.
An interactive application MAY set `required_acr` to `urn:robine-id:acr:password` or
`urn:robine-id:acr:password+totp`. The latter requires the global `totp` method and rejects
password-only browser sessions and accounts without an operator-provisioned factor. It MAY also
set `max_authentication_age` to a non-negative number of seconds. This forces active browser
reauthentication after that age and lets UserInfo return an RFC 9470 `max_age` challenge when an
existing access token is too old.
`actor_token_exchange_allowed` defaults to `false`. Enabling it requires a confidential application
with both `client_credentials` and Token Exchange grants and permits only same-client RFC 8693
actor-token delegation unless a distinct source application names it in `authorized_actor_clients`.
That source-side list defaults empty, accepts only configured actor-token clients, and is the
authority for cross-client delegation.

## Loading and Paths

`ROBINE_ID_CONFIG` selects the root document; otherwise `config/robine_id.json` is used.
Application documents are loaded from the adjacent `applications/` directory unless
`ROBINE_ID_APPLICATIONS_DIR` overrides it. Serverless and remote-Docker deployments MAY instead
provide the complete documents through `ROBINE_ID_CONFIG_JSON` and
`ROBINE_ID_APPLICATIONS_JSON`. `DATABASE_URL` selects PostgreSQL and
`KEY_ENCRYPTION_SECRET` supplies at least 32 bytes of deployment-specific entropy for persisted
private-key encryption. A missing, unreadable, syntactically invalid, or semantically invalid
startup document or applications directory MUST prevent readiness and application startup rather
than activate partial defaults.

Each application document MUST be a JSON object containing `schema_version: 1`, `kind: "oidc_application"`, a stable non-empty `id`, and the fields defined by APPL-001. Files without a `.json` suffix are ignored. Application files are composed in lexicographic filename order and duplicate identifiers invalidate the complete revision.

## Commands

- `make config-validate` validates the effective Rust configuration without activation.
- `make config-preview CONFIG=PATH` calculates a reconciliation plan without mutation.
- `make config-apply CONFIG=PATH` validates and activates one revision in the command runtime.
- `make config-effective` prints the redacted effective configuration.
- `make keys-rotate ISSUER=ID ROTATION_ID=ID` performs an idempotent PostgreSQL-backed key rotation.

The equivalent `mix robine_id.*` commands remain available only for the legacy Phoenix parity
suite and are not production runtime entry points.

Effective output MUST redact passwords, hashes, secret references, tokens, and private key material.

## Acceptance Criteria

- A fresh Robine ID instance can be fully initialized from configuration documents, PostgreSQL, and referenced secrets.
- The same inputs produce the same effective configuration on separate instances.
- Validation errors identify the file, path, and reason without displaying secret values.
- An unsupported schema version or unknown field prevents activation.
- HTTP issuer and redirect URLs are accepted only for loopback development hosts; other origins require HTTPS.

## Configuration Precedence

Branding resolution is `built-in safe defaults < global branding < issuer branding < client branding`. Other resources do not merge across layers: the active revision is the complete desired state.
