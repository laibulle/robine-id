# OPS-001 — Observability and Health

## Status

MVP target

## Summary

Robine ID exposes operational signals that make failures diagnosable without compromising identity data.

## Requirements

- The server MUST expose separate liveness and readiness endpoints.
- Readiness MUST reflect whether the active configuration is valid and required dependencies are usable.
- Structured logs MUST include timestamp, severity, event name, request or correlation identifier, and issuer identifier where safe.
- Metrics MUST cover request rate, latency, error rate, authentication outcomes, token issuance, PAR
  and device-authorization outcomes, rate limiting, and configuration reconciliation.
- Telemetry MUST use bounded-cardinality labels and MUST NOT include credentials, tokens, authorization codes, raw personal data, or client secrets.
- Metrics protection MUST be optionally configurable through mutually exclusive
  `METRICS_BEARER_TOKEN` and `METRICS_BEARER_TOKEN_FILE` sources. A configured value MUST contain
  32–256 URL-safe ASCII characters, remain in zeroizing memory, and be compared in constant time.
- When metrics protection is configured, `GET /metrics` MUST accept exactly one matching
  case-insensitive Bearer scheme and reject missing, malformed, duplicate, or incorrect credentials
  with HTTP 401, `WWW-Authenticate: Bearer realm="metrics"`, and the standard no-store policy.
  Omitting both sources MUST preserve unauthenticated scraping for backwards compatibility.
- Audit events MUST be emitted for security-relevant actions and configuration changes.
- Operator-facing errors MUST identify actionable causes while public errors remain non-sensitive.
- `GET /health/live` MUST return HTTP 200 with `{"status":"live"}` whenever the Actix endpoint can serve requests.
- `GET /health/ready` MUST return HTTP 200 only when the instance is accepting traffic, an active configuration exists, and the configured database answers a trivial query.
- Liveness and readiness responses MUST use `Cache-Control: no-store` and `Pragma: no-cache` so a
  browser, proxy, CDN, or orchestrator cannot reuse stale process state. Both endpoints MUST support
  bodyless `HEAD` with the same current status and representation length as `GET`.
- A ready response MUST include the non-secret active revision fingerprint. A failure MUST return HTTP 503 with only `{"status":"not_ready"}`.
- Any readiness indicator rendered on the landing page MUST derive from the same traffic-acceptance
  and PostgreSQL health decision as `/health/ready`; it MUST NOT claim readiness while that probe
  would return HTTP 503.
- Receiving a shutdown signal MUST immediately make readiness return HTTP 503 while liveness remains HTTP 200 for the configured drain delay.
- `robine_id_ready` MUST be `0` while the instance is draining.
- Every HTTP request MUST receive or generate an `x-request-id`; public protocol errors MAY expose it as the correlation reference.
- Authentication, session reuse, rate-limit rejection, token exchange, UserInfo access,
  reconciliation, logout, and key rotation SHOULD produce security or operational events.
- Audit metadata MUST use an allowlist of bounded fields such as outcome, issuer ID, client ID, subject ID, reason category, and correlation ID.
- Token endpoint audit events MUST classify ordinary grants as `token_issuance` and reserve
  `token_exchange` for RFC 8693; accepted DPoP diagnostics MUST expose endpoint/outcome without
  proof thumbprints, identifiers, or nonces.
- Successful MFA events MUST expose only the bounded `totp` or `recovery_code` factor alongside
  allowlisted issuer, client, and subject identifiers; submitted codes and fingerprints are forbidden.
- Logs MUST avoid submitted identifiers unless explicitly classified and protected as personal data.
- Telemetry metric labels MUST never contain subject identifiers, raw IP addresses, arbitrary URLs, tokens, codes, or exception messages.
- Readiness failures MUST remain non-sensitive publicly while the server log retains an actionable internal cause.
- The canonical image MUST include a read-only `robine-id-doctor` command. It MUST validate the
  active configuration, database connectivity, the exact version/success/checksum sequence of all
  embedded migrations, and decryptability of every active and retained signing key without
  applying migrations, creating keys, pruning rows, or starting HTTP.
- Doctor output MUST be bounded JSON containing only status, semantic revision, active object
  counts, migration counts/currentness, and signing-key counts/coverage. Connection or inspection
  failures MUST return a non-zero status without emitting URLs, paths, credentials, key material,
  SQL text, or database exception details. A configured issuer with no lazily created key MAY be
  reported as missing without making an otherwise current deployment fail.

## Metric Contract

`GET /metrics` exports Prometheus text with request count and duration, bounded response status classes,
authentication outcomes, bounded MFA challenge/success/failure/rejection outcomes, rate-limit rejection, token-exchange, UserInfo, PAR, and bounded device-flow
outcomes, configuration reconciliation, readiness, and the active semantic revision. The endpoint
emits `Cache-Control: no-store` plus `Pragma: no-cache` and contains no raw URL,
client, subject, address, token, code, or exception label.
The canonical 384-bit metrics-token generator MUST use operating-system entropy, emit only an
environment-file-safe assignment, and be available both through Make and inside the release image.

`robine_id_http_method_requests_total` and
`robine_id_http_method_request_duration_seconds` MUST classify requests only as `GET`, `POST`,
`HEAD`, `OPTIONS`, or `other`. Unknown extension methods and adapter-level 413/503 responses MUST be
counted without reflecting the submitted method. HTTP tracing spans MUST use the same bounded value.

`robine_id_token_issuance_total` MUST classify token-endpoint success and failure using only the
bounded grant labels `authorization_code`, `refresh_token`, `client_credentials`, `device_code`,
`token_exchange`, and `unsupported`. An arbitrary submitted `grant_type` MUST collapse to
`unsupported` and MUST NOT appear in metrics. The dedicated `robine_id_token_exchange_total` MUST
count only RFC 8693 token exchange rather than every request handled by `/token`.
`robine_id_userinfo_total` MUST expose only the `success` and `failure` outcomes computed from the
final HTTP response. It MUST NOT carry client, subject, token, origin, claim, or error labels.

Expected bounded labels are route or event names known to the application and small outcome enums such as `success`, `failure`, `rejected`, `activated`, and `unchanged`.

## Audit Contract

Audit is append-only from the application's perspective. The MVP adapter writes structured events through Logger. Audit failure MUST NOT cause credentials or tokens to be included in a fallback message. Configuration histories held by the memory store are diagnostic conveniences, not a durable compliance ledger.

## Acceptance Criteria

- An orchestrator can distinguish a live-but-not-ready instance from a dead instance.
- A failed authentication or configuration apply can be traced using a correlation identifier without exposing sensitive values.
- Reapplying unchanged configuration is observable as a successful no-op.
- Health responses never contain database errors, paths, stack traces, user data, or configuration documents.
- A draining instance becomes not-ready before it stops serving, remains live during the drain delay, and exits successfully after graceful shutdown.
- Conventional Actix and Vercel probes return non-cacheable GET/HEAD responses; a HEAD request
  carries no response body and cannot mask a current readiness transition with cached state.
- The landing-page status text and visual state agree with the current readiness decision.
- Prometheus scrapes cannot be satisfied from a stale browser, proxy, or platform cache.
- Actix and Vercel MUST both reject an unauthenticated protected scrape and serve the same metrics
  after a valid Bearer credential without reflecting that credential in the response.
- A token exchange can be correlated by request ID and safe client/issuer metadata without logging its code or tokens.
- Operators can distinguish issuance failures by supported grant family without introducing
  client-, subject-, credential-, or attacker-controlled metric labels.
- Operators can compare traffic and latency by a fixed method family on Actix and Vercel, including
  requests rejected before Actix dispatch, without admitting arbitrary method labels.
- Vercel adapter-level body-limit and overload failures preserve the global bodyless `HEAD`
  contract while retaining the equivalent JSON representation length.
- UserInfo success is audited only after the response is fully deliverable, and its aggregate
  metric exposes no identity or credential dimensions.
- Operators can run one image-native, read-only diagnostic before or after deployment and detect
  an unreachable database, pending/changed/failed migration, or undecryptable persisted key without
  exposing the failing dependency detail.

## Non-Goals

The MVP does not ship a metrics backend, tracing collector, dashboard, alert rules, long-term audit
database, or SLA. Operators integrate structured logs and metrics with their platform.
