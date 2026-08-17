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
- Audit events MUST be emitted for security-relevant actions and configuration changes.
- Operator-facing errors MUST identify actionable causes while public errors remain non-sensitive.
- `GET /health/live` MUST return HTTP 200 with `{"status":"live"}` whenever the Actix endpoint can serve requests.
- `GET /health/ready` MUST return HTTP 200 only when the instance is accepting traffic, an active configuration exists, and the configured database answers a trivial query.
- A ready response MUST include the non-secret active revision fingerprint. A failure MUST return HTTP 503 with only `{"status":"not_ready"}`.
- Receiving a shutdown signal MUST immediately make readiness return HTTP 503 while liveness remains HTTP 200 for the configured drain delay.
- `robine_id_ready` MUST be `0` while the instance is draining.
- Every HTTP request MUST receive or generate an `x-request-id`; public protocol errors MAY expose it as the correlation reference.
- Authentication, session reuse, rate-limit rejection, token exchange, UserInfo access,
  reconciliation, logout, and key rotation SHOULD produce security or operational events.
- Audit metadata MUST use an allowlist of bounded fields such as outcome, issuer ID, client ID, subject ID, reason category, and correlation ID.
- Logs MUST avoid submitted identifiers unless explicitly classified and protected as personal data.
- Telemetry metric labels MUST never contain subject identifiers, raw IP addresses, arbitrary URLs, tokens, codes, or exception messages.
- Readiness failures MUST remain non-sensitive publicly while the server log retains an actionable internal cause.

## Metric Contract

`GET /metrics` exports Prometheus text with request count and duration, bounded response status classes,
authentication outcomes, bounded MFA challenge/success/failure/rejection outcomes, rate-limit rejection, token-exchange, PAR, and bounded device-flow
outcomes, configuration reconciliation, readiness, and the active semantic revision. The endpoint
is non-cacheable and contains no raw URL,
client, subject, address, token, code, or exception label.

Expected bounded labels are route or event names known to the application and small outcome enums such as `success`, `failure`, `rejected`, `activated`, and `unchanged`.

## Audit Contract

Audit is append-only from the application's perspective. The MVP adapter writes structured events through Logger. Audit failure MUST NOT cause credentials or tokens to be included in a fallback message. Configuration histories held by the memory store are diagnostic conveniences, not a durable compliance ledger.

## Acceptance Criteria

- An orchestrator can distinguish a live-but-not-ready instance from a dead instance.
- A failed authentication or configuration apply can be traced using a correlation identifier without exposing sensitive values.
- Reapplying unchanged configuration is observable as a successful no-op.
- Health responses never contain database errors, paths, stack traces, user data, or configuration documents.
- A draining instance becomes not-ready before it stops serving, remains live during the drain delay, and exits successfully after graceful shutdown.
- A token exchange can be correlated by request ID and safe client/issuer metadata without logging its code or tokens.

## Non-Goals

The MVP does not ship a metrics backend, tracing collector, dashboard, alert rules, long-term audit database, or SLA. Operators integrate Logger and Telemetry with their platform.
