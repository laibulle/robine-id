# OIDC-007 — Pushed Authorization Requests

## Status

Rust production extension

## Summary

Robine ID implements OAuth 2.0 Pushed Authorization Requests (PAR) so a client can validate and
store a complete authorization request over a direct POST before sending only an opaque reference
through the browser.

## Requirements

- Discovery MUST advertise `pushed_authorization_request_endpoint`,
  `request_uri_parameter_supported: true`, and the issuer's effective
  `require_pushed_authorization_requests` value.
- PAR MAY be required for every client of an issuer through token policy or for one declaratively
  registered client. Both policies MUST default to `false`; a client policy is valid only for an
  `authorization_code` client.
- A direct GET or form-encoded POST authorization request covered by either policy MUST be refused
  with `invalid_request`. A valid pushed reference MUST continue through the normal flow.
- `POST /:issuer_id/par` MUST accept the same bounded authorization parameters and validation rules
  as the interactive authorization endpoint.
- The PAR endpoint MUST authenticate confidential clients with their configured
  `client_secret_basic`, `client_secret_post`, or `private_key_jwt` method. A public client MUST provide its
  `client_id` without a secret.
- OIDC-009 signed JWT request objects MAY be pushed after client authentication and validation.
  External request URI dereferencing remains unsupported. A PAR response MUST return
  a server-generated `urn:ietf:params:oauth:request_uri:` value and a positive `expires_in`.
- The lifetime MUST be configurable per issuer from 10 through 600 seconds and default to 90.
- Valid PAR creation MUST enforce independent shared PostgreSQL counters for the canonical remote
  address and issuer/client pair. The configurable limit MUST default to 120 requests per 60-second
  window, with bounded overrides and HTTP 429 plus `Retry-After` on exhaustion.
- PostgreSQL MUST store only a cryptographic hash of the request URI plus the validated request,
  issuer, client binding, and expiry.
- After front-channel validation, PostgreSQL MUST retain the complete authorization request behind
  a separate short-lived, single-use browser transaction. Login forms MUST expose only that opaque
  transaction and CSRF token, never client, redirect, state, nonce, PKCE, resource, or DPoP values.
- The front-channel authorization request MUST contain exactly `client_id` and the generated
  `request_uri`; GET and form-encoded POST transports MUST both be accepted.
- A request URI MUST be bound to its issuer and client, expire, and be consumed atomically at most
  once. A wrong-client attempt MUST NOT consume a valid reference.
- PAR success and error responses MUST disable caching. Logs and metrics MUST never contain the
  request URI, authorization state, nonce, login hint, credentials, or client secret.
- A registered public-client redirect origin MAY call PAR from a browser through the same strict
  POST/`Content-Type` CORS policy as the token endpoint. Confidential and unrelated origins MUST
  receive no cross-origin grant.
- Invalid, expired, replayed, malformed, wrong-client, and wrong-issuer references MUST fail locally
  without redirecting to an untrusted URI.
- Direct authorization requests MUST remain supported for issuers and clients whose PAR policy is
  optional.

## Acceptance Criteria

- A public client can push a PKCE request through one Actix instance, consume the returned reference
  through another instance sharing PostgreSQL, and complete the normal login/consent journey.
- Replaying the consumed reference fails and cannot issue a second authorization code.
- Arbitrary external `request_uri` values retain the standard `request_uri_not_supported` behavior.
- Invalid confidential-client authentication returns OAuth `invalid_client` without storing a
  request.
- Rotating source addresses or client identifiers cannot bypass the corresponding independent PAR
  creation counter.
- Discovery, Actix, and the Vercel entrypoint expose the same PAR capability.
- Global and per-client mandatory-PAR policies reject direct GET and POST initiation while a pushed
  request still reaches login across another instance.
- A browser authorization transaction is issuer-bound, expires, is consumed atomically, and is
  replaced after a failed password attempt without reflecting protocol parameters into HTML.

## Standards

- RFC 9126, OAuth 2.0 Pushed Authorization Requests.

## Non-Goals

Encrypted request objects and external request URI dereferencing are outside this extension.
