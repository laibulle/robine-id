# OAUTH-010 — Client Secret JWT Authentication

## Status

Rust production extension

## Summary

Confidential clients can authenticate with a short-lived HS256 JWT derived from their configured
client secret. This avoids transmitting the reusable secret while retaining declarative secret
references and PostgreSQL-coordinated replay protection.

## Requirements

- A client using `client_secret_jwt` MUST be confidential, MUST configure an environment
  `secret_reference`, MUST NOT configure `jwks`, and MUST resolve a secret of at least 32 octets.
- Token, PAR, device authorization, introspection, and revocation requests MUST include
  `client_id`, `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, and
  one bounded `client_assertion`. Basic credentials or `client_secret` MUST NOT be mixed with it.
- The assertion MUST use HS256. Its `iss` and `sub` claims MUST exactly equal `client_id`.
- `aud` MUST contain the canonical issuer-derived URL of the receiving endpoint. Assertions MUST
  NOT be reusable between `/token`, `/par`, `/device_authorization`, `/introspect`, and `/revoke`.
- `exp` and a non-empty bounded `jti` MUST be present. `iat` MAY be present. The assertion MUST
  expire within five minutes; when `iat` is present, it MUST be recent and the lifetime from `iat`
  to `exp` MUST NOT exceed five minutes. Issuer clock skew applies.
- PostgreSQL MUST atomically register the digest of `(issuer, client_id, jti)` before accepting an
  assertion. Reuse on the same or another instance MUST return `invalid_client`.
- Assertions, signatures, secret values, and `jti` values MUST NOT be persisted or logged.
- Discovery MUST advertise `client_secret_jwt` and HS256 for token, introspection, and revocation
  client authentication.
- Actix and the Vercel adapter MUST expose identical behavior.

## Acceptance Criteria

- Valid assertions authenticate PAR, device authorization, client-credentials issuance,
  introspection, and revocation.
- A short or wrong secret, wrong audience, invalid signature, mixed credential transport, expired
  assertion, excessive lifetime, or invalid client binding is rejected.
- Replaying a valid assertion through another instance is rejected while a fresh assertion works.
- A configured secret can be rotated through the existing environment-secret deployment process.

## Standards

- OpenID Connect Core 1.0 section 9, `client_secret_jwt` client authentication.
- RFC 7519, JSON Web Token.
- RFC 7518, HMAC using SHA-256 (`HS256`).

## Non-Goals

Asymmetric client authentication is defined by OAUTH-004. Remote secret management, dynamic client
registration, and additional HMAC algorithms are outside this extension.
