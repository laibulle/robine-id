# OIDC-009 — Signed Authorization Request Objects

## Status

Rust production extension

## Summary

Robine ID accepts RS256-signed OpenID Connect Request Objects so a confidential client can protect
its authorization parameters against browser or intermediary modification before authentication.

## Requirements

- A Request Object MUST be a bounded RS256 JWT whose `kid` selects a public key from the client's
  configured `jwks`. The outer authorization request MUST still contain the exact `client_id`.
- `iss` MUST equal `client_id`; `aud` MUST contain the exact configured issuer identifier. `iat`,
  `exp`, and a bounded non-empty `jti` MUST be present, and lifetime MUST NOT exceed five minutes.
- The signed object MUST contain the complete effective authorization request, including
  `response_type`, `redirect_uri`, `scope`, and `state`, plus nonce, PKCE, response mode, resource,
  prompt, locale, maximum age, and login hint when used.
- Any meaningful parameter repeated outside the JWT MUST exactly equal its signed value. A mismatch
  MUST fail with `invalid_request_object`; unsigned outer values MUST NOT override signed values.
- Nested `request` and `request_uri` claims MUST be rejected. Valid resolution MUST remove the JWT
  before rendering login or persisting PAR, so it is not echoed into browser continuations.
- Direct GET, form POST, and authenticated PAR MUST share the same verification and merge rules.
- PostgreSQL MUST atomically register a digest of `(issuer, client_id, jti)` through the assertion's
  expiration plus clock skew. Replay on the same or another instance MUST fail.
- Discovery MUST advertise `request_parameter_supported: true` and RS256 in
  `request_object_signing_alg_values_supported`.
- Invalid signatures, unknown keys, stale or overlong assertions, wrong audience, parameter
  conflicts, and replay MUST not expose key material, JWT bodies, or `jti` values in logs.

## Acceptance Criteria

- A request containing only outer `client_id` plus a valid `request` JWT reaches login with the
  signed state and redirect URI.
- Replaying that object through another instance fails, and conflicting an outer scope fails.
- A valid Request Object can be authenticated and stored through PAR, then consumed on another
  instance without forwarding the original JWT to the browser.
- Actix and the Vercel adapter preserve the same behavior.

## Standards

- OpenID Connect Core 1.0, Request Object.
- RFC 9101, The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR).
- RFC 7515, JSON Web Signature.

## Non-Goals

Encrypted Request Objects, remote `request_uri` dereferencing, unsigned JWTs, and algorithms other
than RS256 are outside this extension. PAR-issued `request_uri` references remain supported by
OIDC-007 and contain the already resolved request rather than the original JWT.
