# OAUTH-011 — Signed Token Introspection Responses

## Status

Rust production extension

## Summary

Robine ID implements RFC 9701 JWT responses for OAuth token introspection. An authenticated
resource server can request a signed response and verify its provenance with the issuer JWKS while
plain RFC 7662 JSON remains the default for existing integrations.

## Requirements

- Discovery and RFC 8414 metadata MUST advertise RS256 through
  `introspection_signing_alg_values_supported`.
- An introspection request with an enabled `Accept: application/token-introspection+jwt` media range
  MUST receive a compact JWT with `Content-Type: application/token-introspection+jwt`. A missing,
  wildcard-only, or quality-zero media range MUST retain the RFC 7662 JSON response.
- The JWT protected header MUST contain `typ=token-introspection+jwt`, `alg=RS256`, and the active
  issuer signing-key `kid`.
- The JWT payload MUST contain only the top-level `iss`, authenticated resource-server `aud`, `iat`,
  and `token_introspection` claims. Token subject, scope, expiry, and other response members MUST
  remain nested to prevent substitution as an access token.
- An invalid, expired, revoked, policy-invalid, or caller-inappropriate access token MUST produce a
  nested response containing only `active: false`.
- A resource-bound token MUST be visible only to an introspection client registered for that exact
  resource. A token without a resource indicator MUST be visible only to its issuing client.
- Signing MUST use the active encrypted PostgreSQL key, including configured automatic rotation.
  Failure to load or use that key MUST return `temporarily_unavailable`, never unsigned JSON.
- JSON and JWT responses MUST disable caching. Tokens, signed responses, key material, and subject
  claims MUST NOT be written to operational logs.

## Acceptance Criteria

- The same authenticated introspection call returns JSON by default and a signed JWT when requested.
- The JWT signature verifies with the matching retained JWKS key and exact issuer/client audience.
- Active and inactive introspection data remains inside `token_introspection`; `sub` and `exp` are
  absent at the JWT top level.
- Actix and the Vercel adapter publish identical signing metadata, and the release smoke crosses
  instances between issuance and signed introspection.

## Standards

- RFC 9701, JSON Web Token (JWT) Response for OAuth Token Introspection.
- RFC 7662, OAuth 2.0 Token Introspection.
- RFC 8414, OAuth 2.0 Authorization Server Metadata.
- RFC 8725, JSON Web Token Best Current Practices.

## Non-Goals

Encrypted introspection responses, signing algorithms other than RS256, unauthenticated
introspection, and a separate dynamically registered resource-server model are outside this
extension.
