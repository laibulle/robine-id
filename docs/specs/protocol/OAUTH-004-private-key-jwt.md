# OAUTH-004 — JWT Bearer Client Authentication

## Status

Rust production extension

## Summary

Confidential clients can authenticate without a shared secret by signing a short-lived JWT with
their own RSA private key. Robine ID stores only the configured public JWKs and a digest of each
consumed assertion identifier.

## Requirements

- A client using `private_key_jwt` MUST be confidential, MUST configure one to sixteen valid RSA
  public JWKs, and MUST NOT configure `secret_reference`.
- Token, PAR, introspection, and revocation requests MUST include `client_id`,
  `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, and one bounded
  `client_assertion`. Basic credentials or `client_secret` MUST NOT be mixed with an assertion.
- The JWS algorithm MUST be RS256 and its `kid` MUST select exactly one configured key. `iss` and
  `sub` MUST exactly equal `client_id`.
- `aud` MUST contain the canonical, issuer-derived URL of the endpoint receiving the assertion. An
  assertion for `/token` MUST NOT authenticate at `/par`, `/introspect`, or `/revoke`.
- `iat`, `exp`, and a non-empty bounded `jti` MUST be present. The assertion lifetime MUST NOT exceed
  five minutes; issue time MUST be recent and MUST respect the issuer clock-skew policy.
- PostgreSQL MUST atomically register the digest of `(issuer, client_id, jti)` before accepting an
  assertion. Reuse on the same or another instance MUST return `invalid_client`.
- Expired replay records MUST be pruned without storing assertion bodies, signatures, or private
  key material. Logs MUST NOT contain assertions or `jti` values.
- Discovery MUST advertise `private_key_jwt` for token, introspection, and revocation authentication.
- Actix and the Vercel adapter MUST expose identical behavior.

## Acceptance Criteria

- A valid assertion authenticates client-credentials issuance, PAR, introspection, and revocation.
- A wrong audience, unknown key, invalid signature, mixed credential transport, stale assertion, or
  assertion longer than five minutes is rejected.
- Replaying a valid assertion through another instance is rejected while a fresh assertion works.
- A client can rotate keys by publishing overlapping JWKs with unique key identifiers.

## Standards

- RFC 7523, JSON Web Token Bearer Profile for OAuth 2.0 Client Authentication.
- OpenID Connect Core 1.0, `private_key_jwt` client authentication.
- RFC 7517 and RFC 7518, JSON Web Key and RS256.

## Non-Goals

Remote `jwks_uri` fetching, symmetric `client_secret_jwt`, EC/EdDSA keys, certificate-bound tokens,
and access-token formatting are outside this extension; OAUTH-007 defines JWT access tokens.
