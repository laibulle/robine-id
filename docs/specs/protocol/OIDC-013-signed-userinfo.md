# OIDC-013 — Signed UserInfo Responses

## Status

Rust production extension

## Summary

A client can require UserInfo claims in an audience-bound RS256 JWT instead of an unsigned JSON
object. JSON remains the default for compatibility.

## Requirements

- An application MAY set `userinfo_signed_response_alg` to `RS256`. Omission MUST retain the JSON
  response. Any other value, including `none`, MUST prevent configuration activation.
- Discovery MUST advertise `userinfo_signing_alg_values_supported: ["RS256"]`.
- A successful signed response MUST use compact JWS serialization and content type
  `application/jwt` for both GET and POST UserInfo requests.
- The protected header MUST use `alg=RS256`, `typ=JWT`, and a `kid` published by the issuer JWKS.
- Claims MUST include the normal authorized UserInfo claims plus exact `iss` and client-bound `aud`,
  a current `iat`, and a short `exp`. Configured identity claims MUST NOT override these members.
- Bearer/DPoP validation, issuer/client/current-policy checks, CORS, no-store caching, and public
  error behavior MUST be identical to JSON UserInfo.
- Signing MUST use the active encrypted PostgreSQL signing key and respect automatic rotation.
  A signing-key or storage failure MUST return a non-cacheable `temporarily_unavailable` response,
  never unsigned fallback data.
- The response MUST remain within the bounded token transport size.

## Acceptance Criteria

- A configured client receives a verifiable JWT whose signature key is present in JWKS and whose
  `iss`, `aud`, `sub`, and mapped claims are exact.
- The same grant for a client without the option continues returning `application/json`.
- An unsupported algorithm is rejected during strict configuration validation.
- A signed response works through a second Actix instance sharing PostgreSQL and with either an
  opaque or locally verifiable JWT access token.

## Standards

- OpenID Connect Core 1.0 sections 5.3.2 and 5.3.4.
- RFC 7515, JSON Web Signature.

## Non-Goals

Encrypted UserInfo responses, signing-algorithm negotiation beyond RS256, and detached or JSON JWS
serializations are outside this extension.
