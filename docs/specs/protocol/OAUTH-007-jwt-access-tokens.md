# OAUTH-007 — JWT Access Token Profile

## Status

Rust production extension

## Summary

An issuer can replace opaque access-token presentation values with RS256 JWTs following RFC 9068,
allowing a resource server to validate authority locally from the issuer JWKS. Opaque remains the
default. Both formats retain a PostgreSQL digest for introspection and revocation.

## Requirements

- `token_policy.access_token_format` MUST accept only `opaque` or `jwt` and default to `opaque`.
- A JWT-enabled issuer MUST advertise `access_token_signing_alg_values_supported: ["RS256"]`.
  An opaque issuer MUST omit that metadata member.
- A JWT access token MUST use an RS256 signature, an active published `kid`, and `typ=at+jwt`.
- Its claims MUST contain exact `iss`, `sub`, `aud`, `client_id`, space-delimited `scope`, `iat`,
  `exp`, and a random `jti`. `aud` is the selected resource, or the client identifier when no
  resource was selected.
- A grant involving an authenticated resource owner MUST additionally preserve `auth_time`, `acr`,
  and `amr` from the originating authentication. Password-only and password-plus-TOTP contexts MUST
  remain unchanged through refresh and token exchange. Machine-only grants MUST omit these
  user-authentication claims.
- Authorized mapped claims MAY be copied into the token. Configuration MUST reserve protocol claim
  names so mappings cannot override signed authority.
- An actor-aware Token Exchange grant MUST contain the RFC 8693 `act` object, including its bounded
  nested delegation history. Configured identity claims MUST NOT override `act` or `may_act`.
- A DPoP-bound token MUST contain `cnf: {"jkt": ...}` and continue to require RFC 9449 proof at
  Robine ID protected endpoints.
- Authorization Code, Device Authorization, Refresh Token, Client Credentials, and Token Exchange
  grants MUST all honor the selected issuer format. Token Exchange MUST not extend the
  subject-token expiry.
- The exact JWT MUST be stored only by digest with its grant. Introspection, UserInfo policy, and
  owning-client revocation MUST behave identically to opaque tokens across instances.
- Retired signing keys MUST remain in JWKS for the greater ID-token/JWT-access-token lifetime plus
  clock skew and the configured safety window.
- Token values MUST remain bounded before signing, form processing, authorization-header use, and
  database lookup. Tokens and private signing material MUST NOT be logged.

## Acceptance Criteria

- A resource server verifies the JWT signature and issuer/audience from discovery and JWKS without
  an introspection request.
- The same JWT is active through another instance's introspection endpoint, then inactive after
  owning-client revocation through either instance.
- The header, required claims, resource audience, scope, client identifier, optional authentication
  context, and optional DPoP confirmation are covered by cryptographic tests.
- The release smoke exercises both an unchanged opaque issuer and a JWT issuer.

## Operational Note

Digest-backed revocation immediately affects Robine ID endpoints and introspection. A resource
server that validates only offline cannot observe that state change before the JWT expires; short
lifetimes or introspection are required where immediate revocation is mandatory.

## Standards

- RFC 9068, JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens.
- RFC 8414, OAuth 2.0 Authorization Server Metadata.
- RFC 9449, OAuth 2.0 Demonstrating Proof of Possession.
