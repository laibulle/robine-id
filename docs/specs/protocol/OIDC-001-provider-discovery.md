# OIDC-001 — OpenID Provider Discovery

## Status

MVP target

## Summary

Robine ID exposes standards-compliant OpenID Connect discovery metadata so clients can configure themselves without hard-coded endpoint details.

## Requirements

- The server MUST expose `/.well-known/openid-configuration` for every configured issuer.
- The response MUST contain the issuer, authorization endpoint, token endpoint, user-info endpoint, JWKS URI, supported response types, supported subject types, supported signing algorithms, supported scopes, and supported claims.
- Every advertised capability MUST be enabled and usable in the active configuration.
- The advertised issuer MUST exactly match the issuer used in issued tokens.
- Discovery responses MUST use `application/json` and MAY be cached using configurable cache headers.
- Secrets and internal-only configuration MUST never appear in discovery metadata.
- Discovery MUST be available at `GET /:issuer_id/.well-known/openid-configuration`.
- Endpoint URLs MUST be derived from the configured issuer URL after removing a trailing slash.
- The MVP MUST advertise only `code`, `authorization_code`, public subjects, `RS256`, PKCE `S256`, and token endpoint authentication methods `none`, `client_secret_basic`, and `client_secret_post`.
- The discovery document MUST advertise the end-session endpoint.
- Scope metadata MUST use the issuer's configured scopes, falling back to `openid`, `profile`, and `email` when omitted.
- Unknown issuers MUST return HTTP 404 with an `invalid_request` response and MUST NOT enumerate valid issuer identifiers.

## Response Contract

The JSON object contains `issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`, `end_session_endpoint`, `response_types_supported`, `grant_types_supported`, `subject_types_supported`, `id_token_signing_alg_values_supported`, `code_challenge_methods_supported`, `token_endpoint_auth_methods_supported`, `scopes_supported`, and `claims_supported`.

Discovery metadata is generated from the active configuration on each request. Applying a new active revision therefore changes subsequent discovery responses without recompiling the application.

## Acceptance Criteria

- A conforming client can discover and use a configured issuer without endpoint overrides.
- Disabling an optional capability removes it from discovery metadata after configuration is applied.
- Requests for an unknown issuer return a non-success response without leaking configured issuer names.
- Every URL in discovery corresponds to a routed endpoint and uses the exact configured issuer origin and path.
- The response contains no password hash, secret reference, storage path, signing private key, or user record.

## Non-Goals

WebFinger discovery and capability negotiation beyond the fixed MVP feature set are not included.
