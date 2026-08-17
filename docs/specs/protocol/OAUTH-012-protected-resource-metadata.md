# OAUTH-012 — Protected Resource Metadata

## Status

Rust production extension

## Summary

Robine ID publishes RFC 9728 metadata for each issuer's UserInfo protected resource. Clients can
discover the exact authorization server, scopes, token presentation method, response-signing
algorithm, and DPoP proof algorithms before calling UserInfo.

## Requirements

- The UserInfo resource identifier MUST be the exact routed endpoint `{issuer}/userinfo`, without
  query or fragment.
- Metadata MUST be available at the deterministic RFC 9728 URL formed by inserting
  `/.well-known/oauth-protected-resource` before the issuer and UserInfo path:
  `/.well-known/oauth-protected-resource/{issuer_id}/userinfo`.
- The metadata `resource` value MUST exactly match the resource identifier. It MUST list only the
  matching issuer in `authorization_servers` and the matching retained-key endpoint in `jwks_uri`.
- `scopes_supported` MUST include `openid` plus only issuer-supported scopes that can release a
  configured UserInfo claim. Service-only and offline-access scopes MUST NOT be advertised merely
  because the authorization server accepts them elsewhere.
- UserInfo MUST advertise header bearer presentation only, RS256 signed resource responses, and
  EdDSA, ES256, and RS256 DPoP proof validation. DPoP-bound access tokens MUST remain optional.
- Human-readable resource name, developer documentation, policy, and terms URLs MUST follow the
  resolved issuer branding without exposing secret configuration.
- Authorization-server metadata MUST cross-advertise the exact UserInfo resource identifier through
  `protected_resources`.
- A UserInfo 401 Bearer or DPoP challenge SHOULD carry the absolute `resource_metadata` URL so a
  client can discover or refresh the metadata dynamically.
- Successful metadata responses MUST use JSON, allow public cross-origin reads, support ETag
  revalidation, and use bounded shared-cache freshness. Unknown issuer identifiers MUST return 404
  without enumerating configured resources.
- The public route MUST support only `GET`, bodyless `HEAD`, and `OPTIONS`; excessive preflight
  methods or headers MUST return a non-cacheable 403 without a CORS grant, while any other method
  MUST return a non-cacheable 405 with `Allow: GET, HEAD, OPTIONS`.

## Acceptance Criteria

- The metadata URL reconstructs exactly the `resource` value for an issuer with a path component.
- Discovery and protected-resource metadata cross-reference one another without hostname inference.
- Missing-token UserInfo returns a challenge pointing to the same metadata document.
- Actix and Vercel return identical metadata, and `make release-smoke` verifies it through a real
  two-instance deployment.

## Standards

- RFC 9728, OAuth 2.0 Protected Resource Metadata.
- RFC 6750, OAuth 2.0 Bearer Token Usage.
- RFC 9449, OAuth 2.0 Demonstrating Proof of Possession.
- RFC 8707, Resource Indicators for OAuth 2.0.

## Non-Goals

Metadata for arbitrary external APIs, signed protected-resource metadata, mTLS-bound tokens, and
dynamic resource registration are outside this extension.
