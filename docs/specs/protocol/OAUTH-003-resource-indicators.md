# OAUTH-003 — Resource Indicators

## Status

Rust production extension

## Summary

Robine ID implements the single-target profile of RFC 8707 so an access token is bound to
one registered protected resource instead of being an unconstrained bearer token.

## Requirements

- A client MAY declare up to 256 unique `resources`. Each value MUST be an absolute HTTPS URI, or
  loopback HTTP URI, no longer than 4096 bytes and without credentials or a fragment.
- Authorization GET/form POST, PAR, authorization-code token, refresh-token, and client-credentials
  requests MAY carry one `resource` parameter. Duplicate parameters MUST be rejected.
- A supplied value MUST exactly match a resource registered by the authenticated client; otherwise
  the endpoint MUST return `invalid_target`.
- The target MUST survive PAR, authentication, consent, authorization-code exchange, and refresh
  rotation. Code exchange and refresh MAY omit it, but MUST NOT replace or add a different target.
- PostgreSQL MUST persist the target with authorization codes, pending authorization transactions,
  access tokens, and refresh-token families.
- A successful token response MUST echo the selected `resource`. Active introspection MUST expose it
  as the string `aud`; configuration removal MUST make the token inactive.
- UserInfo MUST reject resource-bound tokens because their audience is the protected resource, not
  the authorization server.
- This profile accepts one target per request. Multiple `resource` parameters and multi-audience
  tokens are outside scope.

## Standards

- RFC 8707, Resource Indicators for OAuth 2.0.
- RFC 7662, OAuth 2.0 Token Introspection.
