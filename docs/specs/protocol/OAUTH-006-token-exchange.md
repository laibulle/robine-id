# OAUTH-006 — OAuth 2.0 Token Exchange

## Status

Rust production extension

## Summary

Robine ID lets an explicitly authorized confidential client exchange one of its active
access tokens for a shorter-lived, downscoped access token aimed at another registered resource.

## Requirements

- Discovery MUST advertise `urn:ietf:params:oauth:grant-type:token-exchange` only when at least one
  configured client enables it.
- A token-exchange client MUST be confidential, authenticate through its configured token-endpoint
  method, and declare at least one exact resource target.
- `subject_token_type` and the optional `requested_token_type` MUST be
  `urn:ietf:params:oauth:token-type:access_token`. Actor tokens are not supported and MUST fail with
  `invalid_request`.
- The subject token MUST be active, issued by the selected issuer, and owned by the authenticated
  client. Its issuer, client, subject, grant permission, scopes, resource, and expiry MUST remain
  valid under the active configuration.
- A requested scope MUST be a non-empty subset of the subject token scopes and current
  issuer/client scopes. `offline_access` MUST NOT be exchanged and no refresh token may be issued.
- `resource` and `audience` are accepted as exact registered targets. If both are present they MUST
  be identical; an unknown or conflicting target MUST return `invalid_target`.
- The exchanged token MUST expire no later than the subject token and no later than the issuer's
  configured access-token lifetime. Re-exchange MUST NOT extend the original authority lifetime.
- A DPoP-bound subject token MUST require a valid proof with the same JWK thumbprint. A bearer
  subject token MAY be converted to a DPoP-bound token by presenting a valid proof.
- Success MUST return an `access_token` in the issuer-configured format, `issued_token_type`, `token_type`, `expires_in`, and
  `scope`, plus `resource` when selected. It MUST NOT return an ID token or refresh token.
- The exchanged grant MUST be stored by token digest in PostgreSQL and remain introspectable and
  revocable through the existing protected endpoints across all instances.
- Token responses and errors MUST disable caching and MUST NOT log either access token.

## Acceptance Criteria

- A service token created on one instance can be exchanged on another and introspected on either.
- Scope amplification, an unregistered target, actor-token input, a wrong token type, and another
  client's subject token are rejected without issuing a token.
- The response identifies the access-token type, contains no OpenID or refresh credential, and its
  expiry cannot exceed the subject token expiry.
- Removing the client, token-exchange grant, subject grant permission, scope, or resource makes a
  later exchange fail even when the subject row has not yet expired.
- DPoP binding cannot be removed or changed during exchange.

## Non-Goals

Actor-token delegation, impersonation semantics, refresh/ID-token exchange,
multiple simultaneous audiences, and cross-client delegation are outside this extension.

## Standards

- RFC 8693, OAuth 2.0 Token Exchange.
- RFC 7662, OAuth 2.0 Token Introspection.
- RFC 8707, Resource Indicators for OAuth 2.0.
- RFC 9449, OAuth 2.0 Demonstrating Proof of Possession.
