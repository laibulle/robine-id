# OAUTH-002 — Client Credentials Grant

## Status

Rust production extension

## Summary

Robine ID issues short-lived OAuth access tokens in the issuer-configured format to confidential backend services without
creating an end-user session or an OpenID identity token.

## Requirements

- Discovery MUST advertise `client_credentials` only when at least one configured client enables
  that grant.
- A client using `client_credentials` MUST be confidential and MUST authenticate with exactly its
  configured `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, or `private_key_jwt`
  method.
- A service-only client MAY use an empty redirect URI list and does not need the `openid` scope.
  Any client that also enables `authorization_code` MUST still declare a redirect URI and allow
  `openid`.
- The requested `scope` MUST be optional. When omitted, the grant MUST contain every eligible scope
  shared by the client and issuer.
- Requested scopes MUST be a non-empty subset of the client and issuer scope lists. `openid`,
  `offline_access`, and scopes used by configured end-user claim mappings MUST NOT be granted to a
  machine identity.
- A valid response MUST contain `access_token`, `token_type=Bearer`, `expires_in`, and the granted
  `scope`. When selected, it MUST also echo `resource`. It MUST NOT contain `id_token` or `refresh_token`.
- Access tokens MUST be random opaque values stored only by digest in PostgreSQL. The stored grant
  MUST identify `client_credentials` as its provenance and use the client identifier as its
  machine subject.
- A service token MUST be accepted by introspection while the issuer, client, grant permission,
  scopes, and expiry remain active. The active response MUST expose the client identifier as both
  `client_id` and `sub`.
- Machine-subject provenance MUST come from the grant type, not from a lookup in the user catalog.
  A service identifier identical to a configured user identifier MUST therefore remain public,
  carry no mapped user claims, and never require pairwise-subject key material.
- UserInfo MUST reject a service token because it represents no end user.
- The owning client MUST be able to revoke its service token through the standard revocation
  endpoint, with immediate effect across all instances sharing PostgreSQL.
- Token responses and errors MUST disable caching. Logs and metrics MUST not contain the client
  secret or access token.
- The conventional Actix server and Vercel entrypoint MUST expose identical behavior.

## Acceptance Criteria

- A confidential service receives a token with an allowed service scope through one instance and
  introspects it through another.
- The same request with an identity scope fails with `invalid_scope`.
- The token response contains neither an ID token nor a refresh token, and UserInfo returns an
  invalid-token response.
- Cross-instance revocation changes subsequent introspection to exactly `{"active":false}`.
- Removing the client, grant, issuer scope, or client scope makes a previously issued token
  inactive even before its database expiry.
- Configuration rejects a public `client_credentials` client and a service client with no eligible
  machine scope.

## Standards

- RFC 6749 section 4.4, OAuth 2.0 Client Credentials Grant.
- RFC 7662, OAuth 2.0 Token Introspection.
- RFC 7009, OAuth 2.0 Token Revocation.

## Non-Goals

Delegated user impersonation, refresh tokens, and browser CORS for confidential service credentials
are outside this extension. JWT formatting is defined independently by OAUTH-007.
