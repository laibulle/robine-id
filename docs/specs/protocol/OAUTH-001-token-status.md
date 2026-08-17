# OAUTH-001 — Token Introspection and Revocation

## Status

Rust production extension

## Summary

Robine ID exposes protected OAuth endpoints for querying and immediately revoking opaque or JWT
access-token grants stored by digest in PostgreSQL.

## Requirements

- Discovery MUST advertise `introspection_endpoint`, `revocation_endpoint`, and their supported
  client-authentication methods.
- Both endpoints MUST accept only form-encoded HTTP POST requests and MUST reject unbounded token
  values before persistence access.
- Unsupported methods MUST return HTTP 405 with `Allow: POST` for introspection and `Allow: POST,
  OPTIONS` for browser-capable revocation, without invoking client authentication or storage.
- Revocation MUST authenticate the requesting client with its configured token-endpoint method.
- A public client MAY authenticate to revocation with its `client_id` and no secret. A confidential
  client MUST use exactly its configured secret transport, OAUTH-010 `client_secret_jwt`, or
  OAUTH-004 `private_key_jwt` assertion.
- A registered public-client redirect origin MAY invoke revocation from a browser. Its preflight
  MUST permit only `POST` and `Content-Type`, MUST NOT permit `Authorization`, and MUST reject
  confidential-client and unrelated origins. Actual success and OAuth error responses MUST echo
  only an allowed exact origin, expose `WWW-Authenticate`, and remain non-cacheable.
- Revocation form extraction failures, including missing fields and the shared 16 KiB form limit,
  MUST preserve that exact-origin CORS policy even though rejection occurs before client
  authentication. A Vercel adapter-level 413 MAY do the same only after validating the path and
  origin against the active public-client configuration.
- A client MUST be able to revoke only an access or refresh token issued to that same client and
  issuer. Revoking any refresh token member revokes its complete rotation family.
- Revocation of a matching token MUST be immediate and shared across every instance using the same
  PostgreSQL database.
- Revocation MUST return HTTP 200 for a validly authenticated request whether the token was deleted,
  unknown, already expired, already revoked, or belonged to another client.
- `token_type_hint` MUST be accepted as an optimization hint and an unknown hint MUST NOT alter the
  result.
- Introspection MUST require a confidential client with `introspection_allowed: true`; the default
  configuration value is false and public clients MUST NOT opt in.
- An active introspection response MUST contain `active`, `scope`, `client_id`, `token_type`, `exp`,
  `iat`, `sub`, and `iss` derived from the stored grant.
- An actor-aware Token Exchange grant MUST additionally expose the stored RFC 8693 `act` chain.
- An authenticated caller MAY negotiate the OAUTH-011 RFC 9701 signed representation through the
  `Accept` header; plain RFC 7662 JSON remains the default.
- A client-credentials access grant remains active only while the issuing confidential client still
  enables that grant and every granted service scope remains allowed by both client and issuer.
- An unknown, expired, revoked, wrong-issuer, or no-longer-valid grant MUST return only
  `{"active":false}` to an authenticated introspector.
- Invalid client authentication MUST return HTTP 401 with an OAuth `invalid_client` response and a
  Basic challenge. Storage failure MUST NOT be represented as successful revocation or an inactive
  token.
- Responses MUST disable caching, and operational logs MUST never contain the submitted token or
  client secret.

## Acceptance Criteria

- A protected resource explicitly enabled in configuration can introspect an access token issued to
  another configured client and observe its exact issuer, subject, scopes, issue time, and expiry.
- A client cannot revoke another client's token, and the indistinguishable HTTP 200 response does
  not reveal whether a matching token existed.
- After the owning client revokes a token through one instance, UserInfo and introspection through a
  second instance reject it immediately.
- Repeating revocation remains successful and has no additional effect.
- A browser public client can preflight and revoke its own token from an exact registered redirect
  origin; a confidential or unrelated origin receives no CORS authorization.
- Malformed and oversized revocation submissions remain readable to an allowed browser origin and
  never gain CORS through an unrelated endpoint path or origin.
- A PostgreSQL backup restored before revocation preserves active state; revocation after restore
  still takes effect.

## Standards

The request and response behavior follows RFC 7009 for OAuth 2.0 Token Revocation and RFC 7662 for
OAuth 2.0 Token Introspection. Endpoint metadata follows RFC 8414.

## Non-Goals

Administrative subject-wide revocation and a separate resource-server
credential model are not included. Introspection authorization reuses confidential
OIDC client credentials and requires an explicit per-client capability flag.
