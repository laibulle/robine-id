# OAUTH-008 — Device Authorization Grant

## Status

Rust production extension

## Summary

CLI, television, and input-constrained public clients can obtain OpenID tokens through the OAuth
2.0 Device Authorization Grant. The device receives a high-entropy device code and a short
human-readable user code; the user authenticates and confirms the exact code in an Askama page on
a separate browser. PostgreSQL coordinates verification and polling across Actix and Vercel
instances.

## Requirements

- A client MUST explicitly enable
  `urn:ietf:params:oauth:grant-type:device_code`, allow `openid`, and MAY omit redirect URIs when it
  does not enable `authorization_code`.
- Discovery MUST advertise `device_authorization_endpoint` and the device grant only when at least
  one active client can use it with the selected issuer.
- `POST /{issuer}/device_authorization` MUST apply the client's configured endpoint
  authentication, validate requested scopes and an optional registered resource, and return
  `device_code`, `user_code`, `verification_uri`, `verification_uri_complete`, `expires_in`, and
  `interval` with cache disabled.
- An omitted `scope` MAY select the client's issuer-supported defaults but MUST NOT implicitly
  include `offline_access`.
- Device codes MUST contain at least 256 random bits, be stored only by digest, be issuer/client
  bound, and be consumed at most once. User codes MUST use an unambiguous rejection-sampled
  alphabet, be stored only by digest, expire with the device code, and be protected by shared
  rate limiting.
- The browser verification page MUST use CSRF protection, display the code and requesting client,
  list requested scopes, warn against approving a code for an unknown device, and reuse a valid
  browser session without weakening password authentication.
- A pending token request MUST return `authorization_pending`. Polling faster than the current
  interval MUST return `slow_down` and increase the interval by five seconds. Denial MUST return
  `access_denied`, expiry MUST return `expired_token`, and an invalid or consumed code MUST return
  `invalid_grant`.
- A denied authorization MUST retain only the denial state and expiry needed by the polling client;
  it MUST NOT retain or log the denying subject, authentication time, or mapped identity claims.
- Approval MUST preserve subject, authentication time, scopes, optional resource, and mapped
  claims. It MUST issue the configured opaque or RFC 9068 access token plus an ID token. An
  approved `offline_access` request MUST additionally require the client to enable `refresh_token`
  and MUST issue a rotating refresh token.
- DPoP proof supplied at the token endpoint MUST bind the access token and, for a public client,
  its refresh-token family according to OAUTH-005.
- Configuration changes that remove the client, user, device or refresh grant, scope, resource, or
  rich-authorization policy MUST invalidate an outstanding device authorization. Client, grant,
  scope, resource, and rich-authorization policy MUST be revalidated before the browser displays or
  accepts confirmation, not only when the device later polls for tokens.

## Acceptance Criteria

- Unit tests cover strict configuration, discovery gating, user-code shape, and access-grant
  policy.
- A real PostgreSQL test covers rapid and normal polling, approval, denial, one-time consumption,
  mapped state, and the device access-token database constraint.
- The Actix integration test renders both Askama pages, reuses a session, approves a request, and
  obtains access, ID, and refresh tokens accepted by UserInfo.
- The two-instance release smoke creates on one instance, verifies on both, polls on the peer,
  refreshes and introspects the result, and covers the denial response.

## Standards

- RFC 8628, OAuth 2.0 Device Authorization Grant.
- RFC 8414, OAuth 2.0 Authorization Server Metadata.
- OpenID Connect Core 1.0.
- RFC 9449, OAuth 2.0 Demonstrating Proof of Possession.
