# OIDC-002 — Authorization Code Flow

## Status

MVP target

## Summary

Robine ID supports the OpenID Connect Authorization Code Flow, with PKCE, as the primary interactive authentication flow.

## Requirements

- The authorization endpoint MUST validate `client_id`, `redirect_uri`, `response_type`, `scope`, `state`, `nonce`, and PKCE parameters before authentication begins.
- Initial authorization requests MUST be accepted through both query serialization with HTTP GET
  and form serialization with HTTP POST. Interactive login submissions share the POST endpoint but
  remain distinguishable through required CSRF and credential fields.
- `response_mode` MUST default to `query`. A valid `form_post` value MUST follow OIDC-008, while
  `jwt`, `query.jwt`, and `form_post.jwt` MUST follow OIDC-010; every other non-empty value MUST
  return `unsupported_response_mode` after the redirect trust boundary.
- GET and POST MUST apply the same nonce policy and unsupported JWT `request`/external
  `request_uri` behavior. Server-issued PAR references follow OIDC-007. An omitted nonce MUST be
  accepted when the selected confidential client explicitly disables it.
- Empty optional authorization parameters MUST be treated as omitted. Unrecognized extension
  parameters MUST be ignored, while a defined OAuth/OIDC parameter repeated in one request MUST be
  rejected as `invalid_request` rather than selecting the first or last value.
- A serialized GET authorization query MUST be limited to 16 KiB, matching the conventional and
  Vercel POST body limit, before parsing or authentication work begins.
- `redirect_uri` MUST exactly match a URI registered for the client.
- Public clients MUST use PKCE with `S256`. Confidential clients MUST use it by default and MAY opt out only through explicit client policy.
- Authorization codes MUST be short-lived, single-use, bound to the client, redirect URI, subject, nonce, and PKCE challenge.
- The token endpoint MUST authenticate confidential clients using an explicitly configured method.
- Successful exchanges MUST return a signed ID token and an access token in the issuer-configured
  OAUTH-007 format. A refresh token
  is returned only for a client configured for `refresh_token` after explicit `offline_access`
  consent, as defined by OIDC-006.
- Protocol errors MUST use standards-compliant error codes and MUST NOT expose secrets or stack traces.
- `state` MUST be non-empty. `nonce` and PKCE MUST be non-empty when required by client policy. A challenge MUST contain 43–128 URL-safe, unpadded base64 characters.
- Requested scopes MUST contain `openid` and MUST be a subset of the client's allowed scopes.
- A client MUST allow the `authorization_code` grant.
- Login MUST authenticate a configured local identity without disclosing whether the identifier exists.
- Consent MUST be shown when `consent_required` is true. Approval issues a code; denial redirects with `access_denied` and the original `state`.
- Consuming a pending consent MUST revalidate the active issuer, user, client, exact redirect URI,
  authorization-code grant, scopes, resource, PKCE/nonce policy, authentication context, and rich
  authorization details against the current configuration revision. A policy change that makes
  any binding invalid MUST consume the transaction, issue no code, and fail locally without using
  the formerly registered redirect URI.
- A valid authenticated browser session MUST be reusable for SSO without collecting the password
  again. `prompt=login` and `prompt=select_account` force an interactive login screen;
  `prompt=consent` forces consent even when client policy normally skips it.
- `prompt=none` MUST NOT render interaction. It succeeds only when an authenticated session exists
  and consent is not required; otherwise it returns `login_required` or `consent_required` to the
  already validated redirect URI. `none` MUST NOT be combined with another prompt value.
- A non-negative integer `max_age` MUST force reauthentication when the session authentication time
  is older than requested. `max_age=0` always forces an active credential check and returns
  `login_required` when combined with `prompt=none`.
- An application `max_authentication_age` policy MUST apply even when the request omits `max_age`;
  when both are present, the lower value is the effective maximum age.
- A bounded `login_hint` MAY prefill the identifier field, MUST survive the no-JavaScript login
  form round trip, and MUST never bypass credential verification or appear in logs.
- A bounded explicit `ui_locales` preference MUST select localized interaction content. When it is
  omitted, a bounded quality-ranked `Accept-Language` preference MUST be inherited only after PAR
  and signed Request Object resolution, then persisted inside the opaque browser authorization
  transaction. The inferred locale MUST NOT participate in signed-parameter equality checks.
- A bounded `id_token_hint` follows OIDC-012. It MAY identify the expected subject for SSO but MUST
  never replace verification of the issuer, audience, browser session, or current client policy.
- A bounded `acr_values` parameter MAY list up to sixteen Authentication Context Class References
  in preference order. It is a voluntary OIDC request: the server MUST preserve it through direct
  GET/POST, PAR, and signed Request Objects, then return the authentication context actually
  achieved. Unknown requested values do not weaken configured application policy.
- An application `required_acr` policy takes precedence over the voluntary request. A client that
  requires `urn:robine-id:acr:password+totp` MUST reject a password-only session and MUST NOT issue
  a code for an account without a configured TOTP factor.
- The OIDC `claims` parameter defined by OIDC-011 MAY make `acr` or another available claim
  essential. Unlike `acr_values`, an essential value constraint MUST be satisfied by the actual
  session and configured user claims before a code is issued.
- The authorization code MUST be random, stored only as a cryptographic hash, expire according to issuer policy, and be consumed atomically before validation continues.
- Authorization-code token requests MUST use `grant_type=authorization_code` and include the code,
  client identifier, exact redirect URI, and PKCE verifier. Refresh requests follow OIDC-006.
- Public clients authenticate with method `none`. Confidential clients authenticate with their
  configured secret method, `client_secret_jwt` according to OAUTH-010, or `private_key_jwt`
  according to OAUTH-004. Credentials supplied
  through the wrong transport MUST be rejected.
- Token success responses MUST set `Cache-Control: no-store` and `Pragma: no-cache`.
- Browser token requests from a public client MUST support CORS only when `Origin` exactly matches
  an origin derived from that client's registered redirect URIs. Preflight MUST allow only POST and
  `Content-Type`; confidential-client and unrelated origins MUST receive no cross-origin grant.
- Authorization and logout redirects carrying codes or state MUST also disable caching.
- Every successful or redirected error authorization response MUST contain an `iss` parameter that
  exactly matches the selected issuer metadata, preventing authorization-server mix-up.

## Error and Redirect Rules

An invalid request MAY redirect only after both the client and exact redirect URI have been validated. Such redirects include the original `state` when it is a string. Before that trust boundary, errors render locally. Token endpoint errors are JSON; invalid client authentication returns HTTP 401 with `WWW-Authenticate`, while other protocol failures return HTTP 400.

Supported protocol error codes are `invalid_request`, `unsupported_response_type`,
`unsupported_response_mode`, `request_not_supported`, `request_uri_not_supported`, `invalid_scope`,
`unauthorized_client`, `invalid_client`, `unsupported_grant_type`, `invalid_grant`, `access_denied`,
and `server_error` as applicable.

## Acceptance Criteria

- A valid authorization request can complete login and exchange its code exactly once.
- Equivalent GET and form-serialized POST authorization requests render the same login journey.
- GET and POST resolve OIDC-009 signed Request Objects identically, while unsigned requests retain
  the selected client's nonce policy.
- Reusing a code, changing the redirect URI, or providing an invalid PKCE verifier fails safely.
- A rejected request preserves a valid `state` value when redirecting back to a trusted redirect URI.
- A code is unusable after the first exchange attempt, including an attempt with a wrong binding.
- Confidential-client secrets are never accepted from the declarative file as clear text and never returned in an error.
- A valid session skips credential entry, while `prompt=login` forces it and `prompt=none` never
  renders an interactive page.
- A public SPA hosted on a registered redirect origin can exchange and refresh tokens in the
  browser, while an unregistered origin and a confidential-only client origin cannot pass preflight.

## Non-Goals

`plain` PKCE, fragment response modes, dynamic registration, and non-code response types are
outside the current scope. Disabling PKCE is a per-client compatibility exception, not a
server-wide mode.

## Standards

- OpenID Connect Core 1.0.
- RFC 6749, The OAuth 2.0 Authorization Framework.
- RFC 7636, Proof Key for Code Exchange by OAuth Public Clients.
- RFC 9207, OAuth 2.0 Authorization Server Issuer Identification.
