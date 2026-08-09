# OIDC-002 — Authorization Code Flow

## Status

MVP target

## Summary

Robine ID supports the OpenID Connect Authorization Code Flow, with PKCE, as the primary interactive authentication flow.

## Requirements

- The authorization endpoint MUST validate `client_id`, `redirect_uri`, `response_type`, `scope`, `state`, `nonce`, and PKCE parameters before authentication begins.
- `redirect_uri` MUST exactly match a URI registered for the client.
- Public clients MUST use PKCE with `S256`. Confidential clients MUST use it by default and MAY opt out only through explicit client policy.
- Authorization codes MUST be short-lived, single-use, bound to the client, redirect URI, subject, nonce, and PKCE challenge.
- The token endpoint MUST authenticate confidential clients using an explicitly configured method.
- Successful exchanges MUST return a signed ID token and an opaque access token. The MVP MUST NOT issue refresh tokens.
- Protocol errors MUST use standards-compliant error codes and MUST NOT expose secrets or stack traces.
- `state` MUST be non-empty. `nonce` and PKCE MUST be non-empty when required by client policy. A challenge MUST contain 43–128 URL-safe, unpadded base64 characters.
- Requested scopes MUST contain `openid` and MUST be a subset of the client's allowed scopes.
- A client MUST allow the `authorization_code` grant.
- Login MUST authenticate a configured local identity without disclosing whether the identifier exists.
- Consent MUST be shown when `consent_required` is true. Approval issues a code; denial redirects with `access_denied` and the original `state`.
- The authorization code MUST be random, stored only as a cryptographic hash, expire according to issuer policy, and be consumed atomically before validation continues.
- Token requests MUST use `grant_type=authorization_code` and include the code, client identifier, exact redirect URI, and PKCE verifier.
- Public clients authenticate with method `none`. Confidential clients authenticate with their configured `client_secret_basic` or `client_secret_post` method and an environment-resolved secret. A secret supplied through the wrong transport MUST be rejected.
- Token success responses MUST set `Cache-Control: no-store` and `Pragma: no-cache`.

## Error and Redirect Rules

An invalid request MAY redirect only after both the client and exact redirect URI have been validated. Such redirects include the original `state` when it is a string. Before that trust boundary, errors render locally. Token endpoint errors are JSON; invalid client authentication returns HTTP 401 with `WWW-Authenticate`, while other protocol failures return HTTP 400.

Supported protocol error codes are `invalid_request`, `unsupported_response_type`, `invalid_scope`, `unauthorized_client`, `invalid_client`, `unsupported_grant_type`, `invalid_grant`, `access_denied`, and `server_error` as applicable.

## Acceptance Criteria

- A valid authorization request can complete login and exchange its code exactly once.
- Reusing a code, changing the redirect URI, or providing an invalid PKCE verifier fails safely.
- A rejected request preserves a valid `state` value when redirecting back to a trusted redirect URI.
- A code is unusable after the first exchange attempt, including an attempt with a wrong binding.
- Confidential-client secrets are never accepted from the declarative file as clear text and never returned in an error.

## Non-Goals

Refresh tokens, `plain` PKCE, response modes, prompt handling, silent authentication, dynamic registration, and non-code response types are outside the MVP. Disabling PKCE is a per-client compatibility exception, not a server-wide mode.
