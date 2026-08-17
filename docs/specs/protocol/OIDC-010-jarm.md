# OIDC-010 — JWT-Secured Authorization Response Mode

## Status

Rust production extension

## Summary

Robine ID supports JWT-Secured Authorization Response Mode (JARM) so clients can authenticate the
complete authorization success or error returned through an untrusted browser.

## Requirements

- Discovery MUST advertise `jwt`, `query.jwt`, and `form_post.jwt` in `response_modes_supported`
  and RS256 in `authorization_signing_alg_values_supported`.
- `jwt` MUST be an alias for `query.jwt` for the supported code response type. `fragment.jwt` MUST
  remain unsupported because authorization codes are never returned in fragments.
- The provider MUST sign each JARM response with the active issuer RS256 key and publish its `kid`
  through JWKS. The JOSE `typ` MUST be `oauth-authz-resp+jwt`.
- Every response JWT MUST contain exact `iss` and client `aud` claims plus `iat` and an `exp` no more
  than 60 seconds later. Success MUST contain `code`; errors MUST contain `error` and MAY contain
  `error_description`. Both MUST preserve non-empty `state` inside the signed JWT.
- Query delivery MUST return only a `response` parameter in addition to any query already present
  on the registered redirect URI. Form delivery MUST render only a hidden `response` parameter and
  retain the OIDC-008 no-store, escaping, CSP, and accessible fallback behavior.
- Signed response modes MUST survive direct GET, form POST, PAR, login, SSO, consent, and
  cross-instance transaction persistence without being rewritten to an unsigned mode.
- If the database or signing key is unavailable, the provider MUST fail closed and MUST NOT emit an
  unsigned authorization result.

## Acceptance Criteria

- A `query.jwt` success verifies with the issuer JWKS, has the client audience and original state,
  and contains a code exchangeable once on another instance.
- A denied `form_post.jwt` request contains a single signed `response` field whose claims include
  `access_denied` and the original state; unsigned error, state, code, and issuer fields are absent.
- Discovery, token signing, Vercel forwarding, and the complete multi-instance release journey are
  covered by automated tests.

## Standards

- OpenID Financial-grade API — JWT Secured Authorization Response Mode for OAuth 2.0 (JARM).
- RFC 7515, JSON Web Signature.
- RFC 7519, JSON Web Token.

## Non-Goals

Encrypted JARM responses, symmetric signing, algorithms other than RS256, fragment delivery, and
per-client signing-algorithm negotiation are outside this extension.
