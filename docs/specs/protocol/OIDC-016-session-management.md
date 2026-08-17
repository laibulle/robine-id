# OIDC-016 — Session Management

## Status

Rust production extension

## Summary

Robine ID lets a relying party monitor the End-User's OpenID Provider login state with the
standard `check_session_iframe` and opaque `session_state` mechanism. The implementation keeps the
authentication cookie `HttpOnly`: a separate, non-authenticating browser-state cookie supplies only
the state needed by the OP iframe.

## Requirements

- Discovery MUST publish `check_session_iframe` for HTTPS issuers and MUST NOT advertise Session
  Management for a plain-HTTP issuer.
- Every successful HTTPS Authentication Response MUST contain `session_state`. A consent-denial
  Authentication Error Response SHOULD contain it when an authenticated session is known.
- Query and `form_post` responses MUST carry `session_state` as a direct parameter. JARM responses
  MUST carry it only inside the signed authorization-response JWT.
- Session State MUST contain no spaces and MUST be a salted SHA-256 value bound to the client ID,
  the exact redirect origin, the current OP browser state, and a fresh random salt.
- The OP browser-state cookie MUST be distinct from the authenticated-session cookie and public
  `sid`. It MUST contain neither a user identifier nor a credential and MUST NOT be accepted for
  authentication. It MUST expire no later than the corresponding absolute session lifetime.
- On HTTPS, the browser-state cookie MUST use the `__Host-` prefix, `Secure`, `SameSite=None`, and
  `Path=/`. JavaScript access is required by this protocol; the authenticated-session cookie MUST
  remain `HttpOnly` and `SameSite=Lax`.
- Login and authenticated authorization MUST establish or refresh the browser state. Logout and
  invalid-session cleanup MUST remove it so existing RP checks return `changed`.
- The OP iframe MUST accept the standard `client_id + " " + session_state` message and reply only
  `unchanged`, `changed`, or `error` to the exact source origin.
- Before accepting a caller, the iframe MUST validate the posted client/origin pair against an
  exact registered redirect origin. Successful validations MAY be cached for the iframe lifetime;
  repeated status checks MUST be calculated locally with Web Crypto and MUST NOT poll the server.
- A missing or malformed origin-validation query MUST return an empty non-cacheable `400`; it MUST
  NOT render a localized HTML page, emit `Content-Language`, or disclose client registration state.
- Malformed messages, opaque origins, unknown clients, unregistered origins, invalid browser state,
  or unavailable browser cryptography MUST return `error` and MUST NOT start reauthentication.
- The iframe MUST use an external script, disable caching, allow framing, and apply a CSP limited to
  its own script and origin-validation endpoint. Other application pages MUST retain their global
  anti-framing policy.
- Actix and the Vercel adapter MUST expose the same discovery metadata, iframe, origin validation,
  and security headers.

## Response Contract

For a supported issuer, Discovery contains:

```json
{
  "check_session_iframe": "https://id.example/issuer/check-session"
}
```

The RP embeds that URL and sends `client_id session_state` with `postMessage`. The iframe validates
the source origin once and returns one of the three standard status strings. Session State is opaque
to the RP and has the implementation shape `base64url(sha256(input)).base64url(salt)`.

## Acceptance Criteria

- Discovery truthfully distinguishes HTTPS production issuers from plain-HTTP development issuers.
- Query, form-post, and JARM successes expose the same origin-bound session semantics.
- Changing the client, origin, browser state, or salt changes the computed value.
- A registered RP origin can embed and use the iframe; an unregistered origin receives `error`.
- The iframe response has no `X-Frame-Options`, while unrelated responses remain `DENY`.
- The main session credential never becomes JavaScript-readable.
- Rust unit tests, the PostgreSQL journey, Vercel transport tests, and the release smoke verify the
  advertised and real behavior.

## Operational Note

Browsers that block third-party cookies can hide the OP browser state from the iframe and cause a
`changed` result. RPs must follow the standard defensive behavior and avoid infinite
`prompt=none` loops. Back-Channel Logout remains the reliable option when third-party state is
unavailable.

## Standards

- [OpenID Connect Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html).
