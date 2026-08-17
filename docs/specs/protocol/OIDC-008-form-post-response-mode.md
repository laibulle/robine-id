# OIDC-008 — Form Post Response Mode

## Status

Rust production extension

## Summary

Robine ID can deliver authorization success and error parameters to a registered redirect URI in
an auto-submitted HTML form, keeping codes and protocol errors out of the browser address bar.

## Requirements

- Discovery MUST advertise `query` and `form_post` in `response_modes_supported`. Omitted
  `response_mode` MUST continue to mean `query`.
- GET, form POST, and PAR authorization requests MUST accept `response_mode=form_post`. Values not
  defined here or by OIDC-010 MUST return `unsupported_response_mode`; an invalid mode itself MUST
  not be used to select an error transport.
- The selected mode MUST survive authentication, SSO reuse, consent, denial, PostgreSQL-backed
  pending authorization, and routing between instances.
- A successful form response MUST use HTTP 200 and contain `code`, `state`, and `iss` as hidden
  form fields. A protocol failure safe to return to the registered redirect URI MUST contain
  `error`, `error_description`, optional `state`, and `iss` as hidden fields.
- The form action MUST be the exact registered redirect URI, including an existing query. Response
  parameters MUST NOT be appended to that URI when `form_post` is selected.
- Every action and hidden value MUST be HTML escaped by Askama. The page MUST contain no inline
  script and MUST load only the same-origin bundled `/assets/app.js`.
- JavaScript SHOULD submit the form after document parsing. A visible, keyboard-accessible submit
  button MUST remain as a no-JavaScript or failed-script fallback.
- The response MUST disable browser and intermediary caching and use `Referrer-Policy: no-referrer`.
- Content Security Policy MUST preserve the normal restrictive defaults while limiting
  `form-action` to the exact registered redirect origin. Generic response hardening MUST NOT
  overwrite that narrower dynamic policy.
- The authorization code MUST retain the same expiry, client, redirect URI, PKCE, issuer, subject,
  nonce, and one-time-consumption bindings as a query response.
- Actix and the Vercel adapter MUST return the same status, content, caching policy, and dynamic CSP.

## Acceptance Criteria

- A consented request enters through one instance and returns a form-posted code through another;
  the code exchanges successfully exactly once with the original redirect URI and PKCE verifier.
- The HTML contains no `Location` response header and no raw unescaped attacker-controlled value.
- Consent denial and a redirectable authorization error use hidden error fields instead of URL
  parameters when `form_post` was validly selected.
- The generated CSP permits the registered RP origin and does not permit an unrelated origin.
- Disabling JavaScript leaves a labeled submit button that completes delivery.
- Query mode remains protocol-compatible and remains the default.

## Standards

OpenID Connect Form Post Response Mode 1.0 and OAuth 2.0 Multiple Response Type Encoding Practices.

## Non-Goals

Fragment, `web_message`, encrypted response objects, and RP-provided scripts are outside this
extension. Signed form responses are specified separately by OIDC-010.
