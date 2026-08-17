# OIDC-005 — RP-Initiated Logout

## Status

MVP target

## Summary

Robine ID ends the local authenticated session and optionally returns the browser to a registered client URI.

## Requirements

- Logout initiation MUST accept both query-serialized GET and form-serialized POST requests at
  `/:issuer_id/logout`.
- Every initiation MUST show an explicit confirmation before ending the session. The state-changing
  confirmation POST shares the endpoint, MUST contain only its opaque transaction and CSRF value,
  and MUST be protected by CSRF validation.
- A request without `post_logout_redirect_uri` MAY complete on a local signed-out page.
- A request with `post_logout_redirect_uri` MUST identify a registered client through either a
  valid `id_token_hint` or an explicit `client_id`.
- A supplied `client_id` MUST resolve to a configured client. When both `client_id` and
  `id_token_hint` are present, they MUST identify the same client.
- The ID-token hint MUST have a valid RS256 signature, issuer, retained key, and known audience.
  Expiration alone MUST NOT invalidate a logout hint because confirmation remains mandatory.
- The return URI MUST exactly match a `post_logout_redirect_uris` entry belonging to that audience client.
- A supplied `state` MUST be appended unchanged only after the return URI is trusted.
- A bounded `ui_locales` preference MUST select the localized confirmation content when available.
  A bounded provider-defined `logout_hint` MAY be accepted but MUST NOT identify a redirect client
  or bypass explicit confirmation.
- Completion MUST revoke the authenticated session registration, clear the browser session, and drop the session cookie.
- An invalid return request MUST fail locally and MUST NOT redirect to the supplied URI.
- Empty optional logout parameters MUST be treated as omitted. ID-token hints MUST be limited to
  16 KiB, redirect URIs to 4 KiB, and state to 1 KiB before key or database work begins.

## Acceptance Criteria

- A valid ID-token hint permits only a return URI registered for its audience.
- A valid explicit client identifier permits only one of that client's registered return URIs.
- A forged or wrong-issuer hint is rejected; an expired but otherwise authentic hint is accepted
  for the confirmation journey.
- Conflicting `client_id` and hint audience values are rejected.
- Equivalent GET and form-serialized POST initiations produce the same confirmation journey.
- After logout, the former session identifier is no longer accepted.
- Logout without a return URI renders a complete branded confirmation page.
- State is preserved on a validated post-logout redirect.

## Non-Goals

Global logout across multiple providers is outside the MVP. Back-channel and front-channel
notification of participating RPs are specified by OIDC-014 and OIDC-015. Access and refresh credentials can be revoked through the separate
OAuth revocation endpoint; browser logout does not implicitly revoke them.
