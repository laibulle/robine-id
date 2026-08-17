# OIDC-005 — RP-Initiated Logout

## Status

MVP target

## Summary

Robine ID ends the local authenticated session and optionally returns the browser to a registered client URI.

## Requirements

- Logout MUST be exposed as a browser flow at `GET` and `POST /:issuer_id/logout`.
- `GET` MUST show an explicit confirmation before ending the session.
- The state-changing `POST` MUST be protected by CSRF validation.
- A request without `post_logout_redirect_uri` MAY complete on a local signed-out page.
- A request with `post_logout_redirect_uri` MUST also contain an `id_token_hint`.
- The ID-token hint MUST have a valid signature, issuer, lifetime, and audience.
- The return URI MUST exactly match a `post_logout_redirect_uris` entry belonging to that audience client.
- A supplied `state` MUST be appended unchanged only after the return URI is trusted.
- Completion MUST revoke the authenticated session registration, clear the browser session, and drop the session cookie.
- An invalid return request MUST fail locally and MUST NOT redirect to the supplied URI.
- Empty optional logout parameters MUST be treated as omitted. ID-token hints MUST be limited to
  16 KiB, redirect URIs to 4 KiB, and state to 1 KiB before key or database work begins.

## Acceptance Criteria

- A valid ID-token hint permits only a return URI registered for its audience.
- A forged, expired, wrong-issuer, or wrong-audience hint is rejected.
- After logout, the former session identifier is no longer accepted.
- Logout without a return URI renders a complete branded confirmation page.
- State is preserved on a validated post-logout redirect.

## Non-Goals

Back-channel logout, front-channel logout notifications, and global logout across multiple
providers are outside the MVP. Access and refresh credentials can be revoked through the separate
OAuth revocation endpoint; browser logout does not implicitly revoke them.
