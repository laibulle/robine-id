# OIDC-014 — Back-Channel Logout

## Status

MVP target

## Summary

Robine ID notifies every participating relying party when an authenticated OpenID Provider session
is ended, using a signed, session-bound Logout Token over a direct HTTP POST.

## Requirements

- Discovery MUST advertise `backchannel_logout_supported` and
  `backchannel_logout_session_supported` as `true`.
- A client MAY register one absolute `backchannel_logout_uri` without credentials or a fragment.
  HTTPS is required except for loopback HTTP development endpoints registered by confidential
  clients. A query component MUST be retained when the logout request is sent.
- `backchannel_logout_session_required` MUST default to `false` and MUST NOT be enabled without a
  registered back-channel URI.
- The provider MUST generate a distinct opaque `sid` for every browser session and include it in
  ID Tokens issued from Authorization Code, Refresh Token, and Device Authorization grants.
- PostgreSQL MUST remember each `(sid, issuer, client_id)` association only after the RP has been
  authorized, including authorization journeys that pass through consent.
- Ending a browser session MUST atomically revoke it and load all associated RP registrations.
- Each Logout Token MUST be signed with the issuer's active RS256 key, explicitly typed
  `logout+jwt`, expire no more than 120 seconds after issuance, and contain `iss`, `sub`, `aud`,
  `iat`, `exp`, a unique `jti`, `sid`, and the standard back-channel logout event. It MUST NOT
  contain `nonce`.
- The provider MUST POST exactly one `application/x-www-form-urlencoded` `logout_token` parameter
  to each registered RP. Notifications SHOULD run in parallel.
- Outbound delivery MUST use a two-second connect/read/write bound, MUST NOT follow redirects, and
  MUST treat only HTTP 200 and 204 as success. A failed RP notification MUST be logged without
  preventing local logout or a validated post-logout redirect.
- Configuration MUST bound back-channel delivery to 32 possible client-issuer combinations per
  revision.

## Acceptance Criteria

- Discovery, ID Token, and Logout Token claims match the registered metadata and session.
- Consent and silent SSO preserve the same `sid` through code exchange and refresh rotation.
- A session used with several RPs produces one audience-bound Logout Token per registered RP.
- A callback query is retained, the POST body is form encoded, and redirects are not followed.
- A callback timeout or non-success status does not restore the revoked local session.
- The two-instance release smoke receives and decodes a real callback emitted after logout.

## Non-Goals

Front-Channel Logout, Logout Token encryption, automatic retransmission, dynamic client
registration, and revocation of `offline_access` refresh tokens are outside this scope.
