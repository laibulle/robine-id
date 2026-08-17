# OIDC-006 — Offline Access and Refresh Tokens

## Status

Rust production extension

## Summary

Robine ID can grant explicitly consented offline access and rotate opaque refresh tokens without
requiring the user to maintain a browser session.

## Requirements

- Refresh tokens MUST be issued only when the issuer and client both allow `offline_access`, the
  client declares the `refresh_token` grant, and the authorization request includes that scope.
- Offline access MUST always require an explicit consent screen, including when normal client
  consent is disabled or an authenticated SSO session exists. `prompt=none` MUST return
  `consent_required` instead of issuing offline access silently.
- The token endpoint MUST accept `grant_type=refresh_token` through form-encoded POST and authenticate
  the client using its registered method. Public clients MUST supply their `client_id` and no secret.
- A registered public-client browser origin MAY perform the refresh request through the token
  endpoint's strict CORS policy; confidential client credentials MUST NOT be enabled for browser CORS.
- Every refresh token MUST be an opaque high-entropy credential stored only as a cryptographic hash.
- Each family MUST remain bound to its issuer, subject, client, original authentication time,
  consented scopes, and an absolute configured expiry. Stored claims are historical input only;
  each successful rotation MUST rebuild mapped values from the active user and mappings.
- Refresh-token lifetime MUST be independently configurable from 60 through 31,536,000 seconds.
- A successful refresh MUST atomically consume the presented token and return a new refresh token in
  the same family. Only one concurrent use of one family member may succeed.
- Reuse of a consumed family member MUST revoke every active member in that family and return the
  generic OAuth `invalid_grant` error.
- An optional refresh `scope` MAY narrow the original scope set but MUST NOT add a scope and MUST
  retain `openid`. Invalid scope requests MUST NOT consume the presented token.
- The refreshed access token and ID token MUST retain the original issuer, subject, audience, and
  authentication time. The refreshed ID token MUST use a new issue/expiry time and MUST NOT copy the
  original nonce.
- Rotation MUST retain the original password/TOTP context even when current interactive policy is
  stronger. It MUST NOT label a password-only family as MFA; UserInfo enforces any resulting step-up.
- Claims no longer authorized by a narrowed or changed active scope policy MUST be removed before
  issuing refreshed tokens, and changed active user values MUST replace stored values.
- A deleted user, removed client, removed scope, expired family, explicit revocation, or wrong
  issuer/client binding MUST return `invalid_grant` without disclosing the reason.
- Token responses MUST disable caching. Tokens and their hashes MUST never appear in logs or
  diagnostics.

## Acceptance Criteria

- An authorization request for `offline_access` cannot bypass consent, even with SSO.
- An authorization-code exchange returns a refresh token only for an eligible consented grant.
- A refresh on one Actix instance returns a new access token, new nonce-free ID token, and rotated
  refresh token usable on another instance sharing PostgreSQL.
- Restarting or restoring PostgreSQL preserves the active family and its original `auth_time`.
- Replaying a consumed token revokes the latest replacement; both attempts return only
  `invalid_grant` publicly.
- A rejected scope elevation leaves the original refresh token usable.
- Client-bound RFC 7009 revocation invalidates the complete refresh-token family.

## Standards

Offline access and refreshed ID-token behavior follow OpenID Connect Core sections 11 and 12.
Rotation and family-wide replay response follow the OAuth 2.0 Security Best Current Practice,
RFC 9700 section 4.14.

## Non-Goals

Sender-constrained mTLS tokens, sliding family expiry, administrative grant management,
password-change hooks, and refresh-token issuance without `offline_access` are not included.
