# OAUTH-013 — Step-Up Authentication Challenge

## Status

Rust production extension

## Summary

Robine ID implements RFC 9470 for UserInfo. A protected-resource request carrying an otherwise
valid access token receives an interoperable challenge when the authentication level or age no
longer satisfies the active application policy.

## Requirements

- Interactive applications MAY set `required_acr` to require password or password-plus-TOTP and
  MAY set `max_authentication_age` to a non-negative number of seconds.
- `max_authentication_age` MUST be rejected for service-only applications. At the authorization
  endpoint it MUST combine with a requested OIDC `max_age` by applying the stricter value.
- Authorization Code SSO MUST actively reauthenticate when the effective maximum age is exceeded.
  Device authorization already performs an active authentication and MUST preserve its
  `auth_time` in the resulting access token.
- UserInfo MUST first validate the access token and, for a sender-constrained token, its DPoP proof.
  It MUST then compare the stored `auth_time` and authentication context with the current policy.
- Current policy includes both the client's `required_acr` and whether the active user now has a
  configured TOTP factor. A password-only token for such a user MUST request the TOTP ACR even when
  the client itself has no stronger static requirement.
- A valid token with insufficient strength or recentness MUST return HTTP 401 and the registered
  `insufficient_user_authentication` error in both the JSON body and `WWW-Authenticate` challenge.
- The challenge MUST carry `acr_values`, `max_age`, or both according to the unmet requirements.
  Bearer tokens use the `Bearer` scheme; DPoP-bound tokens use the `DPoP` scheme and continue to
  advertise supported proof algorithms.
- The challenge SHOULD include the OAUTH-012 `resource_metadata` URL and MUST be non-cacheable.
- Invalid, expired, revoked, issuer-mismatched, or policy-invalid grants MUST continue to return
  `invalid_token`; step-up MUST NOT turn a structurally invalid grant into an authentication prompt.
- Refresh and token-exchange operations MUST preserve the original `auth_time` and authentication
  context so they cannot silently bypass a resource's recency or strength policy.

## Acceptance Criteria

- A password-only token receives an `acr_values=urn:robine-id:acr:password+totp` challenge after
  the client policy is strengthened to require TOTP or TOTP is enabled for its active user.
- A token whose authentication is older than `max_authentication_age` receives the corresponding
  `max_age` challenge, while a token at or inside the boundary remains accepted.
- When both requirements fail, one challenge contains both parameters.
- A DPoP-bound token must satisfy nonce, proof, key, endpoint, and replay checks before the step-up
  policy is disclosed.
- Unit tests cover policy classification and exact challenge serialization; `make release-smoke`
  verifies the recentness challenge across two Actix instances sharing PostgreSQL.

## Standards

- RFC 9470, OAuth 2.0 Step Up Authentication Challenge Protocol.
- OpenID Connect Core 1.0, `acr_values`, `max_age`, `acr`, and `auth_time`.
- RFC 6750, OAuth 2.0 Bearer Token Usage.
- RFC 9449, OAuth 2.0 Demonstrating Proof of Possession.

## Non-Goals

Arbitrary external resource-server policy engines, dynamic risk scoring, additional authentication
methods, and automatic client-side authorization redirects are outside this extension.
