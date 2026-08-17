# OIDC-004 — UserInfo

## Status

MVP target

## Summary

Robine ID exposes subject claims authorized by a bearer or DPoP-bound access token in either
issuer-configured presentation format.

## Requirements

- UserInfo MUST be available at both `GET` and `POST /:issuer_id/userinfo`.
- The request MUST carry exactly one Bearer credential for an unbound token, or one DPoP credential
  plus a fresh matching RFC 9449 proof for a DPoP-bound token.
- The token digest MUST exist in PostgreSQL and MUST not be expired.
- The token's issuer MUST match the requested issuer endpoint.
- The subject MUST still resolve to a configured identity.
- The issuing client, originating authorization or refresh grant, and every granted scope MUST
  remain enabled in the active configuration. A machine token MUST never satisfy UserInfo.
- A successful response MUST contain `sub` and MAY contain only non-nil claims authorized by the
  token scopes. Mapped values MUST be rebuilt from the active user and mapping definitions for each
  response rather than copied from the stored access-token grant.
- By default a successful response MUST be JSON. A client configured according to OIDC-013 MUST
  instead receive an audience-bound RS256 JWT with `application/jwt` through both GET and POST.
- Claim values MUST come from validated claim mappings; reserved token claims MUST NOT be injected through configuration.
- Missing, malformed, unknown, expired, or issuer-mismatched tokens MUST return HTTP 401 with `WWW-Authenticate: Bearer error="invalid_token"`.
- Bearer and DPoP challenges SHOULD also include the OAUTH-012 `resource_metadata` URL for this exact
  UserInfo endpoint.
- An otherwise valid token that no longer meets the application's `required_acr` or
  `max_authentication_age` policy, or whose active user now requires TOTP, MUST return the OAUTH-013
  `insufficient_user_authentication` challenge with the unmet `acr_values`, `max_age`, or both.
- A bound token presented as Bearer, without a valid `ath` proof, with another key, or with a replayed
  proof MUST return HTTP 401 with a DPoP authentication challenge.
- Error bodies MUST NOT distinguish why a bearer token was rejected.
- JSON and signed-JWT responses containing identity claims MUST emit `Cache-Control: no-store` and
  `Pragma: no-cache` and MUST NOT be cached by browser or shared caches.
- A bounded UserInfo outcome metric MUST count final successful and failed responses without token,
  client, subject, origin, or claim labels. The structured success audit event MUST be emitted only
  after subject derivation, optional JWT signing, and response construction have all succeeded.
- Browser CORS preflight and claim responses MUST allow only origins derived from registered client
  redirect URIs; arbitrary origins and unsupported requested headers MUST be rejected.

## Acceptance Criteria

- An access token carrying only `openid` returns `sub` without profile or email claims.
- Tokens authorized for `profile` or `email` return only the mapped claims associated with those scopes.
- Changing an active mapped user value changes the next opaque-token UserInfo response; removing
  its mapping removes the claim without requiring token reissuance.
- Changing or expiring a token returns the same public `invalid_token` failure.
- A token issued for one issuer cannot be used at another issuer's UserInfo endpoint.
- The same bearer credential returns the same claims through GET and POST.
- A signed response verifies against issuer JWKS and binds `iss` and `aud` to the issuer and client.
- A DPoP-bound credential returns the same claims only when each request carries a fresh proof for
  the exact method, endpoint URI, access token, and bound key.
- A registered browser-client origin can call UserInfo through CORS, while an unregistered origin
  receives no cross-origin access grant.
- Authentication-context and recentness policy failures are distinguishable from invalid tokens
  only after token and, when applicable, DPoP proof validation.
- Pairwise-subject or signing failures cannot be recorded as successful UserInfo access; the final
  HTTP outcome and `robine_id_userinfo_total` remain consistent.

## Runtime behavior

Access-token grants are stored by digest in PostgreSQL. Process restart and routing between instances
sharing the same database preserve an unexpired token; the bearer value itself is never stored.
