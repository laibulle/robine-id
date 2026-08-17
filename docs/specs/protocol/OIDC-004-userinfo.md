# OIDC-004 — UserInfo

## Status

MVP target

## Summary

Robine ID exposes subject claims authorized by an opaque bearer access token.

## Requirements

- UserInfo MUST be available at `GET /:issuer_id/userinfo`.
- The request MUST carry exactly one bearer credential in the `Authorization` header.
- The token digest MUST exist in PostgreSQL and MUST not be expired.
- The token's issuer MUST match the requested issuer endpoint.
- The subject MUST still resolve to a configured identity.
- A successful response MUST contain `sub` and MAY contain only non-nil claims captured for scopes granted during authorization.
- Claim values MUST come from validated claim mappings; reserved token claims MUST NOT be injected through configuration.
- Missing, malformed, unknown, expired, or issuer-mismatched tokens MUST return HTTP 401 with `WWW-Authenticate: Bearer error="invalid_token"`.
- Error bodies MUST NOT distinguish why a bearer token was rejected.
- Responses containing identity claims MUST NOT be cached by shared caches.

## Acceptance Criteria

- An access token carrying only `openid` returns `sub` without profile or email claims.
- Tokens authorized for `profile` or `email` return only the mapped claims associated with those scopes.
- Changing or expiring a token returns the same public `invalid_token` failure.
- A token issued for one issuer cannot be used at another issuer's UserInfo endpoint.

## Runtime behavior

Access-token grants are stored by digest in PostgreSQL. Process restart and routing between instances
sharing the same database preserve an unexpired token; the bearer value itself is never stored.
