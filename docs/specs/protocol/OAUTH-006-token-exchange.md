# OAUTH-006 — OAuth 2.0 Token Exchange

## Status

Rust production extension

## Summary

Robine ID lets an explicitly authorized confidential client exchange its own active access token,
or a subject token whose source client delegates to it, for a shorter-lived downscoped access token
aimed at another registered resource.

## Requirements

- Discovery MUST advertise `urn:ietf:params:oauth:grant-type:token-exchange` only when at least one
  configured client enables it.
- A token-exchange client MUST be confidential, authenticate through its configured token-endpoint
  method, and declare at least one exact resource target.
- `subject_token_type` and the optional `requested_token_type` MUST be
  `urn:ietf:params:oauth:token-type:access_token`.
- Actor-token delegation MUST default to disabled. A client MAY opt in with
  `actor_token_exchange_allowed: true` only when it enables both Token Exchange and Client
  Credentials. `actor_token` and `actor_token_type` MUST occur together, and the supported actor
  type is the OAuth access-token type.
- A subject-token client MAY authorize specific actor clients through `authorized_actor_clients`.
  Every identifier MUST resolve to a distinct confidential actor-token client. The source
  allowlist, not the broker's own configuration, is authoritative for cross-client delegation.
- The subject token MUST be active, issued by the selected issuer, and owned by the authenticated
  client. Its issuer, client, subject, grant permission, scopes, resource, and expiry MUST remain
  valid under the active configuration.
- For a user subject, mapped claims in the exchanged grant MUST be rebuilt from the active user and
  target scopes; a captured value from the subject token MUST NOT outlive an attribute change.
- An actor token MUST be a distinct, active Client Credentials token issued to the authenticated
  actor client. Cross-client exchange MUST require it. It identifies the acting party without
  contributing scopes or target authority. Invalid or policy-unacceptable subject and actor tokens
  MUST return `invalid_request`.
- A requested scope MUST be a non-empty subset of the subject token scopes and current
  issuer, source-client, and actor-client scopes. `offline_access` MUST NOT be exchanged and no
  refresh token may be issued.
- `resource` and `audience` are accepted as exact registered targets. If both are present they MUST
  be identical; an unknown or conflicting target MUST return `invalid_target`.
- The exchanged token MUST expire no later than the subject token, the optional actor token, and
  the issuer's configured access-token lifetime. Re-exchange MUST NOT extend the original authority
  lifetime.
- A DPoP-bound subject or actor token MUST require a valid proof with the same JWK thumbprint. If
  both inputs are bound, they MUST be bound to that same proof key. A bearer subject token MAY be
  converted to a DPoP-bound token by presenting a valid proof.
- A delegated token MUST carry the current actor in the RFC 8693 `act` claim in JWT format and
  introspection. Re-exchange with another actor MUST nest the prior chain. Only `sub` and nested
  `act` are retained, and the chain MUST be limited to eight actors. Its `client_id` MUST identify
  the authenticated actor client while `sub` remains the subject-token principal.
- A delegated service token MUST remain introspectable even though its service `sub` differs from
  the broker `client_id`. Its machine subject MUST remain public and MUST NOT be mistaken for a
  same-named configured user. Active-policy validation MUST recheck that the source service still
  enables Client Credentials, still grants every effective service scope and authorization detail,
  and still authorizes the broker; removing that delegation makes the exchanged grant inactive.
- Success MUST return an `access_token` in the issuer-configured format, `issued_token_type`, `token_type`, `expires_in`, and
  `scope`, plus `resource` when selected. It MUST NOT return an ID token or refresh token.
- The exchanged grant MUST be stored by token digest in PostgreSQL and remain introspectable and
  revocable through the existing protected endpoints across all instances.
- Token responses and errors MUST disable caching and MUST NOT log either access token.

## Acceptance Criteria

- A service token created on one instance can be exchanged on another and introspected on either.
- Scope amplification, an unregistered target, an incomplete/disabled/identical actor-token input,
  a wrong token type, an unapproved subject client, and another client's actor token are rejected
  without issuance.
- The response identifies the access-token type, contains no OpenID or refresh credential, and its
  expiry cannot exceed the subject token expiry.
- Removing the client, token-exchange grant, subject grant permission, scope, or resource makes a
  later exchange fail even when the subject row has not yet expired.
- DPoP binding cannot be removed or changed during exchange.
- Actor identity survives opaque storage, JWT issuance, introspection, and bounded nested exchange.
- A cross-client service exchange remains active and introspectable with the source service as
  `sub`; removing the source-to-broker allowlist invalidates the stored exchanged grant.

## Non-Goals

Unrestricted impersonation, external `may_act` claims, refresh/ID-token exchange, and multiple
simultaneous audiences are outside this extension.

## Standards

- RFC 8693, OAuth 2.0 Token Exchange.
- RFC 7662, OAuth 2.0 Token Introspection.
- RFC 8707, Resource Indicators for OAuth 2.0.
- RFC 9449, OAuth 2.0 Demonstrating Proof of Possession.
