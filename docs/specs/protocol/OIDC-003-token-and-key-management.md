# OIDC-003 — Token and Key Management

## Status

MVP target

## Summary

Robine ID issues verifiable tokens and supports safe signing-key rotation without interrupting clients.

## Requirements

- ID tokens MUST contain at least `iss`, `sub`, `aud`, `iat`, and `exp`, plus `nonce` when supplied in the authorization request.
- Token lifetimes, signing algorithm, and claim mappings MUST be configurable within safe validation limits.
- Signing keys MUST have unique `kid` values and public keys MUST be exposed through the configured JWKS endpoint.
- Exactly one key MUST be active for signing per issuer and algorithm.
- Previously active public keys MUST remain published after rotation so tokens issued by retained keys remain verifiable.
- Private signing material MUST never be returned by HTTP endpoints or rendered in administrative diagnostics.
- Key rotation MUST be idempotent when the desired key state has already been reached.
- ID tokens MUST be compact JWS values signed with RS256 and carry the active key's `kid` header.
- `iat` and `exp` MUST use integer epoch seconds. `exp` MUST equal `iat` plus the configured ID-token lifetime.
- Access tokens MUST be opaque, random bearer credentials; only their hashes MUST be used as runtime lookup keys.
- Access-token lifetime and ID-token lifetime MUST be independently configurable between 1 and 86,400 seconds.
- JWKS MUST expose RSA public parameters and the metadata `kid`, `use=sig`, and `alg=RS256`; it MUST NOT expose private RSA parameters.
- Private signing state MUST be encrypted with AES-256-GCM using key material derived from `KEY_ENCRYPTION_SECRET` (or the compatibility fallback `SECRET_KEY_BASE`) before PostgreSQL persistence.
- Encrypted private material, its nonce, public parameters, active status, and stable rotation identifier MUST be committed atomically.
- Rotation MUST take a caller-provided stable rotation identifier. Repeating that identifier for the current key MUST be a no-op.
- Operator diagnostics MUST redact key material and token values.

## Acceptance Criteria

- A relying party can validate every non-expired ID token using the published JWKS.
- Applying the same key configuration repeatedly does not create duplicate keys or change the active key unexpectedly.
- Removing a key still required to validate a non-expired token is rejected or deferred with a clear diagnostic.
- Restarting against the same PostgreSQL database and encryption secret preserves token verification and active `kid`.
- A missing issuer key initializes one active key through an atomic database operation.

## Operational Constraints

The PostgreSQL backup and its encryption secret are both required for recovery. Losing either invalidates all outstanding ID tokens. Operators MUST NOT rotate `KEY_ENCRYPTION_SECRET` independently of stored keys. Rotation identifiers and database constraints make retry and multi-instance coordination idempotent.

Opaque access-token grants are stored by digest in PostgreSQL and survive process restart until expiry. Introspection and revocation endpoints are not included.
