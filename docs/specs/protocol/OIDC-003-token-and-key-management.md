# OIDC-003 — Token and Key Management

## Status

MVP target

## Summary

Robine ID issues verifiable tokens and supports safe signing-key rotation without interrupting clients.

## Requirements

- ID tokens MUST contain at least `iss`, `sub`, `aud`, `iat`, and `exp`, plus `nonce` when supplied in the authorization request.
- Every ID token returned alongside an access token MUST contain the RS256 `at_hash` value for that
  exact access token so relying parties can detect token substitution.
- Password-authenticated ID tokens MUST contain `acr=urn:robine-id:acr:password` and `amr=["pwd"]`;
  refreshed tokens retain that original authentication context.
- TOTP-authenticated ID tokens MUST contain `acr=urn:robine-id:acr:password+totp` and
  `amr=["pwd", "otp"]`; authorization codes, Device Flow grants, access-token grants, and rotating
  refresh tokens MUST retain that context without deriving it again from mutable user
  configuration. JWT access tokens and introspection expose the retained context for resource-server
  policy; token exchange MUST copy it unchanged.
- ID tokens MUST carry `auth_time` for the authentication event that established the browser
  session, including when a later authorization reuses that session or requested `max_age`.
- Token lifetimes, signing algorithm, and claim mappings MUST be configurable within safe validation limits.
- Signing keys MUST have unique `kid` values and public keys MUST be exposed through the configured JWKS endpoint.
- Exactly one key MUST be active for signing per issuer and algorithm.
- Previously active public keys MUST remain published after rotation so tokens issued by retained keys remain verifiable.
- Every rotation MUST persist an immutable retention deadline for the retired key. The deadline MUST
  equal the retirement time plus the greater configured ID-token/JWT-access-token lifetime, configured clock skew, and a
  five-minute operational safety margin captured at rotation time.
- Retained keys MUST be removed only after their persisted retention deadline. Pruning MUST be
  idempotent and MUST never remove the active signing key.
- Private signing material MUST never be returned by HTTP endpoints or rendered in administrative diagnostics.
- Key rotation MUST be idempotent when the desired key state has already been reached.
- An issuer MAY declare an automatic rotation interval from 3,600 through 31,536,000 seconds.
  A due decision MUST be rechecked while holding the active PostgreSQL key row lock so concurrent
  instances create at most one replacement. The automatic idempotency identifier MUST derive from
  the key being retired.
- Automatic rotation MUST skip issuers whose active configuration sets `enabled: false`. Their
  active and retained key rows MUST remain persisted and normal expiry-based retained-key pruning
  MUST continue, so reactivation preserves the prior key history without unnecessary rollover.
- ID tokens MUST be compact JWS values signed with RS256 and carry the active key's `kid` header.
- `iat` and `exp` MUST use integer epoch seconds. `exp` MUST equal `iat` plus the configured ID-token lifetime.
- Access tokens MUST be opaque, random bearer credentials; only their hashes MUST be used as runtime lookup keys.
- Access-token lifetime and ID-token lifetime MUST be independently configurable between 1 and 86,400 seconds.
- Refresh-token lifetime MUST be independently configurable between 60 and 31,536,000 seconds.
- JWKS MUST expose RSA public parameters and the metadata `kid`, `use=sig`, and `alg=RS256`; it MUST NOT expose private RSA parameters.
- JWKS MUST expose a representation ETag and a shared-cache lifetime no longer than five minutes;
  key rotation MUST change the validator and matching conditional requests MUST return HTTP 304.
- JWKS MUST allow credential-free cross-origin reads with `Access-Control-Allow-Origin: *` and
  `Cross-Origin-Resource-Policy: cross-origin`. Its public route MUST support `GET`, bodyless
  `HEAD`, and an `OPTIONS` preflight limited to `GET, HEAD, OPTIONS` and `If-None-Match`.
- Private signing state MUST be encrypted with AES-256-GCM using key material derived from `KEY_ENCRYPTION_SECRET` (or the compatibility fallback `SECRET_KEY_BASE`) before PostgreSQL persistence.
- A temporary `KEY_ENCRYPTION_SECRET_PREVIOUS` MAY decrypt existing rows during a staged secret
  rollover. It MUST be at least 32 bytes, differ from the current secret, and never encrypt new
  material.
- The operator re-encryption command MUST lock and rewrite all active and retained signing-key rows
  with the current secret in one PostgreSQL transaction. Any decryption or update failure MUST roll
  back every rewrite.
- Encrypted private material, its nonce, public parameters, active status, and stable rotation identifier MUST be committed atomically.
- Manual rotation MUST take a caller-provided stable rotation identifier containing 1–128 URL-safe
  characters. Repeating that identifier for the current key MUST be a no-op.
- Operator diagnostics MUST redact key material and token values.

## Acceptance Criteria

- A relying party can validate every non-expired ID token using the published JWKS.
- Applying the same key configuration repeatedly does not create duplicate keys or change the active key unexpectedly.
- Removing a key still required to validate a non-expired token is rejected or deferred with a clear diagnostic.
- Startup, periodic maintenance, and the operator pruning command remove only retained keys whose
  verification window has elapsed, including keys for issuers later removed from configuration.
- Restarting against the same PostgreSQL database and encryption secret preserves token verification and active `kid`.
- After staged re-encryption, the same active and retained `kid` values remain usable with the new
  secret alone; the former secret can be removed.
- A missing issuer key initializes one active key through an atomic database operation.
- A not-yet-due automatic check is a no-op; repeated or concurrent due checks produce one active
  replacement and one retained predecessor.

## Operational Constraints

The PostgreSQL backup and its matching encryption secret are both required for recovery. Losing
either invalidates all outstanding ID tokens. Operators MUST use the staged previous-secret and
transactional re-encryption procedure instead of replacing `KEY_ENCRYPTION_SECRET` independently.
Backups taken before the rewrite still require the former secret; backups taken afterward require
the new one. The backup includes each retired key's retention deadline. Rotation identifiers and
database constraints make retry and multi-instance coordination idempotent.

Conventional servers prune elapsed retained keys at startup and during database maintenance.
`prune_keys` performs the same idempotent operation on demand. Serverless instances perform the
startup pass because they intentionally do not run background maintenance loops. Migrating legacy
retained rows assigns a conservative seven-day deadline before pruning becomes possible.

Conventional servers check configured active-issuer automatic rotation every five minutes in addition to startup.
Vercel checks during cold initialization and immediately before an ID token is signed, because a
function process cannot rely on a background timer. Both paths use the same row-locked PostgreSQL
operation.

Opaque access-token grants are stored by digest in PostgreSQL and survive process restart until
expiry or client-bound revocation. Their status can be queried through the protected introspection
endpoint described by OAUTH-001.

Rotating refresh-token families are also stored only by digest and survive process restart. Their
absolute family expiry, original authentication time, subject, client, scopes, and captured claims
remain bound across rotations as described by OIDC-006.
