# SECU-001 — Authentication Session Security

## Status

MVP target

## Summary

Interactive authentication sessions resist fixation, forgery, replay, and accidental disclosure.

## Requirements

- Session cookies MUST be `Secure`, `HttpOnly`, use an appropriate `SameSite` policy, and have the narrowest practical scope.
- The session identifier MUST rotate after successful authentication and privilege changes.
- State-changing browser requests MUST use CSRF protection.
- Authentication attempts MUST be rate-limited by configurable, privacy-preserving dimensions.
- Passwords, authorization codes, access tokens, refresh tokens, session identifiers, and client secrets MUST never appear in logs.
- DPoP proof thumbprints, proof `jti` values, and nonces MUST NOT appear in logs. Accepted proofs
  MAY emit only bounded fields such as endpoint and outcome.
- Environment-resolved client and TOTP secrets MUST use zeroizing memory wrappers so transient
  buffers are overwritten when released.
- Submitted passwords, MFA/recovery and CSRF codes, authorization and device codes,
  refresh/access tokens, PKCE verifiers, client secrets/assertions, token-exchange subject/actor
  tokens, logout hints, and decoded HTTP Basic secrets MUST remain in zeroizing wrappers for their
  complete owned lifetime.
- Current and staged signing-key encryption secrets MUST use zeroizing wrappers while they are
  validated and derived. Every in-memory derived wrapping-key copy MUST be cleared when its
  database handle is dropped.
- Generated or decrypted signing-key PEM and raw opaque-token entropy buffers MUST be zeroized on
  every success and error path. Signing-key structures MUST NOT derive a plaintext-revealing debug
  representation.
- Server-generated CSRF values MUST use a zeroizing wrapper until copied into the unavoidable HTTP
  representation. Raw browser-token entropy MUST be cleared immediately after Base64URL encoding.
- `DATABASE_URL`, `PGPASSWORD`, `POSTGRES_PASSWORD`, and any component-built connection URL MUST
  use zeroizing wrappers during configuration parsing. Percent-encoding a component password MUST
  NOT place it in an ordinary owned string or a general-purpose URL object.
- Failed-login responses MUST not disclose account existence by default.
- Session idle timeout, absolute timeout, and maximum concurrent sessions MUST be configurable.
- Logout MUST invalidate the local session and honor validated post-logout redirects when supported.
- Browser cookies MUST contain only an opaque, high-entropy session credential; subject and policy state MUST remain server-side.
- CSRF credentials, session-state salts, JWT identifiers, and generated request identifiers MUST
  use fallible operating-system entropy. A failure MUST reject secret-bearing work or omit optional
  session state without panicking; only non-security request correlation MAY use a bounded
  process-local sequence fallback.
- A persisted grant that no longer resolves to an active issuer or client MUST become invalid or
  temporarily unavailable without panicking token issuance, introspection, or UserInfo.
- The public OIDC `sid` MUST be a distinct opaque value and MUST NOT reveal or be accepted as the
  browser's session credential.
- OIDC Session Management MUST keep the browser authentication credential `HttpOnly`. Its separate
  JavaScript-readable OP browser-state cookie MUST be one-way derived, non-authenticating,
  `SameSite=None; Secure` on HTTPS, and removed with the authenticated session.
- Authentication success MUST issue a fresh session credential before storing the subject registration.
- Idle and absolute age MUST be evaluated on each browser request. An invalid or unknown authenticated session MUST be cleared and replaced with a fresh anonymous session.
- Concurrent-session enforcement MUST retain no more than the configured maximum most-recent session identifiers for a subject.
- Rate limiting MUST enforce independent counters for the remote network address and the selected
  issuer plus normalized submitted identifier, use a bounded time window, and return HTTP 429 with `Retry-After` when
  either dimension is exhausted. This prevents rotating identifiers from bypassing a network limit
  and rotating source addresses from bypassing protection for one account, without allowing one
  tenant to exhaust another tenant's same-identifier account counter.
- A trusted `X-Forwarded-For` value used for authentication throttling MUST parse as an IP address
  and be canonicalized; malformed or untrusted values MUST fall back to the socket peer.
- Password comparison and PKCE comparison MUST use appropriate cryptographic verification functions.
- Password authentication MUST use one uniform bcrypt cost per configuration revision and perform
  a same-cost dummy verification for an unknown identifier.
- Submitted identifiers MUST contain 1–320 UTF-8 bytes. Submitted bcrypt passwords MUST contain
  1–72 bytes so two accepted credentials can never differ only beyond bcrypt's input boundary;
  invalid shapes receive the same generic failure and dummy-hash work as an unknown identity.
- Production MUST force HTTPS, emit HSTS, and mark cookies Secure. Development MAY relax Secure cookies only for loopback HTTP.
- Authorization requests, identity claims, and consent transactions MUST remain server-side and be consumed atomically.
- A consumed consent transaction MUST be revalidated against active issuer, user, client, redirect,
  grant, scope, resource, PKCE/nonce, MFA, essential-claim, and authorization-detail policy. Mapped
  output claims MUST be rebuilt from active user state. Revoked policy MUST fail locally rather
  than sending a code or denial to a redirect no longer registered.
- A rendered login form MUST carry only an opaque issuer-bound browser authorization transaction;
  it MUST NOT reflect redirect URIs, OAuth state, nonce, scope, PKCE, resource, request objects, or
  DPoP bindings. Failed authentication MUST consume and replace the transaction before retry.
- OAuth parameters with security meaning MUST reject duplicate definitions so a proxy, client, and
  provider cannot select conflicting values from the same serialized request.
- Post-logout redirects MUST be protected by exact registration and a verified ID-token hint or
  explicit active client. The single-use confirmation transaction MUST store structured
  issuer/client/URI/state bindings and revalidate them against active policy before redirecting;
  policy revocation MUST fail closed for the redirect without cancelling local logout.
- A validated authenticated session MAY satisfy a later authorization request without another
  password check, except when prompt policy explicitly requires interaction or the user's current
  factor policy requires TOTP and the stored session did not verify it.
- A global browser session whose active subject is not available on the selected issuer MUST be
  treated as unauthenticated for that request without deleting its cookie. Deleted or disabled
  subjects and insufficient current authentication context MAY clear it.
- Refresh tokens MUST rotate on successful use. Reuse of an already consumed token MUST revoke its
  entire refresh family without logging any member of that family.
- Authorization success and redirected error responses MUST identify the issuer according to RFC
  9207 so multi-provider clients can detect authorization-server mix-up.
- Form-post authorization responses MAY replace only the static CSP `form-action` directive with
  the exact registered redirect origin; all other restrictive directives MUST remain active.
- HTTP compression MUST be limited to public resources. Authentication forms, consent, Device
  verification, token and UserInfo responses, logout, and other credential-bearing representations
  MUST remain uncompressed even when the client advertises `Accept-Encoding`.
- JSON errors, rejected cross-origin preflights, and session-origin validation responses MUST emit
  `Cache-Control: no-store` and `Pragma: no-cache`. Public metadata is cacheable only through its
  dedicated ETag-aware response path.
- CORS evaluation MUST require a single valid UTF-8 `Origin`, request-method, and requested-headers
  field wherever each field is required. Duplicate, non-UTF-8, or non-canonical method values MUST
  be rejected before any access-control grant is emitted.
- A known public, OAuth, or OIDC protocol route invoked with an unsupported HTTP method MUST return
  HTTP 405, an exact bounded `Allow` header, and the same non-cacheable JSON error policy. It MUST
  remain distinguishable from an unknown route's HTTP 404 without exposing issuer or client state.
- Every `HEAD` response, including 404 and 405 errors, MUST be bodyless while preserving the status,
  representation media type and non-zero GET-equivalent `Content-Length`. Actix and Vercel MUST
  preserve the same contract.

## Session State

The cookie carries only a random session credential. PostgreSQL is authoritative for the distinct
public `sid`, subject, creation time, last-seen time, absolute expiry, revocation, participating RPs,
and concurrent-session policy. Restarting
or routing to another instance preserves the session when both instances share the database and cookie policy.

The absolute timeout is measured from `session_started_at`; idle timeout is measured from `session_last_seen_at`. Successful validation updates the last-seen timestamp without extending the absolute deadline.

## Acceptance Criteria

- A pre-authentication session identifier cannot be reused as the authenticated session identifier.
- Requests without valid CSRF evidence cannot mutate browser session state.
- Security logs provide a correlation trail while redacting credentials and tokens.
- Exceeding maximum concurrent sessions invalidates the oldest retained registration.
- Changing identifiers from one source or changing sources against one identifier cannot bypass
  the corresponding authentication-attempt counter.
- Two issuers using the same normalized login identifier share the global source-address counter
  but retain independent account counters.
- Visiting an issuer outside an active subject's `issuer_ids` cannot destroy the browser session
  that remains valid for an authorized issuer.
- Restarting the process preserves unexpired authenticated registrations through PostgreSQL.
- Silent authorization never displays login or consent and returns a standard interaction-required
  protocol error when the existing session is insufficient.
- Unsupported methods on authorization, consent, PAR, device, token, introspection, revocation,
  UserInfo, and logout routes return exact method negotiation rather than a misleading 404.

## Threat Boundaries

The runtime mitigates session fixation, credential guessing through shared PostgreSQL rate limits,
CSRF on browser mutations, authorization-code replay, refresh-token replay, authorization-server
mix-up, PKCE interception, open post-logout redirects, and accidental credential logging. It does
not claim protection against a compromised host, stolen
unlocked browser profile, phishing, or denial of service.
