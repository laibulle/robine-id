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
- Failed-login responses MUST not disclose account existence by default.
- Session idle timeout, absolute timeout, and maximum concurrent sessions MUST be configurable.
- Logout MUST invalidate the local session and honor validated post-logout redirects when supported.
- Browser cookies MUST contain only an opaque, high-entropy session credential; subject and policy state MUST remain server-side.
- Authentication success MUST issue a fresh session credential before storing the subject registration.
- Idle and absolute age MUST be evaluated on each browser request. An invalid or unknown authenticated session MUST be cleared and replaced with a fresh anonymous session.
- Concurrent-session enforcement MUST retain no more than the configured maximum most-recent session identifiers for a subject.
- Rate limiting MUST enforce independent counters for the remote network address and the normalized
  submitted identifier, use a bounded time window, and return HTTP 429 with `Retry-After` when
  either dimension is exhausted. This prevents rotating identifiers from bypassing a network limit
  and rotating source addresses from bypassing protection for one account.
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
- A rendered login form MUST carry only an opaque issuer-bound browser authorization transaction;
  it MUST NOT reflect redirect URIs, OAuth state, nonce, scope, PKCE, resource, request objects, or
  DPoP bindings. Failed authentication MUST consume and replace the transaction before retry.
- OAuth parameters with security meaning MUST reject duplicate definitions so a proxy, client, and
  provider cannot select conflicting values from the same serialized request.
- Post-logout redirects MUST be protected by exact registration and a verified ID-token hint.
- A validated authenticated session MAY satisfy a later authorization request without another
  password check, except when prompt policy explicitly requires interaction or the user's current
  factor policy requires TOTP and the stored session did not verify it.
- Refresh tokens MUST rotate on successful use. Reuse of an already consumed token MUST revoke its
  entire refresh family without logging any member of that family.
- Authorization success and redirected error responses MUST identify the issuer according to RFC
  9207 so multi-provider clients can detect authorization-server mix-up.
- Form-post authorization responses MAY replace only the static CSP `form-action` directive with
  the exact registered redirect origin; all other restrictive directives MUST remain active.

## Session State

The cookie carries only a random session credential. PostgreSQL is authoritative for the subject,
creation time, last-seen time, absolute expiry, revocation, and concurrent-session policy. Restarting
or routing to another instance preserves the session when both instances share the database and cookie policy.

The absolute timeout is measured from `session_started_at`; idle timeout is measured from `session_last_seen_at`. Successful validation updates the last-seen timestamp without extending the absolute deadline.

## Acceptance Criteria

- A pre-authentication session identifier cannot be reused as the authenticated session identifier.
- Requests without valid CSRF evidence cannot mutate browser session state.
- Security logs provide a correlation trail while redacting credentials and tokens.
- Exceeding maximum concurrent sessions invalidates the oldest retained registration.
- Changing identifiers from one source or changing sources against one identifier cannot bypass
  the corresponding authentication-attempt counter.
- Restarting the process preserves unexpired authenticated registrations through PostgreSQL.
- Silent authorization never displays login or consent and returns a standard interaction-required
  protocol error when the existing session is insufficient.

## Threat Boundaries

The runtime mitigates session fixation, credential guessing through shared PostgreSQL rate limits,
CSRF on browser mutations, authorization-code replay, refresh-token replay, authorization-server
mix-up, PKCE interception, open post-logout redirects, and accidental credential logging. It does
not claim protection against a compromised host, stolen
unlocked browser profile, phishing, or denial of service.
