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
- Rate limiting MUST combine remote network address and normalized submitted identifier, use a bounded time window, and return HTTP 429 with `Retry-After` when exhausted.
- Password comparison and PKCE comparison MUST use appropriate cryptographic verification functions.
- Production MUST force HTTPS, emit HSTS, and mark cookies Secure. Development MAY relax Secure cookies only for loopback HTTP.
- Authorization requests, identity claims, and consent transactions MUST remain server-side and be consumed atomically.
- Post-logout redirects MUST be protected by exact registration and a verified ID-token hint.

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
- Restarting the process preserves unexpired authenticated registrations through PostgreSQL.

## Threat Boundaries

The runtime mitigates session fixation, credential guessing through shared PostgreSQL rate limits,
CSRF on browser mutations, authorization-code replay, PKCE interception, open post-logout redirects,
and accidental credential logging. It does not claim protection against a compromised host, stolen
unlocked browser profile, phishing, or denial of service.
