# SECU-002 — TOTP Multi-Factor Authentication

## Status

Production target

## Summary

Robine ID can require a second, time-based one-time password for selected local users without
placing the shared authenticator secret in versioned configuration or browser state.

## Requirements

- TOTP MUST be enabled explicitly by adding `totp` to `authentication.methods`; `password` remains
  mandatory. A user MAY then declare one `totp_secret_reference` using the existing strict
  `{provider: "env", key: "..."}` secret-reference shape.
- The referenced value MUST be unpadded RFC 4648 Base32 and decode to 160 through 512 bits. The
  effective configuration, diagnostics, HTML, metrics, and logs MUST never expose the reference or
  secret value.
- Verification MUST implement RFC 6238 with HMAC-SHA-1, a 30-second time step, six decimal digits,
  and a window containing only the current, immediately previous, and immediately next step.
- Password verification MUST complete before a TOTP challenge is created. A missing or malformed
  operator secret MUST fail closed as a service-unavailable error, not silently downgrade to
  password-only authentication.
- Browser challenges MUST be opaque, issuer- and subject-bound, stored only by digest, expire no
  later than the originating browser or device authorization, contain no credential, and be
  consumed atomically after successful verification.
- PostgreSQL MUST retain the greatest accepted time-step counter for each issuer and subject. A
  counter already accepted through any challenge, purpose, or application instance MUST be rejected
  and the attempted challenge consumed.
- TOTP attempts MUST share the independent network and issuer-bound account rate limits used by
  password authentication. User-visible failures MUST not reveal the shared secret or whether a replay,
  skew, or incorrect code caused rejection.
- Both Authorization Code and Device Authorization browser journeys MUST enforce TOTP for a
  configured user. A pre-existing password-only session MUST NOT bypass the second factor after a
  configuration revision enables TOTP for that user.
- An interactive client MAY require the TOTP ACR independently of which account signs in. Such a
  policy MUST reject password-only sessions and accounts without a factor, while voluntary
  `acr_values` preferences MUST never downgrade the configured requirement.
- Authenticated sessions, pending consent, authorization codes, device grants, access-token grants,
  and rotating refresh tokens MUST retain whether TOTP was verified. Refresh and token exchange
  MUST preserve the original authentication context.
- Password-only ID tokens MUST continue to emit
  `acr=urn:robine-id:acr:password` and `amr=["pwd"]`. TOTP-authenticated ID tokens MUST emit
  `acr=urn:robine-id:acr:password+totp` and `amr=["pwd", "otp"]`.
- User JWT access tokens and active introspection responses MUST expose the same `auth_time`, `acr`,
  and `amr`; machine-only grants MUST omit them.
- Discovery MUST advertise the TOTP ACR only when `totp` is enabled in the active authentication
  methods.

## Acceptance Criteria

- An enabled user cannot complete Authorization Code or Device Authorization with the correct
  password alone, including through a session created before TOTP was enabled.
- A current authenticator code completes authentication; malformed and out-of-window values return
  an accessible generic error without destroying a still-valid challenge.
- Concurrent submissions of one challenge produce at most one success, and the same TOTP counter
  cannot complete a second challenge on the same or another instance.
- The MFA context survives consent, code exchange, refresh rotation, token exchange, Device Flow
  polling, restart, and cross-instance routing and is represented correctly in ID tokens, JWT
  access tokens, and active introspection responses.
- Configuration validation rejects inline, malformed, or user-enabled-without-method secret
  declarations, and redacted output contains neither the environment key nor secret.

## Operational Constraints

Provisioning and recovery are operator-managed. Generate an independent random secret per user,
enroll it in that user's authenticator application over a trusted channel, store it in the
deployment secret manager, and reference only the environment variable name. Self-service
enrollment, QR-code display, recovery codes, factor reset, and WebAuthn are not part of this feature.

Database restore includes TOTP replay counters and outstanding challenge state. Clock
synchronization is required on the database and application hosts; operators should alert on clock
drift rather than widening the verification window.
