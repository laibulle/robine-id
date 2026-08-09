# IDEN-001 — Local Identities and Claims

## Status

MVP target

## Summary

Operators declare local password identities and scope-constrained OIDC claim mappings in the active configuration.

## Requirements

- Every user MUST have a unique stable `id`, unique login `identifier`, and bcrypt `password_hash`.
- Bcrypt hashes MUST use a supported `$2a$`, `$2b$`, or `$2y$` form with cost from 10 through 16.
- Optional standard sources are `name` and `email`; arbitrary additional sources MAY be stored in the user's `claims` map.
- Clear-text passwords MUST NOT be accepted in configuration.
- Authentication MUST trim the submitted identifier and perform a bcrypt verification.
- Missing users MUST trigger a dummy bcrypt verification so the public response and dominant work factor do not disclose account existence.
- Failed authentication MUST return one generic invalid-credentials outcome.
- Claim mappings MUST declare a target claim name, user source, and required scope.
- Reserved claims `iss`, `sub`, `aud`, `iat`, `exp`, and `nonce` MUST NOT be configured through identity mapping.
- A mapped claim MUST be omitted when its required scope was not granted or its source value is nil.
- `sub` MUST always use the stable configured user identifier and MUST not use the mutable login identifier or email address.
- ID-token and UserInfo claims MUST derive from the same claims captured during authorization.

## Acceptance Criteria

- Correct credentials resolve exactly one identity; a wrong password and unknown identifier produce the same public error.
- Duplicate user IDs or identifiers prevent configuration activation.
- Mapped `name`, `email`, and custom claims appear only when their configured scope is present.
- Attempting to map a reserved protocol claim is rejected during configuration validation.
- No effective-configuration or audit output contains password hashes.

## Lifecycle and Limitations

Users are managed only by editing and applying configuration. Password reset, account recovery, enrollment, email verification, lockout state, groups, roles, external directories, and identity federation are outside the MVP. Removing a user makes subsequent login and UserInfo lookup fail after the revision activates; existing in-memory tokens are not proactively enumerated or revoked.
