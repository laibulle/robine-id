# IDEN-001 — Local Identities and Claims

## Status

MVP target

## Summary

Operators declare local password identities and scope-constrained OIDC claim mappings in the active configuration.
Selected users may additionally reference an operator-provisioned TOTP factor as specified by SECU-002.

## Requirements

- Every user MUST have a globally unique stable `id`, a login `identifier`, and a bcrypt
  `password_hash`. An identifier MUST be unique on every issuer where the user is available; the
  same normalized identifier MAY identify distinct users only when their non-empty `issuer_ids`
  sets are disjoint.
- A user MAY set `enabled: false`; omitted `enabled` MUST default to `true` for backward compatibility.
- A user MAY declare `issuer_ids` as a unique list of configured issuer identifiers. Omitted or
  empty means every active issuer for backward compatibility. A non-empty list limits login,
  browser-session reuse, device authorization, refresh, token exchange, UserInfo, introspection,
  and pairwise-subject resolution to those tenants. Correct credentials on another issuer MUST
  follow the same dummy-verification and generic-error path as an unknown identifier.
- Disabled users MUST remain part of the validated configuration but MUST NOT resolve as active
  identities for login, browser sessions, device authorization, refresh, token exchange, UserInfo,
  or introspection.
- Bcrypt hashes MUST use a supported `$2a$`, `$2b$`, or `$2y$` form with cost from 10 through 16.
- Every user in one active revision MUST use the same bcrypt cost. Unknown identifiers MUST be
  verified against a configured hash at that same cost, or a cost-12 fallback when no users exist,
  so account presence does not change the dominant password-verification work factor.
- Optional standard sources are `name` and `email`; arbitrary additional sources MAY be stored in the user's `claims` map.
- Clear-text passwords MUST NOT be accepted in configuration.
- Clear-text TOTP secrets MUST NOT be accepted in configuration; only strict environment secret
  references MAY be attached to a user.
- Authentication MUST trim the submitted identifier and perform a bcrypt verification.
- Missing users MUST trigger a dummy bcrypt verification so the public response and dominant work factor do not disclose account existence.
- Disabled users MUST follow the same dummy-verification and generic-error path as unknown identifiers.
- Failed authentication MUST return one generic invalid-credentials outcome.
- Claim mappings MUST declare a target claim name, user source, and required scope.
- Reserved claims `iss`, `sub`, `aud`, `iat`, `exp`, `nbf`, `jti`, `nonce`, `auth_time`, `at_hash`,
  `c_hash`, `acr`, `amr`, and `azp` MUST NOT be configured through identity mapping.
- A mapped claim MUST be omitted when its required scope was not granted or its source value is nil.
- `sub` MUST always use the stable configured user identifier and MUST not use the mutable login identifier or email address.
- ID-token and UserInfo claims MUST derive from one server-side claim set. When consent is pending,
  that set MUST be rebuilt from the active user attributes and mappings immediately before code
  issuance so a revoked or changed attribute is not emitted from stale transaction state.

## Acceptance Criteria

- Correct credentials resolve exactly one identity; a wrong password and unknown identifier produce the same public error.
- Correct credentials for a disabled identity produce that same public error, and disabling an
  identity makes server-validated sessions and grants inactive as soon as the revision activates.
- Correct credentials for an identity outside the selected issuer produce the generic error; an
  existing session or server-validated grant becomes inactive on that issuer when its scope is
  removed. The global session cookie remains available for other authorized issuers.
- Duplicate user IDs or identifier scopes that overlap on any issuer prevent configuration
  activation; the same identifier on two disjoint explicit tenant sets resolves independently.
- Mixed bcrypt costs prevent activation, and an unknown identifier performs bcrypt work at the
  active revision's configured cost.
- Mapped `name`, `email`, and custom claims appear only when their configured scope is present.
- Attempting to map a reserved protocol claim is rejected during configuration validation.
- No effective-configuration or audit output contains password hashes.

## Lifecycle and Limitations

Users are managed only by editing and applying configuration. Set `enabled: false` to suspend an
identity without deleting its stable internal identifier or changing its pairwise subject mapping.
Set `issuer_ids` to isolate an identity to selected tenants while retaining the same stable subject
on those tenants; omitting it preserves the all-issuer behavior.
Removing or disabling a user makes subsequent login and server-side session, device, refresh,
token-exchange, UserInfo, and introspection validation fail after the revision activates. Existing
PostgreSQL grants are not proactively enumerated or revoked, and a self-contained JWT already
accepted by an offline resource server remains bounded by its expiry. Re-enabling an identity can
therefore make an otherwise current server-side grant usable again; use explicit token revocation
as well when suspension must remain irreversible. Active server-side code, Device, refresh,
exchange, and UserInfo paths rebuild mapped claims, so changed user attributes take effect without
enumerating those grants; already issued self-contained JWTs remain immutable. Password reset, account recovery, enrollment,
email verification, lockout state, groups, roles, external directories, and identity federation
are outside the MVP.
