# APPL-001 — Declarative Application Registration

## Status

MVP target

## Summary

Relying applications are declared in individual configuration files and reconciled into the OpenID Connect server state predictably.

## Requirements

- A client definition MUST support an identifier, display name, type, redirect URIs, post-logout redirect URIs, resource URIs, allowed scopes, grant types, authentication method, consent policy, and optional branding.
- Client identifiers MUST be globally unique in one configuration revision.
- Redirect URIs MUST be absolute, MUST NOT contain fragments, and MUST satisfy configurable HTTPS rules.
- The exact origins derived from a public client's redirect URIs form its browser CORS allowlist for
  the token endpoint; no wildcard or separately supplied origin list is accepted.
- Client secrets MUST be accepted only through supported secret references and MUST NOT be stored in plain text when persisted.
- Client type MUST be `public` or `confidential`.
- A public client MUST use authentication method `none` and MUST NOT require a secret.
- A confidential client MUST use `client_secret_basic`, `client_secret_post`, or `private_key_jwt`.
  Secret methods MUST declare an environment secret reference. `private_key_jwt` MUST instead
  declare an inline public `jwks` set and MUST NOT configure a shared secret.
- PKCE MUST default to required. A confidential client MAY set `pkce_required: false` for a verified integration that cannot implement PKCE; a public client MUST NOT disable PKCE.
- Nonce validation MUST default to required. A confidential client MAY set `nonce_required: false` for a verified integration that does not send one; a public client MUST NOT disable it.
- Supported grant types are limited to `authorization_code`, `refresh_token`, `client_credentials`,
  `urn:ietf:params:oauth:grant-type:token-exchange`, and
  `urn:ietf:params:oauth:grant-type:device_code`; unsupported grants
  MUST prevent activation. Token exchange requires a confidential client and at least one exact
  resource target. Authorization endpoint use
  still requires `authorization_code`. Only confidential clients MAY use `client_credentials`.
- Allowed scopes MUST default to `openid`, and authorization requests MUST remain a subset of the
  declared list. An `authorization_code` client MUST allow `openid` and declare at least one
  redirect URI. A service-only client MAY declare an empty redirect list and omit `openid`, but
  MUST declare at least one non-identity scope. A device-only client MAY declare an empty redirect
  list but MUST allow `openid`.
- Consent MUST default to required and MAY be disabled per client with `consent_required: false`.
- Pushed authorization requests MUST default to optional. An `authorization_code` client MAY set
  `require_pushed_authorization_requests: true`; other grant-only clients MUST NOT set it.
- `required_acr` MAY impose password or password-plus-TOTP authentication on an interactive
  Authorization Code or Device client. Requiring TOTP is invalid unless the global method is
  enabled; service-only clients MUST NOT declare an authentication context.
- Token introspection MUST default to denied. Only a confidential client MAY opt in with
  `introspection_allowed: true`.
- Defaults MUST be deterministic: omitted name uses the identifier, omitted type is public, omitted post-logout list is empty, and omitted grant list contains only `authorization_code`.
- Reapplying unchanged configuration MUST not resolve or rotate a client secret.

## Configuration Shape

Each entry accepts `id`, `name`, `type`, `redirect_uris`, `post_logout_redirect_uris`, `resources`, `scopes`,
`grant_types`, `authentication_method`, `pkce_required`, `nonce_required`, `secret_reference`, `jwks`,
`consent_required`, `introspection_allowed`, `require_pushed_authorization_requests`, `required_acr`,
and `branding`.
Unknown fields are invalid.

`secret_reference` accepts only an environment reference of the form
`{"provider":"env","key":"VARIABLE_NAME"}`. Environment values are resolved only when
authenticating the client. Missing values cause authentication failure. Literal client secrets are
invalid, and effective configuration output MUST redact the reference.

`jwks.keys` accepts one to sixteen unique RSA public signing keys. Each key requires `kid`, `n`, and
`e`; optional `use` and `alg` values are restricted to `sig` and `RS256`. Overlapping old and new
keys permits client-key rotation without downtime. Robine ID never receives the client private key.

Redirect URIs use exact string comparison at protocol boundaries. HTTPS is required except for HTTP loopback development hosts. Fragments and user-info components are forbidden.
Resource URIs follow the same URL safety rules, are unique, and are matched as exact strings.

## Acceptance Criteria

- Two consecutive applications of the same client configuration result in identical effective state.
- Invalid or duplicate client definitions prevent activation and report the exact configuration location.
- Changing a client redirects list updates that client without changing its identifier or secret.
- A public client succeeds without HTTP Basic credentials; a confidential client fails without the configured Basic credentials.
- A redirect that differs by path, query, port, case, or trailing slash is rejected unless independently registered.

## MVP Storage Model

Clients are read directly from the active immutable configuration snapshot. There is no dynamic registration API or client database. Removal takes effect atomically when the new configuration activates; the configured reconciliation deletion policy is retained for future persistent adapters but does not create tombstones in the MVP memory adapter.
