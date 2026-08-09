# APPL-001 — Declarative Application Registration

## Status

MVP target

## Summary

Relying applications are declared in individual configuration files and reconciled into the OpenID Connect server state predictably.

## Requirements

- A client definition MUST support an identifier, display name, type, redirect URIs, post-logout redirect URIs, allowed scopes, grant types, authentication method, consent policy, and optional branding.
- Client identifiers MUST be globally unique in one configuration revision.
- Redirect URIs MUST be absolute, MUST NOT contain fragments, and MUST satisfy configurable HTTPS rules.
- Client secrets MUST be accepted only through supported secret references and MUST NOT be stored in plain text when persisted.
- Client type MUST be `public` or `confidential`.
- A public client MUST use authentication method `none` and MUST NOT require a secret.
- A confidential client MUST use `client_secret_basic` or `client_secret_post` and MUST declare an environment secret reference with a non-empty key.
- PKCE MUST default to required. A confidential client MAY set `pkce_required: false` for a verified integration that cannot implement PKCE; a public client MUST NOT disable PKCE.
- Nonce validation MUST default to required. A confidential client MAY set `nonce_required: false` for a verified integration that does not send one; a public client MUST NOT disable it.
- Supported grant types are limited to `authorization_code`; unsupported grants MUST prevent use of the authorization endpoint.
- Allowed scopes MUST default to `openid`, and authorization requests MUST remain a subset of the declared list.
- Consent MUST default to required and MAY be disabled per client with `consent_required: false`.
- Defaults MUST be deterministic: omitted name uses the identifier, omitted type is public, omitted post-logout list is empty, and omitted grant list contains only `authorization_code`.
- Reapplying unchanged configuration MUST not resolve or rotate a client secret.

## Configuration Shape

Each entry accepts `id`, `name`, `type`, `redirect_uris`, `post_logout_redirect_uris`, `scopes`, `grant_types`, `authentication_method`, `pkce_required`, `nonce_required`, `secret_reference`, `consent_required`, and `branding`. Unknown fields are invalid.

`secret_reference` accepts either a non-empty string containing the secret itself or an environment reference of the form `{"provider":"env","key":"VARIABLE_NAME"}`. Environment values are resolved only when authenticating the client. Missing values cause authentication failure. Effective configuration output MUST redact both literal secrets and references.

Redirect URIs use exact string comparison at protocol boundaries. HTTPS is required except for HTTP loopback development hosts. Fragments and user-info components are forbidden.

## Acceptance Criteria

- Two consecutive applications of the same client configuration result in identical effective state.
- Invalid or duplicate client definitions prevent activation and report the exact configuration location.
- Changing a client redirects list updates that client without changing its identifier or secret.
- A public client succeeds without HTTP Basic credentials; a confidential client fails without the configured Basic credentials.
- A redirect that differs by path, query, port, case, or trailing slash is rejected unless independently registered.

## MVP Storage Model

Clients are read directly from the active immutable configuration snapshot. There is no dynamic registration API or client database. Removal takes effect atomically when the new configuration activates; the configured reconciliation deletion policy is retained for future persistent adapters but does not create tombstones in the MVP memory adapter.
