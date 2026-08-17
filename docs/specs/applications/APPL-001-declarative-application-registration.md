# APPL-001 — Declarative Application Registration

## Status

MVP target

## Summary

Relying applications are declared in individual configuration files and reconciled into the OpenID Connect server state predictably.

## Requirements

- A client definition MUST support an identifier, display name, type, redirect URIs, post-logout redirect URIs, optional front-channel and back-channel logout URIs, resource URIs, allowed scopes, grant types, authentication method, consent policy, and optional branding.
- Client identifiers MUST be globally unique in one configuration revision.
- A client MAY declare `issuer_ids` as a unique list of configured issuer identifiers. An omitted
  or empty list preserves compatibility by allowing every active issuer. A non-empty list limits
  the client to those tenants across authorization, PAR, device authorization, token,
  introspection, revocation, UserInfo, session check, logout callbacks, CORS, and conditional
  Discovery capabilities. Correct credentials presented to another issuer MUST receive
  `invalid_client` without revealing the registration.
- A client MAY set `enabled: false`; omitted `enabled` MUST default to `true`. Disabled clients
  remain fully validated and inspectable as configured state but MUST NOT authenticate, authorize,
  validate existing grants, contribute dynamic Discovery capabilities, authorize browser origins,
  or receive front-channel/back-channel logout callbacks.
- Redirect URIs MUST be absolute, MUST NOT contain fragments, and MUST satisfy configurable HTTPS rules.
- The exact origins derived from redirect URIs form endpoint-specific browser CORS allowlists. Token,
  PAR, and revocation accept only active public-client origins; UserInfo binds an actual response to
  the client that owns the access grant. No wildcard or separately supplied sensitive-endpoint
  origin list is accepted.
- Client secrets MUST be accepted only through supported secret references and MUST NOT be stored in plain text when persisted.
- Client type MUST be `public` or `confidential`.
- A public client MUST use authentication method `none` and MUST NOT require a secret.
- A confidential client MUST use `client_secret_basic`, `client_secret_post`, `client_secret_jwt`,
  or `private_key_jwt`. Secret methods MUST declare an environment secret reference.
  `client_secret_jwt` additionally requires at least 32 octets of resolved secret material.
  `private_key_jwt` MUST instead
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
- `max_authentication_age` MAY impose a non-negative authentication-age limit on an interactive
  client. Service-only clients MUST NOT set it. Authorization uses the stricter of this policy and
  request `max_age`; UserInfo exposes unmet recency through OAUTH-013.
- `actor_token_exchange_allowed` MUST default to false and MAY be enabled only for a confidential
  client declaring both Client Credentials and Token Exchange. It opts the client into same-client
  RFC 8693 actor-token delegation.
- `authorized_actor_clients` MUST default to an empty list. Each value MUST identify a distinct
  configured actor-token client. It is the source-side authorization for cross-client delegation;
  an actor client MUST NOT authorize itself to consume another client's subject tokens.
- Token introspection MUST default to denied. Only a confidential client MAY opt in with
  `introspection_allowed: true`.
- `userinfo_signed_response_alg` MAY be `RS256` to request signed, audience-bound UserInfo JWTs.
  It MUST default to omitted JSON behavior; other algorithm values are invalid.
- `authorization_details_types` MAY enable globally registered RFC 9396 detail types for a client.
  Values MUST be unique and MUST reference existing global definitions. Fine-grained details always
  require consent, independently of `consent_required`.
- `backchannel_logout_uri` MAY register the OIDC-014 RP callback. It follows the web-URL safety
  rules; only a confidential client MAY use loopback HTTP.
  `backchannel_logout_session_required` MUST be false when the URI is omitted. A revision MUST
  expose at most 32 active client-issuer callback combinations.
- `frontchannel_logout_uri` MAY register the OIDC-015 iframe callback. It MUST share scheme, host,
  and effective port with a redirect URI. Only a confidential client MAY use loopback HTTP.
  `frontchannel_logout_session_required` MUST be false when the URI is omitted, and a revision MUST
  expose at most 32 active client-issuer front-channel combinations.
- Defaults MUST be deterministic: omitted name uses the identifier, omitted type is public, omitted post-logout list is empty, and omitted grant list contains only `authorization_code`.
- Reapplying unchanged configuration MUST not resolve or rotate a client secret.

## Configuration Shape

Each entry accepts `id`, `name`, `enabled`, `issuer_ids`, `type`, `subject_type`, `sector_identifier`, `redirect_uris`, `post_logout_redirect_uris`, `frontchannel_logout_uri`, `frontchannel_logout_session_required`, `backchannel_logout_uri`, `backchannel_logout_session_required`, `resources`, `scopes`,
`grant_types`, `authentication_method`, `pkce_required`, `nonce_required`, `secret_reference`, `jwks`, `userinfo_signed_response_alg`,
`consent_required`, `introspection_allowed`, `require_pushed_authorization_requests`, `require_signed_request_object`, `request_object_jwks`, `required_acr`, `max_authentication_age`, `actor_token_exchange_allowed`, `authorized_actor_clients`, `authorization_details_types`,
and `branding`.
Unknown fields are invalid.

`secret_reference` accepts only an environment reference of the form
`{"provider":"env","key":"VARIABLE_NAME"}`. Environment values are resolved only when
authenticating the client. Missing values cause authentication failure. Literal client secrets are
invalid, and effective configuration output MUST redact the reference.

`jwks.keys` accepts one to sixteen unique RSA, P-256, or Ed25519 public signing keys. RSA keys require `kid`,
`n`, and `e`, with optional `alg=RS256`; EC keys require `kid`, `crv=P-256`, `x`, and `y`, with
optional `alg=ES256`. Ed25519 keys use `kty=OKP`, require `crv=Ed25519` and `x`, and optionally
declare `alg=EdDSA`. Optional `use` is restricted to `sig`. Key material for another family or
curve is rejected, as are mixed key parameters. Overlapping old and new keys, even across the two
families, permits client-key rotation without downtime. Robine ID never receives the private key.

`request_object_jwks` uses the same strict public-JWK shape but is exclusively for verifying JAR
Request Objects. It can be configured for public or confidential authorization-code clients and
does not authenticate the client at token endpoints. `require_signed_request_object: true` requires
one valid request-object key and rejects unsigned direct and pushed authorization requests.

Redirect URIs use exact string comparison at protocol boundaries. HTTPS is required except for HTTP loopback development hosts. Fragments and user-info components are forbidden.
Resource URIs follow the same URL safety rules, are unique, and are matched as exact strings.

## Acceptance Criteria

- Two consecutive applications of the same client configuration result in identical effective state.
- Invalid or duplicate client definitions prevent activation and report the exact configuration location.
- Changing a client redirects list updates that client without changing its identifier or secret.
- A public client succeeds without HTTP Basic credentials; a confidential client fails without the configured Basic credentials.
- A disabled client receives the same `invalid_client` result as an unknown client even when it
  presents its formerly correct authentication material.
- A client with a non-empty `issuer_ids` list authenticates only on those issuers; excluding an
  issuer immediately stops server-side grants, browser origins, and logout callbacks for that
  client-issuer pair.
- A redirect that differs by path, query, port, case, or trailing slash is rejected unless independently registered.

## MVP Storage Model

Clients are read directly from the active immutable configuration snapshot. There is no dynamic
registration API or client database. Setting `enabled: false` or removing a client takes effect
atomically when the new configuration activates. Suspension preserves the complete validated
registration for a later operator-controlled reactivation, but a self-contained access JWT already
accepted by an offline resource server remains bounded by its expiry. The configured reconciliation
deletion policy is retained for future persistent adapters but does not create tombstones in the
MVP memory adapter.
