# OIDC-001 — OpenID Provider Discovery

## Status

MVP target

## Summary

Robine ID exposes standards-compliant OpenID Connect discovery metadata so clients can configure themselves without hard-coded endpoint details.

## Requirements

- A configured issuer with `enabled: false` MUST be indistinguishable from an unknown issuer at
  both OIDC and RFC 8414 metadata routes and MUST NOT be returned through WebFinger.
- Metadata construction MUST fail closed without panicking if an internally supplied issuer URL no
  longer satisfies the validated configuration invariant.

- The server MUST expose `/.well-known/openid-configuration` for every configured issuer.
- The response MUST contain the issuer, authorization endpoint, token endpoint, user-info endpoint, JWKS URI, supported response types, supported subject types, supported signing algorithms, supported scopes, and supported claims.
- Every advertised capability MUST be enabled and usable in the active configuration.
- The advertised issuer MUST exactly match the issuer used in issued tokens.
- Discovery responses MUST use `application/json`, expose a representation ETag, and permit
  browser and shared-CDN caching for at most five minutes. A matching `If-None-Match`, including a
  weak validator, MUST return HTTP 304 without a body.
- Public discovery responses MUST allow credential-free cross-origin reads with
  `Access-Control-Allow-Origin: *` and `Cross-Origin-Resource-Policy: cross-origin`. `GET` and
  bodyless `HEAD` MUST be supported, and `OPTIONS` MUST advertise only `GET, HEAD, OPTIONS` plus
  the `If-None-Match` request header with a bounded preflight lifetime.
- A preflight requesting another method or header MUST return a non-cacheable HTTP 403 without an
  access-control grant. Any other unsupported method MUST return a non-cacheable HTTP 405 with
  `Allow: GET, HEAD, OPTIONS`.
- Secrets and internal-only configuration MUST never appear in discovery metadata.
- Discovery MUST be available at `GET /:issuer_id/.well-known/openid-configuration`.
- The RFC 8414-shaped compatibility route
  `GET /.well-known/openid-configuration/:issuer_id` MUST return the identical OIDC document and
  preserve the same CORS, cache, ETag, conditional GET, `HEAD`, and `OPTIONS` behavior.
- OAuth Authorization Server Metadata MUST expose the same truthful document at the RFC 8414 path
  `GET /.well-known/oauth-authorization-server/:issuer_id`; the issuer-suffix compatibility path
  MAY also be served.
- `GET /.well-known/webfinger` MUST return an RFC 7033 JRD for URL and `acct:` resources whose
  authority maps unambiguously to a configured issuer. The local account part MUST NOT be checked,
  so the response cannot reveal whether a user exists.
- WebFinger MUST filter unrelated `rel` values, support browser CORS, bound reflected inputs, and
  return the OpenID issuer relationship with the exact configured issuer URL.
- A structurally malformed WebFinger query MUST return a non-cacheable `400` JRD with an empty
  subject and link set, preserve credential-free public CORS, and MUST NOT fall through to a
  localized browser HTML error or reflect the malformed input.
- WebFinger JRD responses MUST expose a weak content ETag and bounded browser/shared-cache policy.
  `GET`, bodyless `HEAD`, matching `If-None-Match`, and the same credential-free public `OPTIONS`
  policy as provider metadata MUST work on conventional Actix and Vercel runtimes.
- Endpoint URLs MUST be derived from the configured issuer URL after removing a trailing slash.
- The provider MUST advertise only `code`, configured `authorization_code`/`refresh_token`/`client_credentials`/token-exchange grants,
  public subjects, the password authentication context, `RS256`, PKCE `S256`, and token endpoint authentication methods `none`,
  `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, and `private_key_jwt`.
- Because JWT client authentication is advertised, token, introspection, and revocation
  metadata MUST also advertise `EdDSA`, `ES256`, `HS256`, and `RS256` through their corresponding
  `*_auth_signing_alg_values_supported` members.
- DPoP metadata MUST advertise the asymmetric proof algorithms EdDSA, ES256, and RS256.
- The provider MUST advertise query and form-post authorization responses and
  `authorization_response_iss_parameter_supported: true`.
- Signed EdDSA, ES256, and RS256 JWT request objects MUST be advertised through
  `request_parameter_supported` and `request_object_signing_alg_values_supported`. The `claims`
  request parameter MUST be advertised and implemented according to OIDC-011.
- JARM MUST advertise `jwt`, `query.jwt`, and `form_post.jwt` response modes plus RS256 through
  `authorization_signing_alg_values_supported`.
  Arbitrary OpenID Connect Request URI dereferencing MUST be advertised as unsupported through
  `request_uri_parameter_supported: false`. PAR support MUST still be advertised through the
  pushed authorization request endpoint and the issuer's effective requirement policy because
  RFC 9126 references remain usable independently of the OIDC Request URI flag. Supported user-interface
  locales MUST reflect resolved issuer branding; the default theme advertises `en` and `fr`.
- The discovery document MUST advertise the end-session endpoint.
- The discovery document MUST advertise session-bound Back-Channel Logout through
  `backchannel_logout_supported: true` and `backchannel_logout_session_supported: true` according
  to OIDC-014.
- The discovery document MUST advertise Front-Channel Logout through
  `frontchannel_logout_supported: true` and `frontchannel_logout_session_supported: true`
  according to OIDC-015.
- HTTPS issuer discovery MUST advertise the OIDC-016 OP iframe through
  `check_session_iframe`. Plain-HTTP issuers MUST omit it because the Session Management standard
  requires an HTTPS iframe URL.
- The discovery document MUST advertise RS256 signed UserInfo support through
  `userinfo_signing_alg_values_supported`.
- The discovery document MUST link `service_documentation` to the routed `/docs` page and SHOULD
  expose configured privacy and terms links as `op_policy_uri` and `op_tos_uri`.
- The discovery document MUST advertise protected introspection and client-bound revocation
  endpoints plus the client-authentication methods each endpoint supports.
- The discovery document MUST advertise RS256 signed introspection responses through
  `introspection_signing_alg_values_supported` according to OAUTH-011.
- The discovery document MUST enumerate the issuer's UserInfo resource through
  `protected_resources` so it cross-references OAUTH-012 metadata.
- Scope metadata MUST use the issuer's configured scopes, falling back to `openid`, `profile`, and `email` when omitted.
- Unknown issuers MUST return HTTP 404 with an `invalid_request` response and MUST NOT enumerate valid issuer identifiers.

## Response Contract

The JSON object contains `issuer`, `authorization_endpoint`, `token_endpoint`,
`introspection_endpoint`, `revocation_endpoint`, `userinfo_endpoint`, `jwks_uri`,
`userinfo_signing_alg_values_supported`,
`end_session_endpoint`, optional `check_session_iframe`, `frontchannel_logout_supported`, `frontchannel_logout_session_supported`, `backchannel_logout_supported`, `backchannel_logout_session_supported`, `response_types_supported`, `response_modes_supported`, `grant_types_supported`,
`subject_types_supported`, `id_token_signing_alg_values_supported`,
`acr_values_supported`,
`code_challenge_methods_supported`, `token_endpoint_auth_methods_supported`,
`token_endpoint_auth_signing_alg_values_supported`,
`introspection_endpoint_auth_methods_supported`,
`introspection_endpoint_auth_signing_alg_values_supported`,
`revocation_endpoint_auth_methods_supported`,
`revocation_endpoint_auth_signing_alg_values_supported`, `service_documentation`, optional
`op_policy_uri`, optional `op_tos_uri`,
`scopes_supported`, `claims_supported`, `ui_locales_supported`,
`claims_parameter_supported`, `request_parameter_supported`,
`request_object_signing_alg_values_supported`,
`authorization_signing_alg_values_supported`,
`request_uri_parameter_supported`, `pushed_authorization_request_endpoint`,
`require_pushed_authorization_requests`, and `authorization_response_iss_parameter_supported`.

Discovery metadata is generated from the active configuration on each request. Applying a new active revision therefore changes subsequent discovery responses without recompiling the application.
`claims_parameter_supported` is `true`; OIDC-011 defines the corresponding bounded request and
essential-claim behavior.
`request_uri_parameter_supported` is `false`; only server-issued RFC 9126 PAR references are
accepted, and arbitrary external Request URIs are never dereferenced.

## Acceptance Criteria

- A conforming client can discover and use a configured issuer without endpoint overrides.
- Disabling an optional capability removes it from discovery metadata after configuration is applied.
- Requests for an unknown issuer return a non-success response without leaking configured issuer names.
- `HEAD` errors on public metadata and unknown routes retain status, media type, cache policy and
  representation length while carrying no body on Actix or Vercel.
- Every URL in discovery corresponds to a routed endpoint and uses the exact configured issuer origin and path.
- WebFinger returns the same issuer link for existing-looking and unknown account local parts on a
  configured authority, and no issuer for an unrelated authority.
- WebFinger returns the same validator through `GET` and `HEAD`; revalidation yields a bodyless 304
  and its preflight permits only `GET`, `HEAD`, `OPTIONS`, and `If-None-Match`.
- The response contains no password hash, secret reference, storage path, signing private key, or user record.
- Unchanged metadata returns HTTP 304 for its ETag, while a configuration change affecting the
  selected representation produces a different ETag and full response.
- Both OIDC Discovery route shapes return byte-equivalent metadata and the same representation
  validator; disabled and unknown issuers remain indistinguishable on either route.
- A browser on an unrelated origin can read public discovery metadata and revalidate it, while the
  response grants neither credentials nor access to any sensitive endpoint.

## Non-Goals

Capability negotiation beyond the fixed implemented feature set is not included.

## Standards

- OpenID Connect Discovery 1.0.
- RFC 7033, WebFinger.
- RFC 8414, OAuth 2.0 Authorization Server Metadata.
- RFC 9207, OAuth 2.0 Authorization Server Issuer Identification.
- RFC 9126, OAuth 2.0 Pushed Authorization Requests.
