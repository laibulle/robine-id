# OAUTH-014 — Authorization Server Metadata

## Status

Implemented in the Rust runtime.

## Intent

OAuth clients that do not implement OpenID Connect can discover Robine ID through the standard
RFC 8414 well-known location while receiving exactly the same endpoint and capability policy as
OpenID Provider discovery.

## Normative Requirements

- An issuer `https://host/{issuer_id}` MUST publish metadata at
  `GET https://host/.well-known/oauth-authorization-server/{issuer_id}`.
- The retained postfixed compatibility route
  `GET /{issuer_id}/.well-known/oauth-authorization-server` MAY return the same document.
- `issuer` MUST exactly equal the configured issuer URL. Endpoint URLs MUST be absolute and rooted
  at that issuer; request host headers or proxy headers MUST NOT rewrite them.
- The response MUST expose the actual authorization, token, device authorization, PAR,
  introspection, revocation and JWKS endpoints, plus only currently usable grants, response types,
  response modes, PKCE methods, DPoP algorithms and client-authentication methods.
- The response MUST advertise `request_uri_parameter_supported: false` because arbitrary Request
  URI dereferencing is not implemented. The advertised PAR endpoint and its server-issued
  references remain usable independently of that OpenID Connect metadata member.
- OAuth and OpenID discovery MUST be generated from one canonical metadata model so their shared
  values cannot drift. Registered OpenID and OAuth extension members MAY be included in the RFC
  8414 response.
- Successful responses MUST be public JSON with bounded shared-cache freshness, a revision-bound
  ETag, and conditional `304 Not Modified` support.
- Successful responses MUST allow credential-free cross-origin reads with
  `Access-Control-Allow-Origin: *` and `Cross-Origin-Resource-Policy: cross-origin`. `GET`, bodyless
  `HEAD`, and an `OPTIONS` preflight limited to `GET, HEAD, OPTIONS` and `If-None-Match` MUST use the
  same public route policy.
- A preflight requesting another method or header MUST return a non-cacheable HTTP 403 without an
  access-control grant. Any other unsupported method MUST return a non-cacheable HTTP 405 with
  `Allow: GET, HEAD, OPTIONS`.
- Unknown issuer identifiers MUST return a non-cacheable `404 invalid_request` response without
  listing configured issuers.

## Acceptance Evidence

- Actix tests verify the standard and compatibility paths, required metadata, cache headers, ETag,
  public CORS/preflight behavior and unknown-issuer response.
- Vercel adapter tests verify that the standard route preserves the canonical issuer, token
  endpoint, PKCE policy and ETag.
- `make release-smoke` verifies the standard path, core endpoints and capabilities, caching and
  unknown issuer handling against the real release image.

## Reference

[RFC 8414 — OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html)
