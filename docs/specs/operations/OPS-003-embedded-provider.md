# OPS-003 — Embedded Provider

## Status

Legacy Phoenix compatibility; not part of the Rust production image

## Summary

Robine ID can run either as its standalone Phoenix release or as an embedded OTP
library inside another Phoenix product without changing its OpenID Connect behavior.

## Requirements

- Standalone mode MUST remain the default and MUST start the endpoint, repository,
  migrations, PubSub, telemetry, and provider runtime.
- Embedded mode MUST start only provider runtime services and MUST NOT start the
  Robine ID endpoint or repository.
- An embedded host MUST own all HTML routes, templates, forms, navigation, and assets.
- Robine ID MUST expose headless authorization operations that return domain data and
  redirect locations without rendering or depending on a host UI.
- The host MAY reuse JSON protocol controllers for discovery, JWKS, token exchange,
  and UserInfo, but MUST declare their routes explicitly.
- The provider MUST depend on host identity and persistence concerns only through
  configured adapter modules; it MUST NOT compile against the host application.
- The host SHOULD use Authorization Code Flow with PKCE through the embedded backend,
  rather than bypassing the protocol with an internal login shortcut.
- A released host MUST pin an immutable Robine ID version. A relative path dependency
  MAY be used for local development only.
- Standalone and embedded modes MUST use the same declarative provider and client
  configuration formats.

## Acceptance Criteria

- The standalone test suite and production release build still pass.
- An embedded host boots without `RobineIdWeb.Endpoint` or `RobineId.Repo` running.
- Discovery, JWKS, host-rendered authorization, code exchange, ID-token validation,
  and host-session creation complete through the configured prefix.
- The host can authenticate an existing account through repository and password
  adapters without duplicating identity records.
- Moving the relying party to a separately hosted Robine ID instance requires only
  issuer, redirect, client, and deployment configuration changes.

## Non-Goals

Embedding does not merge the provider session with the host product session, replace
OIDC with direct function calls, or make node-local runtime stores horizontally
scalable.
