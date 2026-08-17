# Robine ID Specifications

Robine ID is a configurable, idempotent OpenID Connect provider whose production runtime is built with Rust, Actix Web, Askama, and PostgreSQL. The retained Elixir/Phoenix implementation is a compatibility oracle and regression suite. These specifications define externally observable behavior and product requirements independently of implementation details.

## Conventions

- Specifications live at `docs/specs/<domain>/<feature-id>-<feature-name>.md`.
- Feature identifiers are stable and use an uppercase domain prefix.
- `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` are normative terms.
- A feature is complete only when all acceptance criteria are covered by automated tests or an explicitly documented manual accessibility or interoperability check.
- `MVP target` means the document is normative for the MVP; it does not by itself assert that every requirement is already implemented.

## Specification Catalog

- [OIDC-001 — OpenID Provider Discovery](protocol/OIDC-001-provider-discovery.md)
- [OIDC-002 — Authorization Code Flow](protocol/OIDC-002-authorization-code-flow.md)
- [OIDC-003 — Token and Key Management](protocol/OIDC-003-token-and-key-management.md)
- [OIDC-004 — UserInfo](protocol/OIDC-004-userinfo.md)
- [OIDC-005 — RP-Initiated Logout](protocol/OIDC-005-rp-initiated-logout.md)
- [OIDC-006 — Offline Access and Refresh Tokens](protocol/OIDC-006-offline-access.md)
- [OIDC-007 — Pushed Authorization Requests](protocol/OIDC-007-pushed-authorization-requests.md)
- [OIDC-008 — Form Post Response Mode](protocol/OIDC-008-form-post-response-mode.md)
- [OIDC-009 — Signed Authorization Request Objects](protocol/OIDC-009-signed-authorization-request-objects.md)
- [OIDC-010 — JWT-Secured Authorization Response Mode](protocol/OIDC-010-jarm.md)
- [OIDC-011 — Claims Parameter](protocol/OIDC-011-claims-parameter.md)
- [OIDC-012 — ID Token Hint](protocol/OIDC-012-id-token-hint.md)
- [OIDC-013 — Signed UserInfo Responses](protocol/OIDC-013-signed-userinfo.md)
- [OIDC-014 — Back-Channel Logout](protocol/OIDC-014-backchannel-logout.md)
- [OIDC-015 — Front-Channel Logout](protocol/OIDC-015-frontchannel-logout.md)
- [OIDC-016 — Session Management](protocol/OIDC-016-session-management.md)
- [OIDC-017 — Pairwise Subject Identifiers](protocol/OIDC-017-pairwise-subject-identifiers.md)
- [OAUTH-001 — Token Introspection and Revocation](protocol/OAUTH-001-token-status.md)
- [OAUTH-002 — Client Credentials Grant](protocol/OAUTH-002-client-credentials.md)
- [OAUTH-003 — Resource Indicators](protocol/OAUTH-003-resource-indicators.md)
- [OAUTH-004 — JWT Bearer Client Authentication](protocol/OAUTH-004-private-key-jwt.md)
- [OAUTH-005 — Demonstrating Proof of Possession](protocol/OAUTH-005-dpop.md)
- [OAUTH-006 — OAuth 2.0 Token Exchange](protocol/OAUTH-006-token-exchange.md)
- [OAUTH-007 — JWT Access Token Profile](protocol/OAUTH-007-jwt-access-tokens.md)
- [OAUTH-008 — Device Authorization Grant](protocol/OAUTH-008-device-authorization.md)
- [OAUTH-009 — Rich Authorization Requests](protocol/OAUTH-009-rich-authorization-requests.md)
- [OAUTH-010 — Client Secret JWT Authentication](protocol/OAUTH-010-client-secret-jwt.md)
- [OAUTH-011 — Signed Token Introspection Responses](protocol/OAUTH-011-signed-introspection.md)
- [OAUTH-012 — Protected Resource Metadata](protocol/OAUTH-012-protected-resource-metadata.md)
- [OAUTH-013 — Step-Up Authentication Challenge](protocol/OAUTH-013-step-up-authentication.md)
- [OAUTH-014 — Authorization Server Metadata](protocol/OAUTH-014-authorization-server-metadata.md)
- [APPL-001 — Declarative Application Registration](applications/APPL-001-declarative-application-registration.md)
- [CONF-001 — File-Based Configuration](configuration/CONF-001-file-based-configuration.md)
- [CONF-002 — Atomic and Idempotent Reconciliation](configuration/CONF-002-atomic-idempotent-reconciliation.md)
- [UX-001 — Responsive Authentication Experience](experience/UX-001-responsive-authentication-experience.md)
- [UX-002 — Configurable Branding and Content](experience/UX-002-configurable-branding-and-content.md)
- [IDEN-001 — Local Identities and Claims](identity/IDEN-001-local-identities-and-claims.md)
- [SECU-001 — Authentication Session Security](security/SECU-001-authentication-session-security.md)
- [SECU-002 — TOTP Multi-Factor Authentication](security/SECU-002-totp-multi-factor-authentication.md)
- [OPS-001 — Observability and Health](operations/OPS-001-observability-and-health.md)
- [OPS-002 — Production Deployment](operations/OPS-002-production-deployment.md)
- [OPS-003 — Embedded Provider](operations/OPS-003-embedded-provider.md)

## Production scope

The production runtime is a file-configured Rust OpenID Provider for trusted operators. It supports
local password identities, Authorization Code Flow with mandatory PKCE S256 for public clients,
public and `client_secret_basic`/`client_secret_post`/`client_secret_jwt`/`private_key_jwt` confidential clients, signed ID tokens,
bearer or DPoP sender-constrained opaque or RFC 9068 JWT access tokens, rotating refresh tokens for consented offline access, UserInfo, consent, and
RP-initiated and session-bound back-channel logout. Clients may push validated authorization requests into PostgreSQL before the
browser redirect and use a short-lived single-use PAR reference. Confidential backend services can
also obtain short-lived issuer-formatted tokens through the Client Credentials Grant without creating an end-user session.
An explicitly enabled confidential client can exchange its own active access token for a
downscoped, shorter-lived token aimed at another registered resource.
Browser clients may receive authorization results through query redirects, hardened auto-submitted
forms, or audience-bound RS256 JARM responses over either transport.
CLI, television, and input-constrained clients may use the Device Authorization Grant with a
rate-limited Askama verification journey and PostgreSQL-coordinated polling across instances.

The following are explicitly outside the current scope: dynamic client registration, implicit and
hybrid flows, resource-owner password grants,
federation, social login, self-service MFA enrollment or recovery, account recovery, and an administration UI.

Authorization codes, access/refresh-token grants, rate-limit counters, authenticated sessions,
consent/logout transactions, and encrypted signing keys are persisted in PostgreSQL. Atomic
consumption and shared storage allow conventional Actix and Vercel instances to coordinate through
the same database.

## Domains

- `protocol`: OpenID Connect endpoints, flows, tokens, and keys.
- `applications`: relying-application lifecycle and OpenID Connect client policy.
- `configuration`: declarative files, validation, and reconciliation.
- `experience`: user-facing authentication UX, accessibility, and branding.
- `identity`: configured users, password authentication, and claim mapping.
- `security`: browser, session, and authentication safeguards.
- `operations`: health, telemetry, diagnostics, and auditability.

## Product Principles

1. Standards compliance is externally verifiable.
2. The complete desired state is expressible as configuration files and secret references.
3. Applying the same desired state repeatedly has no additional side effects.
4. Configuration changes are validated before activation and applied atomically.
5. Secure, accessible, polished defaults work without custom front-end development.

## Acceptance Verification

| Specification | Evidence |
| --- | --- |
| OIDC-001 | Rust discovery/protocol, disabled-issuer routing/WebFinger tests, and `make release-smoke` |
| OIDC-002 | Rust protocol/web tests, PostgreSQL atomic-consumption test, and the two-instance smoke journey |
| OIDC-003 | Rust token/PostgreSQL tests plus rotation and restore checks in `make release-smoke` |
| OIDC-004 | Rust bearer/DPoP JSON and signed-JWT UserInfo tests plus cross-instance UserInfo in `make release-smoke` |
| OIDC-005 | Rust hint/client validation, GET/POST and Vercel transport tests, plus cross-instance client-only and hinted logout in `make release-smoke` |
| OIDC-006 | Rust protocol/PostgreSQL tests plus cross-instance rotation, restore, and replay detection in `make release-smoke` |
| OIDC-007 | Rust protocol/PostgreSQL tests plus cross-instance PAR creation, consumption, and replay rejection in `make release-smoke` |
| OIDC-008 | Rust protocol/Askama/PostgreSQL/Vercel tests plus cross-instance consent, form delivery, and code exchange in `make release-smoke` |
| OIDC-009 | Rust RS256/ES256/EdDSA JWT, merge, PostgreSQL, and Vercel tests plus direct, conflicting, replayed, PAR, and cross-instance checks in `make release-smoke` |
| OIDC-010 | Rust signing/discovery tests plus signed query success, signed form error, cross-instance code exchange, and JWKS checks in `make release-smoke` |
| OIDC-011 | Rust parser, policy, GET/POST/PAR/JAR propagation tests plus essential MFA enforcement in `make release-smoke` |
| OIDC-012 | Rust signature/audience/lifetime tests, GET/POST/PAR/JAR propagation, PostgreSQL session integration, and silent SSO in `make release-smoke` |
| OIDC-013 | Rust signing/configuration/discovery tests, PostgreSQL signature verification, and cross-instance JWT UserInfo in `make release-smoke` |
| OIDC-014 | Rust signing, discovery, transport and configuration tests, PostgreSQL session-to-RP persistence, plus a decoded real callback in `make release-smoke` |
| OIDC-015 | Rust configuration, URL, CSP and Askama tests plus a real iframe interstitial and RP GET in `make release-smoke` |
| OIDC-016 | Rust hash/cookie/origin/CSP tests, PostgreSQL query/form/JARM coverage, Vercel transport, and the real iframe/session calculation in `make release-smoke` |
| OIDC-017 | Rust derivation/configuration/discovery tests plus cross-instance ID token, UserInfo, and introspection consistency in `make release-smoke` |
| OAUTH-001 | Rust configuration/PostgreSQL tests plus cross-instance introspection and revocation in `make release-smoke` |
| OAUTH-002 | Rust configuration/PostgreSQL/Vercel tests plus cross-instance issuance, introspection, UserInfo rejection, and revocation in `make release-smoke` |
| OAUTH-003 | Rust protocol/configuration/PostgreSQL tests plus cross-instance audience issuance, introspection, target rejection, and code exchange in `make release-smoke` |
| OAUTH-004 | Rust RS256/ES256/EdDSA JWT, strict JWK, configuration, Vercel, and PostgreSQL tests plus cross-instance PAR, token, introspection, revocation, wrong-audience, cross-algorithm rotation, and replay checks in `make release-smoke` |
| OAUTH-005 | Rust EdDSA/ES256/RS256 proof, strict JWK, discovery, PostgreSQL, and Vercel tests plus bound code, token, UserInfo, refresh, introspection, and cross-instance replay checks in `make release-smoke` |
| OAUTH-006 | Rust configuration/policy/JWT/PostgreSQL tests plus cross-instance downscoping, actor-chain, target, introspection, and rejection checks in `make release-smoke` |
| OAUTH-007 | Rust signing/discovery tests, PostgreSQL offline-verification test, and opaque/JWT cross-instance checks in `make release-smoke` |
| OAUTH-008 | Rust configuration/discovery/Askama tests, PostgreSQL state-machine test, and cross-instance approval, denial, polling, refresh, UserInfo, and introspection in `make release-smoke` |
| OAUTH-009 | Rust parser/subset/JWT/Askama tests, PostgreSQL persistence and atomic refresh downscoping tests, plus `make release-smoke` |
| OAUTH-010 | Rust HS256/configuration/Vercel tests plus device authorization, cross-instance PAR, token, introspection, revocation, audience, and replay checks in `make release-smoke` |
| OAUTH-011 | Rust signing, media negotiation, audience-policy, discovery, Vercel, and PostgreSQL verification tests plus cross-instance signed introspection in `make release-smoke` |
| OAUTH-012 | Rust exact-resource, scope-filtering, cache/CORS/challenge, Discovery, and Vercel tests plus real-server metadata checks in `make release-smoke` |
| OAUTH-013 | Rust authentication-policy and exact Bearer challenge tests plus a cross-instance DPoP recentness challenge in `make release-smoke` |
| OAUTH-014 | Rust Actix/Vercel metadata, cache and unknown-issuer tests plus standard-path verification in `make release-smoke` |
| APPL-001 | Rust strict configuration, suspension, per-issuer isolation, Discovery/CORS/grant/logout, client-authentication, Vercel tests, and disabled/cross-issuer client rejection in `make release-smoke` |
| CONF-001 | Rust configuration tests and `make config-*` delivery gates |
| CONF-002 | Rust semantic fingerprint, preview, polling/SIGHUP reload, deduplication, and atomic snapshot tests |
| UX-001 | Rust Askama/web tests and the manual browser/accessibility release checklist |
| UX-002 | Rust branding, escaping, locale-fallback, and rendered-login tests |
| IDEN-001 | Rust configuration, credential-generation, suspension, per-issuer isolation, bcrypt authentication, claim mapping, and UserInfo tests plus disabled/cross-issuer login rejection in `make release-smoke` |
| SECU-001 | Rust web/PostgreSQL tests, zeroizing deployment and submitted-credential lifecycles, and multi-instance session/replay checks in `make release-smoke` |
| SECU-002 | RFC 6238 vectors, canonical secret/recovery generators, Rust configuration/Askama/token tests, PostgreSQL challenge/counter tests, and Authorization Code plus Device Flow journeys in `make release-smoke` |
| OPS-001 | Rust health/metrics tests, JSON operational events, and the real-server smoke gate |
| OPS-002 | `make release-smoke` (two-instance OIDC and restore drill), canonical encryption-secret generator, zeroizing database credential initialization, release build, readiness, and real-client manual gates |
| OPS-003 | retained Phoenix compatibility only: clean SQLite migration, authentication-context trigger, `runtime_test.exs`, and embedded-host tests |

Before a release, perform these documented manual checks against the built production assets:

1. Complete login, consent, denial, protocol error, and logout using keyboard navigation only; focus order and focus indicators must remain visible.
2. Complete the same journey with VoiceOver, NVDA, or Orca; headings, field labels, error alert, consent list, and button names must be announced meaningfully.
3. At 320 CSS pixels and at 200% browser zoom, verify that every action remains visible and that no horizontal page scrolling is required.
4. Enable reduced motion and forced colors; verify that no information depends on animation or custom colors alone.
5. Run an OpenID Connect conformance client against discovery, Authorization Code + PKCE, token validation, UserInfo, and RP-initiated logout.

## Release Gate

A release candidate is acceptable only when `make preflight`, `make rust-integration`, and
`make release-smoke` succeed; the optimized Vercel binary compiles; the manual checks above are
recorded; a real relying party completes the end-to-end flow; production secrets differ from
development values; and the deployment's own PostgreSQL backup policy is restore-tested with the
matching key-encryption secret.
