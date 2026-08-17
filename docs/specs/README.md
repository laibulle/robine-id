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
- [APPL-001 — Declarative Application Registration](applications/APPL-001-declarative-application-registration.md)
- [CONF-001 — File-Based Configuration](configuration/CONF-001-file-based-configuration.md)
- [CONF-002 — Atomic and Idempotent Reconciliation](configuration/CONF-002-atomic-idempotent-reconciliation.md)
- [UX-001 — Responsive Authentication Experience](experience/UX-001-responsive-authentication-experience.md)
- [UX-002 — Configurable Branding and Content](experience/UX-002-configurable-branding-and-content.md)
- [IDEN-001 — Local Identities and Claims](identity/IDEN-001-local-identities-and-claims.md)
- [SECU-001 — Authentication Session Security](security/SECU-001-authentication-session-security.md)
- [OPS-001 — Observability and Health](operations/OPS-001-observability-and-health.md)
- [OPS-002 — Production Deployment](operations/OPS-002-production-deployment.md)
- [OPS-003 — Embedded Provider](operations/OPS-003-embedded-provider.md)

## Production scope

The production runtime is a file-configured Rust OpenID Provider for trusted operators. It supports local password identities, Authorization Code Flow with mandatory PKCE S256 for public clients, public and `client_secret_basic`/`client_secret_post` confidential clients, signed ID tokens, opaque bearer access tokens, UserInfo, consent, and RP-initiated logout.

The following are explicitly outside the current scope: dynamic client registration, refresh tokens, implicit and hybrid flows, device authorization, resource-owner password grants, federation, social login, MFA, account recovery, self-service enrollment, an administration UI, token introspection, and token revocation.

Authorization codes, access-token grants, rate-limit counters, authenticated sessions, consent/logout transactions, and encrypted signing keys are persisted in PostgreSQL. Atomic consumption and shared storage allow conventional Actix and Vercel instances to coordinate through the same database.

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
| OIDC-001 | Rust web/protocol tests plus `discover_provider_test.exs`, `discovery_controller_test.exs` |
| OIDC-002 | `validate_authorization_request_test.exs`, `authorization_code_flow_test.exs`, `authorization_controller_test.exs` |
| OIDC-003 | Rust token/PostgreSQL integration tests plus `token_and_key_management_test.exs`, `jwks_controller_test.exs` |
| OIDC-004 | `user_info_controller_test.exs`, `authorization_code_flow_test.exs` |
| OIDC-005 | `logout_controller_test.exs`, `security_test.exs` |
| APPL-001 | `clients_test.exs`, `configuration_test.exs` |
| CONF-001 | `configuration_test.exs` and the `robine_id.config.*` delivery gates |
| CONF-002 | `configuration_test.exs`, `configuration/memory_store_test.exs` |
| UX-001 | `authorization_controller_test.exs`, `logout_controller_test.exs`, `page_controller_test.exs` |
| UX-002 | `experience_test.exs`, localized authorization controller tests |
| IDEN-001 | `identity_test.exs`, authorization controller tests |
| SECU-001 | `security_test.exs`, authorization and logout controller tests |
| OPS-001 | `health_controller_test.exs` plus the real-server smoke gate |
| OPS-002 | `make release-smoke` (two-instance OIDC and restore drill), release build, readiness, and real-client manual gates |
| OPS-003 | retained Phoenix compatibility only: `runtime_test.exs` and embedded-host tests |

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
