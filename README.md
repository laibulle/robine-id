# Robine ID

[![build](https://ci.base59.dev/badges/github/laibulle/robine-id/build.svg)](https://ci.base59.dev/repositories)
[![coverage](https://ci.base59.dev/badges/github/laibulle/robine-id/coverage.svg)](https://ci.base59.dev/repositories)
[![release](https://img.shields.io/github/v/release/laibulle/robine-id?display_name=tag&sort=semver)](https://github.com/laibulle/robine-id/releases)

Robine ID is a file-configured OpenID Connect provider. Its production runtime uses Rust, Actix Web,
Askama, and PostgreSQL. It implements the Authorization
Code Flow with PKCE, signed ID tokens, JWKS, GET/POST UserInfo with registered-origin CORS,
OAuth token introspection and revocation, consent, reusable SSO sessions with OpenID
`prompt`/`max_age`, bounded `login_hint`, OIDC `claims` requests with essential-value enforcement,
password `acr`/`amr`, rotating refresh tokens for consented
`offline_access`, single-use Pushed Authorization Requests (PAR), signed RS256 Authorization
Request Objects (JAR), confidential-service
`client_credentials`, query or hardened `form_post` authorization responses, signed JARM responses,
RFC 9449 DPoP sender-constrained access and public refresh tokens,
operator-provisioned per-user RFC 6238 TOTP MFA, and RP-initiated logout.
Authorization responses identify their issuer according to RFC 9207 so multi-provider clients can
reject authorization-server mix-up.

The former Phoenix implementation remains in the repository as a parity oracle and regression suite;
it is no longer packaged by the canonical `Dockerfile` or release Compose stack. The same Actix
application runs as a conventional server and through the Vercel Function entrypoint.

## Getting started with Docker

You only need Docker. Clone the repository, then prepare the runtime environment:

```sh
cp .env.release.example .env.release
openssl rand -base64 48
openssl rand -base64 48
```

Put independent generated values in `POSTGRES_PASSWORD` and `KEY_ENCRYPTION_SECRET` inside
`.env.release`. Keep both in the deployment secret store.

The application container runs without root privileges. Make the read-only configuration mounts
accessible, then start the Rust application and PostgreSQL:

```sh
chmod 755 deploy deploy/config deploy/config/applications
chmod 644 deploy/config/robine_id.json
docker compose --env-file .env.release -f compose.release.yml up --detach --build --wait
```

Check readiness and open the built-in documentation:

```sh
curl --fail http://127.0.0.1:4001/health/ready
```

- Home: <http://127.0.0.1:4001>
- Documentation: <http://127.0.0.1:4001/docs>
- Provider discovery: <http://127.0.0.1:4001/default/.well-known/openid-configuration>

Production identities belong in `deploy/config/robine_id.json`, and relying applications belong in
`deploy/config/applications/`, one JSON file per application. Both are intentionally empty by
default; the identities and applications under `config/` are development material and are not
mounted into the release container. Add production identities, applications, and the intended
issuer URL before exposing the service publicly.
The same empty production template is embedded in the canonical image, so running the image without
configuration mounts never falls back to the checked-in development account.

Stop the stack without deleting the persistent PostgreSQL volume:

```sh
docker compose --env-file .env.release -f compose.release.yml down
```

## Local setup

Rust runtime requirements:

- Rust 1.88 or newer
- Docker with Compose for PostgreSQL

Run:

```sh
make dev
```

Run the complete quality gate and generate the coverage reports locally with:

```sh
make rust-preflight
make rust-integration
make release-smoke
```

`make release-smoke` uses an isolated production Compose project. It completes GET and POST
Authorization Code requests with PKCE plus cross-instance PAR, Form Post, and Client Credentials across two Actix instances, exercises SSO, silent consent
errors, UserInfo GET/POST and registered-origin CORS, rejects a replayed code, rotates a refresh
token across instances, performs RP-initiated logout, introspects and revokes a client-bound access
token, then dumps, recreates, and restores PostgreSQL before checking refresh-token replay
detection, the restored access grant, and both current and retained signing keys. It removes only
its own temporary containers, network, volume, and files.

The legacy Phoenix regression suite remains available through `mix precommit`; its coverage reports
are written to `cover/` and retained by Robine CI.

Then open <http://localhost:4001>.

## Rust runtime

The production runtime uses Actix Web for both the conventional HTTP server and the Vercel Function
entrypoint, with Askama for server-rendered HTML.

Run the Rust server against the existing JSON configuration:

```sh
make dev
```

It listens on `127.0.0.1:4001` by default. `HOST`, `PORT` (1 through 65535), `ROBINE_ID_CONFIG`, and
`ROBINE_ID_APPLICATIONS_DIR` can override those defaults. `DATABASE_URL` selects a PostgreSQL
database and `KEY_ENCRYPTION_SECRET` encrypts persisted RSA private keys with AES-256-GCM. The
server applies embedded SQL migrations at startup. `make dev` starts the PostgreSQL 17 development
container automatically; `make dev-down` stops it without deleting its named data volume.
Set `TRUST_PROXY_HEADERS=true` (or `1`) only behind a trusted reverse proxy; `false`/`0` disables it,
and Vercel enables forwarded-header handling automatically.
Operational events are emitted as JSON with bounded fields; `RUST_LOG` overrides the validated
`telemetry.log_level` when platform-specific filtering is required.
`DATABASE_MAX_CONNECTIONS` defaults to five on the server and two per Vercel instance.
`DATABASE_ACQUIRE_TIMEOUT_MS` bounds pool waits (five seconds conventionally, two seconds on
Vercel) and accepts values from 100 through 30000 milliseconds.
`DATABASE_STATEMENT_TIMEOUT_MS` independently bounds every PostgreSQL statement with the same
defaults and accepted range, preventing an acquired connection from waiting indefinitely.
Database settings are strict: malformed URLs, partial `PG*` credentials, missing or weak encryption
secrets, and numeric values outside their documented ranges stop application initialization with a
non-secret diagnostic instead of silently selecting a fallback.
Long-running servers remove expired protocol state hourly; `DATABASE_CLEANUP_INTERVAL` overrides the
interval in seconds (`0` disables the task; otherwise it must be 60 through 86400).
Conventional-server settings are strict too: an empty host, invalid port, malformed proxy boolean,
or interval outside its documented range stops startup without echoing the submitted value.
Use `make dev-container` to build and run both the Rust application and PostgreSQL in Docker. The
Rust image is built from the canonical `Dockerfile`, runs as an unprivileged user, and includes a readiness
health check implemented by the bounded `robine-id-healthcheck` Rust binary; the runtime image does
not install `curl` solely for container health polling.

The Rust runtime implements the home, sign-in, consent, logout, and error pages; health and OIDC
discovery endpoints and `/docs`; strict declarative application loading; bcrypt authentication with database-backed
independent network/account rate limiting, optional per-user TOTP, and persistent session policy; single-use authorization
codes and pushed authorization references; PKCE exchange;
RFC 8628 device authorization; RS256 ID tokens; retained-key JWKS; per-issuer opaque or RFC 9068 JWT user, service, device, and exchanged access tokens; UserInfo; and protected token
introspection/revocation. Browser transactions, sessions, access/refresh tokens, rate limits, and
encrypted signing keys are shared through PostgreSQL so the same
application can run as a conventional Actix server or across Vercel Function invocations.
Validated authorization parameters never round-trip through hidden login fields. The browser gets
only an issuer-bound, short-lived, single-use transaction whose hash and request remain in
PostgreSQL; an invalid password consumes and replaces it.
Discovery and JWKS use content ETags and bounded browser/CDN caching to avoid repeatedly
transferring unchanged public metadata, including on Vercel.
Warm Vercel processes retain one Actix worker and route service behind a 128-request queue and a
32-request concurrency limit, avoiding per-invocation Actix system/router construction and
returning a secure retryable 503 instead of growing work without bound.
Registered public-client redirect origins can call the token and PAR endpoints from a browser
through a strict POST-only CORS policy; confidential and unrelated origins are never granted CORS.
Set `token_policy.require_pushed_authorization_requests` on an issuer to require PAR globally, or
set `require_pushed_authorization_requests` on one `authorization_code` application to enforce it
only there. Discovery publishes the global policy. `browser_authorization_lifetime` defaults to 600
seconds and accepts 60 through 3600.
Conventional servers reload file-backed configuration atomically every second by default. Invalid
or partially written candidates are rejected while the last valid revision remains active;
`ROBINE_ID_RELOAD_INTERVAL=0` disables watching; non-zero intervals must be 100 through 60000
milliseconds. Inline/Vercel configuration is immutable.

Rotate an issuer signing key with a stable deployment identifier:

```sh
make keys-rotate ISSUER=default ROTATION_ID=deployment-2026-08
```

Repeating the same identifier is a no-op. Previously active keys remain published for the greater
captured ID-token/JWT-access-token lifetime plus clock skew and a five-minute safety margin. Startup and hourly maintenance
remove only retained keys whose deadline elapsed; the active key is never targeted. Run the same
idempotent cleanup explicitly with:

```sh
make keys-prune
```

Set `token_policy.signing_key_rotation_interval` on an issuer to rotate automatically every 3,600
through 31,536,000 seconds. Conventional Actix servers check every five minutes; Vercel checks at
cold start and opportunistically before signing, so concurrent instances still converge on one
PostgreSQL-serialized rotation. Manual rotation remains available for deployment-driven rollover.

Run the Rust quality gate with:

```sh
make rust-preflight
make rust-integration
```

Inspect configuration changes and the redacted effective configuration with:

```sh
make config-preview
make config-preview CONFIG=path/to/robine_id.json
make config-apply CONFIG=path/to/robine_id.json
make config-effective
```

The `api/index.rs` binary and `vercel.json` expose the same Actix routes as one Vercel Function.
Configuration files are immutable for a Vercel deployment. PostgreSQL is required and
`KEY_ENCRYPTION_SECRET` (or `SECRET_KEY_BASE`) must be supplied as deployment secret material.
For a filesystem-independent deployment, set `ROBINE_ID_CONFIG_JSON` to the complete root JSON
document and `ROBINE_ID_APPLICATIONS_JSON` to a JSON array of complete application documents.
The Vercel entrypoint refuses to start from the checked-in development defaults: either
`ROBINE_ID_CONFIG_JSON` or an explicit `ROBINE_ID_CONFIG` path is required. The file-based variables
remain supported for conventional servers and containers.
The release smoke gate exercises the canonical image and shared PostgreSQL topology; an external
deployment still needs proxy, platform, and real relying-party validation.
See the [Vercel deployment runbook](docs/operations/vercel.md) for the immutable configuration,
connection-pool, verification, and recovery checklist.

Signing-key encryption secrets can be rotated without losing the persisted RSA keys. Deploy the
new `KEY_ENCRYPTION_SECRET` together with the former value as `KEY_ENCRYPTION_SECRET_PREVIOUS`, run
`reencrypt_keys` (or `make keys-reencrypt NEW_KEY_ENCRYPTION_SECRET=...` locally), verify JWKS and
token issuance, then remove the previous secret. Both secrets are strictly validated, must differ,
and diagnostics never echo either value.

The checked-in development configuration contains one public client and one development identity:

- client ID: `development-client`
- fast-path client ID: `rust-development-client` (consent disabled for development testing)
- redirect URI: `http://localhost:4002/callback`
- user: `admin@example.com`
- password: `change-me`

These credentials are development-only and must be replaced in production.
All configured user password hashes in one revision must use the same bcrypt cost (10 through 16),
which also determines the dummy verification work performed for unknown identifiers.

### Optional TOTP MFA

Enable `totp` beside `password`, then attach an environment secret reference only to users who need
the second factor. The environment value is an unpadded Base32 secret containing 160 through 512
bits; it is resolved only while verifying a code and is redacted from effective configuration.

```json
{
  "authentication": {"methods": ["password", "totp"]},
  "users": [{
    "id": "alice",
    "identifier": "alice@example.com",
    "password_hash": "$2b$12$...",
    "totp_secret_reference": {
      "provider": "env",
      "key": "ALICE_TOTP_SECRET"
    }
  }]
}
```

Generate and enroll an independent secret per user through a trusted operator workflow, for example
`openssl rand 20 | base32 | tr -d '='`, then inject it into the server, container, or Vercel secret
environment. TOTP uses six digits and 30-second steps. PostgreSQL prevents reuse of an accepted
step across instances. ID tokens, user JWT access tokens, and active introspection responses report
`amr=["pwd","otp"]` with `acr=urn:robine-id:acr:password+totp`; refresh and token exchange preserve
that context. Self-service enrollment and recovery codes are not yet provided.

An Authorization Code or Device application can require MFA for every account by setting
`"required_acr": "urn:robine-id:acr:password+totp"`. This rejects password-only SSO sessions and
users without an enrolled operator-managed factor. Relying parties may also send the standard
space-delimited `acr_values` authorization parameter as a voluntary preference through direct
GET/POST requests, PAR, or signed Request Objects. Start from
[`config/templates/mfa-client-application.json`](config/templates/mfa-client-application.json).

## Configuration

The default root file is [`config/robine_id.json`](config/robine_id.json). Each relying application has its own document in [`config/applications`](config/applications). Set `ROBINE_ID_CONFIG` to select another root document and `ROBINE_ID_APPLICATIONS_DIR` to override its adjacent `applications/` directory.

Every document declares `schema_version: 1`. The root supports these sections:

- `issuers`: issuer URLs, supported scopes, token policy, claim mappings, and issuer branding;
- `applications/*.json`: exact redirect URIs, post-logout redirect URIs, scopes, grants,
  authentication, consent, optional introspection authorization, and application branding;
- `users`: local identities with bcrypt password hashes, optional TOTP secret references, and source claims;
- `claims`: mapping from OIDC claim names to identity sources and required scopes;
- `branding`: product name, assets, accessible theme tokens, locales, message overrides, and legal/support links;
- `reconciliation`: explicit removal policy;
- `authentication`: session and rate-limit policy;
- `storage`: legacy Phoenix storage compatibility metadata (Rust persistence is configured through PostgreSQL environment variables);
- `telemetry`: validated operational log level.

Configuration precedence is deterministic:

```text
built-in safe defaults < global branding < issuer branding < client branding
```

Application secrets may use a typed environment reference:

```json
{
  "type": "confidential",
  "authentication_method": "client_secret_basic",
  "secret_reference": {"provider": "env", "key": "MY_CLIENT_SECRET"}
}
```

Literal client secrets are rejected. This keeps versioned configuration safe to inspect and makes
the deployment secret store the only supported source of confidential-client credentials.
Effective configuration output redacts the environment reference.

HTTP issuer and redirect URLs are accepted only for loopback development hosts. Other URLs must use HTTPS. Unknown fields and incompatible values fail validation before activation.

Every application document declares `schema_version: 1` and `kind: "oidc_application"`. The application watches the complete composed configuration and reloads it every second by default; `ROBINE_ID_RELOAD_INTERVAL` overrides that interval in milliseconds (`0` or 100 through 60000). A valid change activates atomically; an unchanged revision is ignored; an invalid or partially written file is recorded as a failed attempt while the last valid revision remains active.

### Configuration commands

```sh
# Rust runtime
make config-validate
make config-preview CONFIG=path/to/robine_id.json
make config-apply CONFIG=path/to/robine_id.json
make config-effective
make keys-rotate ISSUER=default ROTATION_ID=deployment-2026-08

# Phoenix runtime
mix robine_id.config.validate path/to/robine_id.json
mix robine_id.config.preview path/to/robine_id.json
mix robine_id.config.apply path/to/robine_id.json
mix robine_id.config.effective
mix robine_id.keys.rotate default deployment-2026-08
```

`preview` does not mutate state. File-backed Rust servers activate valid changes automatically;
Phoenix `apply` validates the complete revision before atomically activating it. Applying an
equivalent semantic revision is a no-op. Both effective commands redact passwords, hashes, secret
references, tokens, and private material.

## OpenID Connect endpoints

For the configured issuer `https://id.base59.dev/default`:

| Capability | Endpoint |
| --- | --- |
| Discovery | `GET /default/.well-known/openid-configuration` |
| OAuth metadata | `GET /.well-known/oauth-authorization-server/default` |
| WebFinger issuer discovery | `GET /.well-known/webfinger` |
| Authorization | `GET /default/authorize` |
| Pushed authorization request | `POST /default/par` |
| Device authorization | `POST /default/device_authorization` |
| Device verification | `GET`, `POST /default/device` |
| Token | `POST /default/token` |
| Token introspection | `POST /default/introspect` |
| Token revocation | `POST /default/revoke` |
| UserInfo | `GET /default/userinfo` |
| JWKS | `GET /default/jwks.json` |
| Logout | `GET`, `POST /default/logout` |

Authorization requests require `response_type=code`, `openid` scope, `state`, and `nonce`. PKCE using `S256` is mandatory by default and always required for public clients; a confidential integration that cannot send PKCE may opt out explicitly. Redirect URIs match registered values exactly. Authorization codes are short-lived, stored only by hash, bound to issuer/client/redirect/subject/nonce and the PKCE challenge when present, and consumed atomically once.

Clients may first POST the same authorization parameters to the discovered PAR endpoint. A valid
request returns a hashed-at-rest, single-use `request_uri`; send only that reference and its
`client_id` to `/authorize` using GET or form POST. The reference is issuer/client-bound, shared
through PostgreSQL, and expires after `token_policy.pushed_authorization_request_lifetime` seconds
(90 by default, configurable from 10 through 600). Independent PostgreSQL counters limit creation
by canonical source address and issuer/client pair; the defaults are 120 requests per 60 seconds.
Direct authorization remains supported unless the issuer or client enables
`require_pushed_authorization_requests`; covered direct requests then receive `invalid_request` as
required by RFC 9126. Once validated, every login continuation keeps the complete request in
PostgreSQL and renders only a separate opaque transaction token.

Confidential clients with configured `jwks` may protect the complete authorization request in an
RS256 `request` JWT. The outer request still carries the exact `client_id`; any repeated outer
parameter must match its signed value. Objects are issuer-audience-bound, expire within five
minutes, and use a single-use `jti` enforced through PostgreSQL across Actix and Vercel instances.
Signed objects work with direct GET/POST authorization and authenticated PAR. Encrypted objects,
remote `request_uri` dereferencing, and algorithms other than RS256 are intentionally unsupported.

Authorization responses use query redirects by default. Set `response_mode=form_post` to receive
success or redirectable error parameters in an Askama-rendered, auto-submitted HTML form. The page
has a visible no-JavaScript fallback, disables caching, escapes every hidden value, and narrows its
CSP `form-action` to the registered redirect origin. The selected mode survives PAR, SSO, consent,
and routing between instances.

Set `response_mode=jwt` or `query.jwt` to receive the complete success or error response as a
short-lived RS256 JARM JWT in the `response` query parameter. `form_post.jwt` delivers that single
signed parameter through the same hardened form page. JARM responses are audience-bound to the
client, use the issuer's published signing key, contain `iss`, `aud`, `iat`, and `exp`, and never
downgrade to unsigned parameters when signing is unavailable.

A client configured with the `refresh_token` grant can request the `offline_access` scope. Robine ID
always shows consent before granting offline access, stores refresh tokens only by hash, and returns
a replacement on every refresh. Replaying a consumed token revokes its complete token family. A
refresh request may retain the original scopes or atomically narrow them, but cannot add scopes.

A public CLI, television, or other input-constrained client may enable
`urn:ietf:params:oauth:grant-type:device_code`. It POSTs its client identifier and scopes to the
discovered `device_authorization_endpoint`, displays the returned `user_code` and
`verification_uri`, then polls `/token` no faster than the returned interval. The browser journey
is rendered by Askama, reuses an active session, shows the requesting client and scopes, and
requires explicit approval. Device and user codes are stored only by digest in PostgreSQL, so the
journey can cross Actix or Vercel instances. Pending, rapid, denied, and expired polling returns the
standard `authorization_pending`, `slow_down`, `access_denied`, and `expired_token` errors. Start
from [`config/templates/device-client-application.json`](config/templates/device-client-application.json).

```sh
curl --data-urlencode 'client_id=device-client' \
  --data-urlencode 'scope=openid profile offline_access' \
  http://127.0.0.1:4001/default/device_authorization

curl --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
  --data-urlencode "device_code=$DEVICE_CODE" \
  --data-urlencode 'client_id=device-client' \
  http://127.0.0.1:4001/default/token
```

A confidential backend client configured with `client_credentials` can obtain a short-lived
service token without a browser or user session. Its scopes must be service scopes shared by the
client and issuer; `openid`, `offline_access`, and scopes used by configured user-claim mappings are
rejected. The response deliberately contains no ID or refresh token, UserInfo rejects it, and
introspection reports the client ID as the machine subject. Start from
[`config/templates/service-client-application.json`](config/templates/service-client-application.json)
and add its service scope to the issuer.

A confidential client may additionally enable
`urn:ietf:params:oauth:grant-type:token-exchange` and register its exact target resources. It can
then exchange one of its own active access tokens for a downscoped token whose expiry never exceeds
the source token. Opaque and configured JWT access tokens are accepted and issued; actor tokens, scope
amplification, cross-client delegation, ID tokens, and refresh tokens are rejected. For example:
Start from
[`config/templates/token-exchange-client-application.json`](config/templates/token-exchange-client-application.json)
for a strict confidential-client configuration.

```sh
curl --user 'service-client:secret' \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  --data-urlencode "subject_token=$ACCESS_TOKEN" \
  --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:access_token' \
  --data-urlencode 'scope=service.read' \
  --data-urlencode 'resource=https://api.example.test' \
  http://127.0.0.1:4001/default/token
```

Clients may register exact `resources` and send one RFC 8707 `resource` parameter to authorization,
PAR, token, or refresh requests. The selected target is bound to every persisted grant, returned in
the token response, and exposed as `aud` by introspection. Changing the target during code exchange
or refresh fails with `invalid_target`; resource-bound access tokens are deliberately rejected by
UserInfo.

Clients may send an RFC 9449 `DPoP` proof to `/token` to receive a sender-constrained
access token with `token_type=DPoP`. Authorization requests can pre-bind the code with `dpop_jkt`;
PAR can carry that parameter or derive it from its own DPoP header. Public refresh tokens created
with DPoP remain bound to the same key. UserInfo requires the `DPoP` authorization scheme plus a
fresh proof containing the access-token hash, while introspection exposes the binding as `cnf.jkt`.
ES256 and RS256 proofs are supported, and PostgreSQL rejects proof replay across instances.
Set `token_policy.dpop_nonce_required` to `true` to additionally require an opaque server-provided
nonce. Missing or stale values return `use_dpop_nonce` plus `DPoP-Nonce`; recent nonce digests are
shared through PostgreSQL, kept separately for authorization-server and UserInfo proofs, and exposed
to browser clients through CORS. `dpop_nonce_lifetime` defaults to 300 seconds and accepts 30–3600.

Access tokens are opaque by default. Set an issuer's `token_policy.access_token_format` to `jwt`
to issue RS256 RFC 9068 tokens with `typ=at+jwt`, `iss`, `sub`, resource `aud`, `client_id`,
`scope`, `iat`, `exp`, `jti`, mapped claims, and `cnf.jkt` for DPoP. User grants also include their
stable `auth_time`, `acr`, and `amr`; machine grants omit user-authentication context. Discovery then advertises
`access_token_signing_alg_values_supported`. Resource servers can verify these tokens locally from
JWKS; Robine ID still stores only their digest so introspection and immediate server-side
revocation keep working. A purely offline verifier cannot observe revocation until token expiry.

Confidential clients may set `authentication_method` to `private_key_jwt` and register their RSA
public keys in `jwks`. Each request uses an RS256 assertion with an endpoint-specific audience and a
single-use `jti`; PostgreSQL rejects replay across instances. This works on token, PAR,
introspection, and revocation endpoints without Robine ID ever receiving the client private key.
Generate a private key and matching application document with
`scripts/generate-private-key-jwt-client.sh OUTPUT_DIRECTORY [CLIENT_ID]`; keep the resulting PEM only
on the client side.

Revocation accepts the same configured client-authentication method as the token endpoint and is
idempotent for unknown tokens. A client can revoke only its own access or refresh tokens.
Introspection is
disabled by default and requires a confidential application with `introspection_allowed: true`;
inactive or unauthorized token state is returned only as `{"active":false}`.
[`config/templates/resource-server-application.json`](config/templates/resource-server-application.json)
is a ready-to-copy confidential resource-server definition.
[`config/templates/offline-client-application.json`](config/templates/offline-client-application.json)
is a public-client example for refresh rotation; add `offline_access` to the matching issuer's
configured scopes before using it.

ID tokens use RS256. JWKS publishes public material only. Private signing material is encrypted with
AES-256-GCM using `KEY_ENCRYPTION_SECRET` (or `SECRET_KEY_BASE`) before it is persisted in PostgreSQL.
Manual key rotation takes a stable rotation identifier; repeating the same identifier is a no-op.
Optional policy-driven rotation derives an idempotency identity from the current key and rechecks
its age under a PostgreSQL lock. Retained keys continue validating tokens issued before either kind
of rotation and across restarts.

## Operations

- `GET /health/live` reports process liveness.
- `GET /health/ready` checks traffic acceptance, active configuration, and database connectivity.
- `GET /metrics` exports bounded Prometheus counters, including MFA, PAR, and Device Flow outcomes, request duration, readiness, and the active revision.
- SIGTERM and SIGINT disable readiness immediately, preserve liveness during the configurable drain delay, then stop Actix gracefully.
- `x-request-id` is returned as the public correlation reference.
- security and reconciliation events use structured, bounded metadata.
- credentials, password hashes, authorization codes, bearer tokens, session identifiers, and client secrets are excluded from audit events.

Production requires PostgreSQL connectivity and `KEY_ENCRYPTION_SECRET` with at least 32 bytes of
deployment-specific entropy. `DATABASE_URL` is accepted for managed databases; the release Compose
stack uses `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, and `POSTGRES_PASSWORD`.

### Container release

The production image and Compose definition are ready for the Caddy deployment:

```sh
cp .env.release.example .env.release
# Fill POSTGRES_PASSWORD, KEY_ENCRYPTION_SECRET, and application secrets.
docker compose --env-file .env.release -f compose.release.yml build
docker compose --env-file .env.release -f compose.release.yml up -d --wait
docker compose --env-file .env.release -f compose.release.yml ps
```

The service binds only to `127.0.0.1:4001`; Caddy publishes `https://id.base59.dev`. PostgreSQL data,
including encrypted signing keys and short-lived protocol state, lives in the persistent
`robine_id_postgres` volume. Root and application configuration are mounted read-only and continue
to reload automatically. See [`docs/operations/release.md`](docs/operations/release.md) for release,
backup, rollback, and verification procedures.

To publish the image to Docker Hub, authenticate once and use the Makefile. The default namespace is `laibulle`; override `DOCKERHUB_USER` or the complete `IMAGE` when needed:

```sh
make login
make publish

# Example override
make publish DOCKERHUB_USER=your-account VERSION=0.1.0
```

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
make rust-integration
make release-smoke
mix precommit # legacy parity regression suite
```

The test suite covers domain entities and use cases, adapter contracts, idempotent reconciliation,
cryptographic verification, protocol failures, complete login/consent/code exchange, UserInfo,
logout, session policy, health endpoints, localization, responsive authentication markup,
cross-instance state sharing, one-time code replay protection, and PostgreSQL disaster recovery.
