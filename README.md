# Robine ID

[![build](https://ci.base59.dev/badges/github/laibulle/robine-id/build.svg)](https://ci.base59.dev/repositories)
[![coverage](https://ci.base59.dev/badges/github/laibulle/robine-id/coverage.svg)](https://ci.base59.dev/repositories)
[![release](https://img.shields.io/github/v/release/laibulle/robine-id?display_name=tag&sort=semver)](https://github.com/laibulle/robine-id/releases)

Robine ID is a file-configured OpenID Connect provider. Its production runtime uses Rust, Actix Web,
Askama, and PostgreSQL. It implements the Authorization
Code Flow with PKCE, signed ID tokens, JWKS, registered-origin CORS for GET/POST UserInfo and
public-client token/revocation requests, OAuth token introspection, consent, reusable SSO sessions with OpenID
`prompt`/`max_age`, bounded `login_hint` and audience-checked `id_token_hint`, OIDC `claims` requests with essential-value enforcement,
password `acr`/`amr`, rotating refresh tokens for consented
`offline_access`, single-use Pushed Authorization Requests (PAR), signed RS256/ES256/EdDSA Authorization
Request Objects (JAR), confidential-service
`client_credentials`, query or hardened `form_post` authorization responses, signed JARM responses,
RFC 9449 DPoP sender-constrained access and public refresh tokens,
operator-provisioned per-user RFC 6238 TOTP MFA, RP-initiated logout, and session-bound OIDC
Front-Channel and Back-Channel Logout, plus origin-bound OIDC Session Management through
`check_session_iframe`.
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

Put independent generated values in `POSTGRES_PASSWORD`, `KEY_ENCRYPTION_SECRET`, and
`OAUTH2_PROXY_CLIENT_SECRET` inside `.env.release`. Keep all three in the deployment secret store.

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
  (also available as `/.well-known/openid-configuration/default` for RFC 8414-shaped clients)

Run the repeatable third-party relying-party journey after `make dev-container`:

```sh
make rp-smoke
```

This starts a pinned OAuth2 Proxy container on loopback, completes Authorization Code + PKCE using
the development identity, proves that the RP exchanged the code and validated the resulting OIDC
session, then removes the temporary RP container. No RP port remains published afterward.

The development PostgreSQL port is likewise bound only to `127.0.0.1:54329`, which lets host-side
Rust integration tests run while the Actix container remains healthy. The production Compose model
does not publish PostgreSQL and keeps it on an internal-only Docker network.

Production identities belong in `deploy/config/robine_id.json`, and relying applications belong in
`deploy/config/applications/`, one JSON file per application. The identities and applications under
`config/` are development material and are not mounted into the release container. The image itself
contains only the neutral, credential-free fallback under `deploy/image-config`; Compose mounts the
operator-owned `deploy/config` tree over it. Production identity metadata and password hashes
therefore do not become image layers.

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
make compose-validate
make rust-integration
make release-smoke
```

`make release-smoke` uses an isolated production Compose project. It completes GET and POST
Authorization Code requests with PKCE plus cross-instance PAR, Form Post, and Client Credentials across two Actix instances, exercises SSO, silent consent
errors, disabled-user and disabled-client rejection, UserInfo GET/POST and registered-origin CORS,
rejects a replayed code, rotates a refresh
token across instances, performs RP-initiated logout, introspects and revokes a client-bound access
token, then dumps, recreates, and restores PostgreSQL before checking refresh-token replay
detection, the restored access grant, and both current and retained signing keys. It removes only
its own temporary containers, network, volume, and files.

The legacy Phoenix regression suite remains available through `mix precommit`; its coverage reports
are written to `cover/` and retained by Robine CI.
Set `ROBINE_ID_TEST_DATABASE` to an isolated SQLite path to prove that the retained migration chain
can initialize a completely empty database without reusing local state.

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
runtime keeps generated and decrypted private-key PEM only in zeroizing memory through encryption,
rotation, and JWT signing. The server applies embedded SQL migrations at startup. `make dev` starts the PostgreSQL 17 development
container automatically and publishes it only on `127.0.0.1:54329`; `make dev-down` stops it
without deleting its named data volume. `make dev-container` keeps PostgreSQL private to the
project-scoped internal database network because only the containerized application needs to reach
it. Robine ID is dual-homed onto a separate application network so outbound protocol callbacks
remain available, and only the application is published on `127.0.0.1:4001`. The `make dev-db`
host overlay deliberately makes the database network non-internal before publishing PostgreSQL on
loopback for local Rust tooling.
Set `TRUST_PROXY_HEADERS=true` (or `1`) only behind a trusted reverse proxy; `false`/`0` disables it,
and Vercel enables forwarded-header handling automatically.
Operational events are emitted as JSON with bounded fields; `RUST_LOG` overrides the validated
`telemetry.log_level` when platform-specific filtering is required.
`METRICS_BEARER_TOKEN` optionally protects `GET /metrics`; the mutually exclusive
`METRICS_BEARER_TOKEN_FILE` form supports mounted secrets. The value must contain 32–256
URL-safe ASCII characters and is held in zeroizing memory. Generate a 384-bit value with
`make metrics-token`. Without either setting, metrics remain public for backwards compatibility.
`DATABASE_MAX_CONNECTIONS` defaults to five on the server and two per Vercel instance.
`DATABASE_ACQUIRE_TIMEOUT_MS` bounds pool waits (five seconds conventionally, two seconds on
Vercel) and accepts values from 100 through 30000 milliseconds.
`DATABASE_STATEMENT_TIMEOUT_MS` independently bounds every PostgreSQL statement with the same
defaults and accepted range, preventing an acquired connection from waiting indefinitely.
Database settings are strict: malformed URLs, partial `PG*` credentials, missing or weak encryption
secrets, and numeric values outside their documented ranges stop application initialization with a
non-secret diagnostic instead of silently selecting a fallback.
Runtime entropy, signing-key generation, encoding, and encryption failures propagate as bounded
errors rather than panicking the Actix or Vercel process or committing partial key state.
Long-running servers remove expired protocol state hourly; `DATABASE_CLEANUP_INTERVAL` overrides the
interval in seconds (`0` disables the task; otherwise it must be 60 through 86400).
Conventional-server settings are strict too: an empty host, invalid port, malformed proxy boolean,
or interval outside its documented range stops startup without echoing the submitted value.
Use `make dev-container` to build and run both the Rust application and PostgreSQL in Docker. The
Rust image is built from the canonical `Dockerfile`, runs as an unprivileged user, and includes a readiness
health check implemented by the bounded `robine-id-healthcheck` Rust binary; the runtime image does
not install `curl` solely for container health polling. In both development and release Compose,
the application root filesystem is read-only, all Linux capabilities are dropped, privilege
escalation is disabled, and only a bounded `noexec,nosuid,nodev` in-memory `/tmp` remains writable.
PostgreSQL likewise has a read-only root and `no-new-privileges`; writes are limited to its data
volume plus bounded, non-executable `/tmp` and `/var/run/postgresql` tmpfs mounts.
Application and PostgreSQL services use Docker's init shim and a 256-process cgroup limit. The
Compose definitions also retain at most three 10 MiB `json-file` log segments per service. The
known development database password and host-published `make dev` database are development
conveniences, not a production security boundary.
The two-network topology requires Docker Compose 2.33.1 or newer so the non-internal application
network remains the explicit default gateway.

The Rust runtime implements the home, sign-in, consent, logout, and error pages; health and OIDC
discovery endpoints and `/docs`; strict declarative application loading; bcrypt authentication with database-backed
global-network and issuer-account rate limiting, optional per-user TOTP, and persistent session policy; single-use authorization
codes and pushed authorization references; PKCE exchange;
RFC 8628 device authorization; RS256 ID tokens; retained-key JWKS; per-issuer opaque or RFC 9068 JWT user, service, device, and exchanged access tokens; UserInfo; and protected token
introspection/revocation. Browser transactions, sessions, access/refresh tokens, rate limits, and
encrypted signing keys are shared through PostgreSQL so the same
application can run as a conventional Actix server or across Vercel Function invocations.
Owned copies of submitted passwords, MFA/recovery and CSRF codes, OAuth tokens, PKCE verifiers, client
secrets/assertions, and logout hints use zeroizing memory wrappers throughout request processing.
Generated CSRF values and OIDC Session Management hash preimages remain zeroizing until their
unavoidable public HTTP representation is constructed.
The landing-page runtime badge uses the same drainage and PostgreSQL health decision as
`/health/ready`, so it never presents an unavailable instance as ready.
The landing page and built-in documentation expose bodyless `HEAD` alongside `GET`, preserving the
HTML representation's content length, language, cache policy, and media type through Actix and
Vercel.
Authentication forms use one shared progressive enhancement for password visibility, accessible busy
feedback, and duplicate-submit suppression. Login, TOTP, consent, device, and logout submissions remain
fully functional without JavaScript, inert reveal controls stay hidden until enhancement is active,
and enhanced consent keeps the selected approve or deny value intact. Progress is localized and
announced outside the busy form subtree; the zoom layout has no fixed 320-pixel minimum width.
Validated authorization parameters never round-trip through hidden login fields. The browser gets
only an issuer-bound, short-lived, single-use transaction whose hash and request remain in
PostgreSQL; an invalid password consumes and replaces it.
Discovery, WebFinger, and JWKS use weak content ETags and bounded browser/CDN caching to avoid
repeatedly transferring unchanged public metadata, including on Vercel.
Discovery, WebFinger, OAuth and protected-resource metadata, and JWKS also permit credential-free
reads from any origin. Their bounded preflight exposes only `GET`, `HEAD`, `OPTIONS`, and
`If-None-Match`; requests for any other method or header are rejected without CORS permission.
Credential-bearing endpoints keep their registered-origin or same-origin policy.
The default favicon, light and dark marks, legacy SVG logo, stylesheet, scripts, and deny-all
`robots.txt` are embedded in the Rust binary. They need no runtime asset directory and support
bounded caching, weak content ETags, conditional GET, and bodyless HEAD responses on Actix and Vercel.
The Askama theme also embeds complete English and French catalogs. `ui_locales=fr-FR` safely falls
back to configured `fr`, while global, issuer, and client message maps can still override individual
keys without recompiling either runtime. When `ui_locales` is omitted, bounded quality-ranked
`Accept-Language` preferences select the browser locale; the inferred preference is retained across
the opaque login, TOTP, and consent transaction. Every rendered HTML page returns a validated
`Content-Language` matching its document `lang`, through both Actix and Vercel.
Public text, SVG, metadata, documentation, and operational representations negotiate gzip, Brotli,
deflate, or Zstandard through Actix when the client advertises support. Login, consent, token,
UserInfo, logout, and other credential-bearing responses stay outside compression to avoid exposing
secrets through compression side channels.
Warm Vercel processes retain one Actix worker and route service behind a 128-request queue and a
32-request concurrency limit, avoiding per-invocation Actix system/router construction and
returning a secure retryable 503 instead of growing work without bound. Registered public-browser
token, PAR, and revocation callers can read its `Retry-After` signal only after the same strict
single-origin policy used for adapter-level body-limit rejection has passed.
Registered public-client redirect origins can call the token, PAR, and revocation endpoints from a
browser through strict POST-only CORS policies. Revocation permits only `Content-Type` and never
browser `Authorization`; confidential and unrelated origins are never granted CORS. Malformed and
oversized form rejections preserve CORS only after the endpoint path and exact public-client origin
have been validated, including before Actix dispatch on Vercel. Duplicate/non-UTF-8 CORS fields and
non-canonical requested methods are rejected without an access-control grant.
Set `token_policy.require_pushed_authorization_requests` on an issuer to require PAR globally, or
set `require_pushed_authorization_requests` on one `authorization_code` application to enforce it
only there. Discovery publishes the global policy. `browser_authorization_lifetime` defaults to 600
seconds and accepts 60 through 3600.
Conventional servers reload file-backed configuration atomically every second by default. Invalid
or partially written candidates are rejected while the last valid revision remains active;
`ROBINE_ID_RELOAD_INTERVAL=0` disables watching; non-zero intervals must be 100 through 60000
milliseconds. On Unix, `SIGHUP` requests the same validated reload immediately, even when watching
is disabled. Inline/Vercel configuration is immutable. Pending consent is revalidated when it is
consumed: disabling a user/client or removing its grant, redirect, scope, resource, PKCE/nonce, MFA,
essential claim, or rich-authorization policy consumes the stale transaction without issuing a code
or redirecting to a formerly registered URI. Mapped claims are rebuilt from active user attributes
at that point, so pending consent cannot emit a superseded role or profile value. Logout
confirmations receive the same reload safety: their
issuer/client/URI/state bindings are stored separately and revalidated, so a removed client return
URI is discarded while the local session is still ended.
Pending Device Flow confirmations likewise recheck device/refresh grants, scopes, resources, and
rich-authorization details before displaying or accepting browser approval.
Authorization-code, Device, refresh, and Token Exchange issuance plus opaque-token UserInfo rebuild
mapped identity claims from the active user, so a changed email, role, or mapping is not prolonged
by stored grant state. Already issued self-contained JWTs remain valid only until their bounded expiry.
Before first token issuance, authorization codes and Device grants also adopt newly activated
user/client MFA policy. Existing refresh and exchanged grants keep their truthful original context;
UserInfo answers with an RFC 9470 MFA challenge when that context is no longer strong enough.

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
Generate a fresh 144-bit initial password and its configuration-safe bcrypt hash without putting
the plaintext in a command argument or shell history:

```sh
make user-password BCRYPT_COST=12
```

Deliver the displayed password once through a trusted channel and retain only the emitted
`password_hash`. Use the same cost for every user in one revision.
All configured user password hashes in one revision must use the same bcrypt cost (10 through 16),
which also determines the dummy verification work performed for unknown identifiers.
Set `"enabled": false` on a local identity to suspend login and server-validated sessions or grants
without deleting its stable internal or pairwise subject. Disabled credentials use the same generic
failure path and dummy bcrypt work as an unknown identifier.

Set a user's `issuer_ids` to a non-empty list of configured issuer identifiers to restrict that
identity to selected tenants. An omitted or empty list keeps the backwards-compatible all-issuer
behavior. Login, existing browser sessions, Device Flow, refresh, token exchange, UserInfo,
introspection, and pairwise-subject resolution enforce the boundary; a correct password on another
issuer receives the same generic result and bcrypt work as an unknown identity.
Opening an unauthorized issuer does not erase a still-valid global SSO cookie, so one tenant cannot
sign the browser out of another merely by failing the identity-scope check.
Distinct tenants may reuse the same normalized login identifier when both users declare non-empty,
disjoint `issuer_ids` lists. A global user (empty list) conflicts with that identifier everywhere,
and any overlapping tenant scope is rejected during configuration validation.

### Optional TOTP MFA

Enable `totp` beside `password`, then attach an environment secret reference only to users who need
the second factor. The value is an unpadded Base32 secret containing 160 through 512 bits; it is
resolved only while verifying a code and is redacted from effective configuration. Set
`ALICE_TOTP_SECRET_FILE` instead of `ALICE_TOTP_SECRET` to load the same reference from a mounted
secret file.

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

Generate an independent canonical 160-bit secret per user with `make totp-secret`, enroll it through
a trusted operator workflow, then inject it into the server, container, or Vercel secret
environment. TOTP uses six digits and 30-second steps. PostgreSQL prevents reuse of an accepted
step across instances. ID tokens, user JWT access tokens, and active introspection responses report
`amr=["pwd","otp"]` with `acr=urn:robine-id:acr:password+totp`; refresh and token exchange preserve
that context.

Generate an optional one-time recovery set with `make recovery-codes` (or set `COUNT`, from 1 through
16). Give the displayed codes to the user once through a trusted channel and add only the emitted
`recovery_code_hashes` array to that user. Each code carries 80 bits of entropy, is accepted
case-insensitively after password verification, and is consumed atomically in PostgreSQL across all
instances. The 80-bit codes are stored only as strict SHA-256 fingerprints, and effective
configuration redacts the whole field. Replacing the complete hash array issues
a new operator-managed set; self-service enrollment and factor reset are not provided.

An Authorization Code or Device application can require MFA for every account by setting
`"required_acr": "urn:robine-id:acr:password+totp"`, and can bound authentication freshness with
`"max_authentication_age": 900`. These policies reject password-only or stale SSO sessions and let
UserInfo issue RFC 9470 `insufficient_user_authentication` challenges for existing tokens. Relying
parties may also send the standard
space-delimited `acr_values` authorization parameter as a voluntary preference through direct
GET/POST requests, PAR, or signed Request Objects. Start from
[`config/templates/mfa-client-application.json`](config/templates/mfa-client-application.json).

## Configuration

The default root file is [`config/robine_id.json`](config/robine_id.json). Each relying application has its own document in [`config/applications`](config/applications). Set `ROBINE_ID_CONFIG` to select another root document and `ROBINE_ID_APPLICATIONS_DIR` to override its adjacent `applications/` directory.

Every document declares `schema_version: 1`. The root supports these sections:

- `issuers`: issuer URLs, supported scopes, token policy, claim mappings, and issuer branding;
- `pairwise_subject_salt_reference`: durable environment-secret reference used only when pairwise subjects are enabled;
- `applications/*.json`: exact redirect URIs, post-logout, front-channel, and back-channel logout URIs, scopes, grants,
  authentication, consent, optional issuer isolation/introspection authorization, and application branding;
- `users`: local identities with bcrypt password hashes, optional `enabled` suspension and `issuer_ids` tenant isolation, TOTP secret references, and source claims;
- `claims`: mapping from OIDC claim names to identity sources and required scopes;
- `branding`: product name, assets, accessible theme tokens, locales, message overrides, and legal/support links;
- `reconciliation`: explicit removal policy;
- `authentication`: session and rate-limit policy;
- `storage`: legacy Phoenix storage compatibility metadata (Rust persistence is configured through PostgreSQL environment variables);
- `telemetry`: validated operational log level.

Set `"enabled": false` on an issuer to suspend the complete tenant without deleting its URL,
policy, branding, or persisted signing-key history. Its protocol and metadata routes return the
same not-found response as an unknown issuer, WebFinger stops advertising it, and automatic key
rotation skips it until reactivation.

Set `"enabled": false` in an application document to suspend the relying party without deleting its
redirects, keys, secret reference, pairwise sector, or policy. The client immediately stops
authenticating, validating server-side grants, contributing conditional Discovery capabilities,
authorizing CORS/session-check origins, and receiving logout callbacks. Start from
[`config/templates/suspended-application.json`](config/templates/suspended-application.json).

Set an application's `issuer_ids` to a non-empty list of configured issuer identifiers to bind that
client to selected tenants. An omitted or empty list keeps the backwards-compatible all-issuer
behavior. Authorization, client authentication, active server-side grants, CORS/session-check
origins, logout callbacks, and conditional Discovery capabilities all enforce the binding. Start
from [`config/templates/tenant-scoped-application.json`](config/templates/tenant-scoped-application.json).

Configuration precedence is deterministic:

```text
built-in safe defaults < global branding < issuer branding < client branding
```

Configured branding logos and favicons accept either an absolute local path or an HTTPS URL
(`http` is limited to loopback development). Local paths reject authority-like prefixes,
backslashes, whitespace, fragments, and literal or percent-encoded dot traversal. The active
semantic revision is appended after existing query parameters so browser/CDN cache invalidation
stays deterministic on Actix and Vercel.

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
For every configured key, the runtime also accepts the mutually exclusive `<KEY>_FILE` variable;
for example, `MY_CLIENT_SECRET_FILE=/run/secrets/my_client_secret`. The same convention applies to
TOTP and pairwise-subject salt references.

To isolate a user's `sub` between relying-party sectors, set an application's `subject_type` to
`pairwise`. A single redirect host is inferred as its sector; otherwise declare a canonical
lowercase hostname in `sector_identifier`. The root configuration must reference a durable secret
of at least 32 bytes:

```json
{
  "pairwise_subject_salt_reference": {
    "provider": "env",
    "key": "PAIRWISE_SUBJECT_SALT"
  }
}
```

Do not rotate this salt as routine credential maintenance: doing so changes all pairwise subject
identifiers. See [`config/templates/pairwise-application.json`](config/templates/pairwise-application.json).

HTTP issuer and redirect URLs are accepted only for loopback development hosts. Other URLs must use HTTPS. Unknown fields and incompatible values fail validation before activation.

Every application document declares `schema_version: 1` and `kind: "oidc_application"`. The application watches the complete composed configuration and reloads it every second by default; `ROBINE_ID_RELOAD_INTERVAL` overrides that interval in milliseconds (`0` or 100 through 60000). On Unix, `SIGHUP` triggers the same complete reload immediately, including when polling is disabled. A valid change activates atomically; an unchanged revision is ignored; an invalid or partially written file is recorded as a failed attempt while the last valid revision remains active.

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

For the development issuer `http://127.0.0.1:4001/default` (replace it with the deployment's HTTPS
issuer in production):

| Capability | Endpoint |
| --- | --- |
| Discovery | `GET /default/.well-known/openid-configuration` or `GET /.well-known/openid-configuration/default` |
| OAuth metadata | `GET /.well-known/oauth-authorization-server/default` |
| UserInfo resource metadata | `GET /.well-known/oauth-protected-resource/default/userinfo` |
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
| Session status iframe | `GET /default/check-session` |
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

Public and confidential clients with configured `request_object_jwks` may protect the complete
authorization request in an RS256, ES256, or EdDSA `request` JWT, using a matching RSA, P-256, or
Ed25519 key. Existing `private_key_jwt` clients may reuse their authentication `jwks`. The outer request
still carries the exact `client_id`; any repeated outer parameter must match its signed value.
Objects are issuer-audience-bound, expire within five minutes, and use a single-use `jti` enforced
through PostgreSQL across Actix and Vercel instances. Signed objects work with direct GET/POST
authorization and authenticated PAR. Set `require_signed_request_object` to reject unsigned direct
and pushed requests before browser or PAR state is created. Dedicated request-object keys do not
turn a public client into a confidential one. Encrypted objects, remote `request_uri` dereferencing, and
other signing algorithms are intentionally unsupported.

An authorization request may send a previously issued ID Token as `id_token_hint`. Robine ID
verifies the issuer, RS256 signature, retained signing key, and exact client audience, then requires
the active browser session to identify the same subject for silent SSO. In accordance with OpenID
Connect Core, expiration alone does not invalidate a hint: the token never creates or extends a
session and never bypasses current MFA, `max_age`, consent, claims, or client policy. The parameter
works identically through GET, POST, PAR, and signed Request Objects; conflicting outer and signed
values are rejected.

Authorization responses use query redirects by default. Set `response_mode=form_post` to receive
success or redirectable error parameters in an Askama-rendered, auto-submitted HTML form. The page
has a visible no-JavaScript fallback, disables caching, escapes every hidden value, and narrows its
CSP `form-action` to the registered redirect origin. The selected mode survives PAR, SSO, consent,
and routing between instances. Its localized title, explanation, fallback action, HTML language,
and `Content-Language` header retain the authorization request's `ui_locales` preference across the
PostgreSQL consent transaction.

Set `response_mode=jwt` or `query.jwt` to receive the complete success or error response as a
short-lived RS256 JARM JWT in the `response` query parameter. `form_post.jwt` delivers that single
signed parameter through the same hardened form page. JARM responses are audience-bound to the
client, use the issuer's published signing key, contain `iss`, `aud`, `iat`, and `exp`, and never
downgrade to unsigned parameters when signing is unavailable.

A client configured with the `refresh_token` grant can request the `offline_access` scope. Robine ID
always shows consent before granting offline access, stores refresh tokens only by hash, and returns
a replacement on every refresh. Replaying a consumed token revokes its complete token family. A
refresh request may retain the original scopes or atomically narrow them, but cannot add scopes.

Clients can request RFC 9396 fine-grained permissions with `authorization_details` after the
operator registers each type globally and enables it through the client's
`authorization_details_types`. Robine ID validates bounded type-specific fields, always shows these
details during consent, persists them through authorization code, device, access, and refresh
grants, and returns them in token responses, JWT access tokens, and introspection. Token and refresh
requests may remove object fields or array members but cannot expand the original grant. Start from
[`config/templates/rich-authorization-client-application.json`](config/templates/rich-authorization-client-application.json)
and add the matching root definition:

```json
{
  "authorization_detail_types": [{
    "type": "account_information",
    "name": "Account information",
    "allowed_fields": ["actions", "identifier", "locations"],
    "required_fields": ["actions"]
  }]
}
```

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

RP-Initiated Logout accepts GET or form-serialized POST requests and always asks for explicit
confirmation. A registered `post_logout_redirect_uri` can be associated with the RP through either
an `id_token_hint` or `client_id`; when both are sent they must identify the same application.
Signed hints remain usable after expiration for this confirmation-only purpose, but still require a
valid issuer, retained RS256 key, and known audience. `state` is returned only after an exact
registered redirect match, and the final confirmation is protected by CSRF and an opaque,
single-use PostgreSQL transaction. That transaction stores issuer, client, return URI, state, and
the bounded locale preference as separate bindings. Confirmation revalidates them against the active configuration; a disabled
issuer/client or removed URI suppresses the client redirect but never preserves the local session.
An active client retains its localized branding through the signed-out or front-channel page.

When an application registers `backchannel_logout_uri`, successful browser or device authorization
associates that RP with the opaque `sid` published in its ID Token. Confirming logout then sends a
short-lived RS256 `logout+jwt` to every participating RP in parallel before completing the browser
response. Delivery is best effort, bounded to two seconds, never follows redirects, and does not
undo local logout when an RP is unavailable. Start from
[`config/templates/backchannel-logout-application.json`](config/templates/backchannel-logout-application.json).

An application can additionally register `frontchannel_logout_uri`. Robine ID renders every
participating RP in a sandboxed iframe interstitial whose CSP contains only registered callback
origins, retains any callback query, and appends `iss` plus `sid` when requested. It continues to
the validated post-logout destination after the frames settle or 1.5 seconds; the normal link and
iframe requests still work without JavaScript. Start from
[`config/templates/frontchannel-logout-application.json`](config/templates/frontchannel-logout-application.json).

HTTPS issuers also advertise `check_session_iframe`. Successful query, form-post, and JARM
authorization responses receive an opaque `session_state` bound to the client, exact redirect
origin, and current OP browser state. The iframe validates the caller against a registered redirect
origin once, then recalculates locally with Web Crypto and replies with the standard `unchanged`,
`changed`, or `error` status. The authentication cookie remains `HttpOnly`; only a separate
one-way-derived, non-authenticating `__Host-robine_opbs` value is readable by the iframe. Browsers
that block third-party cookies can produce `changed` notifications, so clients must avoid
`prompt=none` loops and should prefer Back-Channel Logout when it is available.

A confidential backend client configured with `client_credentials` can obtain a short-lived
service token without a browser or user session. Its scopes must be service scopes shared by the
client and issuer; `openid`, `offline_access`, and scopes used by configured user-claim mappings are
rejected. The response deliberately contains no ID or refresh token, UserInfo rejects it, and
introspection reports the client ID as the machine subject. Start from
[`config/templates/service-client-application.json`](config/templates/service-client-application.json)
and add its service scope to the issuer.

An authenticated resource server can request an RFC 9701 signed introspection response with
`Accept: application/token-introspection+jwt`. The RS256 JWT uses
`typ=token-introspection+jwt`, binds `iss` and `aud` to the issuer and authenticated caller, and
keeps the RFC 7662 data nested under `token_introspection` to prevent access-token confusion.
Discovery advertises `introspection_signing_alg_values_supported`; plain JSON remains the default.

A confidential client may additionally enable
`urn:ietf:params:oauth:grant-type:token-exchange` and register its exact target resources. It can
then exchange one of its own active access tokens for a downscoped token whose expiry never exceeds
the source token. With `actor_token_exchange_allowed: true`, a distinct Client Credentials token
from the authenticated broker identifies the acting party; issued JWTs and introspection expose the
bounded RFC 8693 `act` delegation chain. A source application can explicitly delegate to that
broker through `authorized_actor_clients`; the resulting token keeps the original subject and
identifies the broker in both `client_id` and `act`. Opaque and configured JWT access tokens are
accepted and issued. Delegated service grants remain introspectable while the source service still
authorizes the broker; removing that allowlist entry makes them inactive. Machine subjects are
classified from grant provenance, so a same-named local user cannot inject mapped identity claims
or pairwise pseudonymization. Scope amplification, unapproved delegation, ID tokens, and refresh
tokens are rejected.
For example:
Start from
[`config/templates/token-exchange-client-application.json`](config/templates/token-exchange-client-application.json)
for the broker and
[`config/templates/delegating-client-application.json`](config/templates/delegating-client-application.json)
for an explicitly delegating source.

```sh
curl --user 'service-client:secret' \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  --data-urlencode "subject_token=$ACCESS_TOKEN" \
  --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:access_token' \
  --data-urlencode "actor_token=$ACTOR_ACCESS_TOKEN" \
  --data-urlencode 'actor_token_type=urn:ietf:params:oauth:token-type:access_token' \
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
EdDSA, ES256, and RS256 proofs are supported with strict Ed25519, P-256, and RSA JWK matching, and
PostgreSQL rejects proof replay across instances.
Set `token_policy.dpop_nonce_required` to `true` to additionally require an opaque server-provided
nonce. Missing or stale values return `use_dpop_nonce` plus `DPoP-Nonce`; recent nonce digests are
shared through PostgreSQL, kept separately for authorization-server and UserInfo proofs, and exposed
to browser clients through CORS. `dpop_nonce_lifetime` defaults to 300 seconds and accepts 30–3600.

Applications may set `userinfo_signed_response_alg` to `RS256` to receive UserInfo as a compact
`application/jwt` response. The response carries issuer and client audience binding, short
`iat`/`exp` timestamps, and the authorized claims, and verifies against normal issuer JWKS. JSON
remains the default. See
[`config/templates/signed-userinfo-application.json`](config/templates/signed-userinfo-application.json).
UserInfo also publishes RFC 9728 protected-resource metadata at
`/.well-known/oauth-protected-resource/:issuer_id/userinfo`; Discovery cross-advertises the exact
resource identifier, and authentication challenges point clients back to that metadata document.

Access tokens are opaque by default. Set an issuer's `token_policy.access_token_format` to `jwt`
to issue RS256 RFC 9068 tokens with `typ=at+jwt`, `iss`, `sub`, resource `aud`, `client_id`,
`scope`, `iat`, `exp`, `jti`, mapped claims, and `cnf.jkt` for DPoP. User grants also include their
stable `auth_time`, `acr`, and `amr`; machine grants omit user-authentication context. Discovery then advertises
`access_token_signing_alg_values_supported`. Resource servers can verify these tokens locally from
JWKS; Robine ID still stores only their digest so introspection and immediate server-side
revocation keep working. A purely offline verifier cannot observe revocation until token expiry.

Confidential clients may set `authentication_method` to `private_key_jwt` and register RSA, P-256,
or Ed25519 public keys in `jwks`. Each request uses an RS256, ES256, or EdDSA assertion with an endpoint-specific audience and a
single-use `jti`; PostgreSQL rejects replay across instances. This works on token, PAR,
introspection, and revocation endpoints without Robine ID ever receiving the client private key.
Generate a private key and matching application document with
`scripts/generate-private-key-jwt-client.sh OUTPUT_DIRECTORY [CLIENT_ID] [RS256|ES256|EdDSA]`; RS256 remains
the default. Keep the resulting PEM only on the client side. Overlapping RSA, P-256, and Ed25519 JWKs allow
algorithm migration without downtime.

Confidential clients that already share a strong secret may instead use `client_secret_jwt`. Each
request carries a short-lived HS256 assertion whose `iss` and `sub` equal the client identifier,
whose `aud` is the exact endpoint URL, and whose `jti` is single-use across all PostgreSQL-backed
instances. The resolved environment secret must contain at least 32 octets. Token, PAR, device
authorization, introspection, and revocation all use the same strict assertion transport.
[`config/templates/client-secret-jwt-application.json`](config/templates/client-secret-jwt-application.json)
is a ready-to-copy service definition.

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

- `GET`/`HEAD /health/live` reports process liveness without allowing caches to retain the result.
- `GET`/`HEAD /health/ready` checks traffic acceptance, active configuration, and database
  connectivity; both health endpoints emit `Cache-Control: no-store` and `Pragma: no-cache`.
- JSON errors, rejected CORS preflights, and session-origin checks also emit `Cache-Control:
  no-store` and `Pragma: no-cache`; only explicit public metadata and asset responses opt into
  cacheability.
- Unsupported methods on known public, OAuth, and OIDC routes return `405 Method Not Allowed` with
  an exact endpoint-specific `Allow` header on both Actix and Vercel; unknown routes remain HTTP
  404.
- `HEAD` preserves those error statuses, cache headers and GET-equivalent representation lengths
  without returning a body. Malformed WebFinger remains a public non-cacheable JRD, while malformed
  Session Management origin checks return an empty non-cacheable `400` on Actix and Vercel.
- Vercel-generated body-limit `413` and worker-overload `503` errors follow the same bodyless `HEAD`
  contract before a request reaches Actix.
- `GET /metrics` exports bounded Prometheus counters, including per-grant token issuance,
  RFC 8693 exchange, aggregate UserInfo, MFA, PAR and Device Flow outcomes, request duration,
  readiness, and the active revision. Arbitrary grant values collapse to the fixed `unsupported`
  label; UserInfo metrics contain no identity dimensions. HTTP volume and latency are split only
  across `GET`, `POST`, `HEAD`, `OPTIONS`, and `other`, never raw paths or extension methods. The
  metrics response emits `Cache-Control: no-store` and `Pragma: no-cache`.
  When a metrics token is configured, the route requires exactly one matching Bearer credential,
  compares it in constant time, and returns a non-cacheable Bearer challenge otherwise.
- SIGTERM and SIGINT disable readiness immediately, preserve liveness during the configurable drain delay, then stop Actix gracefully.
- `make doctor` (or `robine-id-doctor` inside the image) performs a read-only configuration,
  PostgreSQL, exact migration-checksum, and encrypted-key diagnostic. It emits bounded JSON and
  never applies migrations or creates/prunes/rotates keys.
- `x-request-id` is returned as the public correlation reference.
- security and reconciliation events use structured, bounded metadata.
- credentials, password hashes, authorization codes, bearer tokens, session identifiers, client
  secrets, and DPoP proof thumbprints/identifiers/nonces are excluded from audit events, including
  debug-level accepted-proof diagnostics.

Production requires PostgreSQL connectivity and `KEY_ENCRYPTION_SECRET` with at least 32 bytes of
deployment-specific entropy. `DATABASE_URL` is accepted for managed databases; the release Compose
stack uses `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, and `POSTGRES_PASSWORD`.
The runtime keeps direct and component-built connection URLs and database passwords in zeroizing
transient storage while SQLx constructs its connection pool.
Every sensitive database input also accepts a mutually exclusive file source: `DATABASE_URL_FILE`,
`PGPASSWORD_FILE`, `POSTGRES_PASSWORD_FILE`, `KEY_ENCRYPTION_SECRET_FILE`,
`KEY_ENCRYPTION_SECRET_PREVIOUS_FILE`, `SECRET_KEY_BASE_FILE`, or
`METRICS_BEARER_TOKEN_FILE`. Secret files are bounded to
16 KiB and loaded into zeroizing memory. This supports Docker/Swarm/Kubernetes secret mounts
without exposing the values through the container environment.
Generate the wrapping secret with `make encryption-secret`; it emits one environment-file-safe
`KEY_ENCRYPTION_SECRET` containing 384 bits of operating-system entropy. Store that value with the
matching database backups and do not commit it.
For a new release deployment, prefer `make deployment-secrets`: it emits independent 384-bit
`POSTGRES_PASSWORD`, `KEY_ENCRYPTION_SECRET`, and `OAUTH2_PROXY_CLIENT_SECRET` assignments ready
for `.env.release`, without a host OpenSSL dependency.
Generate the optional metrics credential with `make metrics-token`; it emits an independent,
environment-file-safe `METRICS_BEARER_TOKEN` containing 384 bits of operating-system entropy.

### Container release

The production image and Compose definition are ready for the Caddy deployment:

```sh
cp .env.release.example .env.release
# Fill POSTGRES_PASSWORD, KEY_ENCRYPTION_SECRET, and application secrets.
docker compose --env-file .env.release -f compose.release.yml build
docker compose --env-file .env.release -f compose.release.yml up -d --wait
docker compose --env-file .env.release -f compose.release.yml ps
```

For file-mounted PostgreSQL and wrapping secrets, copy `.env.release.files.example` to
`.env.release.files`, run `make deployment-secret-files`, and add the overlay to each Compose
command. Set the two `ROBINE_ID_SECRET_OWNER_*` values to the numeric owner and group of the
generated files. The generator restricts the directory and files, never overwrites existing
material, and does not print the values:

```sh
ROBINE_ID_ENV_FILE=.env.release.files docker compose --env-file .env.release.files \
  -f compose.release.yml -f compose.release.secrets.yml up -d --build --wait
```

The same PostgreSQL password file is mounted only into PostgreSQL and Robine ID; the wrapping-key
file is mounted only into Robine ID. Do not retain the direct variables alongside their file forms.
During wrapping-key rotation, the temporary `compose.release.secrets-rotation.yml` overlay mounts
the former key separately and is removed after `reencrypt_keys` succeeds.

The release service binds only to `127.0.0.1:4042`; Caddy publishes `https://id.base59.dev`. The
development stack remains independently available on port 4001 because the two Compose files use
distinct project names. PostgreSQL data,
including encrypted signing keys and short-lived protocol state, lives in the persistent
`robine_id_postgres` volume. PostgreSQL has no published port and joins only an internal database
network. Robine ID also joins a distinct non-internal application network for outbound OIDC logout
callbacks. Root and application configuration are mounted read-only and continue to reload
automatically. See [`docs/operations/release.md`](docs/operations/release.md) for release, backup,
rollback, and verification procedures.

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
