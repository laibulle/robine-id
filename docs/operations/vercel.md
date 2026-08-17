# Vercel deployment

The Vercel function in `api/index.rs` forwards every request through the same Actix route
configuration as the conventional server. PostgreSQL remains authoritative for codes, access and
refresh grants, sessions, rate limits, browser transactions, and signing keys, so function instances are stateless
apart from bounded in-process metrics and their immutable configuration snapshot.
The adapter caps request bodies at 16 KiB before forwarding them into Actix, matching the form
limit used by the conventional server. For token, PAR, and revocation only, an adapter-level 413
echoes `Access-Control-Allow-Origin` only for POST after the exact path and one unambiguous origin
pass the same active public-client redirect-origin policy; every other oversized request remains
same-origin.
Liveness and readiness probes preserve the shared Actix `GET`/bodyless-`HEAD` contract and always
emit `Cache-Control: no-store` plus `Pragma: no-cache`; Vercel and intermediary caches must not
retain an instance's former traffic-acceptance state.
The same adapter preserves the route layer's non-cacheable policy for JSON errors, unknown issuers,
rejected browser preflights, and session-origin validation. Only the explicit public metadata and
static-asset helpers opt into shared caching.
Known protocol paths also preserve Actix method negotiation through Vercel: unsupported verbs return
HTTP 405, the endpoint's exact `Allow` header, and a non-cacheable bounded JSON error.
Each warm function process owns one long-lived Actix worker instead of rebuilding an Actix system
and router for every invocation. A bounded 128-request channel provides back-pressure and a
semaphore permits at most 32 requests to execute concurrently on the worker's local Actix
scheduler, while request-body collection remains on the Vercel Tokio runtime. A full queue or
unavailable worker returns a security-hardened HTTP 503 with `Retry-After: 1`; it is also counted in
HTTP metrics. Configuration, the SQL pool, migrations, metrics, and the route service are therefore
initialized at most once per warm process.
HTTP method counters and duration summaries use only `GET`, `POST`, `HEAD`, `OPTIONS`, and `other`.
Body-limit 413 and worker/queue 503 responses are recorded even when rejection happens before Actix;
an arbitrary extension method can never become a Prometheus label or tracing-span value. These
adapter-generated rejections carry both `Cache-Control: no-store` and `Pragma: no-cache`, matching
route-layer transient errors. On `HEAD`, they retain the status, headers, and JSON representation
length but suppress the body exactly like route-layer errors.
Public browser clients can use the shared token, PAR, and revocation routes cross-origin when their
exact origin is derived from a registered redirect URI. Revocation preflight permits only POST with
`Content-Type` and never enables browser `Authorization` or CORS for confidential-client
credentials. Duplicate or non-UTF-8 CORS control fields and non-canonical requested methods are
rejected without an access-control grant before Actix and Vercel can diverge.
Pushed authorization requests use the same PostgreSQL authority as conventional Actix instances,
so a PAR reference created by one warm function process can be consumed by another. References are
single-use and short-lived; clients must not assume invocation affinity.
Form-post success and error pages pass through the same adapter with their no-store policy and
redirect-origin-specific CSP intact.
Client-credentials access grants use that same database authority. A token issued by one warm
function process can be introspected or revoked by another without session affinity.
Discovery, WebFinger, and JWKS responses publish weak content-derived ETags plus `s-maxage=300` and
a bounded stale-while-revalidate window. Vercel's shared cache can therefore answer repeated
metadata reads without transferring the JSON or JRD representation on every request, while a
changed configuration or rotated key produces a new validator.
OIDC Discovery is available through both `/:issuer_id/.well-known/openid-configuration` and the
RFC 8414-shaped compatibility path `/.well-known/openid-configuration/:issuer_id`; both forward to
the same Actix representation and therefore share their validator and cache policy.
Discovery, WebFinger, OAuth and protected-resource metadata, and JWKS allow credential-free reads
from any origin. Their public preflight is bounded to `GET`, `HEAD`, `OPTIONS`, and `If-None-Match`;
this does not broaden the registered-origin policy of token, PAR, UserInfo, or other sensitive
routes.
Default visual assets and `robots.txt` are compiled into the same Rust binary rather than read from
an invocation filesystem. They expose exact media types, bounded cache lifetimes, content-derived
ETags, conditional GET, and bodyless HEAD responses through the same Actix adapter.
The complete English/French Askama message catalogs are embedded as well; regional `ui_locales`
lookup, bounded quality-ranked `Accept-Language` fallback, and configured per-key overrides therefore
behave identically on conventional servers and warm or cold functions. The shared renderer derives
the same validated `Content-Language` as each document's HTML `lang`; the adapter forwards it
unchanged without adding it to redirects or JSON responses.
Configured remote logo and favicon URLs remain supported without bundling their bytes; validation
permits safe HTTPS targets and the rendered URL receives the semantic-revision cache key after any
operator-supplied query parameters.
The shared route layer negotiates standard Actix compression only for public resources such as
assets, metadata, documentation, health, and metrics. Authentication and token-bearing routes are
deliberately outside that middleware; `Accept-Encoding` never enables compression for them.

## Required environment

- `DATABASE_URL`: a TLS-enabled production PostgreSQL connection string.
- `KEY_ENCRYPTION_SECRET`: at least 32 bytes of deployment-specific entropy, retained with backups.
- `ROBINE_ID_CONFIG_JSON` or `ROBINE_ID_CONFIG`: an explicit production root configuration.
- `ROBINE_ID_APPLICATIONS_JSON` or `ROBINE_ID_APPLICATIONS_DIR`: the complete application set.
- Every environment variable referenced by a confidential application's `secret_reference`.

Use `RUST_LOG=robine_id=info,vercel=info` when overriding the configuration log level so both
library audit events and function-adapter request completions remain visible.

`DATABASE_MAX_CONNECTIONS` defaults to `2` per warm function instance. Keep the total potential
connection count within the database or pooler's limits. Vercel proxy headers are trusted
automatically; do not use client-supplied forwarding headers in a different hosting environment
unless its trusted proxy overwrites them.
`DATABASE_ACQUIRE_TIMEOUT_MS` defaults to `2000` on Vercel (`5000` conventionally) so an exhausted
or unavailable pool fails within the request latency budget; accepted values are 100 through 30000.
`DATABASE_STATEMENT_TIMEOUT_MS` uses the same defaults and range, but applies inside PostgreSQL to
every statement after a connection is acquired. Tune both below the function's execution timeout.
Invalid database URLs, incomplete component credentials, weak encryption secrets, and out-of-range
pool or timeout settings reject the cold start without including credential values in the error.
Conventional-only settings (`HOST`, `PORT`, reload/cleanup intervals, drain, shutdown, and manual
proxy trust) are not consumed by the Vercel adapter.

For an entirely environment-backed deployment, minify the root document and inject it as
`ROBINE_ID_CONFIG_JSON`; inject an array of full `oidc_application` documents as
`ROBINE_ID_APPLICATIONS_JSON`. Alternatively, ship non-secret production documents in the function
bundle and set explicit file paths. Client secrets must still use typed environment references.
The entrypoint refuses an implicit fallback to the checked-in development configuration.

## Verification

1. Build the optimized adapter with `cargo build --locked --release --bin vercel`.
2. Deploy one immutable configuration revision and wait for `/health/ready` to return that revision.
3. Verify discovery uses the public HTTPS issuer and every endpoint resolves through `vercel.json`.
4. Complete Authorization Code with PKCE, consented `offline_access`, cross-instance refresh
   rotation, Client Credentials, UserInfo, protected introspection, client-bound revocation,
   RP-initiated logout, session-bound front/back-channel notifications, and the embeddable OIDC
   Session Management iframe
   through real clients.
5. Exercise two concurrent function instances against the same database when the platform permits.
6. Restore a PostgreSQL backup with the matching key-encryption secret and verify current and
   retained JWKS keys.

File watching and background cleanup loops are intentionally disabled in the function runtime.
Configuration changes require a new deployment. Expired rows are removed opportunistically during
migration/startup, including retained signing keys whose persisted verification window has elapsed;
conventional deployments also run periodic maintenance. A rotation captures that window from the
greater ID-token/JWT-access-token lifetime, clock skew, and a five-minute safety margin, so a later configuration change
cannot shorten it. When `token_policy.signing_key_rotation_interval` is configured, Vercel checks
for a due rollover at cold start and before signing each ID token. The PostgreSQL row lock makes
that opportunistic path converge across warm instances without a background timer.

For wrapping-secret rotation, first deploy the new `KEY_ENCRYPTION_SECRET` together with the former
value as `KEY_ENCRYPTION_SECRET_PREVIOUS`. Run `reencrypt_keys` from the canonical Docker image or a
trusted Rust operator environment against the same PostgreSQL database, verify a fresh deployment,
then remove the previous secret. A pre-rewrite backup still requires the former secret.
Signal handling and configurable drain delays belong to the conventional Actix process. Vercel
manages function instance termination; the shared route-level readiness check still reports
database availability, but function deployments do not run the server signal loop.
