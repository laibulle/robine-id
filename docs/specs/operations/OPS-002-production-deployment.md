# OPS-002 — Production Deployment

## Status

Rust production target

## Summary

Robine ID runs as an unprivileged Actix service behind a trusted HTTPS reverse proxy. PostgreSQL is
the shared durable store for protocol state and encrypted signing keys.

## Requirements

- Production MUST provide PostgreSQL through `DATABASE_URL` or the documented `PG*` variables.
- Production MUST provide `KEY_ENCRYPTION_SECRET` with at least 32 bytes of deployment-specific entropy.
- The canonical operator generator MUST emit an environment-file-safe `KEY_ENCRYPTION_SECRET`
  containing exactly 384 bits of operating-system entropy, zeroize its raw random buffer, and be
  included in the production image.
- A staged encryption-secret rotation MUST support a distinct, equally strong
  `KEY_ENCRYPTION_SECRET_PREVIOUS`, an atomic re-encryption command, and removal of the previous
  secret after verification.
- Partial database credentials, invalid connection URLs, non-Unicode environment values, and
  out-of-range pool/timeout settings MUST fail initialization without echoing secret values.
- `HOST` MUST be non-empty, `PORT` MUST be 1 through 65535, proxy trust MUST use an explicit
  boolean spelling, and reload, cleanup, drain, and shutdown intervals MUST remain inside their
  documented bounds. Invalid values MUST fail before the server binds and MUST NOT be echoed.
- `ROBINE_ID_CONFIG` and `ROBINE_ID_APPLICATIONS_DIR` MUST identify readable operator-managed configuration.
- TLS MUST terminate at the service or a trusted proxy. Forwarded headers MUST be honored only when `TRUST_PROXY_HEADERS=true`.
- HSTS, CSP, no-sniff, frame denial, referrer policy, and a correlation identifier MUST be returned.
- Embedded SQL migrations MUST complete before readiness becomes true.
- PostgreSQL pool acquisition and statement execution MUST use independent bounded timeouts.
- Startup MUST fail or readiness MUST remain false for missing database/secret inputs, invalid configuration, or migration failure.
- The service MUST run as a non-root OS user.
- The conventional application container MUST use a read-only root filesystem, drop Linux
  capabilities, and prevent privilege escalation.
- PostgreSQL and `KEY_ENCRYPTION_SECRET` MUST be backed up through independent operator-controlled systems.
- The canonical image MUST include idempotent signing-key rotation and elapsed-retained-key pruning
  commands plus transactional key re-encryption; startup and conventional maintenance MUST prune
  only persisted deadlines that elapsed.
- The canonical container image MUST contain the Rust runtime and MUST NOT require BEAM, Erlang, Elixir, Node.js, or Phoenix.
- Default browser assets MUST be embedded in that Rust runtime so both the conventional image and
  Vercel entrypoint work without a mutable or separately deployed static directory.
- Container readiness MUST use the bounded native Rust healthcheck binary; the runtime image MUST
  NOT install a general-purpose HTTP client solely to poll itself.
- The image's embedded runtime configuration MUST contain no development identity or relying
  application; development examples MAY be mounted only by the development Compose profile.
- The same route implementation MUST compile for the conventional Actix server and Vercel Function entrypoint.
- Public compressible representations MUST negotiate supported content encodings through that
  shared route implementation and emit `Vary: Accept-Encoding`; sensitive routes MUST remain
  outside compression.
- A warm Vercel process MUST reuse one initialized Actix route service and apply bounded
  back-pressure plus a fixed concurrency ceiling instead of constructing a new Actix system or
  spawning unbounded request work for every invocation. Saturation MUST return a non-sensitive,
  retryable response with the standard security headers.
- The conventional server MUST handle SIGTERM and SIGINT by disabling readiness, waiting the configured drain delay, and then asking Actix to stop gracefully within a bounded timeout.
- Failure to install one platform signal listener MUST emit an operational error and retain the
  other supported graceful-shutdown path rather than panic a running process.
- Failure to install the Unix `SIGHUP` listener MUST retain periodic configuration reload. A valid
  `SIGHUP` MUST trigger the same fail-closed atomic reload pipeline without affecting readiness.
- The orchestrator stop grace period MUST exceed the drain delay plus the Actix shutdown timeout.

## Release procedure

1. Validate Rust and legacy parity gates with `make preflight`.
2. Run the isolated canonical stack, two-instance OIDC journey, and recovery test with `make release-smoke`.
3. Provision configuration, PostgreSQL, key-encryption secret, and client secrets.
4. Start the stack and wait for `/health/ready` to report the intended semantic revision.
5. Complete discovery, login, consent, callback, code exchange, refresh rotation, UserInfo,
   client-credentials issuance, introspection, revocation, and logout through real clients.
6. Take and restore-test a logical PostgreSQL backup with the matching encryption secret.

## Rollback and recovery

- A rollback MUST preserve the public issuer URL and compatible configuration/database schemas.
- Restoring encrypted signing keys requires the matching `KEY_ENCRYPTION_SECRET`.
- Configuration rollback SHOULD restore a previously validated complete document.
- Application rollback MUST NOT automatically restore an older database backup.
- A recovery drill MUST prove that the restored current and retained keys publish the same `kid` values.

## Scaling

Pushed authorization requests, authorization codes, access/refresh tokens, sessions, rate limits,
and signing keys use PostgreSQL with atomic
consumption/update operations. Multiple Actix or Vercel instances MAY share one database and immutable
configuration. Operators MUST size the connection pool per instance and coordinate migrations and key
rotation. File-backed hot reload is a conventional-server feature; Vercel configuration is immutable per deployment.

## Acceptance criteria

- The canonical Docker/Compose stack starts without source-tree mutation.
- Restart preserves signing identity, sessions, access grants, and unexpired authorization state.
- Readiness remains false until configuration, migrations, and database connectivity succeed.
- The canonical image runs as `robine-id` and contains no Phoenix runtime.
- The canonical image contains and uses `robine-id-healthcheck` and does not contain `curl`.
- Starting the bare image cannot expose the checked-in development credentials.
- The release gate MUST prove that invalid database environment values stop initialization without
  reproducing submitted URL, password, secret, or invalid numeric text.
- The release gate MUST prove that an invalid conventional-server setting stops initialization
  without reproducing the submitted value.
- Compose proves the application container is non-root, read-only, capability-free, and protected
  by `no-new-privileges`.
- The release gate MUST prove that SIGTERM makes an instance not-ready but live during drainage and that the container exits with status zero.
- The Vercel release binary compiles from the same Actix routes.
- Vercel adapter tests MUST prove sequential and concurrent requests reuse one warm Actix worker.
- Vercel adapter tests MUST prove a full worker queue returns a correlated, secure HTTP 503 with a
  bounded retry indication. Registered public-browser token, PAR, and revocation requests MUST be
  able to read that indication through the same exact-origin CORS policy, without granting CORS to
  another method, path, duplicate origin, confidential client, or unrelated origin.
- The automated release gate passes a pushed authorization request, form-post response, pending authorization, session, authorization code, user and service access
  grants, rotating refresh family with replay detection, introspection, revocation, and logout
  transaction between two instances sharing PostgreSQL.
- The automated recovery gate restores the current signing key, a live access grant, and an active
  refresh family from a logical PostgreSQL dump using the matching key-encryption secret.
- The automated recovery gate MUST preserve a retained signing key and its deadline, then prove
  elapsed-key pruning leaves the active key published.
- The release gate MUST re-encrypt active and retained keys with a new secret, then prove the same
  JWKS is readable after the previous secret is removed.
- A real client completes the full OIDC journey through the production proxy.

## Non-goals

Kubernetes manifests, automated certificate issuance, provider-specific secret managers, and managed
PostgreSQL provisioning are platform-specific and outside this specification.
