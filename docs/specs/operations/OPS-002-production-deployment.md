# OPS-002 — Production Deployment

## Status

Rust production target

## Summary

Robine ID runs as an unprivileged Actix service behind a trusted HTTPS reverse proxy. PostgreSQL is
the shared durable store for protocol state and encrypted signing keys.

## Requirements

- Production MUST provide PostgreSQL through `DATABASE_URL` or the documented `PG*` variables.
- Production MUST provide `KEY_ENCRYPTION_SECRET` with at least 32 bytes of deployment-specific entropy.
- `ROBINE_ID_CONFIG` and `ROBINE_ID_APPLICATIONS_DIR` MUST identify readable operator-managed configuration.
- TLS MUST terminate at the service or a trusted proxy. Forwarded headers MUST be honored only when `TRUST_PROXY_HEADERS=true`.
- HSTS, CSP, no-sniff, frame denial, referrer policy, and a correlation identifier MUST be returned.
- Embedded SQL migrations MUST complete before readiness becomes true.
- Startup MUST fail or readiness MUST remain false for missing database/secret inputs, invalid configuration, or migration failure.
- The service MUST run as a non-root OS user.
- PostgreSQL and `KEY_ENCRYPTION_SECRET` MUST be backed up through independent operator-controlled systems.
- The canonical container image MUST contain the Rust runtime and MUST NOT require BEAM, Erlang, Elixir, Node.js, or Phoenix.
- The same route implementation MUST compile for the conventional Actix server and Vercel Function entrypoint.

## Release procedure

1. Validate Rust and legacy parity gates with `make preflight`.
2. Run the isolated canonical stack, two-instance OIDC journey, and recovery test with `make release-smoke`.
3. Provision configuration, PostgreSQL, key-encryption secret, and client secrets.
4. Start the stack and wait for `/health/ready` to report the intended semantic revision.
5. Complete discovery, login, consent, callback, code exchange, UserInfo, and logout through a real relying party.
6. Take and restore-test a logical PostgreSQL backup with the matching encryption secret.

## Rollback and recovery

- A rollback MUST preserve the public issuer URL and compatible configuration/database schemas.
- Restoring encrypted signing keys requires the matching `KEY_ENCRYPTION_SECRET`.
- Configuration rollback SHOULD restore a previously validated complete document.
- Application rollback MUST NOT automatically restore an older database backup.
- A recovery drill MUST prove that the restored current and retained keys publish the same `kid` values.

## Scaling

Authorization codes, access tokens, sessions, rate limits, and signing keys use PostgreSQL with atomic
consumption/update operations. Multiple Actix or Vercel instances MAY share one database and immutable
configuration. Operators MUST size the connection pool per instance and coordinate migrations and key
rotation. File-backed hot reload is a conventional-server feature; Vercel configuration is immutable per deployment.

## Acceptance criteria

- The canonical Docker/Compose stack starts without source-tree mutation.
- Restart preserves signing identity, sessions, access grants, and unexpired authorization state.
- Readiness remains false until configuration, migrations, and database connectivity succeed.
- The canonical image runs as `robine-id` and contains no Phoenix runtime.
- The Vercel release binary compiles from the same Actix routes.
- The automated release gate passes a pending authorization, session, authorization code, access
  grant, and logout transaction between two instances sharing PostgreSQL.
- The automated recovery gate restores the current signing key and a live access grant from a
  logical PostgreSQL dump using the matching key-encryption secret.
- A real client completes the full OIDC journey through the production proxy.

## Non-goals

Kubernetes manifests, automated certificate issuance, provider-specific secret managers, and managed
PostgreSQL provisioning are platform-specific and outside this specification.
