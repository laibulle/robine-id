# OPS-002 — Production Deployment

## Status

MVP target

## Summary

Robine ID runs as one Phoenix release behind a trusted HTTPS reverse proxy with explicit secrets, configuration, and persistent signing-key storage.

## Requirements

- Production MUST provide `SECRET_KEY_BASE` with deployment-specific high-entropy material.
- `PHX_HOST` MUST match the public host used by configured issuer URLs.
- `PHX_SERVER=true` MUST enable the HTTP server in a release; `PORT` and `POOL_SIZE` MAY tune runtime defaults.
- `ROBINE_ID_CONFIG` SHOULD point to an operator-managed immutable configuration document.
- `DATABASE_PATH` or the storage configuration MUST resolve to a writable SQLite path for readiness and future persistent adapters.
- The signing-key path MUST be on a persistent, backed-up filesystem and writable only by the service account.
- The deployment MUST preserve `SECRET_KEY_BASE` together with the encrypted signing-key file across restart and rollback.
- TLS MUST terminate either in the endpoint or a trusted proxy. Forwarded HTTPS information MUST be accepted only from trusted infrastructure.
- Production MUST force HTTPS and HSTS. Health-check routing MAY be exempted only when required inside a protected network.
- Database migrations MUST complete before the release accepts production traffic.
- Static assets MUST be built and digested with `mix assets.deploy` before assembling the release.
- Startup MUST fail on missing required secrets, invalid configuration, unavailable key material, or unrecoverable migration failure.
- The service MUST run as a non-root OS user with least filesystem privilege.

## Release Procedure

1. Validate the candidate configuration with `mix robine_id.config.validate`.
2. Run `mix precommit` and `mix assets.deploy` from a clean checkout.
3. Build the production release with the target runtime versions.
4. Provision the configuration, database location, signing-key volume, and secrets.
5. Start one instance and wait for `/health/ready` to report the intended revision.
6. Complete the real relying-party smoke flow: discovery, login, consent, callback, code exchange, UserInfo, and logout.
7. Record the accessibility and interoperability checks from the specification index.
8. Back up newly initialized signing-key material before considering the deployment recoverable.

## Rollback and Recovery

- A rollback MUST preserve the same public issuer URL and compatible configuration schema.
- Restoring signing keys requires both the encrypted file and the matching `SECRET_KEY_BASE`.
- Losing access-token or session memory after restart is expected; clients and users reauthenticate.
- A corrupt signing-key file MUST be restored from backup rather than silently replaced, because replacement breaks verification of outstanding ID tokens.
- Configuration rollback SHOULD reapply a previously validated complete document, not edit active state manually.

## Scaling Constraint

The MVP is single-instance. Codes, access tokens, sessions, rate-limit counters, configuration history, and audit history are not coordinated between nodes. DNS clustering does not make these stores distributed. Horizontal scaling requires shared adapters, cross-node atomic code consumption, shared session/rate-limit state, and a coordinated signing-key strategy before it is supported.

## Acceptance Criteria

- A production release starts from documented environment and filesystem inputs without source-tree mutation.
- Restart preserves issuer signing identity but invalidates only documented node-local state.
- Readiness remains false until configuration and database checks succeed.
- A restore drill proves that backed-up signing keys remain decryptable and published with the same `kid` values.
- A real client completes the full MVP journey through the production proxy.

## Non-Goals

Kubernetes manifests, container images, zero-downtime multi-node upgrades, automated certificate issuance, secret-manager integrations, and disaster-recovery automation are platform-specific and outside the MVP specification.
