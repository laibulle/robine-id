# OPS-002 — Production Deployment

## Status

MVP target

## Summary

Robine ID runs as an unprivileged Go container behind a trusted HTTPS ingress. Configuration and security state are supplied through explicit local or S3-compatible object stores.

## Requirements

- Production MUST provide a deployment-specific `SECRET_KEY_BASE` containing at least 32 high-entropy characters.
- `PORT` MUST select the HTTP listener and defaults to `8080`.
- `ROBINE_ID_BLOB_STORE` MUST select `local` or `s3` for configuration.
- `ROBINE_ID_STATE_BLOB_STORE` MAY independently select the persistent signing-key and account backend.
- Local signing-key state MUST live on a persistent, backed-up filesystem and use mode `0600`.
- S3 state MUST be protected by least-privilege credentials and versioning or backup policy.
- The deployment MUST preserve `SECRET_KEY_BASE` together with the encrypted signing-key object across restart and rollback.
- TLS MUST terminate at the platform or a trusted reverse proxy and browser cookies MUST be Secure in production.
- Startup MUST fail on a missing secret, invalid configuration, unavailable required objects, or corrupt signing-key material.
- The service MUST run as a non-root OS user.
- The release candidate MUST pass `make check`, including the race detector and at least 80% statement coverage.

## Release procedure

1. Run `make check` from a clean checkout.
2. Build the production image and record its immutable digest.
3. Provision configuration, state storage, secrets, and HTTPS ingress.
4. Start one instance and wait for `/health/ready` to report the intended revision fingerprint.
5. Complete the real relying-party flow through UserInfo and RP-initiated logout.
6. Record accessibility checks and back up newly initialized signing-key state.

## Scaling constraint

The built-in authorization-code, access-token, authenticated-session, and rate-limit adapters are process-local. Horizontal scaling requires shared implementations of those ports. Local and S3 blob adapters make configuration, keys, and account overrides portable but do not make the runtime protocol stores distributed.
