# Robine ID Release Operations

## Deployment contract

The supported self-hosted topology is the non-root Actix container behind Caddy plus PostgreSQL 17.
Caddy terminates TLS for `id.base59.dev` and proxies to `127.0.0.1:4001`. The canonical
`Dockerfile` contains only the Rust runtime and its operational commands; Phoenix is not present in
the production image. Compose additionally makes the application root filesystem read-only, drops
all Linux capabilities, and enables `no-new-privileges`; only a small temporary in-memory filesystem
is writable. Docker and Compose poll readiness through the bounded native
`robine-id-healthcheck` binary, so the runtime image does not carry `curl` just to call itself.

PostgreSQL holds pushed and interactive authorization transactions, access grants, rotating refresh-token families,
sessions, rate-limit counters, schema migrations, and AES-256-GCM encrypted signing keys. Root and
application configuration are mounted read-only and reload atomically. An invalid candidate leaves
the last valid revision active.
Pool acquisition and each PostgreSQL statement have independent five-second defaults through
`DATABASE_ACQUIRE_TIMEOUT_MS` and `DATABASE_STATEMENT_TIMEOUT_MS`, so dependency stalls fail within
a bounded request window.
All database environment settings are validated strictly before the pool is created. A malformed
URL, partial `PG*` credential set, missing/weak encryption secret, or invalid numeric bound stops
startup with an allowlisted diagnostic that never echoes the submitted value.
Actix process settings follow the same fail-closed rule. `PORT` accepts 1 through 65535;
`ROBINE_ID_RELOAD_INTERVAL` accepts 0 or 100 through 60000 milliseconds;
`DATABASE_CLEANUP_INTERVAL` accepts 0 or 60 through 86400 seconds; drain accepts 0 through 300000
milliseconds; shutdown accepts 1 through 300 seconds; and proxy trust accepts only
`true`/`false` or `1`/`0`. Zero disables the two periodic tasks.

On SIGTERM or SIGINT, the Actix process immediately reports not-ready, remains live for
`DRAIN_DELAY_MILLISECONDS` (3 seconds by default), then gracefully stops HTTP workers with
`SHUTDOWN_TIMEOUT_SECONDS` (10 seconds by default). Compose allows 20 seconds before forcing the
container, which exceeds both configured phases with margin.

## Required inputs

- `deploy/config/robine_id.json`: root production configuration.
- `deploy/config/applications/*.json`: one document per production relying application.
- `.env.release`: deployment secrets copied from `.env.release.example`; never commit it.
- `robine_id_postgres`: persistent PostgreSQL data volume managed by Compose.

Replace the checked-in development identity, bcrypt hash, and issuer before the first deployment.
Generate independent secrets:

```sh
openssl rand -base64 48 # POSTGRES_PASSWORD
openssl rand -base64 48 # KEY_ENCRYPTION_SECRET
```

`KEY_ENCRYPTION_SECRET` encrypts RSA private material before database persistence. A usable restore
requires both the PostgreSQL backup and the matching encryption secret. Do not rotate this secret
independently of stored signing keys; use the staged procedure below.

Ensure the unprivileged application container can traverse its bind mounts:

```sh
chmod 755 deploy deploy/config deploy/config/applications
chmod 644 deploy/config/robine_id.json
find deploy/config/applications -type f -name '*.json' -exec chmod 644 {} +
```

## Preflight

```sh
make preflight
docker compose --env-file .env.release -f compose.release.yml config --quiet
make release-smoke
```

`make release-smoke` creates an isolated Compose project on port 4011, builds the canonical image,
checks migrations, readiness, documentation, discovery, CLI utilities, the non-root user, and
strict non-leaking rejection of invalid database and Actix server environments. It
then pushes and consumes a single-use authorization request across instances, delivers and
exchanges a form-posted code, issues and revokes a machine token, and completes login, consented offline access, PKCE code exchange, refresh rotation, UserInfo,
introspection, revocation, replay rejection, and logout across two Actix containers sharing
PostgreSQL. It sends SIGTERM to the peer, verifies not-ready/live drainage and a zero exit status,
then rotates the signing key twice with the same idempotency key. Finally, it takes a
logical dump, recreates the database, restores the dump, and proves that the access grant, active
refresh family, and current and retained encrypted signing keys remain usable. The gate then
re-encrypts active and retained keys under a new wrapping secret, removes the previous-secret
fallback, and proves the JWKS is unchanged. It then expires and prunes retained keys while proving
that the active key remains published. It deletes only its temporary containers, network, volume,
and files.

Confirm that:

- `id.base59.dev` resolves to the deployment host;
- Caddy proxies that hostname to `127.0.0.1:4001`;
- `.env.release` contains every environment-backed client secret;
- `POSTGRES_PASSWORD` and `KEY_ENCRYPTION_SECRET` are independent and stored outside Git;
- no other process owns port 4001;
- the platform termination grace exceeds `DRAIN_DELAY_MILLISECONDS / 1000 + SHUTDOWN_TIMEOUT_SECONDS`;
- a logical PostgreSQL backup exists before an upgrade.

## Deploy

```sh
docker compose --env-file .env.release -f compose.release.yml up -d --build --wait
docker compose --env-file .env.release -f compose.release.yml ps
docker compose --env-file .env.release -f compose.release.yml logs --tail=100 robine-id
```

Verify the local service and public proxy:

```sh
curl --fail http://127.0.0.1:4001/health/ready
curl --fail http://127.0.0.1:4001/metrics
curl --fail https://id.base59.dev/default/.well-known/openid-configuration
```

The discovery document must advertise `https://id.base59.dev/default` and HTTPS endpoints. Complete
a login, code exchange, UserInfo request, refresh rotation where configured, and logout through
every configured relying application. For every service client, also issue, introspect, revoke, and
re-introspect a `client_credentials` token with an allowed service scope.

## Configuration reload

Edits to `deploy/config/robine_id.json` and `deploy/config/applications/*.json` are detected by the
Actix server. The complete candidate is validated before atomic activation. Invalid or partially
written files are logged once while the previous revision continues serving traffic. Restart only
for environment changes such as database credentials, key-encryption secret, proxy trust, or pool
size.

Validate a candidate before atomically renaming it into the watched directory:

```sh
ROBINE_ID_CONFIG=/candidate/robine_id.json \
ROBINE_ID_APPLICATIONS_DIR=/candidate/applications \
cargo run --bin validate_config
```

## Backup and restore

Create a consistent logical backup without stopping the application:

```sh
mkdir -p backups
docker compose --env-file .env.release -f compose.release.yml exec -T postgres \
  pg_dump --username robine_id --dbname robine_id --format=custom \
  > "backups/robine-id-$(date +%Y%m%d%H%M%S).dump"
```

Store `.env.release` in the deployment secret store, not beside the database dump. Test restores in
an isolated PostgreSQL instance. To restore into an intentionally empty database:

```sh
docker compose --env-file .env.release -f compose.release.yml stop robine-id
docker compose --env-file .env.release -f compose.release.yml exec -T postgres \
  pg_restore --username robine_id --dbname robine_id --clean --if-exists < backups/robine-id.dump
docker compose --env-file .env.release -f compose.release.yml start robine-id
```

Validate readiness, JWKS, and an ID token signed with the restored current key.
The isolated equivalent of this recovery sequence runs automatically in `make release-smoke` and
in both branch and tag CI workflows.

## Key rotation

Use a stable deployment identifier so retries are idempotent:

```sh
docker compose --env-file .env.release -f compose.release.yml exec -T robine-id \
  rotate_keys default deployment-2026-08
```

The active key changes once. At rotation time, Robine ID stores a retention deadline equal to the
greater ID-token/JWT-access-token lifetime plus clock skew plus a five-minute safety margin. That captured deadline does not
shrink if configuration changes later. Retained public keys remain in JWKS until it elapses.

For scheduled rollover, set `token_policy.signing_key_rotation_interval` to 3,600 through
31,536,000 seconds. The conventional server checks every five minutes and during startup. The age
decision and update are serialized on the active PostgreSQL row, so replicas do not generate
multiple active replacements. Keep the manual command for emergency or deployment-specific
rotation.

Conventional servers prune elapsed retained keys at startup and with hourly database maintenance.
The operation is idempotent and never targets the active key. Run it explicitly when desired:

```sh
docker compose --env-file .env.release -f compose.release.yml exec -T robine-id \
  prune_keys
```

The command prints the number of deleted retained keys. `make keys-prune` is the local-development
equivalent. Backup and restore preserve both encrypted retained keys and their deadlines.

## Encryption-secret rotation

Rotate the wrapping secret without changing public keys or invalidating ID tokens:

1. Generate a new independent secret of at least 32 bytes.
2. Roll every application instance with the new value in `KEY_ENCRYPTION_SECRET` and the former
   value in `KEY_ENCRYPTION_SECRET_PREVIOUS`. New keys are encrypted with the new secret while old
   rows remain readable through the fallback.
3. Run the canonical image command once:

   ```sh
   docker compose --env-file .env.release -f compose.release.yml run --rm --no-deps \
     --entrypoint /usr/local/bin/reencrypt_keys robine-id
   ```

4. Verify readiness, JWKS, a new ID token, and retained-key validation.
5. Remove `KEY_ENCRYPTION_SECRET_PREVIOUS` and roll every instance again.
6. Take a new backup paired with the new secret. Keep pre-rotation backups paired with the former
   secret until their retention period ends.

`reencrypt_keys` locks and rewrites every active and retained row in one transaction. A malformed,
matching, or weak previous secret fails without echoing either value; a wrong previous secret rolls
the transaction back. Do not remove the fallback before the command and verification succeed.

## Rollback

Retag the previous Rust image, restore the previous validated configuration, and run:

```sh
ROBINE_ID_IMAGE=registry.example/robine-id:previous \
docker compose --env-file .env.release -f compose.release.yml up -d --no-deps robine-id
```

Do not restore an older PostgreSQL backup merely to roll back application code. SQL migrations are
forward-only; inspect compatibility before a rollback. Recheck readiness, discovery, JWKS, login,
token exchange, UserInfo, and logout.

## Release checklist

1. `make preflight` and `make release-smoke` pass.
2. Production configuration contains no development identity or redirect URI.
3. PostgreSQL and key-encryption secrets are present only in the secret store.
4. A logical database backup and matching encryption secret are recoverable.
5. Caddy readiness and discovery checks pass.
6. Every relying application completes the full OIDC and logout flow.
7. The deployed image user is `robine-id`, not root.

## Automated tag releases

Pushing a semantic version tag matching `v*` runs the Robine CI release workflow. It first executes
the full production smoke/recovery gate through an isolated Docker daemon, then builds the canonical
Rust image, exports it with `docker save`, generates a SHA-256 checksum, and publishes the retained
payload to the matching GitHub Release.
