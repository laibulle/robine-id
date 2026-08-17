# Robine ID Release Operations

## Deployment contract

The supported self-hosted topology is the non-root Actix container behind Caddy plus PostgreSQL 17.
Caddy terminates TLS for `id.base59.dev` and proxies to `127.0.0.1:4001`. The canonical
`Dockerfile` contains only the Rust runtime and its operational commands; Phoenix is not present in
the production image.

PostgreSQL holds authorization transactions, access grants, sessions, rate-limit counters, schema
migrations, and AES-256-GCM encrypted signing keys. Root and application configuration are mounted
read-only and reload atomically. An invalid candidate leaves the last valid revision active.

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
independently of stored signing keys.

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
checks migrations, readiness, documentation, discovery, CLI utilities, and the non-root user. It
then completes login, consent, PKCE code exchange, UserInfo, replay rejection, and logout across two
Actix containers sharing PostgreSQL. Finally, it takes a logical dump, recreates the database,
restores the dump, and proves that the access grant and encrypted signing key remain usable. It
deletes only its temporary containers, network, volume, and files.

Confirm that:

- `id.base59.dev` resolves to the deployment host;
- Caddy proxies that hostname to `127.0.0.1:4001`;
- `.env.release` contains every environment-backed client secret;
- `POSTGRES_PASSWORD` and `KEY_ENCRYPTION_SECRET` are independent and stored outside Git;
- no other process owns port 4001;
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
a login, code exchange, UserInfo request, and logout through every configured relying application.

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

The active key changes once; retained public keys remain in JWKS for existing token verification.

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
