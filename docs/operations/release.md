# Robine ID Release Operations

## Deployment Contract

The supported MVP topology is one Robine ID container behind Caddy. Caddy terminates TLS for `id.base59.dev` and proxies to `127.0.0.1:4001`. SQLite, authorization state, and signing-key coordination are single-instance concerns.

The image runs as an unprivileged user, exposes port 4001, includes an HTTP readiness healthcheck, and starts the Phoenix release through `/app/bin/server`. Database migrations run during release application startup. Configuration is mounted read-only; SQLite and encrypted signing keys use the `/data` volume.

## Required Inputs

- `deploy/config/robine_id.json`: root production configuration.
- `deploy/config/applications/*.json`: one file per production relying application. The directory is intentionally empty in the repository.
- `.env.release`: deployment secrets and runtime settings, copied from `.env.release.example` and never committed.
- `robine_id_data`: persistent Docker volume containing SQLite and `signing_keys.bin`.

Before the first deployment, replace the checked-in development identity and password hash in `deploy/config/robine_id.json`.

Generate `SECRET_KEY_BASE` with:

```sh
mix phx.gen.secret
```

`SECRET_KEY_BASE` encrypts both browser sessions and the persistent signing-key envelope. Preserve it with the data-volume backup. Changing it without rotating or migrating stored material prevents signing-key recovery.

The container runs as an unprivileged user. Make its read-only bind mounts traversable and readable. These files contain references and password hashes, but no OIDC client secret:

```sh
chmod 755 deploy deploy/config deploy/config/applications
chmod 644 deploy/config/robine_id.json
find deploy/config/applications -type f -name '*.json' -exec chmod 644 {} +
```

## Preflight

```sh
mix precommit
ROBINE_ID_APPLICATIONS_DIR="$PWD/deploy/config/applications" \
  mix robine_id.config.validate deploy/config/robine_id.json
docker compose -f compose.release.yml config --quiet
docker compose -f compose.release.yml build
```

Confirm that:

- `id.base59.dev` resolves to the deployment host;
- Caddy proxies that hostname to `127.0.0.1:4001`;
- `.env.release` contains every environment-backed secret referenced by the production application files;
- no other process owns port 4001;
- the persistent volume has been backed up before an upgrade.

## Deploy

```sh
docker compose -f compose.release.yml up -d
docker compose -f compose.release.yml ps
docker compose -f compose.release.yml logs --tail=100 robine-id
```

Verify both the container-local healthcheck and the public proxy:

```sh
curl --fail http://127.0.0.1:4001/health/ready
curl --fail https://id.base59.dev/default/.well-known/openid-configuration
```

The discovery document must advertise `https://id.base59.dev/default` and public HTTPS endpoints. Complete a real login through each configured relying application before declaring the release successful.

## Configuration Reload

Edits to `deploy/config/robine_id.json` and `deploy/config/applications/*.json` are detected automatically. The complete composed configuration is validated before activation. Invalid files retain the last valid revision. Container restart is required only for runtime environment changes, including secrets, database paths, host, port, and reload interval.

Use atomic file replacement when automation writes configuration: create the candidate outside the watched directory, validate it, then rename it into place.

## Backup and Restore

Stop the service before taking a filesystem-level volume backup so SQLite and the key envelope are mutually consistent:

```sh
docker compose -f compose.release.yml stop robine-id
docker run --rm \
  -v robine-id_robine_id_data:/source:ro \
  -v "$PWD/backups:/backup" \
  debian:trixie-slim \
  tar -C /source -czf /backup/robine-id-data.tar.gz .
docker compose -f compose.release.yml start robine-id
```

Back up `.env.release` through the deployment secret store, not Git. A usable restore requires both the volume archive and the exact matching `SECRET_KEY_BASE`.

## Rollback

Retag or rebuild the previous application revision, restore the previous validated configuration, and run:

```sh
docker compose -f compose.release.yml up -d --no-deps robine-id
```

Do not restore an older data volume unless the application rollback is incompatible with the current schema or stored keys. Validate readiness, discovery, JWKS, and a real login after rollback.

## Release Checklist

1. `mix precommit` passes.
2. Production configuration validates with the application directory.
3. The Docker image builds from a clean checkout.
4. The development identity and password are replaced.
5. Secrets are present only in `.env.release` or the deployment secret store.
6. The data volume and `SECRET_KEY_BASE` are backed up.
7. Readiness and discovery pass through Caddy.
8. Every configured relying application completes login, token exchange, UserInfo, and callback.

## Automated Tag Releases

Pushing a semantic version tag matching `v*` runs the Robine CI release
workflow. It builds the production image through an isolated Docker daemon,
exports it with `docker save`, generates a SHA-256 checksum, and publishes the
retained payload to the matching GitHub Release through the GitHub App. The
GitHub App installation requires `Contents: write`; no installation token is
exposed to the build container.
