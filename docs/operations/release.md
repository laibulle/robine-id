# Production release

Robine ID ships as a small, unprivileged Go container. The same image runs behind Caddy, on Cloud Run, or in any OCI environment.

## Required inputs

- a validated `robine_id.json` and `applications/` prefix;
- a unique `SECRET_KEY_BASE` containing at least 32 random characters;
- a durable local or S3-compatible state backend for `signing_keys.json.enc` and account overrides;
- HTTPS at the platform ingress and secure cookies enabled.

## Verification and build

```sh
make check
docker build --tag robine-id:release .
```

Start with the Compose example:

```sh
cp .env.release.example .env.release
docker compose -f compose.release.yml up --build --detach
curl --fail http://127.0.0.1:4001/health/ready
```

Complete discovery, login, consent, callback, code exchange, UserInfo, account, administration, and logout against a real relying party before promoting a revision.

## Cloud Run

Use the S3 adapter or another durable state adapter when the service can scale to zero. The container filesystem is not a durable signing-key backend. Set a temporary maximum of one instance while authorization codes, access tokens, sessions, and rate limits use the built-in memory adapters.

## Backup and restore

Back up the complete state prefix and preserve its matching `SECRET_KEY_BASE`. A restore is successful only when `/jwks.json` publishes the same active `kid` and an ID token created before the backup still verifies. Never silently replace a corrupt encrypted key object.
