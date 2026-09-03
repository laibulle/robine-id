# Robine ID

[![build](https://ci.base59.dev/badges/github/laibulle/robine-id/build.svg)](https://ci.base59.dev/repositories)
[![coverage](https://ci.base59.dev/badges/github/laibulle/robine-id/coverage.svg)](https://ci.base59.dev/repositories)

Robine ID is a compact OpenID Connect provider written in Go. It implements the Authorization Code Flow with PKCE, signed ID tokens, JWKS, UserInfo, consent, secure browser sessions, and RP-initiated logout. The UI is server-rendered HTML progressively enhanced with a vendored copy of HTMX, so every authentication journey still works without JavaScript.

The runtime is designed for small containers and scale-to-zero platforms such as Google Cloud Run. Configuration and encrypted signing keys use a storage port with local-filesystem and S3-compatible adapters.

## Architecture

The code follows a hexagonal architecture:

```text
cmd/robine-id                 composition root
internal/domain               protocol entities and errors
internal/application          provider use cases
internal/ports                inbound/outbound contracts
internal/adapters/config      strict JSON configuration
internal/adapters/blob        local and S3 object storage
internal/adapters/keystore    encrypted persistent signing keys
internal/adapters/memory      runtime code/token/session stores
internal/adapters/httpserver  HTTP routes, templates, and HTMX
```

The application layer has no dependency on HTTP, AWS, templates, or the local filesystem.

## Run locally

Requirements: Go 1.27 or newer.

```sh
make dev
```

This starts the development proxy on port `4001`, automatically rebuilds the Go server and reloads open browser pages when Go, templates, styles, scripts, configuration, or brand assets change. Air is version-pinned and runs through `go run`, so no global installation is required. Generated state stays under `.dev/state` and secure cookies are disabled for local HTTP. Override the public port normally, for example `PORT=8081 make dev`.

The checked-in development identity is `admin@example.com` with password `change-me`. It is development-only and must be replaced before production use.

Useful URLs:

- Home: <http://localhost:4001>
- Documentation: <http://localhost:4001/docs>
- Liveness: <http://localhost:4001/health/live>
- Readiness: <http://localhost:4001/health/ready>
- Discovery: <http://localhost:4001/default/.well-known/openid-configuration>

Run the full quality gate:

```sh
make check
```

This runs formatting verification, `go vet`, the race-enabled test suite, and an enforced total coverage threshold of 80%.

## Configuration

The existing JSON schema remains the source of truth:

- `config/robine_id.json` contains issuers, users, claims, branding, authentication policy, and operational settings.
- `config/applications/*.json` contains one relying-party client per file.
- unknown JSON fields and unsafe client/redirect policies fail startup.
- HTTP redirect URIs are allowed only for loopback development clients.

Local storage is the default:

```sh
ROBINE_ID_BLOB_STORE=local
ROBINE_ID_STORAGE_ROOT=config
ROBINE_ID_CONFIG_KEY=robine_id.json
ROBINE_ID_APPLICATIONS_PREFIX=applications
ROBINE_ID_STATE_ROOT=state
ROBINE_ID_SIGNING_KEY=signing_keys.json.enc
```

`ROBINE_ID_CONFIG=/absolute/path/to/robine_id.json` is a convenience override for local deployments.

### S3-compatible storage

Configuration and signing keys can be stored in AWS S3, Google Cloud Storage through an S3-compatible gateway, MinIO, or another compatible service:

```sh
ROBINE_ID_BLOB_STORE=s3
ROBINE_ID_STATE_BLOB_STORE=s3
ROBINE_ID_S3_BUCKET=robine-id
ROBINE_ID_S3_PREFIX=configuration
ROBINE_ID_S3_STATE_PREFIX=state
AWS_REGION=eu-west-1
```

Standard AWS credential discovery is used. Set `ROBINE_ID_S3_ENDPOINT` for MinIO or another custom endpoint. Configuration and state may use different drivers: for example, configuration in S3 and signing keys on a persistent local volume.

Signing-key material is encrypted with AES-256-GCM using a key derived from `SECRET_KEY_BASE`. Local replacements use an atomic rename and mode `0600`; S3 replaces the complete object atomically from readers' perspective. Preserve both the encrypted object and its matching secret.

## Docker

```sh
cp .env.release.example .env.release
# Replace every placeholder in .env.release.
docker compose -f compose.release.yml build
docker compose -f compose.release.yml up -d
curl --fail http://127.0.0.1:4001/health/ready
```

The final container runs as an unprivileged user, listens on `PORT`, and contains a single stripped Go binary plus CA certificates and timezone data. The Compose example mounts configuration read-only and keeps encrypted signing keys in a persistent volume.

For Cloud Run, push the same image and set `PORT=8080`, `SECRET_KEY_BASE`, the storage variables, and any client-secret environment references. Do not rely on the container filesystem for persistent keys when scaling to zero.

## OIDC endpoints

For issuer `https://id.example/default`:

| Capability | Endpoint |
| --- | --- |
| Discovery | `GET /default/.well-known/openid-configuration` |
| Authorization | `GET`, `POST /default/authorize` |
| Token | `POST /default/token` |
| UserInfo | `GET`, `POST /default/userinfo` |
| JWKS | `GET /default/jwks.json` |
| Logout | `GET`, `POST /default/logout` |

Authorization codes are random, hash-indexed, short-lived, single-use, and bound to issuer, client, redirect URI, subject, nonce, and PKCE challenge. ID tokens are signed with RS256. Access tokens are opaque bearer values and only their hashes are used as lookup keys.

The runtime code, access-token, session, and rate-limit adapters are currently process-local. Replace those ports with a shared implementation before enabling more than one Cloud Run instance.
