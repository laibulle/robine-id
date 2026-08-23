# Robine ID

[![build](https://ci.base59.dev/badges/github/laibulle/robine-id/build.svg)](https://ci.base59.dev/repositories)
[![coverage](https://ci.base59.dev/badges/github/laibulle/robine-id/coverage.svg)](https://ci.base59.dev/repositories)
[![release](https://img.shields.io/github/v/release/laibulle/robine-id?display_name=tag&sort=semver)](https://github.com/laibulle/robine-id/releases)

Robine ID is a file-configured OpenID Connect provider built with Elixir and Phoenix. It implements the Authorization Code Flow with PKCE, signed ID tokens, JWKS, UserInfo, consent, secure sessions, and RP-initiated logout. Its certification target is the OpenID Foundation Basic OP and Config OP profiles; see [`docs/operations/openid-certification.md`](docs/operations/openid-certification.md).

It can run as a standalone service or as an embedded OTP dependency mounted inside another Phoenix application. Both modes use the same protocol implementation and configuration model. See [`docs/embedding.md`](docs/embedding.md) for the host contract.

The implementation follows clean architecture. Business domains expose one facade made of `defdelegate` calls; Phoenix, file loading, bcrypt, Ecto, JOSE, Logger, and runtime stores are adapters around use cases and ports. See [`AGENTS.md`](AGENTS.md) for the architectural contract and [`docs/specs`](docs/specs) for normative product requirements.

## Getting started with Docker

You only need Docker. Clone the repository, then prepare the runtime environment:

```sh
cp .env.release.example .env.release
openssl rand -base64 64
```

Put the generated value in `SECRET_KEY_BASE` inside `.env.release`. Set `PHX_HOST` to the hostname that will expose the provider.

The container runs without root privileges. Make the read-only configuration mounts accessible, then build the image:

```sh
chmod 755 deploy deploy/config deploy/config/applications
chmod 644 deploy/config/robine_id.json
docker build -t robine-id:local .
```

Create persistent storage and start the provider:

```sh
docker volume create robine-id-data
docker run --detach \
  --name robine-id \
  --publish 127.0.0.1:4001:4001 \
  --env-file .env.release \
  --env DATABASE_PATH=/data/robine_id.db \
  --volume "$PWD/deploy/config/robine_id.json:/config/robine_id.json:ro" \
  --volume "$PWD/deploy/config/applications:/config/applications:ro" \
  --volume robine-id-data:/data \
  robine-id:local
```

Check readiness and open the built-in documentation:

```sh
curl --fail http://127.0.0.1:4001/health/ready
```

- Home: <http://127.0.0.1:4001>
- Account portal: <http://127.0.0.1:4001/account>
- User administration: <http://127.0.0.1:4001/admin>
- Documentation: <http://127.0.0.1:4001/docs>
- Provider discovery: <http://127.0.0.1:4001/default/.well-known/openid-configuration>

Production relying applications belong in `deploy/config/applications/`, one JSON file per application. That directory is intentionally empty by default; the examples under `config/applications/` are development material and are not mounted into the container. Replace the example identity and issuer in `deploy/config/robine_id.json` before exposing the service publicly.

Stop and remove the container without deleting its persistent SQLite and signing-key volume:

```sh
docker stop robine-id
docker rm robine-id
```

## Local setup

Requirements:

- Elixir 1.17 or newer
- Erlang/OTP compatible with the installed Elixir version
- a C compiler for the bcrypt adapter

Run:

```sh
mix setup
mix phx.server
```

Run the complete quality gate and generate the coverage reports locally with:

```sh
mix precommit
mix coverage
```

Coverage reports are written to `cover/`. The project enforces a 70% threshold;
Robine CI retains the reports for 14 days and publishes the percentage through
the badge above.

Then open <http://localhost:4001>.

The checked-in development configuration contains one public client and one development identity:

- client ID: `development-client`
- redirect URI: `http://localhost:4002/callback`
- user: `admin@example.com`
- password: `change-me`

These credentials are development-only and must be replaced in production.

## Configuration

The default root file is [`config/robine_id.json`](config/robine_id.json). Each relying application has its own document in [`config/applications`](config/applications). Set `ROBINE_ID_CONFIG` to select another root document and `ROBINE_ID_APPLICATIONS_DIR` to override its adjacent `applications/` directory.

Every document declares `schema_version: 1`. The root supports these sections:

- `issuers`: issuer URLs, supported scopes, token policy, claim mappings, and issuer branding;
- `applications/*.json`: exact redirect URIs, post-logout redirect URIs, scopes, grants, authentication, consent, and application branding;
- `users`: local identities with bcrypt password hashes, source claims, and optional roles;
- `claims`: mapping from OIDC claim names to identity sources and required scopes;
- `branding`: product name, assets, accessible theme tokens, locales, message overrides, and legal/support links;
- `reconciliation`: explicit removal policy;
- `authentication`: session and rate-limit policy;
- `storage`: SQLite path, pool size, and encrypted signing-key store path;
- `telemetry`: validated operational log level.

Configuration precedence is deterministic:

```text
built-in safe defaults < global branding < issuer branding < client branding
```

Application secrets may use a typed environment reference:

```json
{
  "type": "confidential",
  "authentication_method": "client_secret_basic",
  "secret_reference": {"provider": "env", "key": "MY_CLIENT_SECRET"}
}
```

For private, operator-controlled configuration, a literal string is also accepted and used directly:

```json
{"secret_reference": "replace-with-the-shared-secret"}
```

Effective configuration output redacts both forms.

HTTP issuer and redirect URLs are accepted only for loopback development hosts. Other URLs must use HTTPS. Unknown fields and incompatible values fail validation before activation.

Every application document declares `schema_version: 1` and `kind: "oidc_application"`. The application watches the complete composed configuration and reloads it every second by default; `ROBINE_ID_RELOAD_INTERVAL` overrides that interval in milliseconds. A valid change activates atomically; an unchanged revision is ignored; an invalid or partially written file is recorded as a failed attempt while the last valid revision remains active.

### Account and administration portal

The root configuration remains the read-only provisioning authority for identities: it creates the available user IDs and sign-in identifiers, and removing a user removes access. In standalone mode, `/account` stores user-managed display name, email, and password changes as durable SQLite overrides. The immutable sign-in identifier is never rewritten.

Add the `admin` role to a configured user to grant access to `/admin`:

```json
{
  "id": "operator",
  "identifier": "operator@example.com",
  "password_hash": "$2b$12$...",
  "name": "Identity Operator",
  "email": "operator@example.com",
  "roles": ["admin"]
}
```

Administrators can update configured users, assign comma-separated roles, and enable or disable accounts. They cannot disable their own account or remove their own `admin` role. Overrides live in the same persistent SQLite database as the service, so database backups include account changes while configuration mounts can remain read-only.

### Configuration commands

```sh
mix robine_id.config.validate path/to/robine_id.json
mix robine_id.config.preview path/to/robine_id.json
mix robine_id.config.apply path/to/robine_id.json
mix robine_id.config.effective
mix robine_id.keys.rotate default deployment-2026-08
mix robine_id.oidc.conformance.configure --alias your-unique-alias
```

`preview` does not mutate state. `apply` validates the complete revision before atomically activating it. Applying an equivalent revision is a no-op. The effective command redacts passwords, hashes, secret references, tokens, and private material.

## OpenID Connect endpoints

For the configured issuer `https://id.base59.dev/default`:

| Capability | Endpoint |
| --- | --- |
| Discovery | `GET /default/.well-known/openid-configuration` |
| Authorization | `GET /default/authorize` |
| Authorization by form POST | `POST /default/authorize` |
| Token | `POST /default/token` |
| UserInfo | `GET`, `POST /default/userinfo` |
| JWKS | `GET /default/jwks.json` |
| Logout | `GET`, `POST /default/logout` |
| Account sign-in | `GET`, `POST /login` |
| Account management | `GET`, `PUT /account` |
| User administration | `GET /admin`, `GET`, `PUT /admin/users/*` |

Authorization requests require `response_type=code` and the `openid` scope. `state` and `nonce` are supported and strongly recommended; an individual client may require a nonce. PKCE using `S256` is mandatory by default and always required for public clients; a confidential integration that cannot send PKCE may opt out explicitly. Redirect URIs match registered values exactly. Authorization codes are short-lived, stored only by hash, bound to issuer/client/redirect/subject/nonce and the PKCE challenge when present, and consumed atomically once. Reuse also revokes the access token obtained from the original exchange.

ID tokens use RS256. JWKS publishes public material only. Private and retained signing keys are persisted through an atomically replaced AES-256-GCM envelope with filesystem mode `0600`, derived from the deployment `SECRET_KEY_BASE`. Key rotation takes a stable rotation identifier; repeating the same identifier is a no-op, while retained keys continue validating tokens issued before rotation and across restarts.

## Operations

- `GET /health/live` reports process liveness.
- `GET /health/ready` checks active configuration and database connectivity.
- `x-request-id` is returned as the public correlation reference.
- security and reconciliation events use structured, bounded metadata.
- credentials, password hashes, authorization codes, bearer tokens, session identifiers, and client secrets are excluded from audit events.

Production requires `DATABASE_PATH`, `SECRET_KEY_BASE`, and the usual Phoenix host/server variables described in [`config/runtime.exs`](config/runtime.exs). Production forces HTTPS and HSTS.

### Container release

The production image and Compose definition are ready for the Caddy deployment:

```sh
cp .env.release.example .env.release
# Fill SECRET_KEY_BASE and application secrets.
docker compose -f compose.release.yml build
docker compose -f compose.release.yml up -d
docker compose -f compose.release.yml ps
```

The service binds only to `127.0.0.1:4001`; Caddy publishes `https://id.base59.dev`. SQLite and encrypted signing keys live in the persistent `robine_id_data` volume. Root and application configuration are mounted read-only and continue to reload automatically. See [`docs/operations/release.md`](docs/operations/release.md) for release, backup, rollback, and verification procedures.

To publish the image to Docker Hub, authenticate once and use the Makefile. The default namespace is `laibulle`; override `DOCKERHUB_USER` or the complete `IMAGE` when needed:

```sh
make login
make publish

# Example override
make publish DOCKERHUB_USER=your-account VERSION=0.1.0
```

## Verification

```sh
mix format --check-formatted
mix compile --warnings-as-errors
mix test
mix assets.deploy
```

The test suite covers domain entities and use cases, adapter contracts, idempotent reconciliation, cryptographic verification, protocol failures, complete login/consent/code exchange, UserInfo, logout, session policy, health endpoints, localization, and responsive authentication markup.
