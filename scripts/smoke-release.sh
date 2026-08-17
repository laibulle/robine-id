#!/bin/sh
set -eu

if [ "${1:-}" != "--docker-group" ] && ! docker info >/dev/null 2>&1; then
  exec sg docker -c "'$0' --docker-group"
fi

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary_directory=$(mktemp -d)
project="robine-id-release-smoke-$$"
bind_port=${ROBINE_ID_SMOKE_PORT:-4011}
environment_file="$temporary_directory/release.env"

cleanup() {
  ROBINE_ID_ENV_FILE="$environment_file" ROBINE_ID_BIND_PORT="$bind_port" \
    docker compose --project-directory "$repository_root" \
      --project-name "$project" \
      --file "$repository_root/compose.release.yml" \
      down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$temporary_directory"
}
trap cleanup EXIT INT TERM

cat >"$environment_file" <<'EOF'
POSTGRES_PASSWORD=release-smoke-postgres-password
KEY_ENCRYPTION_SECRET=release-smoke-key-encryption-secret-32-bytes-minimum
DATABASE_MAX_CONNECTIONS=4
ROBINE_ID_RELOAD_INTERVAL=250
TRUST_PROXY_HEADERS=false
RUST_LOG=robine_id=info
EOF

compose() {
  ROBINE_ID_ENV_FILE="$environment_file" ROBINE_ID_BIND_PORT="$bind_port" \
    docker compose --project-directory "$repository_root" \
      --project-name "$project" \
      --file "$repository_root/compose.release.yml" "$@"
}

compose config --quiet
compose up --detach --build --wait

base_url="http://127.0.0.1:$bind_port"
curl --fail --silent "$base_url/health/live" | grep -q '"status":"live"'
curl --fail --silent "$base_url/health/ready" | grep -q '"status":"ready"'
curl --fail --silent "$base_url/docs" | grep -q 'Authorization Code with PKCE'
curl --fail --silent "$base_url/default/.well-known/openid-configuration" \
  | grep -q '"issuer":"https://id.base59.dev/default"'
compose exec --no-TTY robine-id validate_config | grep -q 'configuration is valid'
compose exec --no-TTY robine-id config_apply | grep -q '^unchanged'
compose exec --no-TTY postgres \
  psql --username robine_id --dbname robine_id --tuples-only --command \
  "SELECT count(*) FROM _sqlx_migrations;" | grep -Eq '[1-9]'

container_id=$(compose ps --quiet robine-id)
test "$(docker inspect --format '{{.Config.User}}' "$container_id")" = "robine-id"

printf 'release smoke test passed: %s\n' "$base_url"
