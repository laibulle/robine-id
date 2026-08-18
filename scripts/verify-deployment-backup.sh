#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
environment_file=${ROBINE_ID_ENV_FILE:-.env.release.files}
postgres_password_path=${ROBINE_ID_POSTGRES_PASSWORD_PATH:-$repository_root/deploy/secrets/postgres_password}
key_encryption_secret_path=${ROBINE_ID_KEY_ENCRYPTION_SECRET_PATH:-$repository_root/deploy/secrets/key_encryption_secret}
oauth2_proxy_client_secret_path=${ROBINE_ID_OAUTH2_PROXY_CLIENT_SECRET_PATH:-$repository_root/deploy/secrets/oauth2_proxy_client_secret}
runtime_image=${ROBINE_ID_IMAGE:-robine-id:0.1.0}
postgres_image=${ROBINE_ID_POSTGRES_IMAGE:-postgres:17-alpine}
suffix="$$"
database_container="robine-id-restore-check-postgres-$suffix"
network="robine-id-restore-check-$suffix"
temporary_directory=$(mktemp -d)
dump_path="$temporary_directory/robine-id.dump"

cleanup() {
  docker rm --force "$database_container" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$temporary_directory"
}
trap cleanup EXIT INT TERM

case "$postgres_password_path" in
  /*) ;;
  *) postgres_password_path="$repository_root/$postgres_password_path" ;;
esac
case "$key_encryption_secret_path" in
  /*) ;;
  *) key_encryption_secret_path="$repository_root/$key_encryption_secret_path" ;;
esac
case "$oauth2_proxy_client_secret_path" in
  /*) ;;
  *) oauth2_proxy_client_secret_path="$repository_root/$oauth2_proxy_client_secret_path" ;;
esac

for secret_path in "$postgres_password_path" "$key_encryption_secret_path" "$oauth2_proxy_client_secret_path"; do
  test -f "$secret_path"
  test ! -L "$secret_path"
  test "$(stat -c '%a' "$secret_path")" = 600
done

password_owner=$(stat -c '%u:%g' "$postgres_password_path")
test "$password_owner" = "$(stat -c '%u:%g' "$key_encryption_secret_path")"
test "$password_owner" = "$(stat -c '%u:%g' "$oauth2_proxy_client_secret_path")"
test "${password_owner%%:*}" != 0
test "${password_owner#*:}" != 0

cd "$repository_root"
ROBINE_ID_ENV_FILE="$environment_file" docker compose --env-file "$environment_file" \
  -f compose.release.yml -f compose.release.secrets.yml exec -T postgres \
  pg_dump --username robine_id --dbname robine_id --format=custom --no-owner --no-privileges \
  >"$dump_path"
test -s "$dump_path"

docker network create --internal "$network" >/dev/null
docker run --detach --name "$database_container" --network "$network" \
  --read-only --tmpfs /tmp:size=16m,mode=1777,noexec,nosuid,nodev \
  --tmpfs /var/run/postgresql:size=16m,mode=3775,noexec,nosuid,nodev \
  --tmpfs /var/lib/postgresql/data:size=256m,mode=0700 \
  --env POSTGRES_DB=robine_id --env POSTGRES_USER=robine_id \
  --env POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password \
  --volume "$postgres_password_path:/run/secrets/postgres_password:ro" \
  "$postgres_image" >/dev/null

attempt=0
until docker exec "$database_container" pg_isready --username robine_id --dbname robine_id \
  >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ] || [ "$(docker inspect --format '{{.State.Status}}' "$database_container")" = exited ]; then
    docker logs "$database_container" >&2
    exit 1
  fi
  sleep 1
done

docker exec -i "$database_container" pg_restore --username robine_id --dbname robine_id \
  --clean --if-exists --no-owner --no-privileges <"$dump_path"

doctor_output=$(
  docker run --rm --network "$network" --user "$password_owner" \
    --entrypoint /usr/local/bin/robine-id-doctor \
    --env PGHOST="$database_container" --env PGPORT=5432 --env PGDATABASE=robine_id \
    --env PGUSER=robine_id --env PGPASSWORD_FILE=/run/secrets/postgres_password \
    --env KEY_ENCRYPTION_SECRET_FILE=/run/secrets/key_encryption_secret \
    --env OAUTH2_PROXY_CLIENT_SECRET_FILE=/run/secrets/oauth2_proxy_client_secret \
    --env ROBINE_ID_CONFIG=/config/robine_id.json \
    --env ROBINE_ID_APPLICATIONS_DIR=/config/applications \
    --volume "$postgres_password_path:/run/secrets/postgres_password:ro" \
    --volume "$key_encryption_secret_path:/run/secrets/key_encryption_secret:ro" \
    --volume "$oauth2_proxy_client_secret_path:/run/secrets/oauth2_proxy_client_secret:ro" \
    --volume "$repository_root/deploy/config/robine_id.json:/config/robine_id.json:ro" \
    --volume "$repository_root/deploy/config/applications:/config/applications:ro" \
    "$runtime_image"
)

printf '%s\n' "$doctor_output" | jq -e \
  '.status == "ready" and .database.connected == true and .database.migrations.current == true and .database.signing_keys.missing_for_configured_issuers == 0' \
  >/dev/null
printf '%s\n' "deployment backup restore check passed with the matching encryption secret"
