#!/bin/sh
set -eu

first_argument=$(printf '%s' "$*" | cut -d' ' -f1)
if [ "$first_argument" != "--docker-group" ] && ! docker info >/dev/null 2>&1; then
  exec sg docker -c "sh '$0' --docker-group"
fi

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary_directory=$(mktemp -d)
project="robine-id-release-smoke-$$"
peer_container="$project-peer"
bind_port=$(printenv ROBINE_ID_SMOKE_PORT 2>/dev/null || printf '4011')
redirect_port=$(printenv ROBINE_ID_SMOKE_REDIRECT_PORT 2>/dev/null || printf '4012')
environment_file="$temporary_directory/release.env"
configuration_file="$temporary_directory/robine_id.json"
applications_directory="$temporary_directory/applications"
cookie_jar="$temporary_directory/cookies.txt"
database_dump="$temporary_directory/robine_id.dump"

cleanup() {
  docker rm --force "$peer_container" >/dev/null 2>&1 || true
  ROBINE_ID_ENV_FILE="$environment_file" ROBINE_ID_BIND_PORT="$bind_port" \
  ROBINE_ID_CONFIG_PATH="$configuration_file" \
  ROBINE_ID_APPLICATIONS_PATH="$applications_directory" \
    docker compose --project-directory "$repository_root" \
      --project-name "$project" \
      --file "$repository_root/compose.release.yml" \
      down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$temporary_directory"
}
trap cleanup EXIT INT TERM

mkdir -p "$applications_directory"

cat >"$environment_file" <<'EOF'
POSTGRES_PASSWORD=release-smoke-postgres-password
KEY_ENCRYPTION_SECRET=release-smoke-key-encryption-secret-32-bytes-minimum
DATABASE_MAX_CONNECTIONS=4
ROBINE_ID_RELOAD_INTERVAL=250
TRUST_PROXY_HEADERS=false
RUST_LOG=robine_id=info
EOF

cat >"$configuration_file" <<EOF
{
  "schema_version": 1,
  "issuers": [{
    "id": "default",
    "url": "http://127.0.0.1:$bind_port/default",
    "scopes": ["openid", "profile", "email"],
    "token_policy": {
      "authorization_code_lifetime": 120,
      "id_token_lifetime": 900,
      "access_token_lifetime": 900,
      "clock_skew": 30
    }
  }],
  "users": [{
    "id": "release-smoke-user",
    "identifier": "admin@example.com",
    "password_hash": "\$2b\$12\$.JtidA6ZMWny4XaLMozDSOupYHbVNQurj8NkCdM9D3m/g3v3fyXXa",
    "name": "Release Smoke User",
    "email": "admin@example.com"
  }],
  "claims": {
    "name": {"source": "name", "scope": "profile"},
    "email": {"source": "email", "scope": "email"}
  },
  "branding": {"product_name": "Robine ID Release Smoke", "primary_color": "#176b70"},
  "reconciliation": {"deletion_policy": "disable"},
  "authentication": {
    "methods": ["password"],
    "session": {"idle_timeout": 1800, "absolute_timeout": 28800, "max_concurrent": 5},
    "rate_limit": {"attempts": 10, "window_seconds": 60}
  },
  "telemetry": {"log_level": "info"}
}
EOF

cat >"$applications_directory/release-smoke.json" <<EOF
{
  "schema_version": 1,
  "kind": "oidc_application",
  "id": "release-smoke-client",
  "name": "Release Smoke Client",
  "type": "public",
  "redirect_uris": ["http://127.0.0.1:$redirect_port/callback"],
  "post_logout_redirect_uris": ["http://127.0.0.1:$redirect_port/signed-out"],
  "scopes": ["openid", "profile", "email"],
  "grant_types": ["authorization_code"],
  "authentication_method": "none",
  "pkce_required": true,
  "nonce_required": true,
  "consent_required": true
}
EOF

compose() {
  ROBINE_ID_ENV_FILE="$environment_file" ROBINE_ID_BIND_PORT="$bind_port" \
  ROBINE_ID_CONFIG_PATH="$configuration_file" \
  ROBINE_ID_APPLICATIONS_PATH="$applications_directory" \
    docker compose --project-directory "$repository_root" \
      --project-name "$project" \
      --file "$repository_root/compose.release.yml" "$@"
}

hidden_value() {
  name=$1
  file=$2
  sed -n "s/.*name=\"$name\" value=\"\([^\"]*\)\".*/\1/p" "$file" | head -n 1
}

header_value() {
  name=$1
  file=$2
  awk -v expected="$name" '
    tolower($1) == tolower(expected ":") {
      sub(/^[^:]*:[[:space:]]*/, "")
      sub(/\r$/, "")
      print
    }
  ' "$file" | tail -n 1
}

decode_base64url() {
  encoded=$(printf '%s' "$1" | tr '_-' '/+')
  encoded_length=$(expr length "$encoded")
  case $((encoded_length % 4)) in
    0) padding='' ;;
    2) padding='==' ;;
    3) padding='=' ;;
    *) return 1 ;;
  esac
  printf '%s%s' "$encoded" "$padding" | openssl base64 -d -A
}

wait_for_peer() {
  attempt=0
  while [ "$attempt" -lt 60 ]; do
    health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$peer_container")
    if [ "$health" = "healthy" ]; then
      return 0
    fi
    if [ "$health" = "exited" ] || [ "$health" = "dead" ]; then
      docker logs "$peer_container" >&2
      return 1
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  docker logs "$peer_container" >&2
  return 1
}

compose config --quiet
compose up --detach --build --wait

base_url="http://127.0.0.1:$bind_port"
curl --fail --silent "$base_url/health/live" | grep -q '"status":"live"'
curl --fail --silent "$base_url/health/ready" | grep -q '"status":"ready"'
curl --fail --silent "$base_url/docs" | grep -q 'Authorization Code with PKCE'
curl --fail --silent "$base_url/metrics" | grep -q 'robine_id_ready 1'
curl --fail --silent "$base_url/metrics" \
  | grep -Eq 'robine_id_http_requests_total [1-9][0-9]*'
response_request_id=$(
  curl --fail --silent --dump-header - --output /dev/null \
    --header 'x-request-id: release_smoke.123' "$base_url/health/live" \
    | awk 'tolower($1) == "x-request-id:" {gsub("\r", "", $2); print $2}' \
    | tail -n 1
)
test "$response_request_id" = "release_smoke.123"
curl --fail --silent "$base_url/default/.well-known/openid-configuration" \
  | grep -q "\"issuer\":\"$base_url/default\""
compose exec --no-TTY robine-id validate_config | grep -q 'configuration is valid'
compose exec --no-TTY robine-id config_apply | grep -q '^unchanged'
compose exec --no-TTY postgres \
  psql --username robine_id --dbname robine_id --tuples-only --command \
  "SELECT count(*) FROM _sqlx_migrations;" | grep -Eq '[1-9]'

container_id=$(compose ps --quiet robine-id)
test "$(docker inspect --format '{{.Config.User}}' "$container_id")" = "robine-id"
network=$(docker inspect --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{end}}' "$container_id")
image=$(docker inspect --format '{{.Config.Image}}' "$container_id")

docker run --detach --name "$peer_container" \
  --network "$network" \
  --publish 127.0.0.1::4001 \
  --env HOST=0.0.0.0 \
  --env PORT=4001 \
  --env PGHOST=postgres \
  --env PGPORT=5432 \
  --env PGDATABASE=robine_id \
  --env PGUSER=robine_id \
  --env POSTGRES_PASSWORD=release-smoke-postgres-password \
  --env KEY_ENCRYPTION_SECRET=release-smoke-key-encryption-secret-32-bytes-minimum \
  --env DATABASE_MAX_CONNECTIONS=4 \
  --env ROBINE_ID_CONFIG=/config/robine_id.json \
  --env ROBINE_ID_APPLICATIONS_DIR=/config/applications \
  --mount "type=bind,src=$configuration_file,dst=/config/robine_id.json,readonly" \
  --mount "type=bind,src=$applications_directory,dst=/config/applications,readonly" \
  "$image" >/dev/null
wait_for_peer
peer_port=$(docker port "$peer_container" 4001/tcp | tail -n 1 | sed 's/.*://')
peer_url="http://127.0.0.1:$peer_port"
curl --fail --silent "$peer_url/health/ready" | grep -q '"status":"ready"'

verifier='release-smoke-pkce-verifier-0123456789abcdefghijklmnopqrstuvwxyz'
challenge=$(
  printf '%s' "$verifier" \
    | openssl dgst -sha256 -binary \
    | openssl base64 -A \
    | tr '+/' '-_' \
    | tr -d '='
)
state='release-smoke-state'
nonce='release-smoke-nonce'
redirect_uri="http://127.0.0.1:$redirect_port/callback"
logout_uri="http://127.0.0.1:$redirect_port/signed-out"
login_page="$temporary_directory/login.html"
consent_page="$temporary_directory/consent.html"
authentication_headers="$temporary_directory/authentication.headers"
consent_headers="$temporary_directory/consent.headers"
token_response="$temporary_directory/token.json"

curl --fail --silent --get --cookie-jar "$cookie_jar" \
  --data-urlencode 'response_type=code' \
  --data-urlencode 'client_id=release-smoke-client' \
  --data-urlencode "redirect_uri=$redirect_uri" \
  --data-urlencode 'scope=openid profile email' \
  --data-urlencode "state=$state" \
  --data-urlencode "nonce=$nonce" \
  --data-urlencode "code_challenge=$challenge" \
  --data-urlencode 'code_challenge_method=S256' \
  "$base_url/default/authorize" >"$login_page"
csrf_token=$(hidden_value csrf_token "$login_page")
test -n "$csrf_token"

curl --fail --silent --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
  --dump-header "$authentication_headers" --output "$consent_page" \
  --data-urlencode "csrf_token=$csrf_token" \
  --data-urlencode 'response_type=code' \
  --data-urlencode 'client_id=release-smoke-client' \
  --data-urlencode "redirect_uri=$redirect_uri" \
  --data-urlencode 'scope=openid profile email' \
  --data-urlencode "state=$state" \
  --data-urlencode "nonce=$nonce" \
  --data-urlencode "code_challenge=$challenge" \
  --data-urlencode 'code_challenge_method=S256' \
  --data-urlencode 'identifier=admin@example.com' \
  --data-urlencode 'password=change-me' \
  "$base_url/default/authorize"
grep -q 'id="consent-form"' "$consent_page"
transaction=$(hidden_value transaction "$consent_page")
test -n "$transaction"

curl --fail --silent --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
  --dump-header "$consent_headers" --output /dev/null \
  --data-urlencode "transaction=$transaction" \
  --data-urlencode "csrf_token=$csrf_token" \
  --data-urlencode 'decision=approve' \
  "$peer_url/default/authorize/consent"
authorization_location=$(header_value location "$consent_headers")
code=$(printf '%s' "$authorization_location" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
test -n "$code"
printf '%s' "$authorization_location" | grep -q "[?&]state=$state"

curl --fail --silent \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode "code=$code" \
  --data-urlencode 'client_id=release-smoke-client' \
  --data-urlencode "redirect_uri=$redirect_uri" \
  --data-urlencode "code_verifier=$verifier" \
  "$base_url/default/token" >"$token_response"
access_token=$(sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p' "$token_response")
id_token=$(sed -n 's/.*"id_token":"\([^"]*\)".*/\1/p' "$token_response")
test -n "$access_token"
test -n "$id_token"

jwt_header=$(decode_base64url "$(printf '%s' "$id_token" | cut -d. -f1)")
jwt_payload=$(decode_base64url "$(printf '%s' "$id_token" | cut -d. -f2)")
kid=$(printf '%s' "$jwt_header" | sed -n 's/.*"kid":"\([^"]*\)".*/\1/p')
test -n "$kid"
printf '%s' "$jwt_header" | grep -q '"alg":"RS256"'
printf '%s' "$jwt_payload" | grep -q "\"iss\":\"$base_url/default\""
printf '%s' "$jwt_payload" | grep -q '"sub":"release-smoke-user"'
printf '%s' "$jwt_payload" | grep -q '"aud":"release-smoke-client"'
printf '%s' "$jwt_payload" | grep -q "\"nonce\":\"$nonce\""
curl --fail --silent "$base_url/default/jwks.json" | grep -q "\"kid\":\"$kid\""

user_info=$(curl --fail --silent --header "Authorization: Bearer $access_token" "$peer_url/default/userinfo")
printf '%s' "$user_info" | grep -q '"sub":"release-smoke-user"'
printf '%s' "$user_info" | grep -q '"name":"Release Smoke User"'
printf '%s' "$user_info" | grep -q '"email":"admin@example.com"'

replay_status=$(
  curl --silent --output "$temporary_directory/replay.json" --write-out '%{http_code}' \
    --data-urlencode 'grant_type=authorization_code' \
    --data-urlencode "code=$code" \
    --data-urlencode 'client_id=release-smoke-client' \
    --data-urlencode "redirect_uri=$redirect_uri" \
    --data-urlencode "code_verifier=$verifier" \
    "$peer_url/default/token"
)
test "$replay_status" = '400'
grep -q '"error":"invalid_grant"' "$temporary_directory/replay.json"

logout_page="$temporary_directory/logout.html"
logout_headers="$temporary_directory/logout.headers"
curl --fail --silent --get --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
  --data-urlencode "id_token_hint=$id_token" \
  --data-urlencode "post_logout_redirect_uri=$logout_uri" \
  --data-urlencode 'state=release-smoke-logout-state' \
  "$peer_url/default/logout" >"$logout_page"
logout_transaction=$(hidden_value transaction "$logout_page")
logout_csrf=$(hidden_value csrf_token "$logout_page")
test -n "$logout_transaction"
test -n "$logout_csrf"
curl --fail --silent --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
  --dump-header "$logout_headers" --output /dev/null \
  --data-urlencode "transaction=$logout_transaction" \
  --data-urlencode "csrf_token=$logout_csrf" \
  "$base_url/default/logout"
logout_location=$(header_value location "$logout_headers")
printf '%s' "$logout_location" | grep -q "^$logout_uri?state=release-smoke-logout-state$"
compose exec --no-TTY postgres \
  psql --username robine_id --dbname robine_id --tuples-only --command \
  "SELECT count(*) FROM authenticated_sessions WHERE revoked_at IS NOT NULL;" | grep -Eq '[1-9]'

kid_before_restore=$(
  compose exec --no-TTY postgres \
    psql --username robine_id --dbname robine_id --tuples-only --no-align \
      --command "SELECT kid FROM signing_keys WHERE issuer = '$base_url/default';" \
    | tr -d '[:space:]'
)
test "$kid_before_restore" = "$kid"
compose exec --no-TTY postgres \
  pg_dump --username robine_id --dbname robine_id --format=custom >"$database_dump"
test -s "$database_dump"

docker rm --force "$peer_container" >/dev/null
compose stop robine-id
compose exec --no-TTY postgres dropdb --force --username robine_id robine_id
compose exec --no-TTY postgres createdb --username robine_id --owner robine_id robine_id
compose exec --no-TTY postgres \
  pg_restore --username robine_id --dbname robine_id --no-owner <"$database_dump"
compose up --detach --wait robine-id

curl --fail --silent "$base_url/health/ready" | grep -q '"status":"ready"'
kid_after_restore=$(
  compose exec --no-TTY postgres \
    psql --username robine_id --dbname robine_id --tuples-only --no-align \
      --command "SELECT kid FROM signing_keys WHERE issuer = '$base_url/default';" \
    | tr -d '[:space:]'
)
test "$kid_after_restore" = "$kid_before_restore"
curl --fail --silent "$base_url/default/jwks.json" | grep -q "\"kid\":\"$kid\""
restored_user_info=$(
  curl --fail --silent --header "Authorization: Bearer $access_token" \
    "$base_url/default/userinfo"
)
printf '%s' "$restored_user_info" | grep -q '"sub":"release-smoke-user"'

printf 'release smoke test passed: %s (OIDC, multi-instance, backup/restore)\n' "$base_url"
