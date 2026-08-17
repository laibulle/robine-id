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
docker_host=$(printenv DOCKER_HOST 2>/dev/null || true)
access_host='127.0.0.1'
bind_address='127.0.0.1'
case "$docker_host" in
  tcp://*)
    docker_authority=${docker_host#tcp://}
    access_host=${docker_authority%:*}
    bind_address='0.0.0.0'
    ;;
  ssh://*)
    docker_authority=${docker_host#ssh://}
    docker_authority=${docker_authority%%/*}
    docker_authority=${docker_authority#*@}
    access_host=${docker_authority%%:*}
    bind_address='0.0.0.0'
    ;;
esac
issuer_url="http://127.0.0.1:$bind_port/default"
jwt_issuer_url="http://127.0.0.1:$bind_port/jwt"
environment_file="$temporary_directory/release.env"
configuration_file="$temporary_directory/robine_id.json"
applications_directory="$temporary_directory/applications"
cookie_jar="$temporary_directory/cookies.txt"
database_dump="$temporary_directory/robine_id.dump"
compose_override_file=''
root_configuration_json=''
applications_json=''

cleanup() {
  docker rm --force "$peer_container" >/dev/null 2>&1 || true
  if [ -n "$compose_override_file" ]; then
    ROBINE_ID_ENV_FILE="$environment_file" ROBINE_ID_BIND_PORT="$bind_port" \
    ROBINE_ID_BIND_ADDRESS="$bind_address" \
    ROBINE_ID_CONFIG_PATH="$configuration_file" \
    ROBINE_ID_APPLICATIONS_PATH="$applications_directory" \
    ROBINE_ID_CONFIG_JSON="$root_configuration_json" \
    ROBINE_ID_APPLICATIONS_JSON="$applications_json" \
      docker compose --project-directory "$repository_root" \
        --project-name "$project" \
        --file "$repository_root/compose.release.yml" \
        --file "$compose_override_file" \
        down --volumes --remove-orphans >/dev/null 2>&1 || true
  else
    ROBINE_ID_ENV_FILE="$environment_file" ROBINE_ID_BIND_PORT="$bind_port" \
    ROBINE_ID_BIND_ADDRESS="$bind_address" \
    ROBINE_ID_CONFIG_PATH="$configuration_file" \
    ROBINE_ID_APPLICATIONS_PATH="$applications_directory" \
      docker compose --project-directory "$repository_root" \
        --project-name "$project" \
        --file "$repository_root/compose.release.yml" \
        down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -rf "$temporary_directory"
}
trap cleanup EXIT INT TERM

mkdir -p "$applications_directory"
client_assertion_private_key="$temporary_directory/client-assertion-private.pem"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$client_assertion_private_key" 2>/dev/null
client_assertion_modulus_hex=$(
  openssl rsa -in "$client_assertion_private_key" -noout -modulus 2>/dev/null \
    | sed 's/^Modulus=//'
)
client_assertion_modulus=$(
  printf '%s' "$client_assertion_modulus_hex" \
    | xxd -r -p \
    | openssl base64 -A \
    | tr '+/' '-_' \
    | tr -d '='
)
dpop_jkt=$(
  printf '{"e":"AQAB","kty":"RSA","n":"%s"}' "$client_assertion_modulus" \
    | openssl dgst -sha256 -binary \
    | openssl base64 -A \
    | tr '+/' '-_' \
    | tr -d '='
)
test "$(expr length "$dpop_jkt")" = '43'

cat >"$environment_file" <<'EOF'
POSTGRES_PASSWORD=release-smoke-postgres-password
KEY_ENCRYPTION_SECRET=release-smoke-key-encryption-secret-32-bytes-minimum
DATABASE_MAX_CONNECTIONS=4
ROBINE_ID_RELOAD_INTERVAL=250
TRUST_PROXY_HEADERS=false
RUST_LOG=robine_id=info
INTROSPECTION_CLIENT_SECRET=release-smoke-introspection-secret
RELEASE_SMOKE_TOTP_SECRET=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
EOF

cat >"$configuration_file" <<EOF
{
  "schema_version": 1,
  "issuers": [{
    "id": "default",
    "url": "$issuer_url",
    "scopes": ["openid", "profile", "email", "offline_access", "service.read"],
    "token_policy": {
      "authorization_code_lifetime": 120,
      "id_token_lifetime": 900,
      "access_token_lifetime": 900,
      "refresh_token_lifetime": 2592000,
      "clock_skew": 30,
      "dpop_nonce_required": true,
      "dpop_nonce_lifetime": 3600,
      "signing_key_rotation_interval": 3600
    }
  }, {
    "id": "jwt",
    "url": "$jwt_issuer_url",
    "scopes": ["openid", "service.read"],
    "token_policy": {
      "id_token_lifetime": 900,
      "access_token_lifetime": 900,
      "access_token_format": "jwt",
      "clock_skew": 30,
      "signing_key_rotation_interval": 3600
    }
  }],
  "users": [{
    "id": "release-smoke-user",
    "identifier": "admin@example.com",
    "password_hash": "\$2b\$12\$.JtidA6ZMWny4XaLMozDSOupYHbVNQurj8NkCdM9D3m/g3v3fyXXa",
    "name": "Release Smoke User",
    "email": "admin@example.com"
  }, {
    "id": "release-smoke-mfa-user",
    "identifier": "mfa@example.com",
    "password_hash": "\$2b\$12\$.JtidA6ZMWny4XaLMozDSOupYHbVNQurj8NkCdM9D3m/g3v3fyXXa",
    "totp_secret_reference": {"provider": "env", "key": "RELEASE_SMOKE_TOTP_SECRET"},
    "name": "Release Smoke MFA User",
    "email": "mfa@example.com"
  }],
  "claims": {
    "name": {"source": "name", "scope": "profile"},
    "email": {"source": "email", "scope": "email"}
  },
  "branding": {
    "product_name": "Robine ID Release Smoke",
    "primary_color": "#176b70",
    "privacy_url": "https://docs.release.example/privacy",
    "terms_url": "https://docs.release.example/terms"
  },
  "reconciliation": {"deletion_policy": "disable"},
  "authentication": {
    "methods": ["password", "totp"],
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
  "resources": ["https://api.release.example"],
  "scopes": ["openid", "profile", "email", "offline_access"],
  "grant_types": ["authorization_code", "refresh_token"],
  "authentication_method": "none",
  "pkce_required": true,
  "nonce_required": true,
  "consent_required": true
}
EOF

cat >"$applications_directory/resource-server.json" <<EOF
{
  "schema_version": 1,
  "kind": "oidc_application",
  "id": "release-resource-server",
  "name": "Release Resource Server",
  "type": "confidential",
  "redirect_uris": [],
  "resources": ["https://api.release.example", "https://api-exchanged.release.example"],
  "scopes": ["service.read"],
  "grant_types": ["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
  "authentication_method": "client_secret_basic",
  "secret_reference": {"provider": "env", "key": "INTROSPECTION_CLIENT_SECRET"},
  "introspection_allowed": true
}
EOF

cat >"$applications_directory/assertion-client.json" <<EOF
{
  "schema_version": 1,
  "kind": "oidc_application",
  "id": "release-assertion-client",
  "name": "Release Assertion Client",
  "type": "confidential",
  "redirect_uris": ["http://127.0.0.1:$redirect_port/assertion-callback"],
  "resources": ["https://api.release.example", "https://api-exchanged.release.example"],
  "scopes": ["openid", "service.read"],
  "grant_types": ["authorization_code", "client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
  "authentication_method": "private_key_jwt",
  "jwks": {"keys": [{
    "kty": "RSA",
    "kid": "release-assertion-key",
    "use": "sig",
    "alg": "RS256",
    "n": "$client_assertion_modulus",
    "e": "AQAB"
  }]},
  "pkce_required": false,
  "nonce_required": false,
  "introspection_allowed": true
}
EOF

cat >"$applications_directory/par-required-client.json" <<EOF
{
  "schema_version": 1,
  "kind": "oidc_application",
  "id": "release-par-required-client",
  "name": "Release PAR Required Client",
  "type": "public",
  "redirect_uris": ["http://127.0.0.1:$redirect_port/par-required-callback"],
  "scopes": ["openid"],
  "grant_types": ["authorization_code"],
  "authentication_method": "none",
  "pkce_required": true,
  "nonce_required": true,
  "consent_required": false,
  "require_pushed_authorization_requests": true
}
EOF

cat >"$applications_directory/device-client.json" <<'EOF'
{
  "schema_version": 1,
  "kind": "oidc_application",
  "id": "release-device-client",
  "name": "Release Device Client",
  "type": "public",
  "redirect_uris": [],
  "scopes": ["openid", "profile", "email", "offline_access"],
  "grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
  "authentication_method": "none",
  "pkce_required": true,
  "nonce_required": true,
  "consent_required": true
}
EOF

cat >"$applications_directory/mfa-client.json" <<EOF
{
  "schema_version": 1,
  "kind": "oidc_application",
  "id": "release-mfa-client",
  "name": "Release MFA Client",
  "type": "public",
  "redirect_uris": ["http://127.0.0.1:$redirect_port/callback"],
  "scopes": ["openid", "offline_access"],
  "grant_types": ["authorization_code", "refresh_token"],
  "authentication_method": "none",
  "pkce_required": true,
  "nonce_required": true,
  "consent_required": true,
  "required_acr": "urn:robine-id:acr:password+totp"
}
EOF

root_configuration_json=$(tr -d '\n' <"$configuration_file")
applications_json=$(printf '[%s,%s,%s,%s,%s,%s]' \
  "$(tr -d '\n' <"$applications_directory/release-smoke.json")" \
  "$(tr -d '\n' <"$applications_directory/resource-server.json")" \
  "$(tr -d '\n' <"$applications_directory/assertion-client.json")" \
  "$(tr -d '\n' <"$applications_directory/par-required-client.json")" \
  "$(tr -d '\n' <"$applications_directory/device-client.json")" \
  "$(tr -d '\n' <"$applications_directory/mfa-client.json")")
case "$docker_host" in
  tcp://* | ssh://*)
    compose_override_file="$temporary_directory/compose.remote.yml"
    cat >"$compose_override_file" <<'EOF'
services:
  robine-id:
    volumes: !reset []
    environment:
      - ROBINE_ID_CONFIG_JSON
      - ROBINE_ID_APPLICATIONS_JSON
EOF
    ;;
esac

compose() {
  if [ -n "$compose_override_file" ]; then
    ROBINE_ID_ENV_FILE="$environment_file" ROBINE_ID_BIND_PORT="$bind_port" \
    ROBINE_ID_BIND_ADDRESS="$bind_address" \
    ROBINE_ID_CONFIG_PATH="$configuration_file" \
    ROBINE_ID_APPLICATIONS_PATH="$applications_directory" \
    ROBINE_ID_CONFIG_JSON="$root_configuration_json" \
    ROBINE_ID_APPLICATIONS_JSON="$applications_json" \
      docker compose --project-directory "$repository_root" \
        --project-name "$project" \
        --file "$repository_root/compose.release.yml" \
        --file "$compose_override_file" "$@"
  else
    ROBINE_ID_ENV_FILE="$environment_file" ROBINE_ID_BIND_PORT="$bind_port" \
    ROBINE_ID_BIND_ADDRESS="$bind_address" \
    ROBINE_ID_CONFIG_PATH="$configuration_file" \
    ROBINE_ID_APPLICATIONS_PATH="$applications_directory" \
      docker compose --project-directory "$repository_root" \
        --project-name "$project" \
        --file "$repository_root/compose.release.yml" "$@"
  fi
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

smoke_totp() {
  counter_offset=${1-0}
  counter=$(( $(date +%s) / 30 + counter_offset ))
  counter_hex=$(printf '%016x' "$counter")
  digest_hex=$(
    printf '%s' "$counter_hex" | xxd -r -p \
      | openssl dgst -sha1 -mac HMAC \
          -macopt hexkey:3132333435363738393031323334353637383930 -binary \
      | xxd -p -c 256
  )
  offset_hex=$(printf '%s' "$digest_hex" | cut -c 40)
  offset=$((0x$offset_hex))
  start=$((offset * 2 + 1))
  end=$((start + 7))
  truncated=$(printf '%s' "$digest_hex" | cut -c "$start-$end")
  printf '%06d' $(((0x$truncated & 2147483647) % 1000000))
}

encode_base64url() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

client_assertion() {
  assertion_audience=$1
  assertion_jti=$2
  assertion_now=$(date +%s)
  assertion_exp=$((assertion_now + 120))
  assertion_header=$(
    printf '%s' '{"alg":"RS256","kid":"release-assertion-key","typ":"JWT"}' \
      | encode_base64url
  )
  assertion_payload=$(
    printf '{"iss":"release-assertion-client","sub":"release-assertion-client","aud":"%s","iat":%s,"exp":%s,"jti":"%s"}' \
      "$assertion_audience" "$assertion_now" "$assertion_exp" "$assertion_jti" \
      | encode_base64url
  )
  assertion_signing_input="$assertion_header.$assertion_payload"
  assertion_signature=$(
    printf '%s' "$assertion_signing_input" \
      | openssl dgst -sha256 -sign "$client_assertion_private_key" -binary \
      | encode_base64url
  )
  printf '%s.%s' "$assertion_signing_input" "$assertion_signature"
}

authorization_request_object() {
  request_jti=$1
  request_state=$2
  request_now=$(date +%s)
  request_exp=$((request_now + 120))
  request_header=$(
    printf '%s' '{"alg":"RS256","kid":"release-assertion-key","typ":"oauth-authz-req+jwt"}' \
      | encode_base64url
  )
  request_payload=$(
    printf '{"iss":"release-assertion-client","aud":"%s","iat":%s,"exp":%s,"jti":"%s","response_type":"code","client_id":"release-assertion-client","redirect_uri":"http://127.0.0.1:%s/assertion-callback","scope":"openid","state":"%s"}' \
      "$issuer_url" "$request_now" "$request_exp" "$request_jti" "$redirect_port" \
      "$request_state" \
      | encode_base64url
  )
  request_signing_input="$request_header.$request_payload"
  request_signature=$(
    printf '%s' "$request_signing_input" \
      | openssl dgst -sha256 -sign "$client_assertion_private_key" -binary \
      | encode_base64url
  )
  printf '%s.%s' "$request_signing_input" "$request_signature"
}

oidc_access_token_hash() {
  printf '%s' "$1" \
    | openssl dgst -sha256 -binary \
    | head -c 16 \
    | openssl base64 -A \
    | tr '+/' '-_' \
    | tr -d '='
}

dpop_access_token_hash() {
  printf '%s' "$1" \
    | openssl dgst -sha256 -binary \
    | encode_base64url
}

dpop_proof() {
  proof_method=$1
  proof_uri=$2
  proof_jti=$3
  proof_access_token=${4-}
  proof_nonce=${5-}
  proof_now=$(date +%s)
  proof_header=$(
    printf '{"alg":"RS256","typ":"dpop+jwt","jwk":{"kty":"RSA","n":"%s","e":"AQAB"}}' \
      "$client_assertion_modulus" \
      | encode_base64url
  )
  proof_optional_claims=''
  if [ -n "$proof_access_token" ]; then
    proof_ath=$(dpop_access_token_hash "$proof_access_token")
    proof_optional_claims="$proof_optional_claims,\"ath\":\"$proof_ath\""
  fi
  if [ -n "$proof_nonce" ]; then
    proof_optional_claims="$proof_optional_claims,\"nonce\":\"$proof_nonce\""
  fi
  proof_payload=$(
    printf '{"jti":"%s","htm":"%s","htu":"%s","iat":%s%s}' \
      "$proof_jti" "$proof_method" "$proof_uri" "$proof_now" "$proof_optional_claims" \
      | encode_base64url
  )
  proof_signing_input="$proof_header.$proof_payload"
  proof_signature=$(
    printf '%s' "$proof_signing_input" \
      | openssl dgst -sha256 -sign "$client_assertion_private_key" -binary \
      | encode_base64url
  )
  printf '%s.%s' "$proof_signing_input" "$proof_signature"
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

base_url="http://$access_host:$bind_port"
curl --fail --silent "$base_url/health/live" | grep -q '"status":"live"'
curl --fail --silent "$base_url/health/ready" | grep -q '"status":"ready"'
curl --fail --silent "$base_url/docs" | grep -q 'Authorization Code with PKCE'
curl --fail --silent "$base_url/metrics" | grep -q 'robine_id_ready 1'
curl --fail --silent "$base_url/metrics" \
  | grep -Eq 'robine_id_http_requests_total [1-9][0-9]*'
token_cors_headers="$temporary_directory/token-cors.headers"
curl --fail --silent --request OPTIONS --dump-header "$token_cors_headers" --output /dev/null \
  --header "Origin: http://127.0.0.1:$redirect_port" \
  --header 'Access-Control-Request-Method: POST' \
  --header 'Access-Control-Request-Headers: Content-Type, DPoP' \
  "$base_url/default/token"
tr -d '\r' <"$token_cors_headers" \
  | grep -qi "^access-control-allow-origin: http://127.0.0.1:$redirect_port$"
tr -d '\r' <"$token_cors_headers" \
  | grep -qi '^access-control-allow-methods: POST$'
tr -d '\r' <"$token_cors_headers" \
  | grep -qi '^access-control-expose-headers: DPoP-Nonce$'
unregistered_cors_status=$(
  curl --silent --request OPTIONS --output /dev/null --write-out '%{http_code}' \
    --header 'Origin: https://attacker.example' \
    --header 'Access-Control-Request-Method: POST' \
    --header 'Access-Control-Request-Headers: Content-Type' \
    "$base_url/default/token"
)
test "$unregistered_cors_status" = "403"
response_request_id=$(
  curl --fail --silent --dump-header - --output /dev/null \
    --header 'x-request-id: release_smoke.123' "$base_url/health/live" \
    | awk 'tolower($1) == "x-request-id:" {gsub("\r", "", $2); print $2}' \
    | tail -n 1
)
test "$response_request_id" = "release_smoke.123"
curl --fail --silent "$base_url/default/.well-known/openid-configuration" \
  | grep -q "\"issuer\":\"$issuer_url\""
curl --fail --silent "$base_url/default/.well-known/openid-configuration" \
  | grep -q "\"introspection_endpoint\":\"$issuer_url/introspect\""
curl --fail --silent "$base_url/default/.well-known/openid-configuration" \
  | grep -q "\"revocation_endpoint\":\"$issuer_url/revoke\""
curl --fail --silent "$base_url/default/.well-known/openid-configuration" \
  | grep -q '"grant_types_supported":\["authorization_code","refresh_token","client_credentials","urn:ietf:params:oauth:grant-type:token-exchange","urn:ietf:params:oauth:grant-type:device_code"\]'
curl --fail --silent "$base_url/default/.well-known/openid-configuration" \
  | grep -q "\"device_authorization_endpoint\":\"$issuer_url/device_authorization\""
curl --fail --silent "$base_url/default/.well-known/openid-configuration" \
  | grep -q '"response_modes_supported":\["query","form_post","jwt","query.jwt","form_post.jwt"\]'
curl --fail --silent "$base_url/default/.well-known/openid-configuration" \
  | grep -q '"authorization_signing_alg_values_supported":\["RS256"\]'
if curl --fail --silent "$base_url/default/.well-known/openid-configuration" \
  | grep -q '"access_token_signing_alg_values_supported"'; then
  printf '%s\n' 'opaque issuer unexpectedly advertised JWT access-token signing' >&2
  exit 1
fi
curl --fail --silent "$base_url/jwt/.well-known/openid-configuration" \
  | grep -q '"access_token_signing_alg_values_supported":\["RS256"\]'
curl --fail --silent "$base_url/default/.well-known/openid-configuration" \
  | grep -q '"dpop_signing_alg_values_supported":\["ES256","RS256"\]'
curl --fail --silent "$base_url/default/.well-known/openid-configuration" \
  | grep -q '"token_endpoint_auth_signing_alg_values_supported":\["RS256"\]'
curl --fail --silent "$base_url/default/.well-known/openid-configuration" \
  | grep -q '"introspection_endpoint_auth_signing_alg_values_supported":\["RS256"\]'
curl --fail --silent "$base_url/default/.well-known/openid-configuration" \
  | grep -q '"revocation_endpoint_auth_signing_alg_values_supported":\["RS256"\]'
curl --fail --silent "$base_url/default/.well-known/openid-configuration" \
  | grep -q "\"service_documentation\":\"http://127.0.0.1:$bind_port/docs\""
curl --fail --silent "$base_url/default/.well-known/openid-configuration" \
  | grep -q '"op_policy_uri":"https://docs.release.example/privacy"'
curl --fail --silent "$base_url/default/.well-known/openid-configuration" \
  | grep -q '"op_tos_uri":"https://docs.release.example/terms"'
curl --fail --silent "$base_url/default/.well-known/openid-configuration" \
  | grep -q '"authorization_response_iss_parameter_supported":true'
curl --fail --silent "$base_url/default/.well-known/openid-configuration" \
  | grep -q '"acr_values_supported":\["urn:robine-id:acr:password","urn:robine-id:acr:password+totp"\]'
curl --fail --silent "$base_url/default/.well-known/openid-configuration" \
  | grep -q '"claims_parameter_supported":true'
curl --fail --silent "$base_url/default/.well-known/openid-configuration" \
  | grep -q "\"pushed_authorization_request_endpoint\":\"$issuer_url/par\""
curl --fail --silent "$base_url/default/.well-known/openid-configuration" \
  | grep -q '"request_uri_parameter_supported":true'
discovery_headers="$temporary_directory/discovery.headers"
curl --fail --silent --dump-header "$discovery_headers" --output /dev/null \
  "$base_url/default/.well-known/openid-configuration"
discovery_etag=$(
  awk 'tolower($1) == "etag:" {gsub("\r", "", $2); print $2}' "$discovery_headers" \
    | tail -n 1
)
test -n "$discovery_etag"
grep -qi 's-maxage=300' "$discovery_headers"
test "$(
  curl --silent --output /dev/null --write-out '%{http_code}' \
    --header "If-None-Match: $discovery_etag" \
    "$base_url/default/.well-known/openid-configuration"
)" = "304"
curl --fail --silent "$base_url/.well-known/oauth-authorization-server/default" \
  | grep -q "\"issuer\":\"$issuer_url\""
webfinger_response=$(
  curl --fail --silent --get \
    --data-urlencode "resource=$issuer_url/not-a-user" \
    --data-urlencode "rel=http://openid.net/specs/connect/1.0/issuer" \
    "$base_url/.well-known/webfinger"
)
printf '%s' "$webfinger_response" | grep -q "\"href\":\"$issuer_url\""
compose exec --no-TTY robine-id validate_config | grep -q 'configuration is valid'
compose exec --no-TTY robine-id config_apply | grep -q '^unchanged'
compose exec --no-TTY postgres \
  psql --username robine_id --dbname robine_id --tuples-only --command \
  "SELECT count(*) FROM _sqlx_migrations;" | grep -Eq '[1-9]'

container_id=$(compose ps --quiet robine-id)
test "$(docker inspect --format '{{.Config.User}}' "$container_id")" = "robine-id"
test "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container_id")" = "true"
docker inspect --format '{{json .HostConfig.CapDrop}}' "$container_id" | grep -q '"ALL"'
docker inspect --format '{{json .HostConfig.SecurityOpt}}' "$container_id" \
  | grep -q 'no-new-privileges'
network=$(docker inspect --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{end}}' "$container_id")
image=$(docker inspect --format '{{.Config.Image}}' "$container_id")
docker run --rm --entrypoint /bin/sh "$image" -c \
  'test -x /usr/local/bin/robine-id-healthcheck && ! command -v curl'
embedded_configuration="$temporary_directory/embedded-config.json"
docker run --rm --entrypoint /usr/local/bin/config_effective "$image" \
  >"$embedded_configuration"
grep -Eq '"users"[[:space:]]*:[[:space:]]*\[\]' "$embedded_configuration"
grep -Eq '"clients"[[:space:]]*:[[:space:]]*\[\]' "$embedded_configuration"
if grep -Eq 'admin@example\.com|change-me' "$embedded_configuration"; then
  printf '%s\n' 'release image unexpectedly contains development credentials' >&2
  exit 1
fi
invalid_database_environment_log="$temporary_directory/invalid-database-environment.log"
if docker run --rm \
  --env 'DATABASE_URL=postgres://operator:not-logged-database-password@postgres/robine_id' \
  --env 'KEY_ENCRYPTION_SECRET=not-logged-key-encryption-secret-32-bytes' \
  --env 'DATABASE_MAX_CONNECTIONS=invalid-sensitive-value' \
  "$image" >"$invalid_database_environment_log" 2>&1; then
  printf '%s\n' 'release image accepted an invalid database pool bound' >&2
  exit 1
fi
grep -q 'DATABASE_MAX_CONNECTIONS must be an integer between 1 and 50' \
  "$invalid_database_environment_log"
if grep -Eq 'not-logged-database-password|not-logged-key-encryption-secret|invalid-sensitive-value' \
  "$invalid_database_environment_log"; then
  printf '%s\n' 'database configuration diagnostic exposed a submitted value' >&2
  exit 1
fi
invalid_previous_secret_log="$temporary_directory/invalid-previous-secret.log"
if docker run --rm \
  --env 'DATABASE_URL=postgres://operator:password@postgres/robine_id' \
  --env 'KEY_ENCRYPTION_SECRET=current-key-encryption-secret-32-bytes' \
  --env 'KEY_ENCRYPTION_SECRET_PREVIOUS=not-logged-weak-previous' \
  "$image" >"$invalid_previous_secret_log" 2>&1; then
  printf '%s\n' 'release image accepted a weak previous encryption secret' >&2
  exit 1
fi
grep -q 'KEY_ENCRYPTION_SECRET_PREVIOUS must contain at least 32 bytes' \
  "$invalid_previous_secret_log"
if grep -q 'not-logged-weak-previous' "$invalid_previous_secret_log"; then
  printf '%s\n' 'previous-secret diagnostic exposed the submitted value' >&2
  exit 1
fi
invalid_server_environment_log="$temporary_directory/invalid-server-environment.log"
if docker run --rm \
  --env 'PORT=not-logged-server-value' \
  "$image" >"$invalid_server_environment_log" 2>&1; then
  printf '%s\n' 'release image accepted an invalid server port' >&2
  exit 1
fi
grep -q 'PORT must be an integer between 1 and 65535' \
  "$invalid_server_environment_log"
if grep -q 'not-logged-server-value' "$invalid_server_environment_log"; then
  printf '%s\n' 'server configuration diagnostic exposed a submitted value' >&2
  exit 1
fi

login_hint_page="$temporary_directory/login-hint.html"
curl --fail --silent \
  --data-urlencode 'response_type=code' \
  --data-urlencode 'client_id=release-smoke-client' \
  --data-urlencode "redirect_uri=http://127.0.0.1:$redirect_port/callback" \
  --data-urlencode 'scope=openid profile email offline_access' \
  --data-urlencode 'state=post-authorization-smoke' \
  --data-urlencode 'nonce=post-authorization-smoke' \
  --data-urlencode 'code_challenge=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
  --data-urlencode 'code_challenge_method=S256' \
  --data-urlencode 'login_hint=admin@example.com' \
  "$base_url/default/authorize" >"$login_hint_page"
grep -q 'id="login-form"' "$login_hint_page"
grep -q 'name="identifier" type="text" value="admin@example.com"' "$login_hint_page"
test -n "$(hidden_value transaction "$login_hint_page")"
if grep -q 'name="login_hint"' "$login_hint_page"; then
  printf '%s\n' 'login_hint leaked into the login continuation' >&2
  exit 1
fi

docker run --detach --name "$peer_container" \
  --network "$network" \
  --publish "$bind_address::4001" \
  --read-only \
  --tmpfs /tmp:size=16m,mode=1777 \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  --env HOST=0.0.0.0 \
  --env PORT=4001 \
  --env PGHOST=postgres \
  --env PGPORT=5432 \
  --env PGDATABASE=robine_id \
  --env PGUSER=robine_id \
  --env POSTGRES_PASSWORD=release-smoke-postgres-password \
  --env KEY_ENCRYPTION_SECRET=release-smoke-key-encryption-secret-32-bytes-minimum \
  --env DATABASE_MAX_CONNECTIONS=4 \
  --env DRAIN_DELAY_MILLISECONDS=5000 \
  --env SHUTDOWN_TIMEOUT_SECONDS=10 \
  --env INTROSPECTION_CLIENT_SECRET=release-smoke-introspection-secret \
  --env RELEASE_SMOKE_TOTP_SECRET=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ \
  --env "ROBINE_ID_CONFIG_JSON=$root_configuration_json" \
  --env "ROBINE_ID_APPLICATIONS_JSON=$applications_json" \
  "$image" >/dev/null
wait_for_peer
peer_port=$(docker port "$peer_container" 4001/tcp | tail -n 1 | sed 's/.*://')
peer_url="http://$access_host:$peer_port"
curl --fail --silent "$peer_url/health/ready" | grep -q '"status":"ready"'

invalid_service_token="$temporary_directory/invalid-service-token.json"
test "$(
  curl --silent --output "$invalid_service_token" --write-out '%{http_code}' \
    --user 'release-resource-server:release-smoke-introspection-secret' \
    --data-urlencode 'grant_type=client_credentials' \
    --data-urlencode 'scope=openid' \
    "$base_url/default/token"
)" = '400'
grep -q '"error":"invalid_scope"' "$invalid_service_token"
invalid_service_resource="$temporary_directory/invalid-service-resource.json"
test "$(
  curl --silent --output "$invalid_service_resource" --write-out '%{http_code}' \
    --user 'release-resource-server:release-smoke-introspection-secret' \
    --data-urlencode 'grant_type=client_credentials' \
    --data-urlencode 'scope=service.read' \
    --data-urlencode 'resource=https://other-api.release.example' \
    "$base_url/default/token"
)" = '400'
grep -q '"error":"invalid_target"' "$invalid_service_resource"
service_token_response="$temporary_directory/service-token.json"
curl --fail --silent --output "$service_token_response" \
  --user 'release-resource-server:release-smoke-introspection-secret' \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode 'scope=service.read' \
  --data-urlencode 'resource=https://api.release.example' \
  "$base_url/default/token"
service_access_token=$(sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p' "$service_token_response")
test -n "$service_access_token"
grep -q '"token_type":"Bearer"' "$service_token_response"
grep -q '"scope":"service.read"' "$service_token_response"
grep -q '"resource":"https://api.release.example"' "$service_token_response"
if grep -Eq '"(id_token|refresh_token)"' "$service_token_response"; then
  printf '%s\n' 'client_credentials unexpectedly returned an OpenID or refresh token' >&2
  exit 1
fi
service_introspection=$(
  curl --fail --silent \
    --user 'release-resource-server:release-smoke-introspection-secret' \
    --data-urlencode "token=$service_access_token" \
    "$peer_url/default/introspect"
)
printf '%s' "$service_introspection" | grep -q '"active":true'
printf '%s' "$service_introspection" | grep -q '"client_id":"release-resource-server"'
printf '%s' "$service_introspection" | grep -q '"sub":"release-resource-server"'
printf '%s' "$service_introspection" | grep -q '"scope":"service.read"'
printf '%s' "$service_introspection" | grep -q '"aud":"https://api.release.example"'

jwt_service_response="$temporary_directory/jwt-service-token.json"
curl --fail --silent --output "$jwt_service_response" \
  --user 'release-resource-server:release-smoke-introspection-secret' \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode 'scope=service.read' \
  --data-urlencode 'resource=https://api.release.example' \
  "$base_url/jwt/token"
jwt_service_token=$(sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p' "$jwt_service_response")
test -n "$jwt_service_token"
test "$(printf '%s' "$jwt_service_token" | awk -F. '{print NF}')" = '3'
jwt_access_header=$(decode_base64url "$(printf '%s' "$jwt_service_token" | cut -d. -f1)")
jwt_access_payload=$(decode_base64url "$(printf '%s' "$jwt_service_token" | cut -d. -f2)")
jwt_access_kid=$(printf '%s' "$jwt_access_header" | sed -n 's/.*"kid":"\([^"]*\)".*/\1/p')
test -n "$jwt_access_kid"
printf '%s' "$jwt_access_header" | grep -q '"alg":"RS256"'
printf '%s' "$jwt_access_header" | grep -q '"typ":"at+jwt"'
printf '%s' "$jwt_access_payload" | grep -q "\"iss\":\"$jwt_issuer_url\""
printf '%s' "$jwt_access_payload" | grep -q '"sub":"release-resource-server"'
printf '%s' "$jwt_access_payload" | grep -q '"client_id":"release-resource-server"'
printf '%s' "$jwt_access_payload" | grep -q '"aud":"https://api.release.example"'
printf '%s' "$jwt_access_payload" | grep -q '"scope":"service.read"'
printf '%s' "$jwt_access_payload" | grep -Eq '"jti":"[^"]+"'
printf '%s' "$jwt_access_payload" | grep -Eq '"iat":[0-9]+'
printf '%s' "$jwt_access_payload" | grep -Eq '"exp":[0-9]+'
if printf '%s' "$jwt_access_payload" | grep -Eq '"(auth_time|acr|amr)"'; then
  printf '%s\n' 'client_credentials JWT unexpectedly contains user authentication context' >&2
  exit 1
fi
curl --fail --silent "$peer_url/jwt/jwks.json" \
  | grep -q "\"kid\":\"$jwt_access_kid\""
jwt_service_introspection=$(
  curl --fail --silent \
    --user 'release-resource-server:release-smoke-introspection-secret' \
    --data-urlencode "token=$jwt_service_token" \
    "$peer_url/jwt/introspect"
)
printf '%s' "$jwt_service_introspection" | grep -q '"active":true'
printf '%s' "$jwt_service_introspection" | grep -q '"client_id":"release-resource-server"'
if printf '%s' "$jwt_service_introspection" | grep -Eq '"(auth_time|acr|amr)"'; then
  printf '%s\n' 'client_credentials introspection unexpectedly contains user authentication context' >&2
  exit 1
fi
jwt_exchange_response="$temporary_directory/jwt-token-exchange.json"
curl --fail --silent --output "$jwt_exchange_response" \
  --user 'release-resource-server:release-smoke-introspection-secret' \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  --data-urlencode "subject_token=$jwt_service_token" \
  --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:access_token' \
  --data-urlencode 'scope=service.read' \
  --data-urlencode 'resource=https://api-exchanged.release.example' \
  "$peer_url/jwt/token"
jwt_exchanged_token=$(sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p' "$jwt_exchange_response")
test -n "$jwt_exchanged_token"
jwt_exchanged_header=$(decode_base64url "$(printf '%s' "$jwt_exchanged_token" | cut -d. -f1)")
jwt_exchanged_payload=$(decode_base64url "$(printf '%s' "$jwt_exchanged_token" | cut -d. -f2)")
printf '%s' "$jwt_exchanged_header" | grep -q '"typ":"at+jwt"'
printf '%s' "$jwt_exchanged_payload" \
  | grep -q '"aud":"https://api-exchanged.release.example"'
printf '%s' "$jwt_exchanged_payload" | grep -q '"scope":"service.read"'
grep -q '"issued_token_type":"urn:ietf:params:oauth:token-type:access_token"' \
  "$jwt_exchange_response"
jwt_exchanged_introspection=$(
  curl --fail --silent \
    --user 'release-resource-server:release-smoke-introspection-secret' \
    --data-urlencode "token=$jwt_exchanged_token" \
    "$base_url/jwt/introspect"
)
printf '%s' "$jwt_exchanged_introspection" | grep -q '"active":true'
printf '%s' "$jwt_exchanged_introspection" \
  | grep -q '"aud":"https://api-exchanged.release.example"'

jwt_dpop_proof=$(dpop_proof POST "$jwt_issuer_url/token" 'jwt-service-dpop')
jwt_dpop_response="$temporary_directory/jwt-dpop-service-token.json"
curl --fail --silent --output "$jwt_dpop_response" \
  --header "DPoP: $jwt_dpop_proof" \
  --user 'release-resource-server:release-smoke-introspection-secret' \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode 'scope=service.read' \
  --data-urlencode 'resource=https://api.release.example' \
  "$base_url/jwt/token"
jwt_dpop_token=$(sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p' "$jwt_dpop_response")
test -n "$jwt_dpop_token"
grep -q '"token_type":"DPoP"' "$jwt_dpop_response"
jwt_dpop_payload=$(decode_base64url "$(printf '%s' "$jwt_dpop_token" | cut -d. -f2)")
printf '%s' "$jwt_dpop_payload" | grep -q "\"cnf\":{\"jkt\":\"$dpop_jkt\"}"
jwt_dpop_introspection=$(
  curl --fail --silent \
    --user 'release-resource-server:release-smoke-introspection-secret' \
    --data-urlencode "token=$jwt_dpop_token" \
    "$peer_url/jwt/introspect"
)
printf '%s' "$jwt_dpop_introspection" | grep -q '"token_type":"DPoP"'
printf '%s' "$jwt_dpop_introspection" | grep -q "\"cnf\":{\"jkt\":\"$dpop_jkt\"}"
curl --fail --silent --output /dev/null \
  --user 'release-resource-server:release-smoke-introspection-secret' \
  --data-urlencode "token=$jwt_service_token" \
  "$base_url/jwt/revoke"
curl --fail --silent \
  --user 'release-resource-server:release-smoke-introspection-secret' \
  --data-urlencode "token=$jwt_service_token" \
  "$peer_url/jwt/introspect" | grep -q '"active":false'

invalid_exchange_scope="$temporary_directory/invalid-token-exchange-scope.json"
test "$(
  curl --silent --output "$invalid_exchange_scope" --write-out '%{http_code}' \
    --user 'release-resource-server:release-smoke-introspection-secret' \
    --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
    --data-urlencode "subject_token=$service_access_token" \
    --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:access_token' \
    --data-urlencode 'scope=service.write' \
    --data-urlencode 'resource=https://api-exchanged.release.example' \
    "$peer_url/default/token"
)" = '400'
grep -q '"error":"invalid_scope"' "$invalid_exchange_scope"

invalid_actor_exchange="$temporary_directory/invalid-token-exchange-actor.json"
test "$(
  curl --silent --output "$invalid_actor_exchange" --write-out '%{http_code}' \
    --user 'release-resource-server:release-smoke-introspection-secret' \
    --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
    --data-urlencode "subject_token=$service_access_token" \
    --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:access_token' \
    --data-urlencode "actor_token=$service_access_token" \
    --data-urlencode 'actor_token_type=urn:ietf:params:oauth:token-type:access_token' \
    "$base_url/default/token"
)" = '400'
grep -q '"error":"invalid_request"' "$invalid_actor_exchange"

exchange_response="$temporary_directory/token-exchange.json"
curl --fail --silent --output "$exchange_response" \
  --user 'release-resource-server:release-smoke-introspection-secret' \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  --data-urlencode "subject_token=$service_access_token" \
  --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:access_token' \
  --data-urlencode 'requested_token_type=urn:ietf:params:oauth:token-type:access_token' \
  --data-urlencode 'scope=service.read' \
  --data-urlencode 'audience=https://api-exchanged.release.example' \
  "$peer_url/default/token"
exchanged_access_token=$(sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p' "$exchange_response")
test -n "$exchanged_access_token"
grep -q '"issued_token_type":"urn:ietf:params:oauth:token-type:access_token"' "$exchange_response"
grep -q '"token_type":"Bearer"' "$exchange_response"
grep -q '"scope":"service.read"' "$exchange_response"
grep -q '"resource":"https://api-exchanged.release.example"' "$exchange_response"
if grep -Eq '"(id_token|refresh_token)"' "$exchange_response"; then
  printf '%s\n' 'token exchange unexpectedly returned an OpenID or refresh token' >&2
  exit 1
fi
exchanged_introspection=$(
  curl --fail --silent \
    --user 'release-resource-server:release-smoke-introspection-secret' \
    --data-urlencode "token=$exchanged_access_token" \
    "$base_url/default/introspect"
)
printf '%s' "$exchanged_introspection" | grep -q '"active":true'
printf '%s' "$exchanged_introspection" | grep -q '"client_id":"release-resource-server"'
printf '%s' "$exchanged_introspection" | grep -q '"sub":"release-resource-server"'
printf '%s' "$exchanged_introspection" | grep -q '"aud":"https://api-exchanged.release.example"'
test "$(
  curl --silent --output /dev/null --write-out '%{http_code}' \
    --header "Authorization: Bearer $service_access_token" \
    "$peer_url/default/userinfo"
)" = '401'
curl --fail --silent --output /dev/null \
  --user 'release-resource-server:release-smoke-introspection-secret' \
  --data-urlencode "token=$service_access_token" \
  "$peer_url/default/revoke"
curl --fail --silent \
  --user 'release-resource-server:release-smoke-introspection-secret' \
  --data-urlencode "token=$service_access_token" \
  "$base_url/default/introspect" | grep -q '"active":false'

assertion_type='urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
direct_request_object=$(authorization_request_object 'direct-request-single-use' 'signed-direct-state')
direct_request_page="$temporary_directory/direct-request-object.html"
curl --fail --silent --get --output "$direct_request_page" \
  --data-urlencode 'client_id=release-assertion-client' \
  --data-urlencode "request=$direct_request_object" \
  "$peer_url/default/authorize"
grep -q 'id="login-form"' "$direct_request_page"
test -n "$(hidden_value transaction "$direct_request_page")"
if grep -Eq 'name="(request|state|redirect_uri|client_id|code_challenge)"' "$direct_request_page"; then
  printf '%s\n' 'resolved authorization parameters leaked into the login continuation' >&2
  exit 1
fi
test "$(
  curl --silent --get --output /dev/null --write-out '%{http_code}' \
    --data-urlencode 'client_id=release-assertion-client' \
    --data-urlencode "request=$direct_request_object" \
    "$base_url/default/authorize"
)" = '400'
request_mismatch=$(authorization_request_object 'request-mismatch' 'signed-mismatch-state')
test "$(
  curl --silent --get --output /dev/null --write-out '%{http_code}' \
    --data-urlencode 'client_id=release-assertion-client' \
    --data-urlencode 'scope=openid service.read' \
    --data-urlencode "request=$request_mismatch" \
    "$base_url/default/authorize"
)" = '400'

assertion_par=$(client_assertion "$issuer_url/par" 'par-single-use')
assertion_par_dpop=$(dpop_proof POST "$issuer_url/par" 'assertion-par-dpop')
par_request_object=$(authorization_request_object 'par-request-single-use' 'signed-par-state')
assertion_par_nonce_headers="$temporary_directory/assertion-par-nonce.headers"
assertion_par_nonce_response="$temporary_directory/assertion-par-nonce.json"
test "$(
  curl --silent --dump-header "$assertion_par_nonce_headers" \
    --output "$assertion_par_nonce_response" --write-out '%{http_code}' \
    --header "DPoP: $assertion_par_dpop" \
    --data-urlencode 'client_id=release-assertion-client' \
    --data-urlencode "request=$par_request_object" \
    --data-urlencode "client_assertion_type=$assertion_type" \
    --data-urlencode "client_assertion=$assertion_par" \
    "$base_url/default/par"
)" = '400'
grep -q '"error":"use_dpop_nonce"' "$assertion_par_nonce_response"
authorization_server_dpop_nonce=$(header_value dpop-nonce "$assertion_par_nonce_headers")
test -n "$authorization_server_dpop_nonce"

assertion_par=$(client_assertion "$issuer_url/par" 'par-nonce-retry')
assertion_par_dpop=$(dpop_proof POST "$issuer_url/par" 'assertion-par-dpop-retry' '' "$authorization_server_dpop_nonce")
assertion_par_response="$temporary_directory/assertion-par.json"
curl --fail --silent --output "$assertion_par_response" \
  --header "DPoP: $assertion_par_dpop" \
  --data-urlencode 'client_id=release-assertion-client' \
  --data-urlencode "request=$par_request_object" \
  --data-urlencode "client_assertion_type=$assertion_type" \
  --data-urlencode "client_assertion=$assertion_par" \
  "$base_url/default/par"
grep -q '"request_uri":"urn:ietf:params:oauth:request_uri:' "$assertion_par_response"
assertion_par_request_uri=$(sed -n 's/.*"request_uri":"\([^"]*\)".*/\1/p' "$assertion_par_response")
assertion_par_page="$temporary_directory/assertion-par.html"
curl --fail --silent --get --output "$assertion_par_page" \
  --data-urlencode 'client_id=release-assertion-client' \
  --data-urlencode "request_uri=$assertion_par_request_uri" \
  "$peer_url/default/authorize"
grep -q 'id="login-form"' "$assertion_par_page"
test -n "$(hidden_value transaction "$assertion_par_page")"
if grep -q 'name="state"' "$assertion_par_page"; then
  printf '%s\n' 'signed pushed authorization state leaked into the login continuation' >&2
  exit 1
fi
if grep -q 'name="dpop_jkt"' "$assertion_par_page"; then
  printf '%s\n' 'DPoP binding leaked into the login continuation' >&2
  exit 1
fi

assertion_token=$(client_assertion "$issuer_url/token" 'token-single-use')
assertion_dpop_proof=$(dpop_proof POST "$issuer_url/token" 'assertion-token-dpop' '' "$authorization_server_dpop_nonce")
assertion_token_response="$temporary_directory/assertion-token.json"
curl --fail --silent --output "$assertion_token_response" \
  --header "DPoP: $assertion_dpop_proof" \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode 'client_id=release-assertion-client' \
  --data-urlencode 'scope=service.read' \
  --data-urlencode 'resource=https://api.release.example' \
  --data-urlencode "client_assertion_type=$assertion_type" \
  --data-urlencode "client_assertion=$assertion_token" \
  "$base_url/default/token"
assertion_access_token=$(sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p' "$assertion_token_response")
test -n "$assertion_access_token"
grep -q '"resource":"https://api.release.example"' "$assertion_token_response"
grep -q '"token_type":"DPoP"' "$assertion_token_response"

missing_exchange_proof_assertion=$(client_assertion "$issuer_url/token" 'missing-exchange-proof')
missing_exchange_proof="$temporary_directory/missing-token-exchange-proof.json"
test "$(
  curl --silent --output "$missing_exchange_proof" --write-out '%{http_code}' \
    --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
    --data-urlencode 'client_id=release-assertion-client' \
    --data-urlencode "subject_token=$assertion_access_token" \
    --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:access_token' \
    --data-urlencode 'scope=service.read' \
    --data-urlencode 'resource=https://api-exchanged.release.example' \
    --data-urlencode "client_assertion_type=$assertion_type" \
    --data-urlencode "client_assertion=$missing_exchange_proof_assertion" \
    "$peer_url/default/token"
)" = '400'
grep -q '"error":"invalid_dpop_proof"' "$missing_exchange_proof"

dpop_exchange_assertion=$(client_assertion "$issuer_url/token" 'dpop-token-exchange')
dpop_exchange_proof=$(dpop_proof POST "$issuer_url/token" 'dpop-token-exchange-proof' '' "$authorization_server_dpop_nonce")
dpop_exchange_response="$temporary_directory/dpop-token-exchange.json"
curl --fail --silent --output "$dpop_exchange_response" \
  --header "DPoP: $dpop_exchange_proof" \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  --data-urlencode 'client_id=release-assertion-client' \
  --data-urlencode "subject_token=$assertion_access_token" \
  --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:access_token' \
  --data-urlencode 'scope=service.read' \
  --data-urlencode 'resource=https://api-exchanged.release.example' \
  --data-urlencode "client_assertion_type=$assertion_type" \
  --data-urlencode "client_assertion=$dpop_exchange_assertion" \
  "$peer_url/default/token"
dpop_exchanged_access_token=$(sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p' "$dpop_exchange_response")
test -n "$dpop_exchanged_access_token"
grep -q '"issued_token_type":"urn:ietf:params:oauth:token-type:access_token"' "$dpop_exchange_response"
grep -q '"token_type":"DPoP"' "$dpop_exchange_response"
grep -q '"resource":"https://api-exchanged.release.example"' "$dpop_exchange_response"
dpop_exchange_introspection_assertion=$(client_assertion "$issuer_url/introspect" 'dpop-exchange-introspection')
dpop_exchange_introspection=$(
  curl --fail --silent \
    --data-urlencode "token=$dpop_exchanged_access_token" \
    --data-urlencode 'client_id=release-assertion-client' \
    --data-urlencode "client_assertion_type=$assertion_type" \
    --data-urlencode "client_assertion=$dpop_exchange_introspection_assertion" \
    "$base_url/default/introspect"
)
printf '%s' "$dpop_exchange_introspection" | grep -q '"active":true'
printf '%s' "$dpop_exchange_introspection" | grep -q '"token_type":"DPoP"'
printf '%s' "$dpop_exchange_introspection" \
  | grep -q "\"cnf\":{\"jkt\":\"$dpop_jkt\"}"

dpop_replay_assertion=$(client_assertion "$issuer_url/token" 'dpop-replay-fresh-client-assertion')
dpop_replay_response="$temporary_directory/dpop-replay.json"
test "$(
  curl --silent --output "$dpop_replay_response" --write-out '%{http_code}' \
    --header "DPoP: $assertion_dpop_proof" \
    --data-urlencode 'grant_type=client_credentials' \
    --data-urlencode 'client_id=release-assertion-client' \
    --data-urlencode 'scope=service.read' \
    --data-urlencode "client_assertion_type=$assertion_type" \
    --data-urlencode "client_assertion=$dpop_replay_assertion" \
    "$peer_url/default/token"
)" = '400'
grep -q '"error":"invalid_dpop_proof"' "$dpop_replay_response"

assertion_replay_response="$temporary_directory/assertion-replay.json"
test "$(
  curl --silent --output "$assertion_replay_response" --write-out '%{http_code}' \
    --data-urlencode 'grant_type=client_credentials' \
    --data-urlencode 'client_id=release-assertion-client' \
    --data-urlencode 'scope=service.read' \
    --data-urlencode "client_assertion_type=$assertion_type" \
    --data-urlencode "client_assertion=$assertion_token" \
    "$peer_url/default/token"
)" = '401'
grep -q '"error":"invalid_client"' "$assertion_replay_response"

assertion_wrong_audience=$(client_assertion "$issuer_url/revoke" 'wrong-audience')
assertion_wrong_audience_response="$temporary_directory/assertion-wrong-audience.json"
test "$(
  curl --silent --output "$assertion_wrong_audience_response" --write-out '%{http_code}' \
    --data-urlencode 'grant_type=client_credentials' \
    --data-urlencode 'client_id=release-assertion-client' \
    --data-urlencode 'scope=service.read' \
    --data-urlencode "client_assertion_type=$assertion_type" \
    --data-urlencode "client_assertion=$assertion_wrong_audience" \
    "$base_url/default/token"
)" = '401'
grep -q '"error":"invalid_client"' "$assertion_wrong_audience_response"

assertion_introspection=$(client_assertion "$issuer_url/introspect" 'introspection-single-use')
assertion_introspection_response=$(
  curl --fail --silent \
    --data-urlencode "token=$assertion_access_token" \
    --data-urlencode 'client_id=release-assertion-client' \
    --data-urlencode "client_assertion_type=$assertion_type" \
    --data-urlencode "client_assertion=$assertion_introspection" \
    "$peer_url/default/introspect"
)
printf '%s' "$assertion_introspection_response" | grep -q '"active":true'
printf '%s' "$assertion_introspection_response" \
  | grep -q '"aud":"https://api.release.example"'
printf '%s' "$assertion_introspection_response" | grep -q '"token_type":"DPoP"'
printf '%s' "$assertion_introspection_response" \
  | grep -q "\"cnf\":{\"jkt\":\"$dpop_jkt\"}"

assertion_revocation=$(client_assertion "$issuer_url/revoke" 'revocation-single-use')
curl --fail --silent --output /dev/null \
  --data-urlencode "token=$assertion_access_token" \
  --data-urlencode 'client_id=release-assertion-client' \
  --data-urlencode "client_assertion_type=$assertion_type" \
  --data-urlencode "client_assertion=$assertion_revocation" \
  "$base_url/default/revoke"
assertion_post_revoke=$(client_assertion "$issuer_url/introspect" 'post-revoke-single-use')
curl --fail --silent \
  --data-urlencode "token=$assertion_access_token" \
  --data-urlencode 'client_id=release-assertion-client' \
  --data-urlencode "client_assertion_type=$assertion_type" \
  --data-urlencode "client_assertion=$assertion_post_revoke" \
  "$peer_url/default/introspect" | grep -q '"active":false'

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
refresh_response="$temporary_directory/refresh.json"

mandatory_par_direct_headers="$temporary_directory/mandatory-par-direct.headers"
test "$(
  curl --silent --get --dump-header "$mandatory_par_direct_headers" --output /dev/null \
    --write-out '%{http_code}' \
    --data-urlencode 'response_type=code' \
    --data-urlencode 'client_id=release-par-required-client' \
    --data-urlencode "redirect_uri=http://127.0.0.1:$redirect_port/par-required-callback" \
    --data-urlencode 'scope=openid' \
    --data-urlencode 'state=mandatory-par-direct-state' \
    --data-urlencode 'nonce=mandatory-par-direct-nonce' \
    --data-urlencode "code_challenge=$challenge" \
    --data-urlencode 'code_challenge_method=S256' \
    "$base_url/default/authorize"
)" = '302'
mandatory_par_direct_location=$(header_value location "$mandatory_par_direct_headers")
printf '%s' "$mandatory_par_direct_location" | grep -q 'error=invalid_request'
printf '%s' "$mandatory_par_direct_location" | grep -q 'state=mandatory-par-direct-state'

mandatory_par_response=$(
  curl --fail --silent \
    --data-urlencode 'response_type=code' \
    --data-urlencode 'client_id=release-par-required-client' \
    --data-urlencode "redirect_uri=http://127.0.0.1:$redirect_port/par-required-callback" \
    --data-urlencode 'scope=openid' \
    --data-urlencode 'state=mandatory-par-pushed-state' \
    --data-urlencode 'nonce=mandatory-par-pushed-nonce' \
    --data-urlencode "code_challenge=$challenge" \
    --data-urlencode 'code_challenge_method=S256' \
    "$base_url/default/par"
)
mandatory_par_request_uri=$(printf '%s' "$mandatory_par_response" \
  | sed -n 's/.*"request_uri":"\([^"]*\)".*/\1/p')
test -n "$mandatory_par_request_uri"
mandatory_par_login="$temporary_directory/mandatory-par-login.html"
curl --fail --silent --get \
  --data-urlencode 'client_id=release-par-required-client' \
  --data-urlencode "request_uri=$mandatory_par_request_uri" \
  "$peer_url/default/authorize" >"$mandatory_par_login"
grep -q 'id="login-form"' "$mandatory_par_login"
test -n "$(hidden_value transaction "$mandatory_par_login")"

par_response="$temporary_directory/par.json"
par_headers="$temporary_directory/par.headers"
invalid_par_response="$temporary_directory/invalid-par.json"
invalid_par_status=$(
  curl --silent --output "$invalid_par_response" --write-out '%{http_code}' \
    --user 'release-resource-server:wrong-secret' \
    --data-urlencode 'response_type=code' \
    --data-urlencode 'client_id=release-resource-server' \
    --data-urlencode "redirect_uri=http://127.0.0.1:$redirect_port/resource-callback" \
    --data-urlencode 'scope=openid' \
    --data-urlencode 'state=invalid-par-authentication' \
    --data-urlencode 'nonce=invalid-par-authentication' \
    --data-urlencode "code_challenge=$challenge" \
    --data-urlencode 'code_challenge_method=S256' \
    "$base_url/default/par"
)
test "$invalid_par_status" = '401'
grep -q '"error":"invalid_client"' "$invalid_par_response"
curl --fail --silent --dump-header "$par_headers" --output "$par_response" \
  --header "Origin: http://127.0.0.1:$redirect_port" \
  --data-urlencode 'response_type=code' \
  --data-urlencode 'client_id=release-smoke-client' \
  --data-urlencode "redirect_uri=$redirect_uri" \
  --data-urlencode 'scope=openid profile email' \
  --data-urlencode 'state=par-cross-instance-state' \
  --data-urlencode 'nonce=par-cross-instance-nonce' \
  --data-urlencode "code_challenge=$challenge" \
  --data-urlencode 'code_challenge_method=S256' \
  "$base_url/default/par"
grep -qi '^cache-control: no-store' "$par_headers"
tr -d '\r' <"$par_headers" \
  | grep -qi "^access-control-allow-origin: http://127.0.0.1:$redirect_port$"
grep -q '"expires_in":90' "$par_response"
par_request_uri=$(sed -n 's/.*"request_uri":"\([^"]*\)".*/\1/p' "$par_response")
test -n "$par_request_uri"
printf '%s' "$par_request_uri" | grep -q '^urn:ietf:params:oauth:request_uri:'
wrong_par_status=$(
  curl --silent --get --output /dev/null --write-out '%{http_code}' \
    --data-urlencode 'client_id=release-resource-server' \
    --data-urlencode "request_uri=$par_request_uri" \
    "$peer_url/default/authorize"
)
test "$wrong_par_status" = '400'
par_login_page="$temporary_directory/par-login.html"
curl --fail --silent --get \
  --data-urlencode 'client_id=release-smoke-client' \
  --data-urlencode "request_uri=$par_request_uri" \
  "$peer_url/default/authorize" >"$par_login_page"
grep -q 'id="login-form"' "$par_login_page"
test -n "$(hidden_value transaction "$par_login_page")"
if grep -q 'name="state"' "$par_login_page"; then
  printf '%s\n' 'pushed authorization state leaked into the login continuation' >&2
  exit 1
fi
par_replay_status=$(
  curl --silent --get --output /dev/null --write-out '%{http_code}' \
    --data-urlencode 'client_id=release-smoke-client' \
    --data-urlencode "request_uri=$par_request_uri" \
    "$base_url/default/authorize"
)
test "$par_replay_status" = '400'

par_post_response=$(
  curl --fail --silent \
    --data-urlencode 'response_type=code' \
    --data-urlencode 'client_id=release-smoke-client' \
    --data-urlencode "redirect_uri=$redirect_uri" \
    --data-urlencode 'scope=openid profile email' \
    --data-urlencode 'state=par-form-post-state' \
    --data-urlencode 'nonce=par-form-post-nonce' \
    --data-urlencode "code_challenge=$challenge" \
    --data-urlencode 'code_challenge_method=S256' \
    "$peer_url/default/par"
)
par_post_request_uri=$(printf '%s' "$par_post_response" \
  | sed -n 's/.*"request_uri":"\([^"]*\)".*/\1/p')
test -n "$par_post_request_uri"
par_post_login_page="$temporary_directory/par-post-login.html"
curl --fail --silent \
  --data-urlencode 'client_id=release-smoke-client' \
  --data-urlencode "request_uri=$par_post_request_uri" \
  "$base_url/default/authorize" >"$par_post_login_page"
grep -q 'id="login-form"' "$par_post_login_page"
test -n "$(hidden_value transaction "$par_post_login_page")"
if grep -q 'name="state"' "$par_post_login_page"; then
  printf '%s\n' 'form-post pushed authorization state leaked into the login continuation' >&2
  exit 1
fi

curl --fail --silent --get --cookie-jar "$cookie_jar" \
  --data-urlencode 'response_type=code' \
  --data-urlencode 'client_id=release-smoke-client' \
  --data-urlencode "redirect_uri=$redirect_uri" \
  --data-urlencode 'scope=openid profile email offline_access' \
  --data-urlencode "state=$state" \
  --data-urlencode "nonce=$nonce" \
  --data-urlencode "code_challenge=$challenge" \
  --data-urlencode 'code_challenge_method=S256' \
  --data-urlencode "dpop_jkt=$dpop_jkt" \
  "$base_url/default/authorize" >"$login_page"
csrf_token=$(hidden_value csrf_token "$login_page")
login_transaction=$(hidden_value transaction "$login_page")
test -n "$csrf_token"
test -n "$login_transaction"
initial_login_transaction=$login_transaction

invalid_login_page="$temporary_directory/invalid-login.html"
invalid_login_status=$(
  curl --silent --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
    --output "$invalid_login_page" --write-out '%{http_code}' \
    --data-urlencode "csrf_token=$csrf_token" \
    --data-urlencode "transaction=$login_transaction" \
    --data-urlencode 'identifier=admin@example.com' \
    --data-urlencode 'password=incorrect-password' \
    "$base_url/default/authorize"
)
test "$invalid_login_status" = '422'
grep -q 'id="login-error"' "$invalid_login_page"
grep -q 'value="admin@example.com"' "$invalid_login_page"
if grep -q 'incorrect-password' "$invalid_login_page"; then
  printf 'failed: rejected password was rendered back to the browser\n' >&2
  exit 1
fi
csrf_token=$(hidden_value csrf_token "$invalid_login_page")
login_transaction=$(hidden_value transaction "$invalid_login_page")
test -n "$csrf_token"
test -n "$login_transaction"
test "$login_transaction" != "$initial_login_transaction"
test "$(
  curl --silent --cookie "$cookie_jar" --output /dev/null --write-out '%{http_code}' \
    --data-urlencode "csrf_token=$csrf_token" \
    --data-urlencode "transaction=$initial_login_transaction" \
    --data-urlencode 'identifier=admin@example.com' \
    --data-urlencode 'password=change-me' \
    "$base_url/default/authorize"
)" = '400'

curl --fail --silent --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
  --dump-header "$authentication_headers" --output "$consent_page" \
  --data-urlencode "csrf_token=$csrf_token" \
  --data-urlencode "transaction=$login_transaction" \
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
printf '%s' "$authorization_location" \
  | grep -q "[?&]iss=http%3A%2F%2F127.0.0.1%3A${bind_port}%2Fdefault"

authorization_code_dpop=$(dpop_proof POST "$issuer_url/token" 'authorization-code-token-dpop' '' "$authorization_server_dpop_nonce")
curl --fail --silent \
  --header "DPoP: $authorization_code_dpop" \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode "code=$code" \
  --data-urlencode 'client_id=release-smoke-client' \
  --data-urlencode "redirect_uri=$redirect_uri" \
  --data-urlencode "code_verifier=$verifier" \
  "$base_url/default/token" >"$token_response"
access_token=$(sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p' "$token_response")
id_token=$(sed -n 's/.*"id_token":"\([^"]*\)".*/\1/p' "$token_response")
refresh_token=$(sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p' "$token_response")
test -n "$access_token"
test -n "$id_token"
test -n "$refresh_token"
grep -q '"token_type":"DPoP"' "$token_response"

jwt_header=$(decode_base64url "$(printf '%s' "$id_token" | cut -d. -f1)")
jwt_payload=$(decode_base64url "$(printf '%s' "$id_token" | cut -d. -f2)")
kid=$(printf '%s' "$jwt_header" | sed -n 's/.*"kid":"\([^"]*\)".*/\1/p')
test -n "$kid"
printf '%s' "$jwt_header" | grep -q '"alg":"RS256"'
printf '%s' "$jwt_payload" | grep -q "\"iss\":\"$issuer_url\""
printf '%s' "$jwt_payload" | grep -q '"sub":"release-smoke-user"'
printf '%s' "$jwt_payload" | grep -q '"aud":"release-smoke-client"'
printf '%s' "$jwt_payload" | grep -q "\"nonce\":\"$nonce\""
printf '%s' "$jwt_payload" | grep -Eq '"auth_time":[0-9]+'
printf '%s' "$jwt_payload" | grep -q '"acr":"urn:robine-id:acr:password"'
printf '%s' "$jwt_payload" | grep -q '"amr":\["pwd"\]'
at_hash=$(printf '%s' "$jwt_payload" | sed -n 's/.*"at_hash":"\([^"]*\)".*/\1/p')
test "$at_hash" = "$(oidc_access_token_hash "$access_token")"

mfa_policy_cookie_jar="$temporary_directory/mfa-policy-denied-cookies.txt"
mfa_policy_login_page="$temporary_directory/mfa-policy-denied-login.html"
curl --fail --silent --get --cookie-jar "$mfa_policy_cookie_jar" \
  --data-urlencode 'response_type=code' \
  --data-urlencode 'client_id=release-mfa-client' \
  --data-urlencode "redirect_uri=$redirect_uri" \
  --data-urlencode 'scope=openid' \
  --data-urlencode 'state=mfa-policy-denied' \
  --data-urlencode 'nonce=mfa-policy-denied' \
  --data-urlencode "code_challenge=$challenge" \
  --data-urlencode 'code_challenge_method=S256' \
  "$base_url/default/authorize" >"$mfa_policy_login_page"
mfa_policy_csrf=$(hidden_value csrf_token "$mfa_policy_login_page")
mfa_policy_transaction=$(hidden_value transaction "$mfa_policy_login_page")
mfa_policy_headers="$temporary_directory/mfa-policy-denied.headers"
test "$(
  curl --silent --cookie "$mfa_policy_cookie_jar" \
    --dump-header "$mfa_policy_headers" --output /dev/null --write-out '%{http_code}' \
    --data-urlencode "csrf_token=$mfa_policy_csrf" \
    --data-urlencode "transaction=$mfa_policy_transaction" \
    --data-urlencode 'identifier=admin@example.com' \
    --data-urlencode 'password=change-me' \
    "$base_url/default/authorize"
)" = '302'
mfa_policy_location=$(header_value location "$mfa_policy_headers")
printf '%s' "$mfa_policy_location" | grep -q '[?&]error=access_denied'
printf '%s' "$mfa_policy_location" | grep -q '[?&]state=mfa-policy-denied'

mfa_cookie_jar="$temporary_directory/mfa-cookies.txt"
mfa_login_page="$temporary_directory/mfa-login.html"
curl --fail --silent --get --cookie-jar "$mfa_cookie_jar" \
  --data-urlencode 'response_type=code' \
  --data-urlencode 'client_id=release-mfa-client' \
  --data-urlencode "redirect_uri=$redirect_uri" \
  --data-urlencode 'scope=openid offline_access' \
  --data-urlencode 'state=mfa-state' \
  --data-urlencode 'nonce=mfa-nonce' \
  --data-urlencode 'acr_values=urn:robine-id:acr:password+totp urn:robine-id:acr:password' \
  --data-urlencode 'claims={"id_token":{"acr":{"essential":true,"value":"urn:robine-id:acr:password+totp"},"auth_time":{"essential":true}}}' \
  --data-urlencode "code_challenge=$challenge" \
  --data-urlencode 'code_challenge_method=S256' \
  "$base_url/default/authorize" >"$mfa_login_page"
mfa_csrf=$(hidden_value csrf_token "$mfa_login_page")
mfa_login_transaction=$(hidden_value transaction "$mfa_login_page")
test -n "$mfa_csrf"
test -n "$mfa_login_transaction"

mfa_totp_page="$temporary_directory/mfa-totp.html"
curl --fail --silent --cookie "$mfa_cookie_jar" --cookie-jar "$mfa_cookie_jar" \
  --data-urlencode "csrf_token=$mfa_csrf" \
  --data-urlencode "transaction=$mfa_login_transaction" \
  --data-urlencode 'identifier=mfa@example.com' \
  --data-urlencode 'password=change-me' \
  "$base_url/default/authorize" >"$mfa_totp_page"
grep -q 'id="totp-form"' "$mfa_totp_page"
if grep -Eq 'RELEASE_SMOKE_TOTP_SECRET|GEZDGNBVGY3TQOJQ' "$mfa_totp_page"; then
  printf '%s\n' 'TOTP challenge exposed secret material' >&2
  exit 1
fi
mfa_csrf=$(hidden_value csrf_token "$mfa_totp_page")
mfa_transaction=$(hidden_value mfa_transaction "$mfa_totp_page")
test -n "$mfa_csrf"
test -n "$mfa_transaction"
mfa_code=$(smoke_totp 0)
mfa_code_first=$(printf '%s' "$mfa_code" | cut -c 1)
if [ "$mfa_code_first" = '0' ]; then
  wrong_mfa_code="1$(printf '%s' "$mfa_code" | cut -c 2-6)"
else
  wrong_mfa_code="0$(printf '%s' "$mfa_code" | cut -c 2-6)"
fi
mfa_invalid_page="$temporary_directory/mfa-invalid.html"
mfa_invalid_status=$(
  curl --silent --cookie "$mfa_cookie_jar" --cookie-jar "$mfa_cookie_jar" \
    --output "$mfa_invalid_page" --write-out '%{http_code}' \
    --data-urlencode "csrf_token=$mfa_csrf" \
    --data-urlencode "mfa_transaction=$mfa_transaction" \
    --data-urlencode "totp_code=$wrong_mfa_code" \
    "$peer_url/default/authorize"
)
test "$mfa_invalid_status" = '422'
grep -q 'id="totp-error"' "$mfa_invalid_page"
mfa_csrf=$(hidden_value csrf_token "$mfa_invalid_page")
mfa_transaction=$(hidden_value mfa_transaction "$mfa_invalid_page")
mfa_consent_page="$temporary_directory/mfa-consent.html"
curl --fail --silent --cookie "$mfa_cookie_jar" --cookie-jar "$mfa_cookie_jar" \
  --data-urlencode "csrf_token=$mfa_csrf" \
  --data-urlencode "mfa_transaction=$mfa_transaction" \
  --data-urlencode "totp_code=$mfa_code" \
  "$base_url/default/authorize" >"$mfa_consent_page"
grep -q 'id="consent-form"' "$mfa_consent_page"
mfa_consent_transaction=$(hidden_value transaction "$mfa_consent_page")
mfa_csrf=$(hidden_value csrf_token "$mfa_consent_page")
mfa_consent_headers="$temporary_directory/mfa-consent.headers"
curl --fail --silent --cookie "$mfa_cookie_jar" --cookie-jar "$mfa_cookie_jar" \
  --dump-header "$mfa_consent_headers" --output /dev/null \
  --data-urlencode "transaction=$mfa_consent_transaction" \
  --data-urlencode "csrf_token=$mfa_csrf" \
  --data-urlencode 'decision=approve' \
  "$peer_url/default/authorize/consent"
mfa_location=$(header_value location "$mfa_consent_headers")
mfa_authorization_code=$(printf '%s' "$mfa_location" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
test -n "$mfa_authorization_code"
mfa_token_dpop=$(dpop_proof POST "$issuer_url/token" 'mfa-code-token-dpop' '' "$authorization_server_dpop_nonce")
mfa_token_response="$temporary_directory/mfa-token.json"
curl --fail --silent --header "DPoP: $mfa_token_dpop" \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode "code=$mfa_authorization_code" \
  --data-urlencode 'client_id=release-mfa-client' \
  --data-urlencode "redirect_uri=$redirect_uri" \
  --data-urlencode "code_verifier=$verifier" \
  "$base_url/default/token" >"$mfa_token_response"
mfa_id_token=$(sed -n 's/.*"id_token":"\([^"]*\)".*/\1/p' "$mfa_token_response")
mfa_access_token=$(sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p' "$mfa_token_response")
mfa_refresh_token=$(sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p' "$mfa_token_response")
test -n "$mfa_id_token"
test -n "$mfa_access_token"
test -n "$mfa_refresh_token"
mfa_payload=$(decode_base64url "$(printf '%s' "$mfa_id_token" | cut -d. -f2)")
printf '%s' "$mfa_payload" | grep -q '"sub":"release-smoke-mfa-user"'
printf '%s' "$mfa_payload" | grep -q '"aud":"release-mfa-client"'
printf '%s' "$mfa_payload" | grep -q '"acr":"urn:robine-id:acr:password+totp"'
printf '%s' "$mfa_payload" | grep -q '"amr":\["pwd","otp"\]'
mfa_introspection=$(
  curl --fail --silent \
    --user 'release-resource-server:release-smoke-introspection-secret' \
    --data-urlencode "token=$mfa_access_token" \
    "$peer_url/default/introspect"
)
printf '%s' "$mfa_introspection" | grep -q '"active":true'
printf '%s' "$mfa_introspection" | grep -q '"client_id":"release-mfa-client"'
printf '%s' "$mfa_introspection" | grep -Eq '"auth_time":[0-9]+'
printf '%s' "$mfa_introspection" | grep -q '"acr":"urn:robine-id:acr:password+totp"'
printf '%s' "$mfa_introspection" | grep -q '"amr":\["pwd","otp"\]'
mfa_refresh_dpop=$(dpop_proof POST "$issuer_url/token" 'mfa-refresh-token-dpop' '' "$authorization_server_dpop_nonce")
mfa_refresh_response="$temporary_directory/mfa-refresh.json"
curl --fail --silent --header "DPoP: $mfa_refresh_dpop" \
  --data-urlencode 'grant_type=refresh_token' \
  --data-urlencode "refresh_token=$mfa_refresh_token" \
  --data-urlencode 'client_id=release-mfa-client' \
  "$peer_url/default/token" >"$mfa_refresh_response"
mfa_refreshed_id_token=$(sed -n 's/.*"id_token":"\([^"]*\)".*/\1/p' "$mfa_refresh_response")
test -n "$mfa_refreshed_id_token"
mfa_refreshed_payload=$(decode_base64url "$(printf '%s' "$mfa_refreshed_id_token" | cut -d. -f2)")
printf '%s' "$mfa_refreshed_payload" | grep -q '"acr":"urn:robine-id:acr:password+totp"'
printf '%s' "$mfa_refreshed_payload" | grep -q '"amr":\["pwd","otp"\]'
curl --fail --silent "$base_url/metrics" \
  | grep -Eq 'robine_id_mfa_total\{outcome="success"\} [1-9][0-9]*'

jwks_headers="$temporary_directory/jwks.headers"
jwks_body="$temporary_directory/jwks.json"
curl --fail --silent --dump-header "$jwks_headers" --output "$jwks_body" \
  "$base_url/default/jwks.json"
grep -q "\"kid\":\"$kid\"" "$jwks_body"
jwks_etag=$(
  awk 'tolower($1) == "etag:" {gsub("\r", "", $2); print $2}' "$jwks_headers" \
    | tail -n 1
)
test -n "$jwks_etag"
test "$(
  curl --silent --output /dev/null --write-out '%{http_code}' \
    --header "If-None-Match: $jwks_etag" "$base_url/default/jwks.json"
)" = "304"
original_auth_time=$(printf '%s' "$jwt_payload" | sed -n 's/.*"auth_time":\([0-9][0-9]*\).*/\1/p')
test -n "$original_auth_time"

missing_refresh_dpop_response="$temporary_directory/missing-refresh-dpop.json"
test "$(
  curl --silent --output "$missing_refresh_dpop_response" --write-out '%{http_code}' \
    --data-urlencode 'grant_type=refresh_token' \
    --data-urlencode "refresh_token=$refresh_token" \
    --data-urlencode 'client_id=release-smoke-client' \
    "$peer_url/default/token"
)" = '400'
grep -q '"error":"invalid_dpop_proof"' "$missing_refresh_dpop_response"

refresh_dpop=$(dpop_proof POST "$issuer_url/token" 'first-refresh-dpop' '' "$authorization_server_dpop_nonce")
curl --fail --silent \
  --header "DPoP: $refresh_dpop" \
  --data-urlencode 'grant_type=refresh_token' \
  --data-urlencode "refresh_token=$refresh_token" \
  --data-urlencode 'client_id=release-smoke-client' \
  "$peer_url/default/token" >"$refresh_response"
refreshed_access_token=$(sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p' "$refresh_response")
refreshed_id_token=$(sed -n 's/.*"id_token":"\([^"]*\)".*/\1/p' "$refresh_response")
rotated_refresh_token=$(sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p' "$refresh_response")
test -n "$refreshed_access_token"
test -n "$refreshed_id_token"
test -n "$rotated_refresh_token"
test "$rotated_refresh_token" != "$refresh_token"
grep -q '"token_type":"DPoP"' "$refresh_response"
refreshed_payload=$(decode_base64url "$(printf '%s' "$refreshed_id_token" | cut -d. -f2)")
printf '%s' "$refreshed_payload" | grep -q "\"auth_time\":$original_auth_time"
printf '%s' "$refreshed_payload" | grep -q '"acr":"urn:robine-id:acr:password"'
printf '%s' "$refreshed_payload" | grep -q '"amr":\["pwd"\]'
refreshed_at_hash=$(printf '%s' "$refreshed_payload" | sed -n 's/.*"at_hash":"\([^"]*\)".*/\1/p')
test "$refreshed_at_hash" = "$(oidc_access_token_hash "$refreshed_access_token")"
refreshed_introspection=$(
  curl --fail --silent \
    --user 'release-resource-server:release-smoke-introspection-secret' \
    --data-urlencode "token=$refreshed_access_token" \
    "$base_url/default/introspect"
)
printf '%s' "$refreshed_introspection" | grep -q "\"auth_time\":$original_auth_time"
printf '%s' "$refreshed_introspection" | grep -q '"acr":"urn:robine-id:acr:password"'
printf '%s' "$refreshed_introspection" | grep -q '"amr":\["pwd"\]'
if printf '%s' "$refreshed_payload" | grep -q '"nonce"'; then
  printf '%s\n' 'refreshed ID token unexpectedly contains a nonce' >&2
  exit 1
fi
refreshed_userinfo_dpop=$(dpop_proof GET "$issuer_url/userinfo" 'refreshed-userinfo-wrong-context-nonce' "$refreshed_access_token" "$authorization_server_dpop_nonce")
userinfo_nonce_headers="$temporary_directory/userinfo-nonce.headers"
userinfo_nonce_response="$temporary_directory/userinfo-nonce.json"
test "$(
  curl --silent --dump-header "$userinfo_nonce_headers" \
    --output "$userinfo_nonce_response" --write-out '%{http_code}' \
    --header "Authorization: DPoP $refreshed_access_token" \
    --header "DPoP: $refreshed_userinfo_dpop" \
    "$base_url/default/userinfo"
)" = '401'
grep -q '"error":"use_dpop_nonce"' "$userinfo_nonce_response"
grep -q 'DPoP error="use_dpop_nonce"' "$userinfo_nonce_headers"
userinfo_dpop_nonce=$(header_value dpop-nonce "$userinfo_nonce_headers")
test -n "$userinfo_dpop_nonce"
test "$userinfo_dpop_nonce" != "$authorization_server_dpop_nonce"

refreshed_userinfo_dpop=$(dpop_proof GET "$issuer_url/userinfo" 'refreshed-userinfo-dpop' "$refreshed_access_token" "$userinfo_dpop_nonce")
curl --fail --silent --header "Authorization: DPoP $refreshed_access_token" \
  --header "DPoP: $refreshed_userinfo_dpop" \
  "$base_url/default/userinfo" | grep -q '"sub":"release-smoke-user"'

test "$(
  curl --silent --output "$temporary_directory/bound-token-as-bearer.json" --write-out '%{http_code}' \
    --header "Authorization: Bearer $access_token" \
    "$peer_url/default/userinfo"
)" = '401'
grep -q '"error":"invalid_token"' "$temporary_directory/bound-token-as-bearer.json"

userinfo_dpop=$(dpop_proof GET "$issuer_url/userinfo" 'original-userinfo-dpop' "$access_token" "$userinfo_dpop_nonce")
user_info=$(curl --fail --silent --header "Authorization: DPoP $access_token" \
  --header "DPoP: $userinfo_dpop" "$peer_url/default/userinfo")
printf '%s' "$user_info" | grep -q '"sub":"release-smoke-user"'
printf '%s' "$user_info" | grep -q '"name":"Release Smoke User"'
printf '%s' "$user_info" | grep -q '"email":"admin@example.com"'
test "$(
  curl --silent --output "$temporary_directory/replayed-userinfo-dpop.json" --write-out '%{http_code}' \
    --header "Authorization: DPoP $access_token" \
    --header "DPoP: $userinfo_dpop" \
    "$base_url/default/userinfo"
)" = '401'
grep -q '"error":"invalid_dpop_proof"' "$temporary_directory/replayed-userinfo-dpop.json"
introspection=$(
  curl --fail --silent \
    --user 'release-resource-server:release-smoke-introspection-secret' \
    --data-urlencode "token=$access_token" \
    --data-urlencode 'token_type_hint=access_token' \
    "$peer_url/default/introspect"
)
printf '%s' "$introspection" | grep -q '"active":true'
printf '%s' "$introspection" | grep -q '"client_id":"release-smoke-client"'
printf '%s' "$introspection" | grep -q '"scope":"openid profile email offline_access"'
printf '%s' "$introspection" | grep -q '"token_type":"DPoP"'
printf '%s' "$introspection" | grep -q "\"cnf\":{\"jkt\":\"$dpop_jkt\"}"
printf '%s' "$introspection" | grep -q "\"auth_time\":$original_auth_time"
printf '%s' "$introspection" | grep -q '"acr":"urn:robine-id:acr:password"'
printf '%s' "$introspection" | grep -q '"amr":\["pwd"\]'
userinfo_post_dpop=$(dpop_proof POST "$issuer_url/userinfo" 'original-userinfo-post-dpop' "$access_token" "$userinfo_dpop_nonce")
user_info_post=$(curl --fail --silent --request POST \
  --header "Authorization: DPoP $access_token" \
  --header "DPoP: $userinfo_post_dpop" "$peer_url/default/userinfo")
test "$user_info_post" = "$user_info"
cors_headers="$temporary_directory/userinfo-cors.headers"
userinfo_cors_dpop=$(dpop_proof GET "$issuer_url/userinfo" 'original-userinfo-cors-dpop' "$access_token" "$userinfo_dpop_nonce")
curl --fail --silent --output /dev/null --dump-header "$cors_headers" \
  --header "Authorization: DPoP $access_token" \
  --header "DPoP: $userinfo_cors_dpop" \
  --header "Origin: http://127.0.0.1:$redirect_port" \
  "$peer_url/default/userinfo"
test "$(header_value access-control-allow-origin "$cors_headers")" = "http://127.0.0.1:$redirect_port"
test "$(header_value cross-origin-resource-policy "$cors_headers")" = 'cross-origin'
test "$(header_value access-control-expose-headers "$cors_headers")" = 'DPoP-Nonce, WWW-Authenticate'

device_authorization_response="$temporary_directory/device-authorization.json"
curl --fail --silent --output "$device_authorization_response" \
  --data-urlencode 'client_id=release-device-client' \
  --data-urlencode 'scope=openid profile email offline_access' \
  "$base_url/default/device_authorization"
device_code=$(sed -n 's/.*"device_code":"\([^"]*\)".*/\1/p' "$device_authorization_response")
device_user_code=$(sed -n 's/.*"user_code":"\([^"]*\)".*/\1/p' "$device_authorization_response")
test -n "$device_code"
test -n "$device_user_code"
grep -q "\"verification_uri\":\"$issuer_url/device\"" "$device_authorization_response"
grep -q '"verification_uri_complete":"[^"]*user_code=' "$device_authorization_response"
grep -q '"interval":5' "$device_authorization_response"

device_fast_poll="$temporary_directory/device-fast-poll.json"
test "$(
  curl --silent --output "$device_fast_poll" --write-out '%{http_code}' \
    --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
    --data-urlencode "device_code=$device_code" \
    --data-urlencode 'client_id=release-device-client' \
    "$peer_url/default/token"
)" = '400'
grep -q '"error":"slow_down"' "$device_fast_poll"

device_code_page="$temporary_directory/device-code.html"
curl --fail --silent --get --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
  --data-urlencode "user_code=$device_user_code" \
  "$base_url/default/device" >"$device_code_page"
grep -q 'id="device-code-form"' "$device_code_page"
grep -q "value=\"$device_user_code\"" "$device_code_page"
device_csrf=$(hidden_value csrf_token "$device_code_page")
test -n "$device_csrf"

device_confirmation_page="$temporary_directory/device-confirmation.html"
curl --fail --silent --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
  --data-urlencode 'action=verify' \
  --data-urlencode "csrf_token=$device_csrf" \
  --data-urlencode "user_code=$device_user_code" \
  "$peer_url/default/device" >"$device_confirmation_page"
grep -q 'id="device-confirm-form"' "$device_confirmation_page"
grep -q 'id="device-approve"' "$device_confirmation_page"
if grep -q 'id="device_password"' "$device_confirmation_page"; then
  printf '%s\n' 'device confirmation unexpectedly lost the shared browser session' >&2
  exit 1
fi
device_transaction=$(hidden_value transaction "$device_confirmation_page")
device_csrf=$(hidden_value csrf_token "$device_confirmation_page")
test -n "$device_transaction"
test -n "$device_csrf"

device_done_page="$temporary_directory/device-done.html"
curl --fail --silent --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
  --data-urlencode 'action=decision' \
  --data-urlencode "csrf_token=$device_csrf" \
  --data-urlencode "transaction=$device_transaction" \
  --data-urlencode "user_code=$device_user_code" \
  --data-urlencode 'decision=approve' \
  "$base_url/default/device" >"$device_done_page"
grep -q 'id="device-done-title"' "$device_done_page"

device_token_response="$temporary_directory/device-token.json"
curl --fail --silent --output "$device_token_response" \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
  --data-urlencode "device_code=$device_code" \
  --data-urlencode 'client_id=release-device-client' \
  "$peer_url/default/token"
device_access_token=$(sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p' "$device_token_response")
device_refresh_token=$(sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p' "$device_token_response")
test -n "$device_access_token"
test -n "$device_refresh_token"
grep -q '"id_token":"[^"]*"' "$device_token_response"
grep -q '"scope":"openid profile email offline_access"' "$device_token_response"
curl --fail --silent --header "Authorization: Bearer $device_access_token" \
  "$base_url/default/userinfo" | grep -q '"sub":"release-smoke-user"'
device_introspection=$(
  curl --fail --silent \
    --user 'release-resource-server:release-smoke-introspection-secret' \
    --data-urlencode "token=$device_access_token" \
    "$base_url/default/introspect"
)
printf '%s' "$device_introspection" | grep -q '"active":true'
printf '%s' "$device_introspection" | grep -q '"client_id":"release-device-client"'

device_refresh_response="$temporary_directory/device-refresh.json"
curl --fail --silent --output "$device_refresh_response" \
  --data-urlencode 'grant_type=refresh_token' \
  --data-urlencode "refresh_token=$device_refresh_token" \
  --data-urlencode 'client_id=release-device-client' \
  "$base_url/default/token"
grep -q '"access_token":"[^"]*"' "$device_refresh_response"
grep -q '"refresh_token":"[^"]*"' "$device_refresh_response"

mfa_device_authorization="$temporary_directory/mfa-device-authorization.json"
curl --fail --silent --output "$mfa_device_authorization" \
  --data-urlencode 'client_id=release-device-client' \
  --data-urlencode 'scope=openid' \
  "$peer_url/default/device_authorization"
mfa_device_code=$(sed -n 's/.*"device_code":"\([^"]*\)".*/\1/p' "$mfa_device_authorization")
mfa_device_user_code=$(sed -n 's/.*"user_code":"\([^"]*\)".*/\1/p' "$mfa_device_authorization")
test -n "$mfa_device_code"
test -n "$mfa_device_user_code"
mfa_device_cookie_jar="$temporary_directory/mfa-device-cookies.txt"
mfa_device_code_page="$temporary_directory/mfa-device-code.html"
curl --fail --silent --get --cookie-jar "$mfa_device_cookie_jar" \
  --data-urlencode "user_code=$mfa_device_user_code" \
  "$base_url/default/device" >"$mfa_device_code_page"
mfa_device_csrf=$(hidden_value csrf_token "$mfa_device_code_page")
mfa_device_confirmation="$temporary_directory/mfa-device-confirmation.html"
curl --fail --silent --cookie "$mfa_device_cookie_jar" --cookie-jar "$mfa_device_cookie_jar" \
  --data-urlencode 'action=verify' \
  --data-urlencode "csrf_token=$mfa_device_csrf" \
  --data-urlencode "user_code=$mfa_device_user_code" \
  "$peer_url/default/device" >"$mfa_device_confirmation"
grep -q 'id="device_password"' "$mfa_device_confirmation"
mfa_device_transaction=$(hidden_value transaction "$mfa_device_confirmation")
mfa_device_csrf=$(hidden_value csrf_token "$mfa_device_confirmation")
mfa_device_totp_page="$temporary_directory/mfa-device-totp.html"
curl --fail --silent --cookie "$mfa_device_cookie_jar" --cookie-jar "$mfa_device_cookie_jar" \
  --data-urlencode 'action=decision' \
  --data-urlencode "csrf_token=$mfa_device_csrf" \
  --data-urlencode "transaction=$mfa_device_transaction" \
  --data-urlencode "user_code=$mfa_device_user_code" \
  --data-urlencode 'decision=approve' \
  --data-urlencode 'identifier=mfa@example.com' \
  --data-urlencode 'password=change-me' \
  "$base_url/default/device" >"$mfa_device_totp_page"
grep -q 'id="totp-form"' "$mfa_device_totp_page"
mfa_device_csrf=$(hidden_value csrf_token "$mfa_device_totp_page")
mfa_device_mfa_transaction=$(hidden_value mfa_transaction "$mfa_device_totp_page")
mfa_device_code_value=$(smoke_totp 1)
mfa_device_done="$temporary_directory/mfa-device-done.html"
curl --fail --silent --cookie "$mfa_device_cookie_jar" --cookie-jar "$mfa_device_cookie_jar" \
  --data-urlencode 'action=totp' \
  --data-urlencode "csrf_token=$mfa_device_csrf" \
  --data-urlencode "mfa_transaction=$mfa_device_mfa_transaction" \
  --data-urlencode "totp_code=$mfa_device_code_value" \
  "$peer_url/default/device" >"$mfa_device_done"
grep -q 'id="device-done-title"' "$mfa_device_done"
sleep 5
mfa_device_token_response="$temporary_directory/mfa-device-token.json"
curl --fail --silent --output "$mfa_device_token_response" \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
  --data-urlencode "device_code=$mfa_device_code" \
  --data-urlencode 'client_id=release-device-client' \
  "$base_url/default/token"
mfa_device_id_token=$(sed -n 's/.*"id_token":"\([^"]*\)".*/\1/p' "$mfa_device_token_response")
test -n "$mfa_device_id_token"
mfa_device_payload=$(decode_base64url "$(printf '%s' "$mfa_device_id_token" | cut -d. -f2)")
printf '%s' "$mfa_device_payload" | grep -q '"sub":"release-smoke-mfa-user"'
printf '%s' "$mfa_device_payload" | grep -q '"acr":"urn:robine-id:acr:password+totp"'
printf '%s' "$mfa_device_payload" | grep -q '"amr":\["pwd","otp"\]'

denied_device_authorization="$temporary_directory/denied-device-authorization.json"
curl --fail --silent --output "$denied_device_authorization" \
  --data-urlencode 'client_id=release-device-client' \
  --data-urlencode 'scope=openid' \
  "$peer_url/default/device_authorization"
denied_device_code=$(sed -n 's/.*"device_code":"\([^"]*\)".*/\1/p' "$denied_device_authorization")
denied_user_code=$(sed -n 's/.*"user_code":"\([^"]*\)".*/\1/p' "$denied_device_authorization")
test -n "$denied_device_code"
test -n "$denied_user_code"
denied_code_page="$temporary_directory/denied-device-code.html"
curl --fail --silent --get --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
  --data-urlencode "user_code=$denied_user_code" \
  "$peer_url/default/device" >"$denied_code_page"
denied_device_csrf=$(hidden_value csrf_token "$denied_code_page")
denied_confirmation_page="$temporary_directory/denied-device-confirmation.html"
curl --fail --silent --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
  --data-urlencode 'action=verify' \
  --data-urlencode "csrf_token=$denied_device_csrf" \
  --data-urlencode "user_code=$denied_user_code" \
  "$base_url/default/device" >"$denied_confirmation_page"
denied_device_transaction=$(hidden_value transaction "$denied_confirmation_page")
denied_device_csrf=$(hidden_value csrf_token "$denied_confirmation_page")
denied_done_page="$temporary_directory/denied-device-done.html"
curl --fail --silent --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
  --data-urlencode 'action=decision' \
  --data-urlencode "csrf_token=$denied_device_csrf" \
  --data-urlencode "transaction=$denied_device_transaction" \
  --data-urlencode "user_code=$denied_user_code" \
  --data-urlencode 'decision=deny' \
  "$peer_url/default/device" >"$denied_done_page"
grep -q 'id="device-done-title"' "$denied_done_page"
denied_device_poll="$temporary_directory/denied-device-poll.json"
test "$(
  curl --silent --output "$denied_device_poll" --write-out '%{http_code}' \
    --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
    --data-urlencode "device_code=$denied_device_code" \
    --data-urlencode 'client_id=release-device-client' \
    "$base_url/default/token"
)" = '400'
grep -q '"error":"access_denied"' "$denied_device_poll"

sso_consent_page="$temporary_directory/sso-consent.html"
curl --fail --silent --get --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
  --data-urlencode 'response_type=code' \
  --data-urlencode 'client_id=release-smoke-client' \
  --data-urlencode "redirect_uri=$redirect_uri" \
  --data-urlencode 'scope=openid profile email offline_access' \
  --data-urlencode 'state=sso-consent-state' \
  --data-urlencode 'nonce=sso-consent-nonce' \
  --data-urlencode "code_challenge=$challenge" \
  --data-urlencode 'code_challenge_method=S256' \
  "$peer_url/default/authorize" >"$sso_consent_page"
grep -q 'id="consent-form"' "$sso_consent_page"
if grep -q 'id="login-form"' "$sso_consent_page"; then
  printf '%s\n' 'authenticated session unexpectedly returned to login' >&2
  exit 1
fi
sso_transaction=$(hidden_value transaction "$sso_consent_page")
sso_csrf=$(hidden_value csrf_token "$sso_consent_page")
test -n "$sso_transaction"
test -n "$sso_csrf"
sso_deny_location=$(
  curl --silent --dump-header - --output /dev/null --cookie "$cookie_jar" \
    --data-urlencode "transaction=$sso_transaction" \
    --data-urlencode "csrf_token=$sso_csrf" \
    --data-urlencode 'decision=deny' \
    "$peer_url/default/authorize/consent" \
    | awk 'tolower($1) == "location:" {sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); print}' \
    | tail -n 1
)
printf '%s' "$sso_deny_location" | grep -q 'error=access_denied'
printf '%s' "$sso_deny_location" | grep -q 'state=sso-consent-state'
printf '%s' "$sso_deny_location" \
  | grep -q "[?&]iss=http%3A%2F%2F127.0.0.1%3A${bind_port}%2Fdefault"

form_post_consent_page="$temporary_directory/form-post-consent.html"
curl --fail --silent --get --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
  --data-urlencode 'response_type=code' \
  --data-urlencode 'client_id=release-smoke-client' \
  --data-urlencode "redirect_uri=$redirect_uri" \
  --data-urlencode 'scope=openid' \
  --data-urlencode 'state=form-post-state' \
  --data-urlencode 'nonce=form-post-nonce' \
  --data-urlencode "code_challenge=$challenge" \
  --data-urlencode 'code_challenge_method=S256' \
  --data-urlencode 'response_mode=form_post' \
  --data-urlencode 'resource=https://api.release.example' \
  "$peer_url/default/authorize" >"$form_post_consent_page"
grep -q 'id="consent-form"' "$form_post_consent_page"
form_post_transaction=$(hidden_value transaction "$form_post_consent_page")
form_post_csrf=$(hidden_value csrf_token "$form_post_consent_page")
test -n "$form_post_transaction"
test -n "$form_post_csrf"
form_post_headers="$temporary_directory/form-post.headers"
form_post_body="$temporary_directory/form-post.html"
curl --fail --silent --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
  --dump-header "$form_post_headers" --output "$form_post_body" \
  --data-urlencode "transaction=$form_post_transaction" \
  --data-urlencode "csrf_token=$form_post_csrf" \
  --data-urlencode 'decision=approve' \
  "$base_url/default/authorize/consent"
grep -qi '^cache-control: no-store' "$form_post_headers"
tr -d '\r' <"$form_post_headers" \
  | grep -qi "^content-security-policy: .*form-action http://127.0.0.1:$redirect_port;"
if grep -qi '^location:' "$form_post_headers"; then
  printf '%s\n' 'form_post response unexpectedly used a redirect location' >&2
  exit 1
fi
grep -q 'id="authorization-response-form"' "$form_post_body"
grep -q "action=\"$redirect_uri\"" "$form_post_body"
grep -q 'name="state" value="form-post-state"' "$form_post_body"
grep -q "name=\"iss\" value=\"$issuer_url\"" "$form_post_body"
form_post_code=$(hidden_value code "$form_post_body")
test -n "$form_post_code"
form_post_token_response="$temporary_directory/form-post-token.json"
curl --fail --silent --output "$form_post_token_response" \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode "code=$form_post_code" \
  --data-urlencode 'client_id=release-smoke-client' \
  --data-urlencode "redirect_uri=$redirect_uri" \
  --data-urlencode "code_verifier=$verifier" \
  "$peer_url/default/token"
grep -q '"access_token":"' "$form_post_token_response"
grep -q '"id_token":"' "$form_post_token_response"
grep -q '"resource":"https://api.release.example"' "$form_post_token_response"

jarm_consent_page="$temporary_directory/jarm-consent.html"
curl --fail --silent --get --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
  --data-urlencode 'response_type=code' \
  --data-urlencode 'client_id=release-smoke-client' \
  --data-urlencode "redirect_uri=$redirect_uri" \
  --data-urlencode 'scope=openid' \
  --data-urlencode 'state=jarm-query-state' \
  --data-urlencode 'nonce=jarm-query-nonce' \
  --data-urlencode "code_challenge=$challenge" \
  --data-urlencode 'code_challenge_method=S256' \
  --data-urlencode 'response_mode=query.jwt' \
  "$peer_url/default/authorize" >"$jarm_consent_page"
grep -q 'id="consent-form"' "$jarm_consent_page"
jarm_transaction=$(hidden_value transaction "$jarm_consent_page")
jarm_csrf=$(hidden_value csrf_token "$jarm_consent_page")
test -n "$jarm_transaction"
test -n "$jarm_csrf"
jarm_location=$(
  curl --silent --dump-header - --output /dev/null --cookie "$cookie_jar" \
    --data-urlencode "transaction=$jarm_transaction" \
    --data-urlencode "csrf_token=$jarm_csrf" \
    --data-urlencode 'decision=approve' \
    "$base_url/default/authorize/consent" \
    | awk 'tolower($1) == "location:" {sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); print}' \
    | tail -n 1
)
printf '%s' "$jarm_location" | grep -q '[?&]response='
if printf '%s' "$jarm_location" | grep -Eq '[?&](code|state|iss)='; then
  printf '%s\n' 'query.jwt leaked unsigned authorization parameters' >&2
  exit 1
fi
jarm_response=$(printf '%s' "$jarm_location" | sed -n 's/.*[?&]response=\([^&]*\).*/\1/p')
test -n "$jarm_response"
jarm_header=$(decode_base64url "$(printf '%s' "$jarm_response" | cut -d. -f1)")
jarm_payload=$(decode_base64url "$(printf '%s' "$jarm_response" | cut -d. -f2)")
printf '%s' "$jarm_header" | grep -q '"typ":"oauth-authz-resp+jwt"'
printf '%s' "$jarm_header" | grep -q '"alg":"RS256"'
printf '%s' "$jarm_payload" | grep -q "\"iss\":\"$issuer_url\""
printf '%s' "$jarm_payload" | grep -q '"aud":"release-smoke-client"'
printf '%s' "$jarm_payload" | grep -q '"state":"jarm-query-state"'
printf '%s' "$jarm_payload" | grep -Eq '"iat":[0-9]+'
printf '%s' "$jarm_payload" | grep -Eq '"exp":[0-9]+'
jarm_code=$(printf '%s' "$jarm_payload" | sed -n 's/.*"code":"\([^"]*\)".*/\1/p')
test -n "$jarm_code"
jarm_token_response="$temporary_directory/jarm-token.json"
curl --fail --silent --output "$jarm_token_response" \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode "code=$jarm_code" \
  --data-urlencode 'client_id=release-smoke-client' \
  --data-urlencode "redirect_uri=$redirect_uri" \
  --data-urlencode "code_verifier=$verifier" \
  "$peer_url/default/token"
grep -q '"access_token":"' "$jarm_token_response"
grep -q '"id_token":"' "$jarm_token_response"

jarm_error_consent_page="$temporary_directory/jarm-error-consent.html"
curl --fail --silent --get --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
  --data-urlencode 'response_type=code' \
  --data-urlencode 'client_id=release-smoke-client' \
  --data-urlencode "redirect_uri=$redirect_uri" \
  --data-urlencode 'scope=openid' \
  --data-urlencode 'state=jarm-form-error-state' \
  --data-urlencode 'nonce=jarm-form-error-nonce' \
  --data-urlencode "code_challenge=$challenge" \
  --data-urlencode 'code_challenge_method=S256' \
  --data-urlencode 'response_mode=form_post.jwt' \
  "$base_url/default/authorize" >"$jarm_error_consent_page"
jarm_error_transaction=$(hidden_value transaction "$jarm_error_consent_page")
jarm_error_csrf=$(hidden_value csrf_token "$jarm_error_consent_page")
test -n "$jarm_error_transaction"
test -n "$jarm_error_csrf"
jarm_error_body="$temporary_directory/jarm-error.html"
curl --fail --silent --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
  --output "$jarm_error_body" \
  --data-urlencode "transaction=$jarm_error_transaction" \
  --data-urlencode "csrf_token=$jarm_error_csrf" \
  --data-urlencode 'decision=deny' \
  "$peer_url/default/authorize/consent"
grep -q 'id="authorization-response-form"' "$jarm_error_body"
jarm_error_response=$(hidden_value response "$jarm_error_body")
test -n "$jarm_error_response"
if grep -Eq 'name="(error|state|iss)"' "$jarm_error_body"; then
  printf '%s\n' 'form_post.jwt leaked unsigned authorization error parameters' >&2
  exit 1
fi
jarm_error_payload=$(decode_base64url "$(printf '%s' "$jarm_error_response" | cut -d. -f2)")
printf '%s' "$jarm_error_payload" | grep -q '"error":"access_denied"'
printf '%s' "$jarm_error_payload" | grep -q '"state":"jarm-form-error-state"'
printf '%s' "$jarm_error_payload" | grep -q '"aud":"release-smoke-client"'

silent_location=$(
  curl --silent --get --dump-header - --output /dev/null --cookie "$cookie_jar" \
    --data-urlencode 'response_type=code' \
    --data-urlencode 'client_id=release-smoke-client' \
    --data-urlencode "redirect_uri=$redirect_uri" \
    --data-urlencode 'scope=openid profile email offline_access' \
    --data-urlencode 'state=silent-state' \
    --data-urlencode 'nonce=silent-nonce' \
    --data-urlencode "code_challenge=$challenge" \
    --data-urlencode 'code_challenge_method=S256' \
    --data-urlencode 'prompt=none' \
    "$peer_url/default/authorize" \
    | awk 'tolower($1) == "location:" {sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); print}' \
    | tail -n 1
)
printf '%s' "$silent_location" | grep -q 'error=consent_required'
printf '%s' "$silent_location" | grep -q 'state=silent-state'
printf '%s' "$silent_location" \
  | grep -q "[?&]iss=http%3A%2F%2F127.0.0.1%3A${bind_port}%2Fdefault"

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

compose exec --no-TTY postgres \
  psql --username robine_id --dbname robine_id --command \
    "UPDATE signing_keys SET created_at = now() - interval '2 hours' WHERE issuer = '$issuer_url';" \
  >/dev/null
compose restart robine-id
compose up --detach --wait robine-id
automatic_kid=$(
  compose exec --no-TTY postgres \
    psql --username robine_id --dbname robine_id --tuples-only --no-align \
      --command "SELECT kid FROM signing_keys WHERE issuer = '$issuer_url';" \
    | tr -d '[:space:]'
)
test -n "$automatic_kid"
test "$automatic_kid" != "$kid"
compose restart robine-id
compose up --detach --wait robine-id
automatic_retry_kid=$(
  compose exec --no-TTY postgres \
    psql --username robine_id --dbname robine_id --tuples-only --no-align \
      --command "SELECT kid FROM signing_keys WHERE issuer = '$issuer_url';" \
    | tr -d '[:space:]'
)
test "$automatic_retry_kid" = "$automatic_kid"

compose exec --no-TTY robine-id \
  rotate_keys default release-smoke-rotation | grep -q '^rotated issuer default at key '
compose exec --no-TTY robine-id \
  rotate_keys default release-smoke-rotation | grep -q '^unchanged issuer default at key '
compose exec --no-TTY robine-id \
  prune_keys | grep -q '^pruned 0 retained signing keys$'
compose exec --no-TTY postgres \
  psql --username robine_id --dbname robine_id --tuples-only --no-align --command \
    "SELECT count(*) FROM retained_signing_keys WHERE issuer = '$issuer_url' AND retain_until > now();" \
  | grep -q '^2$'
kid_before_restore=$(
  compose exec --no-TTY postgres \
    psql --username robine_id --dbname robine_id --tuples-only --no-align \
      --command "SELECT kid FROM signing_keys WHERE issuer = '$issuer_url';" \
    | tr -d '[:space:]'
)
test -n "$kid_before_restore"
test "$kid_before_restore" != "$kid"
rotated_jwks_headers="$temporary_directory/rotated-jwks.headers"
rotated_jwks_body="$temporary_directory/rotated-jwks.json"
test "$(
  curl --silent --dump-header "$rotated_jwks_headers" --output "$rotated_jwks_body" \
    --write-out '%{http_code}' --header "If-None-Match: $jwks_etag" \
    "$base_url/default/jwks.json"
)" = "200"
grep -q "\"kid\":\"$kid\"" "$rotated_jwks_body"
grep -q "\"kid\":\"$automatic_kid\"" "$rotated_jwks_body"
grep -q "\"kid\":\"$kid_before_restore\"" "$rotated_jwks_body"
rotated_jwks_etag=$(
  awk 'tolower($1) == "etag:" {gsub("\r", "", $2); print $2}' "$rotated_jwks_headers" \
    | tail -n 1
)
test -n "$rotated_jwks_etag"
test "$rotated_jwks_etag" != "$jwks_etag"
compose exec --no-TTY postgres \
  pg_dump --username robine_id --dbname robine_id --format=custom >"$database_dump"
test -s "$database_dump"

docker kill --signal TERM "$peer_container" >/dev/null
draining_status=''
attempt=0
while [ "$attempt" -lt 100 ]; do
  draining_status=$(
    curl --silent --output "$temporary_directory/draining-ready.json" \
      --write-out '%{http_code}' "$peer_url/health/ready" || true
  )
  if [ "$draining_status" = "503" ]; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 0.05
done
test "$draining_status" = "503"
grep -q '"status":"not_ready"' "$temporary_directory/draining-ready.json"
curl --fail --silent "$peer_url/health/live" | grep -q '"status":"live"'
test "$(docker wait "$peer_container")" = "0"
test "$(docker inspect --format '{{.State.ExitCode}}' "$peer_container")" = "0"
docker rm "$peer_container" >/dev/null
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
      --command "SELECT kid FROM signing_keys WHERE issuer = '$issuer_url';" \
    | tr -d '[:space:]'
)
test "$kid_after_restore" = "$kid_before_restore"
restored_jwks=$(curl --fail --silent "$base_url/default/jwks.json")
printf '%s' "$restored_jwks" | grep -q "\"kid\":\"$kid\""
printf '%s' "$restored_jwks" | grep -q "\"kid\":\"$automatic_kid\""
printf '%s' "$restored_jwks" | grep -q "\"kid\":\"$kid_after_restore\""
restored_user_info=$(
  restored_userinfo_dpop=$(dpop_proof GET "$issuer_url/userinfo" 'restored-userinfo-dpop' "$access_token" "$userinfo_dpop_nonce")
  curl --fail --silent --header "Authorization: DPoP $access_token" \
    --header "DPoP: $restored_userinfo_dpop" \
    "$base_url/default/userinfo"
)
printf '%s' "$restored_user_info" | grep -q '"sub":"release-smoke-user"'
post_restore_refresh="$temporary_directory/post-restore-refresh.json"
post_restore_refresh_dpop=$(dpop_proof POST "$issuer_url/token" 'post-restore-refresh-dpop' '' "$authorization_server_dpop_nonce")
curl --fail --silent \
  --header "DPoP: $post_restore_refresh_dpop" \
  --data-urlencode 'grant_type=refresh_token' \
  --data-urlencode "refresh_token=$rotated_refresh_token" \
  --data-urlencode 'client_id=release-smoke-client' \
  "$base_url/default/token" >"$post_restore_refresh"
post_restore_rotated_token=$(sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p' "$post_restore_refresh")
test -n "$post_restore_rotated_token"
test "$post_restore_rotated_token" != "$rotated_refresh_token"
replayed_refresh_status=$(
  replayed_refresh_dpop=$(dpop_proof POST "$issuer_url/token" 'replayed-refresh-dpop' '' "$authorization_server_dpop_nonce")
  curl --silent --output "$temporary_directory/replayed-refresh.json" --write-out '%{http_code}' \
    --header "DPoP: $replayed_refresh_dpop" \
    --data-urlencode 'grant_type=refresh_token' \
    --data-urlencode "refresh_token=$rotated_refresh_token" \
    --data-urlencode 'client_id=release-smoke-client' \
    "$base_url/default/token"
)
test "$replayed_refresh_status" = '400'
grep -q '"error":"invalid_grant"' "$temporary_directory/replayed-refresh.json"
revoked_family_status=$(
  revoked_family_dpop=$(dpop_proof POST "$issuer_url/token" 'revoked-family-refresh-dpop' '' "$authorization_server_dpop_nonce")
  curl --silent --output "$temporary_directory/revoked-refresh-family.json" --write-out '%{http_code}' \
    --header "DPoP: $revoked_family_dpop" \
    --data-urlencode 'grant_type=refresh_token' \
    --data-urlencode "refresh_token=$post_restore_rotated_token" \
    --data-urlencode 'client_id=release-smoke-client' \
    "$base_url/default/token"
)
test "$revoked_family_status" = '400'
grep -q '"error":"invalid_grant"' "$temporary_directory/revoked-refresh-family.json"
curl --fail --silent \
  --user 'release-resource-server:release-smoke-introspection-secret' \
  --data-urlencode "token=$access_token" \
  "$base_url/default/revoke" >/dev/null
pre_revocation_userinfo_dpop=$(dpop_proof GET "$issuer_url/userinfo" 'pre-revocation-userinfo-dpop' "$access_token" "$userinfo_dpop_nonce")
curl --fail --silent --header "Authorization: DPoP $access_token" \
  --header "DPoP: $pre_revocation_userinfo_dpop" \
  "$base_url/default/userinfo" | grep -q '"sub":"release-smoke-user"'
curl --fail --silent \
  --data-urlencode "token=$access_token" \
  --data-urlencode 'token_type_hint=unknown_hint' \
  --data-urlencode 'client_id=release-smoke-client' \
  "$base_url/default/revoke" >/dev/null
revoked_user_info_status=$(
  revoked_userinfo_dpop=$(dpop_proof GET "$issuer_url/userinfo" 'revoked-userinfo-dpop' "$access_token" "$userinfo_dpop_nonce")
  curl --silent --output "$temporary_directory/revoked-userinfo.json" --write-out '%{http_code}' \
    --header "Authorization: DPoP $access_token" \
    --header "DPoP: $revoked_userinfo_dpop" \
    "$base_url/default/userinfo"
)
test "$revoked_user_info_status" = '401'
grep -q '"error":"invalid_token"' "$temporary_directory/revoked-userinfo.json"
revoked_introspection=$(
  curl --fail --silent \
    --user 'release-resource-server:release-smoke-introspection-secret' \
    --data-urlencode "token=$access_token" \
    "$base_url/default/introspect"
)
test "$revoked_introspection" = '{"active":false}'
curl --fail --silent --get \
  --data-urlencode "id_token_hint=$id_token" \
  --data-urlencode "post_logout_redirect_uri=$logout_uri" \
  "$base_url/default/logout" | grep -q 'id="logout-form"'

old_key_encryption_secret='release-smoke-key-encryption-secret-32-bytes-minimum'
new_key_encryption_secret='release-smoke-new-key-encryption-secret-32-bytes-minimum'
reencryption_output=$(
  compose run --rm --no-deps \
    --env "KEY_ENCRYPTION_SECRET=$new_key_encryption_secret" \
    --env "KEY_ENCRYPTION_SECRET_PREVIOUS=$old_key_encryption_secret" \
    --entrypoint /usr/local/bin/reencrypt_keys \
    robine-id
)
printf '%s\n' "$reencryption_output" | grep -q '^reencrypted 2 active and 2 retained signing keys$'
sed -i \
  "s|^KEY_ENCRYPTION_SECRET=.*|KEY_ENCRYPTION_SECRET=$new_key_encryption_secret|" \
  "$environment_file"
printf '%s\n' "KEY_ENCRYPTION_SECRET_PREVIOUS=$old_key_encryption_secret" \
  >>"$environment_file"
compose up --detach --no-deps --force-recreate --wait robine-id
reencrypted_jwks=$(curl --fail --silent "$base_url/default/jwks.json")
printf '%s' "$reencrypted_jwks" | grep -q "\"kid\":\"$kid\""
printf '%s' "$reencrypted_jwks" | grep -q "\"kid\":\"$automatic_kid\""
printf '%s' "$reencrypted_jwks" | grep -q "\"kid\":\"$kid_after_restore\""
sed -i '/^KEY_ENCRYPTION_SECRET_PREVIOUS=/d' "$environment_file"
compose up --detach --no-deps --force-recreate --wait robine-id
current_secret_only_jwks=$(curl --fail --silent "$base_url/default/jwks.json")
test "$current_secret_only_jwks" = "$reencrypted_jwks"

compose exec --no-TTY postgres \
  psql --username robine_id --dbname robine_id --command \
    "UPDATE retained_signing_keys SET retain_until = now() - interval '1 second' WHERE issuer = '$issuer_url';" \
  >/dev/null
compose exec --no-TTY robine-id \
  prune_keys | grep -q '^pruned 2 retained signing keys$'
pruned_jwks=$(curl --fail --silent "$base_url/default/jwks.json")
printf '%s' "$pruned_jwks" | grep -q "\"kid\":\"$kid_after_restore\""
if printf '%s' "$pruned_jwks" | grep -q "\"kid\":\"$kid\""; then
  printf '%s\n' 'expired retained signing key remains in JWKS' >&2
  exit 1
fi
if printf '%s' "$pruned_jwks" | grep -q "\"kid\":\"$automatic_kid\""; then
  printf '%s\n' 'expired automatically retained signing key remains in JWKS' >&2
  exit 1
fi

printf 'release smoke test passed: %s (OIDC/optional+mandatory PAR/device authorization/opaque browser transactions/form-post/JARM/signed request objects, opaque+RFC9068 JWT access tokens, DPoP/nonces, client credentials/token exchange/resource indicators/private-key JWT, rotating refresh, introspection/revocation, multi-instance, graceful drain, automatic/manual key rotation, wrapping-secret re-encryption, pruning, backup/restore)\n' "$base_url"
