#!/bin/sh
set -eu

provider_url=${ROBINE_ID_URL:-http://127.0.0.1:4001}
issuer_url="$provider_url/default"
proxy_url=${OAUTH2_PROXY_URL:-http://127.0.0.1:4180}
proxy_image=${OAUTH2_PROXY_IMAGE:-quay.io/oauth2-proxy/oauth2-proxy:v7.15.3@sha256:10a1165743a192e1940b4708fb9647027185ce11a681a1c5519b442ff7f1f561}
proxy_container=robine-id-oauth2-proxy-smoke
client_id=${OAUTH2_PROXY_CLIENT_ID:-oauth2-proxy-development}
client_secret=${OAUTH2_PROXY_CLIENT_SECRET:-oauth2-proxy-development-only-secret}
identifier=${ROBINE_ID_IDENTIFIER:-admin@example.com}
cookie_secret=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=
temporary_directory=$(mktemp -d)
password_file="$temporary_directory/password"
proxy_environment="$temporary_directory/oauth2-proxy.env"

cleanup() {
  docker rm --force "$proxy_container" >/dev/null 2>&1 || true
  rm -rf "$temporary_directory"
}
trap cleanup EXIT INT TERM

if [ -n "${OAUTH2_PROXY_CLIENT_SECRET_FILE:-}" ]; then
  test -f "$OAUTH2_PROXY_CLIENT_SECRET_FILE"
  client_secret=$(tr -d '\r\n' <"$OAUTH2_PROXY_CLIENT_SECRET_FILE")
fi
if [ -n "${ROBINE_ID_GENERATED_CREDENTIALS_FILE:-}" ]; then
  test -f "$ROBINE_ID_GENERATED_CREDENTIALS_FILE"
  generated_password=$(sed -n '2p' "$ROBINE_ID_GENERATED_CREDENTIALS_FILE")
  printf '%s' "$generated_password" >"$password_file"
elif [ -n "${ROBINE_ID_PASSWORD_FILE:-}" ]; then
  test -f "$ROBINE_ID_PASSWORD_FILE"
  configured_password=$(tr -d '\r\n' <"$ROBINE_ID_PASSWORD_FILE")
  printf '%s' "$configured_password" >"$password_file"
else
  printf '%s' "${ROBINE_ID_PASSWORD:-change-me}" >"$password_file"
fi
test -s "$password_file"
chmod 600 "$password_file"
printf 'OAUTH2_PROXY_CLIENT_SECRET=%s\nOAUTH2_PROXY_COOKIE_SECRET=%s\n' \
  "$client_secret" "$cookie_secret" >"$proxy_environment"
chmod 600 "$proxy_environment"

hidden_value() {
  field=$1
  document=$2
  sed -n "s/.*name=\"$field\"[^>]*value=\"\([^\"]*\)\".*/\1/p" "$document" | head -n 1
}

header_value() {
  field=$1
  document=$2
  tr -d '\r' <"$document" | sed -n "s/^$field: //Ip" | tail -n 1
}

curl --fail --silent --show-error "$provider_url/health/ready" | grep -q '"status":"ready"'
test "$(curl --silent --output /dev/null --write-out '%{http_code}' "$proxy_url/ping")" != 200 || {
  printf '%s\n' "port 4180 is already serving another process" >&2
  exit 1
}

docker rm --force "$proxy_container" >/dev/null 2>&1 || true
docker run --detach --name "$proxy_container" --network host \
  --env-file "$proxy_environment" \
  "$proxy_image" \
  --provider=oidc \
  --oidc-issuer-url="$issuer_url" \
  --client-id="$client_id" \
  --redirect-url="$proxy_url/oauth2/callback" \
  --http-address=127.0.0.1:4180 \
  --upstream=static://200 \
  --scope="openid profile email" \
  --email-domain='*' \
  --code-challenge-method=S256 \
  --cookie-secure=false \
  --insecure-oidc-allow-unverified-email=true \
  --skip-provider-button=true \
  >/dev/null

attempt=0
while [ "$attempt" -lt 30 ]; do
  if curl --fail --silent "$proxy_url/ping" >/dev/null 2>&1; then
    break
  fi
  if [ "$(docker inspect --format '{{.State.Status}}' "$proxy_container")" = exited ]; then
    docker logs "$proxy_container" >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  sleep 1
done
curl --fail --silent "$proxy_url/ping" >/dev/null

cookies="$temporary_directory/cookies"
start_headers="$temporary_directory/start.headers"
login_page="$temporary_directory/login.html"
authorization_headers="$temporary_directory/authorization.headers"
login_headers="$temporary_directory/login.headers"
login_body="$temporary_directory/login-result.html"
callback_body="$temporary_directory/callback.html"

curl --silent --show-error --dump-header "$start_headers" --output /dev/null \
  --cookie-jar "$cookies" "$proxy_url/oauth2/start?rd=%2F"
authorization_url=$(header_value location "$start_headers")
test -n "$authorization_url"

authorization_status=$(
  curl --silent --show-error --cookie "$cookies" --cookie-jar "$cookies" \
    --dump-header "$authorization_headers" --output "$login_page" \
    --write-out '%{http_code}' "$authorization_url"
)
if [ "$authorization_status" != 200 ] || ! grep -q 'id="login-form"' "$login_page"; then
  printf '%s\n' "OAuth2 Proxy authorization did not reach the Robine ID login form" >&2
  tr -d '\r' <"$authorization_headers" >&2
  exit 1
fi
tr -d '\r' <"$authorization_headers" \
  | grep -Fqi "form-action 'self' $proxy_url;"
csrf_token=$(hidden_value csrf_token "$login_page")
transaction=$(hidden_value transaction "$login_page")
test -n "$csrf_token"
test -n "$transaction"

curl --silent --show-error --dump-header "$login_headers" --output "$login_body" \
  --cookie "$cookies" --cookie-jar "$cookies" \
  --data-urlencode "csrf_token=$csrf_token" \
  --data-urlencode "transaction=$transaction" \
  --data-urlencode "identifier=$identifier" \
  --data-urlencode "password@$password_file" \
  "$issuer_url/authorize"
callback_url=$(header_value location "$login_headers")
test -n "$callback_url"
printf '%s' "$callback_url" | grep -q "^$proxy_url/oauth2/callback?"

final_status=$(
  curl --location --silent --show-error --cookie "$cookies" --cookie-jar "$cookies" \
    --output "$callback_body" --write-out '%{http_code}' "$callback_url"
)
test "$final_status" = 200
grep -q '_oauth2_proxy' "$cookies"
test "$(
  curl --silent --output /dev/null --write-out '%{http_code}' \
    --cookie "$cookies" "$proxy_url/oauth2/auth"
)" = 202

docker logs "$proxy_container" 2>&1 | grep -q 'Authenticated via OAuth2'
printf '%s\n' "real relying-party smoke passed: $proxy_url ($proxy_image)"
