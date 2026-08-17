#!/bin/sh
set -eu

output_directory=${1:-}
client_id=${2:-backend-service}

if [ -z "$output_directory" ]; then
  printf '%s\n' 'usage: generate-private-key-jwt-client.sh OUTPUT_DIRECTORY [CLIENT_ID]' >&2
  exit 2
fi
if ! printf '%s' "$client_id" | grep -Eq '^[A-Za-z0-9._~-]{1,128}$'; then
  printf '%s\n' 'CLIENT_ID must be a bounded OAuth identifier' >&2
  exit 2
fi

private_key="$output_directory/$client_id-private.pem"
application="$output_directory/$client_id-application.json"
if [ -e "$private_key" ] || [ -e "$application" ]; then
  printf '%s\n' 'refusing to overwrite an existing client key or application file' >&2
  exit 1
fi

umask 077
mkdir -p "$output_directory"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$private_key" 2>/dev/null
modulus_hex=$(
  openssl rsa -in "$private_key" -noout -modulus 2>/dev/null | sed 's/^Modulus=//'
)
modulus=$(
  printf '%s' "$modulus_hex" \
    | xxd -r -p \
    | openssl base64 -A \
    | tr '+/' '-_' \
    | tr -d '='
)
kid=$(openssl rand -hex 16)

cat >"$application" <<EOF
{
  "schema_version": 1,
  "kind": "oidc_application",
  "id": "$client_id",
  "name": "$client_id",
  "type": "confidential",
  "redirect_uris": [],
  "resources": ["https://api.example.com"],
  "scopes": ["service.read"],
  "grant_types": ["client_credentials"],
  "authentication_method": "private_key_jwt",
  "jwks": {"keys": [{
    "kty": "RSA",
    "kid": "$kid",
    "use": "sig",
    "alg": "RS256",
    "n": "$modulus",
    "e": "AQAB"
  }]},
  "introspection_allowed": false
}
EOF
chmod 600 "$private_key" "$application"

printf 'private key: %s\napplication: %s\nkey id: %s\n' \
  "$private_key" "$application" "$kid"
