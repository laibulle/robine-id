#!/bin/sh
set -eu

output_directory=${1:-}
client_id=${2:-backend-service}
algorithm=${3:-RS256}

if [ -z "$output_directory" ]; then
  printf '%s\n' 'usage: generate-private-key-jwt-client.sh OUTPUT_DIRECTORY [CLIENT_ID] [RS256|ES256|EdDSA]' >&2
  exit 2
fi
if [ "$algorithm" != 'RS256' ] && [ "$algorithm" != 'ES256' ] \
  && [ "$algorithm" != 'EdDSA' ]; then
  printf '%s\n' 'ALGORITHM must be RS256, ES256, or EdDSA' >&2
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
case "$algorithm" in
  RS256)
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
      -out "$private_key" 2>/dev/null
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
    jwk_type='RSA'
    jwk_material=$(printf '    "n": "%s",\n    "e": "AQAB"' "$modulus")
    ;;
  ES256)
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
      -out "$private_key" 2>/dev/null
    public_point_hex=$(
      openssl pkey -in "$private_key" -pubout -outform DER 2>/dev/null \
        | tail -c 65 \
        | xxd -p -c 256
    )
    if [ "$(expr length "$public_point_hex")" != '130' ] \
      || [ "$(printf '%s' "$public_point_hex" | cut -c 1-2)" != '04' ]; then
      printf '%s\n' 'failed to extract the P-256 public key' >&2
      exit 1
    fi
    x=$(
      printf '%s' "$public_point_hex" | cut -c 3-66 | xxd -r -p \
        | openssl base64 -A | tr '+/' '-_' | tr -d '='
    )
    y=$(
      printf '%s' "$public_point_hex" | cut -c 67-130 | xxd -r -p \
        | openssl base64 -A | tr '+/' '-_' | tr -d '='
    )
    jwk_type='EC'
    jwk_material=$(printf '    "crv": "P-256",\n    "x": "%s",\n    "y": "%s"' "$x" "$y")
    ;;
  EdDSA)
    openssl genpkey -algorithm ED25519 -out "$private_key" 2>/dev/null
    x=$(
      openssl pkey -in "$private_key" -pubout -outform DER 2>/dev/null \
        | tail -c 32 \
        | openssl base64 -A \
        | tr '+/' '-_' \
        | tr -d '='
    )
    test "$(expr length "$x")" = '43'
    jwk_type='OKP'
    jwk_material=$(printf '    "crv": "Ed25519",\n    "x": "%s"' "$x")
    ;;
esac
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
    "kty": "$jwk_type",
    "kid": "$kid",
    "use": "sig",
    "alg": "$algorithm",
$jwk_material
  }]},
  "introspection_allowed": false
}
EOF
chmod 600 "$private_key" "$application"

printf 'private key: %s\napplication: %s\nkey id: %s\nalgorithm: %s\n' \
  "$private_key" "$application" "$kid" "$algorithm"
