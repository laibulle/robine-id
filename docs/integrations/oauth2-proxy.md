# OAuth2 Proxy OpenID Connect Integration

## Compatibility profile

Robine ID is verified against OAuth2 Proxy 7.15.3 as an independent relying party. The development
profile uses Authorization Code Flow, PKCE S256, `client_secret_basic`, the `openid profile email`
scopes, and exact loopback redirects. OAuth2 Proxy does not send a `nonce` in this profile, which is
valid for Authorization Code Flow; PKCE remains mandatory. Because Robine ID's operator-configured
local emails are not independently verified, OAuth2 Proxy must explicitly allow an unverified email
claim or use another authorization policy.

The checked-in development registration is
`config/applications/oauth2-proxy-development.json`. It is intentionally absent from the empty
production configuration.

## Repeatable verification

Start the isolated development containers, then run the RP smoke:

```sh
make dev-container
make rp-smoke
```

The smoke starts the pinned
`quay.io/oauth2-proxy/oauth2-proxy:v7.15.3@sha256:10a1165743a192e1940b4708fb9647027185ce11a681a1c5519b442ff7f1f561`
image with host networking and a loopback-only listener. It performs discovery, begins a real RP
authorization request, logs in with the documented development identity, lets OAuth2 Proxy redeem
the PKCE-bound code with confidential client authentication, and verifies both the RP session
cookie and authenticated `/oauth2/auth` response. The temporary container and cookie files are
removed on success or failure.

The script uses only public development credentials and secrets. Never reuse them in production.

## Production registration

Create a deployment application document from this shape:

```json
{
  "schema_version": 1,
  "kind": "oidc_application",
  "id": "oauth2-proxy",
  "name": "OAuth2 Proxy",
  "type": "confidential",
  "redirect_uris": ["https://proxy.example.com/oauth2/callback"],
  "scopes": ["openid", "profile", "email"],
  "grant_types": ["authorization_code"],
  "authentication_method": "client_secret_basic",
  "pkce_required": true,
  "nonce_required": false,
  "secret_reference": {
    "provider": "env",
    "key": "OAUTH2_PROXY_CLIENT_SECRET"
  },
  "consent_required": true
}
```

Generate a unique high-entropy client secret, provide the same value to both services through their
secret stores, use HTTPS for the issuer and redirect URI, and retain OAuth2 Proxy's secure-cookie
default. Decide explicitly whether an operator-configured email is sufficient for access; Robine ID
does not claim that such an address has been independently verified.
