# Penpot OpenID Connect Integration

## Compatibility Profile

This integration targets Penpot 2.16.2. Penpot uses the Authorization Code Flow as a confidential client, sends the client secret in the token request body (`client_secret_post`), and sends neither PKCE parameters nor a nonce. The Robine ID client must therefore declare `authentication_method: client_secret_post`, `pkce_required: false`, and `nonce_required: false`.

Disabling PKCE and nonce enforcement is limited to this confidential client. Public clients continue to require PKCE S256 and a nonce.

## Registered Instance

- Penpot public URI: `https://penpot.base59.dev`
- Client ID: `penpot`
- Callback URI: `https://penpot.base59.dev/api/auth/oidc/callback`
- Scopes: `openid profile email`
- Name attribute: `name`
- Email attribute: `email`
- Token authentication method: `client_secret_post`

The matching application is declared in `config/applications/penpot.json`. A reusable application template is available in `config/templates/penpot-application.json`.

## Penpot Configuration

Use `config/templates/penpot-compose.oidc.yml` as the Compose template. Set both of these values in Penpot's protected environment file:

```env
ROBINE_ID_PUBLIC_ISSUER=https://id.base59.dev/default
PENPOT_OIDC_CLIENT_SECRET=replace-with-a-random-high-entropy-secret
```

Set the same secret in the Robine ID process environment:

```env
PENPOT_OIDC_CLIENT_SECRET=replace-with-the-identical-secret
```

Do not commit the resolved secret. Generate at least 32 random bytes and encode them as URL-safe text.

## Public Issuer Prerequisite

The issuer URL must be reachable by both the user's browser and the Penpot backend. Its discovery document must be available at:

```text
${ROBINE_ID_PUBLIC_ISSUER}/.well-known/openid-configuration
```

The configured issuer is `https://id.base59.dev/default`. The hostname must resolve to this server for browsers and the Penpot backend, and Caddy must reverse-proxy it to Robine ID on `127.0.0.1:4001` before enabling the Penpot flags.

## Verification

1. Validate the composed Robine ID configuration or place the application file in the watched directory.
2. Fetch the discovery URL from inside the Penpot backend container.
3. Restart the Penpot backend and frontend with the OIDC environment.
4. Confirm that the login page shows `Robine ID`.
5. Complete login and confirm Penpot receives non-empty `name` and `email` claims from UserInfo.
6. Confirm password login and OIDC registration behavior match the intended access policy.
