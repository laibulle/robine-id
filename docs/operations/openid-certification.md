# OpenID Connect Certification Runbook

## Target Profiles

Robine ID targets these OpenID Foundation certification profiles:

- **Basic OP** using the Authorization Code Flow (`response_type=code`), static clients, query response mode, RS256 ID tokens, and both `client_secret_basic` and `client_secret_post`.
- **Config OP** using OpenID Provider Discovery and the published JWKS.

Implicit, Hybrid, Dynamic Registration, Form Post Response Mode, and the separate logout profiles are not advertised and are not part of this certification target.

The authoritative test instructions are the OpenID Foundation's [Conformance Testing for OpenID Connect OPs](https://openid.net/certification/connect_op_testing/). Certification is self-certification: the deployment must pass the hosted suite, publish the results, pay the applicable fee, and submit a signed declaration as described in [How to submit your certification request](https://openid.net/certification/op_submission/).

## Deployment Preconditions

Certification applies to a reachable deployment, not only to source code. Before creating a test plan:

1. Deploy the exact release being certified on a stable public HTTPS origin.
2. Set the configured issuer URL to the public issuer exactly, including its path and without a trailing slash (for example, `https://id.example.com/default`).
3. Preserve `SECRET_KEY_BASE` and the encrypted signing-key file throughout the run. Do not rotate or remove keys while a module is exchanging tokens unless the module explicitly tests rotation.
4. Configure a test identity that can supply `name`, `email`, `address`, and `phone` claims. Do not use a production user.
5. Ensure cookies are secure and that the reverse proxy forwards the original HTTPS scheme.

Confirm the public metadata before continuing:

```sh
issuer=https://id.example.com/default
curl --fail --silent --show-error \
  "$issuer/.well-known/openid-configuration" | jq .
curl --fail --silent --show-error "$issuer/jwks.json" | jq .
```

Every advertised endpoint must use HTTPS, the metadata `issuer` must equal `$issuer`, `scopes_supported` must contain `openid`, and the JWKS must contain an RSA signing key with a unique `kid`.

## Register the Static Test Clients

Choose a unique, URL-safe suite alias. The Foundation uses it to form the single callback URI `https://www.certification.openid.net/test/a/<ALIAS>/callback`.

Generate the three required application files:

```sh
mix robine_id.oidc.conformance.configure \
  --alias your-unique-alias \
  --applications-dir deploy/config/applications
```

The task creates:

| Suite field | Client ID | Authentication | Secret environment variable |
| --- | --- | --- | --- |
| `client` | `robine-id-conformance-basic-1` | `client_secret_basic` | `ROBINE_ID_CONFORMANCE_BASIC_1_SECRET` |
| `client2` | `robine-id-conformance-basic-2` | `client_secret_basic` | `ROBINE_ID_CONFORMANCE_BASIC_2_SECRET` |
| `client_secret_post` | `robine-id-conformance-post` | `client_secret_post` | `ROBINE_ID_CONFORMANCE_POST_SECRET` |

Generate three independent high-entropy secrets, place them in the deployment secret store under those names, validate the composed configuration, and restart the release so the new environment variables are available:

```sh
openssl rand -base64 48
ROBINE_ID_APPLICATIONS_DIR="$PWD/deploy/config/applications" \
  mix robine_id.config.validate deploy/config/robine_id.json
```

The generated clients intentionally disable mandatory nonce and PKCE policy because nonce is optional for code flow and the Basic plan includes requests without PKCE. The provider still accepts S256 when the PKCE module supplies it. The clients also disable interactive consent so `prompt=none` can complete silently after the first authentication.

Remove these clients and their secrets after the certification run unless the deployment is dedicated to conformance testing.

## Run the Basic OP Plan

At [certification.openid.net](https://www.certification.openid.net/), create **OpenID Connect Core: Basic Certification Profile Authorization server test** with these choices:

- server metadata: discovery;
- client registration: static client;
- response type: code;
- response mode: default;
- client authentication: the plan default (`client_secret_basic`);
- discovery URL: `<issuer>/.well-known/openid-configuration`;
- alias: the same alias used to generate the clients;
- client, client2, and client-secret-post identifiers and secrets: the values in the table above;
- login hint: the conformance test identity's identifier, if useful;
- UI locale: one of `ui_locales_supported`, such as `en`.

Run every module. Follow its blue-box browser instructions, including clearing cookies and uploading screenshots when requested. The Basic plan exercises ordinary and reordered requests, both client-secret transports, UserInfo GET and POST, optional nonce, the standard scopes, `display`, `prompt`, `max_age`, hints, localization, claims, PKCE, redirect validation, and authorization-code reuse.

The Foundation permits `PASSED`, `REVIEW`, `WARNING`, and `SKIPPED` module outcomes for certification. No module may remain `FAILED` or `INTERRUPTED`. Warnings still deserve review; export the log and resolve any behavior that is under this implementation's control.

## Run the Config OP Plan

Create **OpenID Connect Core: Config Certification Profile Authorization server test** using discovery and static-client variants. Supply the same discovery URL. Run the discovery verification module and inspect any warnings about optional metadata rather than blindly accepting them.

## Publish and Submit

For each completed profile, use **Publish for certification** to obtain its ZIP file. The Basic OP and Config OP profiles each produce a separate artifact. Then:

1. retain the release commit, image digest, public issuer, plan URLs, logs, and ZIP artifacts together;
2. obtain the required payment code;
3. submit both certification requests and declarations through the Foundation form;
4. do not claim that the deployment is OpenID Certified until the Foundation has accepted and published the submission.

The external hosted run, fee, legal declaration, and Foundation acceptance require the operator's account and authority and cannot be completed by the application itself.

## Release Evidence Checklist

- `mix precommit` passes on the exact release commit.
- The dependency audit contains no known vulnerable locked packages.
- The public discovery document and JWKS pass the Config OP plan.
- All Basic OP modules have an acceptable terminal result.
- The three static test clients use independent secrets and the exact suite callback.
- Conformance clients and secrets are removed or disabled after submission.
- Published ZIPs, screenshots, image digest, and configuration fingerprint are archived.
