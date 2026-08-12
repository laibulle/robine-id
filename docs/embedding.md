# Embedding Robine ID

Robine ID supports two deployment modes from the same source tree:

- `:standalone` starts its Phoenix endpoint, SQLite repository, PubSub, telemetry, and OIDC runtime;
- `:embedded` starts only the OIDC runtime stores. The host owns every visible page,
  form, route, and static asset.

The standalone mode remains the default and requires no configuration changes.

## Dependency

During development, a sibling application can use a path dependency:

```elixir
{:robine_id, path: "../robine-id"}
```

Released hosts should pin an immutable Git tag:

```elixir
{:robine_id, git: "git@github.com:laibulle/robine-id.git", tag: "v0.2.0"}
```

## Host configuration

```elixir
config :robine_id,
  mode: :embedded,
  base_path: "/id",
  configuration_path: "/etc/product/id/robine_id.json",
  applications_path: "/etc/product/id/applications",
  key_store_path: "/var/lib/product/id/signing_keys.bin",
  key_store_secret: System.fetch_env!("ROBINE_ID_KEY_STORE_SECRET"),
  adapters: %{
    user_repository: Product.Identity.UserRepository,
    password_hasher: Product.Identity.PasswordHasher,
    database_health: Product.Identity.DatabaseHealth
  }
```

The host explicitly declares its protocol routes. It may reuse the JSON controllers,
while its own controller drives authorization through `RobineId.Authorization`:

```elixir
scope "/id", RobineIdWeb do
  get "/:issuer_id/.well-known/openid-configuration", DiscoveryController, :show
  get "/:issuer_id/jwks.json", JwksController, :show
  post "/:issuer_id/token", TokenController, :create
  get "/:issuer_id/userinfo", UserInfoController, :show
end

get "/id/:issuer_id/authorize", ProductWeb.IdentityController, :new
post "/id/:issuer_id/authorize", ProductWeb.IdentityController, :create
```

The configured issuer must include the same base path, for example
`https://product.example.com/id/default`. The host UI is responsible for its own
assets and form actions; discovery derives from the configured issuer.

## Adapter contract

Embedded hosts normally replace the user repository, password hasher, and database
health dependency. The repository returns `RobineId.Identity.Entities.User` values;
the stable host user identifier becomes the OIDC `sub`. Other runtime adapters can
also be replaced through `RobineId.Runtime.adapter/1` without a compile-time
dependency from Robine ID to the host.

Robine ID owns authorization codes, access-token grants, signing keys, rate limits,
and its authenticated-session registry. The host owns its product session. A host
should consume Robine ID through Authorization Code with PKCE, even when embedded,
so moving the provider to a separate service remains a configuration change.

## Production requirements

- Pin a Robine ID release rather than a mutable branch or path.
- Persist the signing-key file and its matching encryption secret together.
- Provide deployment-specific issuer and redirect URLs in the JSON configuration.
- Mount the application directory read-only.
- Do not start `RobineIdWeb.Endpoint` or `RobineId.Repo` in embedded mode.
- Do not mount Robine ID's standalone router, layouts, templates, or assets.
- Verify discovery, JWKS, callback, session creation, logout, and restart recovery.
