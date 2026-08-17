defmodule RobineId.ClientsTest do
  use ExUnit.Case, async: true

  alias RobineId.Clients.Entities.Client
  alias RobineId.Clients.Adapters.EnvironmentSecretResolver
  alias RobineId.Test.Clients.MemoryRepository

  defmodule SecretResolver do
    @behaviour RobineId.Clients.Ports.SecretResolver
    @impl true
    def resolve(%{"key" => "CLIENT_SECRET"}), do: {:ok, "correct-secret"}
    def resolve(secret) when is_binary(secret), do: {:ok, secret}
    def resolve(_), do: {:error, :missing}
  end

  test "builds and retrieves a public client through the facade" do
    assert {:ok, client} =
             Client.from_config(%{
               "id" => "browser",
               "name" => "Browser",
               "type" => "public",
               "redirect_uris" => ["https://app.example.test/callback"],
               "scopes" => ["openid", "profile"]
             })

    MemoryRepository.put(client)
    assert {:ok, ^client} = RobineId.Clients.get("browser", MemoryRepository)
    assert client.authentication_method == "none"
  end

  test "requires a secret reference for confidential clients" do
    assert {:error, {:invalid_client, message}} =
             Client.from_config(%{
               "id" => "server",
               "type" => "confidential",
               "redirect_uris" => ["https://app.example.test/callback"]
             })

    assert message =~ "authentication method"
  end

  test "authenticates confidential clients through a typed secret reference" do
    assert {:ok, client} =
             Client.from_config(%{
               "id" => "server",
               "type" => "confidential",
               "authentication_method" => "client_secret_basic",
               "secret_reference" => %{"provider" => "env", "key" => "CLIENT_SECRET"},
               "redirect_uris" => ["https://app.example.test/callback"]
             })

    MemoryRepository.put(client)

    assert {:ok, ^client} =
             RobineId.Clients.authenticate(
               "server",
               "correct-secret",
               MemoryRepository,
               SecretResolver
             )

    assert {:error, :invalid_client} =
             RobineId.Clients.authenticate("server", "wrong", MemoryRepository, SecretResolver)
  end

  test "supports client_secret_post only when the client declares that method" do
    assert {:ok, client} =
             Client.from_config(%{
               "id" => "penpot",
               "type" => "confidential",
               "authentication_method" => "client_secret_post",
               "pkce_required" => false,
               "nonce_required" => false,
               "secret_reference" => %{"provider" => "env", "key" => "CLIENT_SECRET"},
               "redirect_uris" => ["https://penpot.example.test/api/auth/oidc/callback"]
             })

    MemoryRepository.put(client)

    assert client.pkce_required == false
    assert client.nonce_required == false

    assert {:ok, ^client} =
             RobineId.Clients.authenticate(
               "penpot",
               "client_secret_post",
               "correct-secret",
               MemoryRepository,
               SecretResolver
             )

    assert {:error, :invalid_client} =
             RobineId.Clients.authenticate(
               "penpot",
               "client_secret_basic",
               "correct-secret",
               MemoryRepository,
               SecretResolver
             )
  end

  test "accepts a literal confidential client secret" do
    assert {:ok, "literal-secret"} = EnvironmentSecretResolver.resolve("literal-secret")

    assert {:ok, client} =
             Client.from_config(%{
               "id" => "inline-secret",
               "type" => "confidential",
               "authentication_method" => "client_secret_basic",
               "secret_reference" => "literal-secret",
               "redirect_uris" => ["https://app.example.test/callback"]
             })

    MemoryRepository.put(client)

    assert {:ok, ^client} =
             RobineId.Clients.authenticate(
               "inline-secret",
               "literal-secret",
               MemoryRepository,
               SecretResolver
             )

    assert {:error, :invalid_client} =
             RobineId.Clients.authenticate(
               "inline-secret",
               "wrong-secret",
               MemoryRepository,
               SecretResolver
             )
  end

  test "public clients must not present a secret" do
    {:ok, client} =
      Client.from_config(%{
        "id" => "browser-public",
        "type" => "public",
        "redirect_uris" => ["https://app.example.test/callback"]
      })

    MemoryRepository.put(client)

    assert {:ok, ^client} =
             RobineId.Clients.authenticate(
               "browser-public",
               nil,
               MemoryRepository,
               SecretResolver
             )

    assert {:error, :invalid_client} =
             RobineId.Clients.authenticate(
               "browser-public",
               "unexpected",
               MemoryRepository,
               SecretResolver
             )
  end

  test "public clients cannot disable PKCE" do
    assert {:error, {:invalid_client, "public clients must require PKCE"}} =
             Client.from_config(%{
               "id" => "unsafe-browser",
               "type" => "public",
               "pkce_required" => false,
               "redirect_uris" => ["https://app.example.test/callback"]
             })
  end

  test "public clients cannot disable nonce validation" do
    assert {:error, {:invalid_client, "public clients must require a nonce"}} =
             Client.from_config(%{
               "id" => "unsafe-browser",
               "type" => "public",
               "nonce_required" => false,
               "redirect_uris" => ["https://app.example.test/callback"]
             })
  end

  test "only confidential clients can opt into token introspection" do
    assert {:ok, client} =
             Client.from_config(%{
               "id" => "resource-server",
               "type" => "confidential",
               "authentication_method" => "client_secret_basic",
               "secret_reference" => %{"provider" => "env", "key" => "CLIENT_SECRET"},
               "redirect_uris" => ["https://resource.example.test/callback"],
               "introspection_allowed" => true
             })

    assert client.introspection_allowed

    assert {:error, {:invalid_client, "public clients cannot use token introspection"}} =
             Client.from_config(%{
               "id" => "browser",
               "type" => "public",
               "redirect_uris" => ["https://app.example.test/callback"],
               "introspection_allowed" => true
             })
  end

  test "accepts rotating refresh grants and rejects unknown or duplicate grants" do
    assert {:ok, client} =
             Client.from_config(%{
               "id" => "offline-browser",
               "type" => "public",
               "redirect_uris" => ["https://app.example.test/callback"],
               "scopes" => ["openid", "offline_access"],
               "grant_types" => ["authorization_code", "refresh_token"]
             })

    assert client.grant_types == ["authorization_code", "refresh_token"]

    assert {:error, {:invalid_client, "grant_types contains an unsupported grant"}} =
             Client.from_config(%{
               "id" => "implicit-browser",
               "type" => "public",
               "redirect_uris" => ["https://app.example.test/callback"],
               "grant_types" => ["implicit"]
             })

    assert {:error, {:invalid_client, "grant_types must be unique"}} =
             Client.from_config(%{
               "id" => "duplicate-browser",
               "type" => "public",
               "redirect_uris" => ["https://app.example.test/callback"],
               "grant_types" => ["authorization_code", "authorization_code"]
             })
  end

  test "accepts redirectless device clients and requires openid" do
    grant = "urn:ietf:params:oauth:grant-type:device_code"

    assert {:ok, client} =
             Client.from_config(%{
               "id" => "television",
               "type" => "public",
               "redirect_uris" => [],
               "scopes" => ["openid", "profile"],
               "grant_types" => [grant]
             })

    assert client.grant_types == [grant]
    assert client.redirect_uris == []

    assert {:error, {:invalid_client, "user authorization grants require the openid scope"}} =
             Client.from_config(%{
               "id" => "unsafe-television",
               "type" => "public",
               "redirect_uris" => [],
               "scopes" => ["profile"],
               "grant_types" => [grant]
             })
  end

  test "accepts client credentials only for confidential clients" do
    assert {:ok, client} =
             Client.from_config(%{
               "id" => "service",
               "type" => "confidential",
               "redirect_uris" => [],
               "scopes" => ["service.read"],
               "grant_types" => ["client_credentials"],
               "authentication_method" => "client_secret_basic",
               "secret_reference" => %{"provider" => "env", "key" => "CLIENT_SECRET"}
             })

    assert client.grant_types == ["client_credentials"]

    assert {:error, {:invalid_client, "client_credentials requires a confidential client"}} =
             Client.from_config(%{
               "id" => "unsafe-service",
               "type" => "public",
               "redirect_uris" => [],
               "scopes" => ["service.read"],
               "grant_types" => ["client_credentials"]
             })
  end

  test "accepts token exchange only for confidential clients with a resource" do
    grant = "urn:ietf:params:oauth:grant-type:token-exchange"

    assert {:ok, client} =
             Client.from_config(%{
               "id" => "broker",
               "type" => "confidential",
               "redirect_uris" => [],
               "resources" => ["https://api.example.test"],
               "scopes" => ["service.read"],
               "grant_types" => [grant],
               "authentication_method" => "client_secret_basic",
               "secret_reference" => %{"provider" => "env", "key" => "BROKER_SECRET"}
             })

    assert client.grant_types == [grant]

    for override <- [
          %{"type" => "public", "resources" => ["https://api.example.test"]},
          %{"type" => "confidential", "resources" => []}
        ] do
      invalid =
        Map.merge(
          %{
            "id" => "unsafe-broker",
            "redirect_uris" => [],
            "scopes" => ["service.read"],
            "grant_types" => [grant]
          },
          override
        )

      assert {:error,
              {:invalid_client,
               "token exchange requires a confidential client with at least one resource"}} =
               Client.from_config(invalid)
    end
  end

  test "validates exact safe resource indicators" do
    assert {:ok, client} =
             Client.from_config(%{
               "id" => "resource-client",
               "type" => "public",
               "redirect_uris" => ["https://app.example.test/callback"],
               "resources" => ["https://api.example.test/orders"]
             })

    assert client.resources == ["https://api.example.test/orders"]

    assert {:error, {:invalid_client, _message}} =
             Client.from_config(%{
               "id" => "unsafe-resource-client",
               "type" => "public",
               "redirect_uris" => ["https://app.example.test/callback"],
               "resources" => ["javascript:alert(1)"]
             })
  end

  test "accepts public JWK credentials only for private_key_jwt" do
    jwks = %{
      "keys" => [
        %{
          "kty" => "RSA",
          "kid" => "primary",
          "use" => "sig",
          "alg" => "RS256",
          "n" => Base.url_encode64(:binary.copy(<<1>>, 256), padding: false),
          "e" => "AQAB"
        }
      ]
    }

    assert {:ok, client} =
             Client.from_config(%{
               "id" => "assertion-client",
               "type" => "confidential",
               "redirect_uris" => [],
               "scopes" => ["service.read"],
               "grant_types" => ["client_credentials"],
               "authentication_method" => "private_key_jwt",
               "jwks" => jwks
             })

    assert client.jwks == jwks

    assert {:error, {:invalid_client, _message}} =
             Client.from_config(%{
               "id" => "mixed-credentials",
               "type" => "confidential",
               "redirect_uris" => [],
               "scopes" => ["service.read"],
               "grant_types" => ["client_credentials"],
               "authentication_method" => "private_key_jwt",
               "secret_reference" => %{"provider" => "env", "key" => "CLIENT_SECRET"},
               "jwks" => jwks
             })
  end
end
