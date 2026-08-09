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
end
