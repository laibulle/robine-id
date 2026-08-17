defmodule RobineId.Protocol.ValidateAuthorizationRequestTest do
  use ExUnit.Case, async: true

  alias RobineId.Clients.Entities.Client
  alias RobineId.Protocol.Entities.AuthorizationRequest
  alias RobineId.Test.Clients.MemoryRepository

  @challenge String.duplicate("A", 43)
  @params %{
    "client_id" => "browser",
    "redirect_uri" => "https://app.example.test/callback",
    "response_type" => "code",
    "scope" => "openid profile",
    "state" => "opaque-state",
    "nonce" => "opaque-nonce",
    "code_challenge" => @challenge,
    "code_challenge_method" => "S256"
  }

  setup do
    {:ok, client} =
      Client.from_config(%{
        "id" => "browser",
        "type" => "public",
        "redirect_uris" => ["https://app.example.test/callback"],
        "resources" => ["https://api.example.test/orders"],
        "scopes" => ["openid", "profile"]
      })

    MemoryRepository.put(client)
    :ok
  end

  test "accepts a registered code flow using PKCE S256" do
    assert {:ok, %AuthorizationRequest{} = request} =
             RobineId.Protocol.validate_authorization_request("main", @params, MemoryRepository)

    assert request.scope == ["openid", "profile"]
    assert request.code_challenge == @challenge
  end

  test "accepts only a resource registered by the client" do
    params = Map.put(@params, "resource", "https://api.example.test/orders")

    assert {:ok, %AuthorizationRequest{resource: "https://api.example.test/orders"}} =
             RobineId.Protocol.validate_authorization_request("main", params, MemoryRepository)

    assert {:error, {:invalid_target, _message}} =
             RobineId.Protocol.validate_authorization_request(
               "main",
               Map.put(@params, "resource", "https://other.example.test/orders"),
               MemoryRepository
             )
  end

  test "requires exact redirect URI matching" do
    params = %{@params | "redirect_uri" => "https://app.example.test/callback?unexpected=1"}

    assert {:error, {:invalid_request, message}} =
             RobineId.Protocol.validate_authorization_request("main", params, MemoryRepository)

    assert message =~ "not registered"
  end

  test "rejects plain PKCE" do
    params = %{@params | "code_challenge_method" => "plain"}

    assert {:error, {:invalid_request, "PKCE S256 is required"}} =
             RobineId.Protocol.validate_authorization_request("main", params, MemoryRepository)
  end

  test "requires allowed scopes and openid" do
    params = %{@params | "scope" => "profile admin"}

    assert {:error, {:invalid_scope, _}} =
             RobineId.Protocol.validate_authorization_request("main", params, MemoryRepository)
  end

  test "allows a confidential client to opt out of PKCE explicitly" do
    {:ok, client} =
      Client.from_config(%{
        "id" => "penpot",
        "type" => "confidential",
        "authentication_method" => "client_secret_post",
        "pkce_required" => false,
        "nonce_required" => false,
        "secret_reference" => %{"provider" => "env", "key" => "PENPOT_SECRET"},
        "redirect_uris" => ["https://penpot.example.test/api/auth/oidc/callback"],
        "scopes" => ["openid", "profile", "email"]
      })

    MemoryRepository.put(client)

    params = %{
      "client_id" => "penpot",
      "redirect_uri" => "https://penpot.example.test/api/auth/oidc/callback",
      "response_type" => "code",
      "scope" => "openid profile email",
      "state" => "opaque-state"
    }

    assert {:ok, %AuthorizationRequest{code_challenge: nil, nonce: nil}} =
             RobineId.Protocol.validate_authorization_request("main", params, MemoryRepository)
  end
end
