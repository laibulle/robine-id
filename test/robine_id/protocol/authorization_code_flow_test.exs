defmodule RobineId.Protocol.AuthorizationCodeFlowTest do
  use ExUnit.Case, async: false

  alias RobineId.Protocol.Adapters.{
    MemoryAccessTokenStore,
    MemoryAuthorizationCodeStore,
    MemoryKeyStore
  }

  alias RobineId.Protocol.Entities.AuthorizationRequest

  @verifier String.duplicate("v", 64)
  @challenge :crypto.hash(:sha256, @verifier) |> Base.url_encode64(padding: false)

  defp request do
    %AuthorizationRequest{
      issuer_id: "main",
      client_id: "browser",
      redirect_uri: "https://app.example.test/callback",
      scope: ["openid", "profile"],
      state: "state",
      nonce: "nonce",
      code_challenge: @challenge,
      code_challenge_method: "S256"
    }
  end

  test "exchanges a bound code exactly once" do
    issuer = "https://code-flow-#{System.unique_integer([:positive])}.example.test"

    assert {:ok, code} =
             RobineId.Protocol.issue_authorization_code(
               request(),
               issuer,
               "user-123",
               MemoryAuthorizationCodeStore,
               now: 100,
               lifetime: 60
             )

    params = %{
      "_issuer" => issuer,
      "grant_type" => "authorization_code",
      "code" => code,
      "client_id" => "browser",
      "redirect_uri" => "https://app.example.test/callback",
      "code_verifier" => @verifier
    }

    assert {:ok, tokens} =
             RobineId.Protocol.exchange_authorization_code(
               params,
               MemoryAuthorizationCodeStore,
               MemoryKeyStore,
               MemoryAccessTokenStore,
               now: 120
             )

    assert tokens["token_type"] == "Bearer"
    assert tokens["scope"] == "openid profile"

    assert {:error, {:invalid_grant, _}} =
             RobineId.Protocol.exchange_authorization_code(
               params,
               MemoryAuthorizationCodeStore,
               MemoryKeyStore,
               MemoryAccessTokenStore,
               now: 120
             )
  end

  test "a wrong verifier consumes and invalidates the code" do
    assert {:ok, code} =
             RobineId.Protocol.issue_authorization_code(
               request(),
               "https://id.example.test",
               "user",
               MemoryAuthorizationCodeStore,
               now: 100
             )

    params = %{
      "_issuer" => "https://id.example.test",
      "grant_type" => "authorization_code",
      "code" => code,
      "client_id" => "browser",
      "redirect_uri" => "https://app.example.test/callback",
      "code_verifier" => String.duplicate("x", 64)
    }

    assert {:error, {:invalid_grant, "PKCE verification failed"}} =
             RobineId.Protocol.exchange_authorization_code(
               params,
               MemoryAuthorizationCodeStore,
               MemoryKeyStore,
               MemoryAccessTokenStore,
               now: 101
             )

    assert {:error, {:invalid_grant, _}} =
             RobineId.Protocol.exchange_authorization_code(
               %{params | "code_verifier" => @verifier},
               MemoryAuthorizationCodeStore,
               MemoryKeyStore,
               MemoryAccessTokenStore,
               now: 101
             )
  end

  test "rejects expired and rebound codes" do
    assert {:ok, expired_code} =
             RobineId.Protocol.issue_authorization_code(
               request(),
               "https://id.example.test",
               "user",
               MemoryAuthorizationCodeStore,
               now: 100,
               lifetime: 1
             )

    base = %{
      "_issuer" => "https://id.example.test",
      "grant_type" => "authorization_code",
      "code" => expired_code,
      "client_id" => "browser",
      "redirect_uri" => "https://app.example.test/callback",
      "code_verifier" => @verifier
    }

    assert {:error, {:invalid_grant, "authorization code expired"}} =
             RobineId.Protocol.exchange_authorization_code(
               base,
               MemoryAuthorizationCodeStore,
               MemoryKeyStore,
               MemoryAccessTokenStore,
               now: 101
             )

    assert {:ok, rebound_code} =
             RobineId.Protocol.issue_authorization_code(
               request(),
               "https://id.example.test",
               "user",
               MemoryAuthorizationCodeStore,
               now: 100
             )

    assert {:error, {:invalid_grant, "authorization code binding mismatch"}} =
             RobineId.Protocol.exchange_authorization_code(
               %{base | "code" => rebound_code, "client_id" => "attacker"},
               MemoryAuthorizationCodeStore,
               MemoryKeyStore,
               MemoryAccessTokenStore,
               now: 101
             )
  end

  test "exchanges a code without a verifier when PKCE was not requested" do
    issuer = "https://id.example.test"
    request = %{request() | client_id: "penpot", code_challenge: nil, code_challenge_method: nil}

    assert {:ok, code} =
             RobineId.Protocol.issue_authorization_code(
               request,
               issuer,
               "user-123",
               MemoryAuthorizationCodeStore,
               now: 100
             )

    assert {:ok, tokens} =
             RobineId.Protocol.exchange_authorization_code(
               %{
                 "_issuer" => issuer,
                 "grant_type" => "authorization_code",
                 "code" => code,
                 "client_id" => "penpot",
                 "redirect_uri" => "https://app.example.test/callback"
               },
               MemoryAuthorizationCodeStore,
               MemoryKeyStore,
               MemoryAccessTokenStore,
               now: 101
             )

    assert tokens["token_type"] == "Bearer"
  end
end
