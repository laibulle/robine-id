defmodule RobineIdWeb.UserInfoControllerTest do
  use RobineIdWeb.ConnCase

  alias RobineId.Protocol.Adapters.MemoryAccessTokenStore
  alias RobineId.Protocol.Entities.AccessGrant

  test "returns claims authorized by bearer-token scopes", %{conn: conn} do
    grant = %AccessGrant{
      issuer: "https://id.base59.dev/default",
      subject: "development-user",
      client_id: "development-client",
      scope: ["openid", "email"],
      expires_at: System.system_time(:second) + 60,
      claims: %{"email" => "admin@example.com"}
    }

    assert {:ok, token} = MemoryAccessTokenStore.issue(grant)

    response =
      conn
      |> put_req_header("authorization", "Bearer #{token}")
      |> get(~p"/default/userinfo")
      |> json_response(200)

    assert response["sub"] == "development-user"
    assert response["email"] == "admin@example.com"
    refute Map.has_key?(response, "name")
  end

  test "rejects missing, unknown, and expired bearer tokens", %{conn: conn} do
    conn = get(conn, ~p"/default/userinfo")
    assert %{"error" => "invalid_token"} = json_response(conn, 401)
    assert get_resp_header(conn, "www-authenticate") == [~s(Bearer error="invalid_token")]

    expired = %AccessGrant{
      issuer: "https://id.base59.dev/default",
      subject: "development-user",
      client_id: "development-client",
      scope: ["openid"],
      expires_at: System.system_time(:second) - 1
    }

    {:ok, token} = MemoryAccessTokenStore.issue(expired)

    conn =
      build_conn()
      |> put_req_header("authorization", "Bearer #{token}")
      |> get(~p"/default/userinfo")

    assert %{"error" => "invalid_token"} = json_response(conn, 401)
  end
end
