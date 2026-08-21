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

  test "supports POST with bearer tokens in either the header or form body", %{conn: conn} do
    grant = %AccessGrant{
      issuer: "https://id.base59.dev/default",
      subject: "development-user",
      client_id: "development-client",
      scope: ["openid"],
      expires_at: System.system_time(:second) + 60
    }

    {:ok, header_token} = MemoryAccessTokenStore.issue(grant)

    header_response =
      conn
      |> put_req_header("authorization", "Bearer #{header_token}")
      |> post(~p"/default/userinfo")
      |> json_response(200)

    assert header_response["sub"] == "development-user"

    {:ok, body_token} = MemoryAccessTokenStore.issue(grant)

    body_conn =
      build_conn()
      |> put_req_header("content-type", "application/x-www-form-urlencoded")
      |> post(~p"/default/userinfo", %{"access_token" => body_token})

    assert json_response(body_conn, 200)["sub"] == "development-user"
    assert get_resp_header(body_conn, "cache-control") == ["no-store"]
  end
end
