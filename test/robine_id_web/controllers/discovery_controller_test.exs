defmodule RobineIdWeb.DiscoveryControllerTest do
  use RobineIdWeb.ConnCase

  test "GET /:issuer/.well-known/openid-configuration", %{conn: conn} do
    conn = get(conn, ~p"/default/.well-known/openid-configuration")

    assert %{
             "issuer" => "http://127.0.0.1:4001/default",
             "response_types_supported" => ["code"]
           } = json_response(conn, 200)

    assert get_resp_header(conn, "cache-control") == ["public, max-age=300"]
  end

  test "returns a generic response for an unknown issuer", %{conn: conn} do
    conn = get(conn, "/unknown/.well-known/openid-configuration")
    assert %{"error" => "not_found"} = json_response(conn, 404)
  end
end
