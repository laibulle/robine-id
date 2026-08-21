defmodule RobineIdWeb.DiscoveryControllerTest do
  use RobineIdWeb.ConnCase

  test "GET /:issuer/.well-known/openid-configuration", %{conn: conn} do
    conn = get(conn, ~p"/default/.well-known/openid-configuration")

    assert %{
             "issuer" => "https://id.base59.dev/default",
             "response_types_supported" => ["code"],
             "response_modes_supported" => ["query"],
             "claims_parameter_supported" => true,
             "request_parameter_supported" => true,
             "request_object_signing_alg_values_supported" => ["none"]
           } = json_response(conn, 200)

    assert get_resp_header(conn, "cache-control") == ["public, max-age=300"]
  end

  test "returns a generic response for an unknown issuer", %{conn: conn} do
    conn = get(conn, "/unknown/.well-known/openid-configuration")
    assert %{"error" => "not_found"} = json_response(conn, 404)
  end
end
