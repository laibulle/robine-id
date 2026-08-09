defmodule RobineIdWeb.JwksControllerTest do
  use RobineIdWeb.ConnCase

  test "publishes only public RSA key material", %{conn: conn} do
    conn = get(conn, ~p"/default/jwks.json")
    assert %{"keys" => [key]} = json_response(conn, 200)
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
    assert is_binary(key["kid"])
    refute Map.has_key?(key, "d")
    refute Map.has_key?(key, "p")
  end

  test "does not expose keys for an unknown issuer", %{conn: conn} do
    conn = get(conn, "/unknown/jwks.json")
    assert %{"error" => "not_found"} = json_response(conn, 404)
  end
end
