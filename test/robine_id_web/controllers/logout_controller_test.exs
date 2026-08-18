defmodule RobineIdWeb.LogoutControllerTest do
  use RobineIdWeb.ConnCase

  alias RobineId.Protocol.Adapters.MemoryKeyStore

  test "ends a local session after explicit confirmation", %{conn: conn} do
    conn = conn |> init_test_session(%{subject: "user"}) |> get(~p"/default/logout")
    assert html_response(conn, 200) =~ "Sign out?"

    conn = post(conn, ~p"/default/logout")
    assert html_response(conn, 200) =~ "You're signed out"
    refute get_session(conn, :subject)
  end

  test "validates post-logout redirects using a signed ID token", %{conn: conn} do
    claims = %{
      "iss" => "http://127.0.0.1:4001/default",
      "sub" => "development-user",
      "aud" => "development-client"
    }

    assert {:ok, token} = RobineId.Protocol.issue_id_token(claims, MemoryKeyStore, [])

    params = %{
      "id_token_hint" => token,
      "post_logout_redirect_uri" => "http://localhost:4002/signed-out",
      "state" => "logout-state"
    }

    conn = get(conn, ~p"/default/logout?#{params}")
    assert html_response(conn, 200) =~ "Sign out?"
    conn = post(conn, ~p"/default/logout")

    query = conn |> redirected_to(302) |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    assert query["state"] == "logout-state"
  end

  test "rejects an unregistered post-logout redirect", %{conn: conn} do
    conn =
      get(conn, ~p"/default/logout?post_logout_redirect_uri=https%3A%2F%2Fevil.example%2Fdone")

    assert %{"error" => "invalid_request"} = json_response(conn, 400)
  end
end
