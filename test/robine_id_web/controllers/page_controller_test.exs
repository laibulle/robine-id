defmodule RobineIdWeb.PageControllerTest do
  use RobineIdWeb.ConnCase

  test "GET /", %{conn: conn} do
    conn = get(conn, ~p"/")
    html = html_response(conn, 200)
    assert html =~ "A secure sign-in experience people will enjoy using."
    assert html =~ "Open discovery document"
    assert html =~ "All systems ready"
    assert html =~ ~s(href="/docs")
  end

  test "GET /docs", %{conn: conn} do
    conn = get(conn, ~p"/docs")
    html = html_response(conn, 200)

    assert html =~ "Build your OpenID Connect integration"
    assert html =~ "Register an application"
    assert html =~ "Authorization Code with PKCE"
    assert html =~ "/default/.well-known/openid-configuration"
  end
end
