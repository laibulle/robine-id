defmodule RobineIdWeb.AuthorizationControllerTest do
  use RobineIdWeb.ConnCase

  @verifier String.duplicate("v", 64)
  @challenge :crypto.hash(:sha256, @verifier) |> Base.url_encode64(padding: false)

  defp authorization_params do
    %{
      "client_id" => "development-client",
      "redirect_uri" => "http://localhost:4002/callback",
      "response_type" => "code",
      "scope" => "openid profile email",
      "state" => "state-123",
      "nonce" => "nonce-123",
      "code_challenge" => @challenge,
      "code_challenge_method" => "S256"
    }
  end

  test "renders an accessible sign-in form for a valid request", %{conn: conn} do
    conn = get(conn, ~p"/default/authorize?#{authorization_params()}")
    html = html_response(conn, 200)

    assert html =~ "Welcome back"
    assert html =~ "Development Client"
    assert html =~ ~s(autocomplete="username")
    assert html =~ ~s(autocomplete="current-password")
    assert html =~ ~s(data-password-toggle)
  end

  test "uses the configured ui_locale", %{conn: conn} do
    params = Map.put(authorization_params(), "ui_locales", "fr en")
    html = conn |> get(~p"/default/authorize?#{params}") |> html_response(200)
    assert html =~ "Heureux de vous revoir"
    assert html =~ "Adresse e-mail"
    assert html =~ "Connectez-vous pour continuer avec"
    refute html =~ "sign_in.intro"
  end

  test "redirects protocol errors only after validating the redirect URI", %{conn: conn} do
    params = %{authorization_params() | "scope" => "openid forbidden"}
    conn = get(conn, ~p"/default/authorize?#{params}")
    query = conn |> redirected_to(302) |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    assert query["error"] == "invalid_scope"
    assert query["state"] == "state-123"

    unsafe = %{params | "redirect_uri" => "https://evil.example/callback"}
    conn = build_conn() |> get(~p"/default/authorize?#{unsafe}")
    html = html_response(conn, 400)
    assert html =~ "Unable to continue"
    assert html =~ "redirect_uri is not registered"
    assert html =~ "Reference"
  end

  test "uses a generic credential error and preserves the authorization session", %{conn: conn} do
    conn = get(conn, ~p"/default/authorize?#{authorization_params()}")

    conn =
      post(conn, ~p"/default/authorize", %{
        "login" => %{"identifier" => "missing@example.com", "password" => "wrong"}
      })

    html = html_response(conn, 422)
    assert html =~ "The email or password is incorrect."
    refute html =~ "account does not exist"
    assert get_session(conn, :authorization_request)
  end

  test "completes login, consent, and exchanges the returned code", %{conn: conn} do
    conn = get(conn, ~p"/default/authorize?#{authorization_params()}")

    conn =
      post(conn, ~p"/default/authorize", %{
        "login" => %{"identifier" => "admin@example.com", "password" => "change-me"}
      })

    html = html_response(conn, 200)
    assert html =~ "Allow access?"
    assert html =~ "View your email address"
    assert get_session(conn, :subject) == "development-user"

    conn = post(conn, ~p"/default/authorize/consent", %{"decision" => "approve"})
    location = redirected_to(conn, 302)
    uri = URI.parse(location)
    query = URI.decode_query(uri.query)
    assert uri.host == "localhost"
    assert query["state"] == "state-123"
    assert is_binary(query["code"])
    assert get_session(conn, :subject) == "development-user"
    refute get_session(conn, :authorization_request)

    token_conn =
      build_conn()
      |> post(~p"/default/token", %{
        "grant_type" => "authorization_code",
        "code" => query["code"],
        "client_id" => "development-client",
        "redirect_uri" => "http://localhost:4002/callback",
        "code_verifier" => @verifier
      })

    assert %{"token_type" => "Bearer", "id_token" => id_token, "access_token" => access_token} =
             json_response(token_conn, 200)

    assert is_binary(id_token)
    assert is_binary(access_token)
    assert get_resp_header(token_conn, "cache-control") == ["no-store"]

    %{"keys" => [key | _]} =
      build_conn()
      |> get(~p"/default/jwks.json")
      |> json_response(200)

    assert {true, jwt, _jws} = JOSE.JWT.verify_strict(JOSE.JWK.from_map(key), ["RS256"], id_token)
    assert jwt.fields["name"] == "Development Administrator"
    assert jwt.fields["email"] == "admin@example.com"
  end

  test "denying consent returns a standards error and preserves state", %{conn: conn} do
    conn = get(conn, ~p"/default/authorize?#{authorization_params()}")

    conn =
      post(conn, ~p"/default/authorize", %{
        "login" => %{"identifier" => "admin@example.com", "password" => "change-me"}
      })

    assert html_response(conn, 200) =~ "Allow access?"
    conn = post(conn, ~p"/default/authorize/consent", %{"decision" => "deny"})
    query = conn |> redirected_to(302) |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    assert query["error"] == "access_denied"
    assert query["state"] == "state-123"
  end

  test "token endpoint challenges invalid client authentication", %{conn: conn} do
    conn =
      post(conn, ~p"/default/token", %{
        "grant_type" => "authorization_code",
        "code" => "unknown",
        "client_id" => "unknown",
        "redirect_uri" => "https://app.example/callback",
        "code_verifier" => @verifier
      })

    assert %{"error" => "invalid_client", "correlation_id" => correlation_id} =
             json_response(conn, 401)

    assert is_binary(correlation_id)

    assert get_resp_header(conn, "www-authenticate") == [
             ~s(Basic realm="Robine ID token endpoint")
           ]
  end

  test "supports the Penpot confidential client profile", %{conn: conn} do
    previous_secret = System.get_env("PENPOT_OIDC_CLIENT_SECRET")
    System.put_env("PENPOT_OIDC_CLIENT_SECRET", "penpot-test-secret")

    on_exit(fn ->
      if previous_secret,
        do: System.put_env("PENPOT_OIDC_CLIENT_SECRET", previous_secret),
        else: System.delete_env("PENPOT_OIDC_CLIENT_SECRET")
    end)

    params = %{
      "client_id" => "penpot",
      "redirect_uri" => "https://penpot.base59.dev/api/auth/oidc/callback",
      "response_type" => "code",
      "scope" => "openid profile email",
      "state" => "penpot-state"
    }

    conn = get(conn, ~p"/default/authorize?#{params}")

    conn =
      post(conn, ~p"/default/authorize", %{
        "login" => %{"identifier" => "admin@example.com", "password" => "change-me"}
      })

    callback = conn |> redirected_to(302) |> URI.parse()
    query = URI.decode_query(callback.query)
    assert callback.host == "penpot.base59.dev"
    assert query["state"] == "penpot-state"

    token_conn =
      build_conn()
      |> post(~p"/default/token", %{
        "grant_type" => "authorization_code",
        "code" => query["code"],
        "client_id" => "penpot",
        "client_secret" => "penpot-test-secret",
        "redirect_uri" => "https://penpot.base59.dev/api/auth/oidc/callback"
      })

    assert %{"token_type" => "Bearer", "id_token" => _, "access_token" => _} =
             json_response(token_conn, 200)
  end
end
