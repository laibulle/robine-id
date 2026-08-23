defmodule RobineIdWeb.AccountPortalTest do
  use RobineIdWeb.ConnCase

  alias RobineId.Identity.Adapters.{AccountOverrides, ConfigurationUserRepository}

  setup do
    :sys.replace_state(RobineId.Security.Adapters.MemoryRateLimiter, fn _state -> %{} end)
    :sys.replace_state(RobineId.Security.Adapters.MemorySessionRegistry, fn _state -> %{} end)
    :ok
  end

  test "redirects anonymous visitors to the local sign-in page", %{conn: conn} do
    conn = get(conn, ~p"/account")

    assert redirected_to(conn, 302) == "/login"
    assert get_session(conn, :return_to) == "/account"
  end

  test "signs in and grants the configured administrator access", %{conn: conn} do
    conn = sign_in(conn)

    assert redirected_to(conn, 302) == "/account"
    assert get_session(conn, :subject) == "development-user"

    account_html = conn |> recycle() |> get(~p"/account") |> html_response(200)
    assert account_html =~ "Your account"
    assert account_html =~ "admin@example.com"

    admin_html = conn |> recycle() |> get(~p"/admin") |> html_response(200)
    assert admin_html =~ "Configured users"
    assert admin_html =~ "Development Administrator"
  end

  test "persists profile and password changes in the managed identity view", %{conn: conn} do
    conn = sign_in(conn)

    conn =
      conn
      |> recycle()
      |> put(~p"/account", %{
        "account" => %{
          "name" => "Updated Administrator",
          "email" => "updated@example.com",
          "current_password" => "change-me",
          "new_password" => "a-new-password-123",
          "password_confirmation" => "a-new-password-123"
        }
      })

    assert redirected_to(conn, 302) == "/account"

    assert {:ok, user} =
             RobineId.Runtime.adapter(:user_repository).get_by_id("development-user")

    assert user.name == "Updated Administrator"
    assert user.email == "updated@example.com"
    assert is_integer(user.claims["updated_at"])

    assert {:error, :invalid_credentials} =
             RobineId.Identity.authenticate(
               "admin@example.com",
               "change-me",
               RobineId.Runtime.adapter(:user_repository),
               RobineId.Runtime.adapter(:password_hasher)
             )

    assert {:ok, _user} =
             RobineId.Identity.authenticate(
               "admin@example.com",
               "a-new-password-123",
               RobineId.Runtime.adapter(:user_repository),
               RobineId.Runtime.adapter(:password_hasher)
             )
  end

  test "rejects a password change without the current password", %{conn: conn} do
    conn = sign_in(conn)

    html =
      conn
      |> recycle()
      |> put(~p"/account", %{
        "account" => %{
          "name" => "Development Administrator",
          "email" => "admin@example.com",
          "current_password" => "wrong",
          "new_password" => "a-new-password-123",
          "password_confirmation" => "different-password"
        }
      })
      |> html_response(422)

    assert html =~ "is incorrect"
    assert html =~ "does not match the new password"
  end

  test "returns forbidden for an authenticated non-admin", %{conn: conn} do
    {:ok, configured_user} = ConfigurationUserRepository.get_by_id("development-user")
    {:ok, _user} = AccountOverrides.upsert(configured_user, %{roles: []})

    conn = sign_in(conn)
    assert conn |> recycle() |> get(~p"/admin") |> response(403) == "Forbidden"
  end

  test "prevents an administrator from locking out their own account", %{conn: conn} do
    conn = sign_in(conn)

    html =
      conn
      |> recycle()
      |> put(~p"/admin/users/development-user", %{
        "user" => %{
          "name" => "Development Administrator",
          "email" => "admin@example.com",
          "roles" => "support",
          "enabled" => "false"
        }
      })
      |> html_response(422)

    assert html =~ "cannot disable your own account"
    assert html =~ "cannot remove your own admin role"
  end

  test "an administrator can persist safe changes over an existing override", %{conn: conn} do
    {:ok, configured_user} = ConfigurationUserRepository.get_by_id("development-user")

    {:ok, _user} =
      AccountOverrides.upsert(configured_user, %{name: "First managed name"})

    conn = sign_in(conn)

    conn =
      conn
      |> recycle()
      |> put(~p"/admin/users/development-user", %{
        "user" => %{
          "name" => "Managed Administrator",
          "email" => "managed@example.com",
          "roles" => "admin, support",
          "enabled" => "true"
        }
      })

    assert redirected_to(conn, 302) == "/admin/users/development-user/edit"
    assert {:ok, user} = RobineId.Runtime.adapter(:user_repository).get_by_id("development-user")
    assert user.name == "Managed Administrator"
    assert user.email == "managed@example.com"
    assert user.roles == ["admin", "support"]
  end

  test "a disabled managed account can no longer sign in", %{conn: conn} do
    {:ok, configured_user} = ConfigurationUserRepository.get_by_id("development-user")
    {:ok, _user} = AccountOverrides.upsert(configured_user, %{enabled: false})

    html = conn |> sign_in() |> html_response(422)
    assert html =~ "The email or password is incorrect."
  end

  test "uses a generic error for invalid local credentials", %{conn: conn} do
    html =
      conn
      |> post(~p"/login", %{
        "login" => %{"identifier" => "missing@example.com", "password" => "wrong"}
      })
      |> html_response(422)

    assert html =~ "The email or password is incorrect."
    refute html =~ "account does not exist"
  end

  defp sign_in(conn) do
    post(conn, ~p"/login", %{
      "login" => %{"identifier" => "admin@example.com", "password" => "change-me"}
    })
  end
end
