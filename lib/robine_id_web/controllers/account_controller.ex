defmodule RobineIdWeb.AccountController do
  use RobineIdWeb, :controller

  alias RobineId.Identity.Accounts

  def show(conn, _params) do
    render_account(conn, Accounts.profile_changeset(conn.assigns.current_user))
  end

  def update(conn, %{"account" => params}) do
    case Accounts.update_profile(
           conn.assigns.current_user,
           params,
           RobineId.Runtime.adapter(:password_hasher)
         ) do
      {:ok, _user} ->
        audit(conn, :account_update, %{
          outcome: :success,
          subject_id: conn.assigns.current_user.id
        })

        conn
        |> put_flash(:info, "Your account has been updated.")
        |> redirect(to: RobineId.Runtime.path("/account"))

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> render_account(changeset)

      {:error, _reason} ->
        audit(conn, :account_update, %{
          outcome: :failure,
          subject_id: conn.assigns.current_user.id
        })

        conn
        |> put_status(:service_unavailable)
        |> put_flash(:error, "Your changes could not be saved.")
        |> render_account(Accounts.profile_changeset(conn.assigns.current_user))
    end
  end

  def update(conn, _params) do
    conn
    |> put_status(:unprocessable_entity)
    |> render_account(Accounts.profile_changeset(conn.assigns.current_user))
  end

  defp render_account(conn, changeset, user \\ nil) do
    user = user || conn.assigns.current_user

    render(conn, :show,
      page_title: "Your account",
      theme: RobineIdWeb.Portal.theme(),
      current_user: user,
      form: Phoenix.Component.to_form(changeset, as: :account)
    )
  end

  defp audit(conn, event, attributes) do
    attributes =
      Map.put(attributes, :correlation_id, List.first(get_resp_header(conn, "x-request-id")))

    RobineId.Operations.audit(event, attributes, RobineId.Runtime.adapter(:audit_sink))
  end
end
