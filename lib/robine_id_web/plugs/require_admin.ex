defmodule RobineIdWeb.Plugs.RequireAdmin do
  @moduledoc "Restricts a browser route to enabled members of the admin role."

  import Plug.Conn

  def init(options), do: options

  def call(%{assigns: %{current_user: user}} = conn, _options) do
    if RobineId.Identity.Accounts.admin?(user) do
      conn
    else
      conn
      |> send_resp(:forbidden, "Forbidden")
      |> halt()
    end
  end
end
