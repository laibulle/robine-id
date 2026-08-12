defmodule RobineIdWeb.Plugs.SessionPolicy do
  @moduledoc "Phoenix inbound adapter for configured session constraints."
  import Plug.Conn

  def init(options), do: options

  def call(conn, _options) do
    policy = session_policy()

    case RobineId.Security.validate_session(
           get_session(conn),
           policy,
           RobineId.Runtime.adapter(:session_registry),
           System.system_time(:second)
         ) do
      {:ok, updates} ->
        Enum.reduce(updates, conn, fn {key, value}, acc -> put_session(acc, key, value) end)

      {:error, _reason} ->
        conn
        |> clear_session()
        |> configure_session(renew: true)
        |> put_session(:session_started_at, System.system_time(:second))
        |> put_session(:session_last_seen_at, System.system_time(:second))
    end
  end

  defp session_policy do
    with {:ok, snapshot} <-
           RobineId.Configuration.active(RobineId.Runtime.adapter(:configuration_store)) do
      get_in(snapshot.data, ["authentication", "session"]) || defaults()
    else
      _ -> defaults()
    end
  end

  defp defaults do
    %{"idle_timeout" => 1_800, "absolute_timeout" => 28_800, "max_concurrent" => 5}
  end
end
