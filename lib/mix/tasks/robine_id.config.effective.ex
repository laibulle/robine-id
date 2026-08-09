defmodule Mix.Tasks.RobineId.Config.Effective do
  use Mix.Task

  @shortdoc "Prints the effective non-secret Robine ID configuration"

  @sensitive ~w(password password_hash secret secret_reference private_key token)

  @impl Mix.Task
  def run(_args) do
    Mix.Task.run("app.start")

    case RobineId.Configuration.active(RobineId.Configuration.Adapters.MemoryStore) do
      {:ok, snapshot} -> Mix.shell().info(Jason.encode!(redact(snapshot.data), pretty: true))
      {:error, reason} -> Mix.raise("configuration unavailable: #{inspect(reason)}")
    end
  end

  defp redact(map) when is_map(map) do
    Map.new(map, fn {key, value} ->
      if sensitive?(key), do: {key, "[REDACTED]"}, else: {key, redact(value)}
    end)
  end

  defp redact(list) when is_list(list), do: Enum.map(list, &redact/1)
  defp redact(value), do: value

  defp sensitive?(key) do
    normalized = key |> to_string() |> String.downcase()
    Enum.any?(@sensitive, &String.contains?(normalized, &1))
  end
end
