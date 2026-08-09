defmodule RobineId.Clients.Adapters.EnvironmentSecretResolver do
  @moduledoc "Resolves typed environment secrets with an optional configured fallback."
  @behaviour RobineId.Clients.Ports.SecretResolver

  @impl true
  def resolve(secret) when is_binary(secret) and secret != "", do: {:ok, secret}

  def resolve(%{"provider" => "env", "key" => key}) do
    case System.fetch_env(key) do
      {:ok, value} when value != "" -> {:ok, value}
      _ -> configured_secret(key)
    end
  end

  def resolve(_), do: {:error, :unsupported_secret_reference}

  defp configured_secret(key) do
    case Application.get_env(:robine_id, :configured_secrets, %{}) do
      %{^key => value} when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, :secret_unavailable}
    end
  end
end
