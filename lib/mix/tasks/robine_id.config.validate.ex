defmodule Mix.Tasks.RobineId.Config.Validate do
  use Mix.Task

  @shortdoc "Validates a Robine ID configuration file"

  @impl Mix.Task
  def run(args) do
    path = List.first(args) || Application.get_env(:robine_id, :configuration_path)

    case RobineId.Configuration.load(
           path,
           RobineId.Configuration.Adapters.ApplicationDirectoryLoader
         ) do
      {:ok, snapshot} ->
        Mix.shell().info("valid revision #{snapshot.fingerprint}")

      {:error, errors} ->
        Mix.raise("invalid configuration:\n#{format_errors(errors)}")
    end
  end

  defp format_errors(errors) when is_list(errors), do: Enum.map_join(errors, "\n", &"- #{&1}")
  defp format_errors(error), do: inspect(error)
end
