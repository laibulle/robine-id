defmodule Mix.Tasks.RobineId.Config.Preview do
  use Mix.Task

  @shortdoc "Previews an idempotent configuration reconciliation"

  @impl Mix.Task
  def run(args) do
    Mix.Task.run("app.start")
    path = List.first(args) || Application.get_env(:robine_id, :configuration_path)

    with {:ok, snapshot} <-
           RobineId.Configuration.load(
             path,
             RobineId.Configuration.Adapters.ApplicationDirectoryLoader
           ),
         {:ok, plan} <-
           RobineId.Configuration.preview(
             snapshot,
             RobineId.Configuration.Adapters.MemoryStore
           ) do
      plan.operations
      |> Enum.each(fn operation ->
        Mix.shell().info("#{operation.action}\t#{operation.resource_type}\t#{operation.id}")
      end)
    else
      {:error, reason} -> Mix.raise("cannot preview configuration: #{inspect(reason)}")
    end
  end
end
