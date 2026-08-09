defmodule Mix.Tasks.RobineId.Config.Apply do
  use Mix.Task

  @shortdoc "Validates, previews, and atomically applies a configuration file"

  @impl Mix.Task
  def run(args) do
    Mix.Task.run("app.start")
    path = List.first(args) || Application.get_env(:robine_id, :configuration_path)
    store = RobineId.Configuration.Adapters.MemoryStore

    case RobineId.Configuration.load(
           path,
           RobineId.Configuration.Adapters.ApplicationDirectoryLoader
         ) do
      {:ok, snapshot} ->
        {:ok, plan} = RobineId.Configuration.preview(snapshot, store)
        {:ok, outcome} = RobineId.Configuration.reconcile(snapshot, store)
        changed = Enum.count(plan.operations, &(&1.action != :unchanged))
        Mix.shell().info("#{outcome} revision #{snapshot.fingerprint} (#{changed} changes)")

      {:error, diagnostics} ->
        :ok = RobineId.Configuration.record_failure(diagnostics, store)
        Mix.raise("configuration apply failed:\n#{Enum.join(diagnostics, "\n")}")
    end
  end
end
