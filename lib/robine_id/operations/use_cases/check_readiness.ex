defmodule RobineId.Operations.UseCases.CheckReadiness do
  @moduledoc "Checks active configuration and required dependencies."

  def execute(configuration_store, dependencies) do
    with {:ok, snapshot} <- RobineId.Configuration.active(configuration_store),
         :ok <- check_dependencies(dependencies) do
      {:ok, %{revision: snapshot.fingerprint}}
    end
  end

  defp check_dependencies(dependencies) do
    Enum.reduce_while(dependencies, :ok, fn dependency, :ok ->
      case dependency.check() do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, {:dependency_unavailable, reason}}}
      end
    end)
  end
end
