defmodule RobineId.Configuration.Adapters.JsonFileLoader do
  @moduledoc "JSON implementation of the configuration loader port."
  @behaviour RobineId.Configuration.Ports.Loader

  @impl true
  def read(path) do
    with {:ok, bytes} <- File.read(path),
         {:ok, document} <- Jason.decode(bytes) do
      {:ok, document}
    else
      {:error, %Jason.DecodeError{} = error} ->
        {:error, {:invalid_json, Exception.message(error)}}

      {:error, reason} ->
        {:error, {:file_error, reason}}
    end
  end
end
