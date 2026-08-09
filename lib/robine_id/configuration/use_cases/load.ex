defmodule RobineId.Configuration.UseCases.Load do
  @moduledoc "Loads and validates one configuration document."
  alias RobineId.Configuration.Entities.Snapshot

  def execute(path, loader) do
    case loader.read(path) do
      {:ok, data} ->
        case Snapshot.new(data) do
          {:ok, snapshot} -> {:ok, snapshot}
          {:error, errors} -> {:error, Enum.map(errors, &"#{path}: #{&1}")}
        end

      {:error, reason} ->
        {:error, ["#{path}: #{format_reason(reason)}"]}
    end
  end

  defp format_reason({:invalid_json, message}), do: "invalid JSON: #{message}"
  defp format_reason({:file_error, reason}), do: "file error: #{:file.format_error(reason)}"
  defp format_reason({:invalid_root, message}), do: message

  defp format_reason({:application_error, path, reason}),
    do: "application #{path}: #{format_reason(reason)}"

  defp format_reason({:invalid_application, message}), do: message

  defp format_reason({:applications_directory_error, directory, reason}),
    do: "applications directory #{directory}: #{:file.format_error(reason)}"

  defp format_reason(_reason), do: "configuration could not be loaded"
end
