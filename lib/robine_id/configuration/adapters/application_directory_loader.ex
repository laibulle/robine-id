defmodule RobineId.Configuration.Adapters.ApplicationDirectoryLoader do
  @moduledoc "Loads the root configuration and composes one JSON document per application."
  @behaviour RobineId.Configuration.Ports.Loader

  alias RobineId.Configuration.Adapters.JsonFileLoader
  alias RobineId.Configuration.Entities.Snapshot

  @impl true
  def read(path), do: read(path, applications_directory(path))

  def read(path, directory) do
    with {:ok, root} <- JsonFileLoader.read(path),
         :ok <- validate_root(root),
         {:ok, applications} <- read_applications(directory) do
      {:ok, Map.put(root, "clients", (root["clients"] || []) ++ applications)}
    end
  end

  def applications_directory(path) do
    case System.get_env("ROBINE_ID_APPLICATIONS_DIR") do
      directory when is_binary(directory) ->
        Path.expand(directory)

      _ ->
        Application.get_env(:robine_id, :applications_path) ||
          Path.join(Path.dirname(Path.expand(path)), "applications")
    end
  end

  defp validate_root(root) when is_map(root) do
    case root["clients"] do
      nil -> :ok
      clients when is_list(clients) -> :ok
      _ -> {:error, {:invalid_root, "clients must be a list when present"}}
    end
  end

  defp validate_root(_root), do: {:error, {:invalid_root, "configuration root must be an object"}}

  defp read_applications(directory) do
    case File.ls(directory) do
      {:ok, entries} ->
        entries
        |> Enum.filter(&String.ends_with?(&1, ".json"))
        |> Enum.sort()
        |> Enum.reduce_while({:ok, []}, fn entry, {:ok, applications} ->
          path = Path.join(directory, entry)

          case read_application(path) do
            {:ok, application} -> {:cont, {:ok, [application | applications]}}
            {:error, reason} -> {:halt, {:error, {:application_error, path, reason}}}
          end
        end)
        |> then(fn
          {:ok, applications} -> {:ok, Enum.reverse(applications)}
          error -> error
        end)

      {:error, reason} ->
        {:error, {:applications_directory_error, directory, reason}}
    end
  end

  defp read_application(path) do
    with {:ok, document} <- JsonFileLoader.read(path),
         :ok <- validate_application_document(document),
         application = Map.drop(document, ["schema_version", "kind"]),
         :ok <- validate_application(application) do
      {:ok, application}
    end
  end

  defp validate_application(application) do
    data = %{
      "schema_version" => 1,
      "issuers" => [%{"id" => "validation", "url" => "https://id.example.test"}],
      "clients" => [application]
    }

    case Snapshot.new(data) do
      {:ok, _snapshot} -> :ok
      {:error, errors} -> {:error, {:invalid_application, Enum.join(errors, "; ")}}
    end
  end

  defp validate_application_document(%{
         "schema_version" => 1,
         "kind" => "oidc_application",
         "id" => id
       })
       when is_binary(id) and id != "",
       do: :ok

  defp validate_application_document(_document) do
    {:error,
     {:invalid_application,
      "requires schema_version 1, kind oidc_application, and a non-empty id"}}
  end
end
