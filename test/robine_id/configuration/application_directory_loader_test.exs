defmodule RobineId.Configuration.ApplicationDirectoryLoaderTest do
  use ExUnit.Case, async: false

  alias RobineId.Configuration.Adapters.{ApplicationDirectoryLoader, MemoryStore}

  setup do
    directory =
      Path.join(
        System.tmp_dir!(),
        "robine-id-applications-#{System.unique_integer([:positive])}"
      )

    applications_directory = Path.join(directory, "applications")
    File.mkdir_p!(applications_directory)

    root_path = Path.join(directory, "robine_id.json")

    File.write!(
      root_path,
      Jason.encode!(%{
        "schema_version" => 1,
        "issuers" => [%{"id" => "main", "url" => "https://id.example.test"}]
      })
    )

    on_exit(fn -> File.rm_rf!(directory) end)

    %{root_path: root_path, applications_directory: applications_directory}
  end

  test "composes one validated root document from application files", context do
    write_application(context.applications_directory, "second.json", "second")
    write_application(context.applications_directory, "first.json", "first")

    assert {:ok, document} =
             ApplicationDirectoryLoader.read(
               context.root_path,
               context.applications_directory
             )

    assert Enum.map(document["clients"], & &1["id"]) == ["first", "second"]
    refute Enum.any?(document["clients"], &Map.has_key?(&1, "kind"))
  end

  test "reports the application filename when a document is invalid", context do
    invalid_path = Path.join(context.applications_directory, "broken.json")
    File.write!(invalid_path, Jason.encode!(%{"id" => "broken"}))

    assert {:error, {:application_error, ^invalid_path, {:invalid_application, _message}}} =
             ApplicationDirectoryLoader.read(
               context.root_path,
               context.applications_directory
             )
  end

  test "reloads atomically and retains the last valid revision", context do
    application_path = write_application(context.applications_directory, "app.json", "first")
    previous_path = Application.get_env(:robine_id, :applications_path)
    Application.put_env(:robine_id, :applications_path, context.applications_directory)

    on_exit(fn ->
      if previous_path,
        do: Application.put_env(:robine_id, :applications_path, previous_path),
        else: Application.delete_env(:robine_id, :applications_path)
    end)

    name = Module.concat(__MODULE__, "Store#{System.unique_integer([:positive])}")

    pid =
      start_supervised!(
        {MemoryStore, name: name, path: context.root_path, reload_interval: :disabled}
      )

    assert {:ok, initial} = GenServer.call(pid, :get)
    assert Enum.map(initial.data["clients"], & &1["id"]) == ["first"]

    write_application(context.applications_directory, "app.json", "second")
    send(pid, :reload_configuration)
    _ = :sys.get_state(pid)

    assert {:ok, reloaded} = GenServer.call(pid, :get)
    assert reloaded.fingerprint != initial.fingerprint
    assert Enum.map(reloaded.data["clients"], & &1["id"]) == ["second"]

    File.write!(application_path, "{invalid")
    send(pid, :reload_configuration)
    _ = :sys.get_state(pid)

    assert {:ok, retained} = GenServer.call(pid, :get)
    assert retained.fingerprint == reloaded.fingerprint
    assert [%{outcome: :failed} | _] = GenServer.call(pid, :history)
  end

  test "uses ROBINE_ID_APPLICATIONS_DIR when it is set", context do
    previous_path = System.get_env("ROBINE_ID_APPLICATIONS_DIR")
    System.put_env("ROBINE_ID_APPLICATIONS_DIR", context.applications_directory)

    on_exit(fn ->
      if previous_path,
        do: System.put_env("ROBINE_ID_APPLICATIONS_DIR", previous_path),
        else: System.delete_env("ROBINE_ID_APPLICATIONS_DIR")
    end)

    assert ApplicationDirectoryLoader.applications_directory(context.root_path) ==
             context.applications_directory
  end

  defp write_application(directory, filename, id) do
    path = Path.join(directory, filename)

    File.write!(
      path,
      Jason.encode!(%{
        "schema_version" => 1,
        "kind" => "oidc_application",
        "id" => id,
        "redirect_uris" => ["https://#{id}.example.test/callback"]
      })
    )

    path
  end
end
