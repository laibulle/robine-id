defmodule RobineId.Configuration.MemoryStoreTest do
  use ExUnit.Case, async: false

  alias RobineId.Configuration.Adapters.MemoryStore
  alias RobineId.Configuration.Entities.Snapshot

  test "records non-secret outcomes for every apply attempt" do
    {:ok, original} = MemoryStore.get()
    on_exit(fn -> MemoryStore.activate(original) end)

    unique = System.unique_integer([:positive])

    data = %{
      "schema_version" => 1,
      "issuers" => [%{"id" => "audit-#{unique}", "url" => "https://audit.example.test"}],
      "clients" => [
        %{"id" => "client-#{unique}", "redirect_uris" => ["https://app.example.test/callback"]}
      ]
    }

    assert {:ok, snapshot} = Snapshot.new(data)
    assert {:ok, :activated} = RobineId.Configuration.reconcile(snapshot, MemoryStore)
    assert {:ok, :unchanged} = RobineId.Configuration.reconcile(snapshot, MemoryStore)

    [latest, previous | _] = RobineId.Configuration.history(MemoryStore)
    assert latest.outcome == :unchanged
    assert previous.outcome == :activated
    assert latest.revision == snapshot.fingerprint
    refute Map.has_key?(latest, :data)
  end

  test "concurrent applications converge with exactly one activation" do
    {:ok, original} = MemoryStore.get()
    on_exit(fn -> MemoryStore.activate(original) end)
    unique = System.unique_integer([:positive])

    data = %{
      "schema_version" => 1,
      "issuers" => [%{"id" => "concurrent-#{unique}", "url" => "https://id.example.test"}],
      "clients" => [
        %{"id" => "client-#{unique}", "redirect_uris" => ["https://app.example.test/callback"]}
      ]
    }

    {:ok, snapshot} = Snapshot.new(data)

    outcomes =
      1..8
      |> Task.async_stream(fn _ -> MemoryStore.activate(snapshot) end, max_concurrency: 8)
      |> Enum.map(fn {:ok, {:ok, outcome}} -> outcome end)

    assert Enum.count(outcomes, &(&1 == :activated)) == 1
    assert Enum.count(outcomes, &(&1 == :unchanged)) == 7
    assert {:ok, active} = MemoryStore.get()
    assert active.fingerprint == snapshot.fingerprint
  end

  test "records failed attempts without changing active state" do
    {:ok, active_before} = MemoryStore.get()

    assert :ok =
             RobineId.Configuration.record_failure(["config.json: invalid field"], MemoryStore)

    assert {:ok, active_after} = MemoryStore.get()
    assert active_after.fingerprint == active_before.fingerprint

    [attempt | _] = RobineId.Configuration.history(MemoryStore)
    assert attempt.outcome == :failed
    assert attempt.revision == nil
    assert attempt.diagnostics == ["config.json: invalid field"]
  end
end
