defmodule RobineId.Protocol.DiscoverProviderTest do
  use ExUnit.Case, async: true

  alias RobineId.Configuration.Entities.Snapshot
  alias RobineId.Test.Configuration.MemoryStore

  setup do
    data = %{
      "schema_version" => 1,
      "issuers" => [%{"id" => "main", "url" => "https://id.example.test/tenant"}],
      "clients" => [%{"id" => "web", "redirect_uris" => ["https://app.example.test/callback"]}]
    }

    {:ok, snapshot} = Snapshot.new(data)
    {:ok, :activated} = MemoryStore.activate(snapshot)
    :ok
  end

  test "advertises endpoints rooted at the exact issuer" do
    assert {:ok, metadata} = RobineId.Protocol.discovery("main", MemoryStore)
    assert metadata["issuer"] == "https://id.example.test/tenant"
    assert metadata["authorization_endpoint"] == "https://id.example.test/tenant/authorize"
    assert metadata["code_challenge_methods_supported"] == ["S256"]
  end

  test "does not disclose configured issuers when the identifier is unknown" do
    assert {:error, :unknown_issuer} = RobineId.Protocol.discovery("missing", MemoryStore)
  end
end
