defmodule RobineId.ConfigurationTest do
  use ExUnit.Case, async: true

  alias RobineId.Configuration.Entities.Snapshot
  alias RobineId.Test.Configuration.{MemoryLoader, MemoryStore}

  @valid %{
    "schema_version" => 1,
    "issuers" => [%{"id" => "main", "url" => "https://id.example.test"}],
    "clients" => [%{"id" => "web", "redirect_uris" => ["https://app.example.test/callback"]}]
  }

  test "loads and validates a configuration through its port" do
    MemoryLoader.put({:ok, @valid})
    assert {:ok, %Snapshot{}} = RobineId.Configuration.load("ignored", MemoryLoader)
  end

  test "rejects duplicate clients and unsafe redirect values" do
    data = %{
      @valid
      | "clients" => [
          %{"id" => "same", "redirect_uris" => ["javascript:alert(1)"]},
          %{"id" => "same", "redirect_uris" => ["https://safe.example.test/callback"]}
        ]
    }

    assert {:error, errors} = Snapshot.new(data)
    assert "client identifiers must be unique" in errors
    assert Enum.any?(errors, &String.contains?(&1, "invalid redirect URI"))
  end

  test "equivalent ordering has the same fingerprint" do
    reordered = %{
      @valid
      | "issuers" => Enum.reverse(@valid["issuers"]),
        "clients" => Enum.reverse(@valid["clients"])
    }

    assert {:ok, first} = Snapshot.new(@valid)
    assert {:ok, second} = Snapshot.new(reordered)
    assert first.fingerprint == second.fingerprint
  end

  test "reconciliation is idempotent" do
    assert {:ok, snapshot} = Snapshot.new(@valid)
    assert {:ok, :activated} = RobineId.Configuration.reconcile(snapshot, MemoryStore)
    assert {:ok, :unchanged} = RobineId.Configuration.reconcile(snapshot, MemoryStore)
    assert {:ok, ^snapshot} = RobineId.Configuration.active(MemoryStore)
  end

  test "rejects unknown fields with their location" do
    data = Map.put(@valid, "surprise", true)
    assert {:error, errors} = Snapshot.new(data)
    assert "root contains unknown field \"surprise\"" in errors

    [client] = @valid["clients"]
    data = %{@valid | "clients" => [Map.put(client, "unknown_policy", true)]}
    assert {:error, errors} = Snapshot.new(data)
    assert Enum.any?(errors, &String.contains?(&1, "unknown_policy"))
  end

  test "rejects mappings for protocol-reserved claims" do
    data = Map.put(@valid, "claims", %{"iss" => %{"source" => "email", "scope" => "email"}})
    assert {:error, errors} = Snapshot.new(data)
    assert Enum.any?(errors, &String.contains?(&1, "reserved by OpenID Connect"))
  end

  test "validates declarative user roles" do
    user = %{
      "id" => "admin",
      "identifier" => "admin@example.test",
      "password_hash" => Bcrypt.hash_pwd_salt("password", log_rounds: 10),
      "roles" => ["admin", "support:read"]
    }

    assert {:ok, _snapshot} = Snapshot.new(Map.put(@valid, "users", [user]))

    invalid_user = %{user | "roles" => ["Admin", "Admin"]}
    assert {:error, errors} = Snapshot.new(Map.put(@valid, "users", [invalid_user]))
    assert Enum.any?(errors, &String.contains?(&1, "roles must be unique role identifiers"))
  end

  test "preview classifies stable resource operations without mutating state" do
    assert {:ok, current} = Snapshot.new(@valid)
    assert {:ok, :activated} = MemoryStore.activate(current)

    desired_data = %{
      @valid
      | "clients" => [
          %{
            "id" => "mobile",
            "redirect_uris" => ["https://mobile.example.test/callback"]
          }
        ]
    }

    assert {:ok, desired} = Snapshot.new(desired_data)
    assert {:ok, plan} = RobineId.Configuration.preview(desired, MemoryStore)

    assert %{resource_type: "clients", id: "mobile", action: :create} in plan.operations
    assert %{resource_type: "clients", id: "web", action: :disable} in plan.operations
    assert %{resource_type: "issuers", id: "main", action: :unchanged} in plan.operations
    assert {:ok, ^current} = MemoryStore.get()
  end
end
