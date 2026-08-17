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

  test "accepts and bounds Rust PAR token policy compatibility fields" do
    [issuer] = @valid["issuers"]

    policy = %{
      "browser_authorization_lifetime" => 600,
      "pushed_authorization_request_lifetime" => 90,
      "pushed_authorization_request_limit" => 120,
      "pushed_authorization_request_window" => 60,
      "device_code_lifetime" => 600,
      "device_poll_interval" => 5,
      "require_pushed_authorization_requests" => true
    }

    assert {:ok, %Snapshot{}} =
             Snapshot.new(%{@valid | "issuers" => [Map.put(issuer, "token_policy", policy)]})

    invalid = Map.put(policy, "pushed_authorization_request_lifetime", 9)

    assert {:error, errors} =
             Snapshot.new(%{@valid | "issuers" => [Map.put(issuer, "token_policy", invalid)]})

    assert Enum.any?(errors, &String.contains?(&1, "must be between 10 and 600"))

    invalid = Map.put(policy, "browser_authorization_lifetime", 59)

    assert {:error, errors} =
             Snapshot.new(%{@valid | "issuers" => [Map.put(issuer, "token_policy", invalid)]})

    assert Enum.any?(errors, &String.contains?(&1, "must be between 60 and 3600"))

    invalid = Map.put(policy, "require_pushed_authorization_requests", "yes")

    assert {:error, errors} =
             Snapshot.new(%{@valid | "issuers" => [Map.put(issuer, "token_policy", invalid)]})

    assert Enum.any?(errors, &String.contains?(&1, "must be a boolean"))

    invalid = Map.put(policy, "device_code_lifetime", 299)

    assert {:error, errors} =
             Snapshot.new(%{@valid | "issuers" => [Map.put(issuer, "token_policy", invalid)]})

    assert Enum.any?(errors, &String.contains?(&1, "must be between 300 and 1800"))

    invalid = Map.put(policy, "device_poll_interval", 4)

    assert {:error, errors} =
             Snapshot.new(%{@valid | "issuers" => [Map.put(issuer, "token_policy", invalid)]})

    assert Enum.any?(errors, &String.contains?(&1, "must be between 5 and 60"))
  end

  test "accepts redirectless device clients but not redirectless browser clients" do
    grant = "urn:ietf:params:oauth:grant-type:device_code"

    device = %{
      "id" => "television",
      "type" => "public",
      "redirect_uris" => [],
      "scopes" => ["openid"],
      "grant_types" => [grant]
    }

    assert {:ok, %Snapshot{}} = Snapshot.new(%{@valid | "clients" => [device]})

    browser = %{device | "grant_types" => ["authorization_code"]}
    assert {:error, errors} = Snapshot.new(%{@valid | "clients" => [browser]})
    assert Enum.any?(errors, &String.contains?(&1, "requires a redirect URI"))
  end

  test "accepts and validates per-client mandatory PAR compatibility" do
    [client] = @valid["clients"]

    assert {:ok, %Snapshot{}} =
             Snapshot.new(%{
               @valid
               | "clients" => [Map.put(client, "require_pushed_authorization_requests", true)]
             })

    invalid =
      client
      |> Map.put("grant_types", ["refresh_token"])
      |> Map.put("require_pushed_authorization_requests", true)

    assert {:error, errors} = Snapshot.new(%{@valid | "clients" => [invalid]})
    assert Enum.any?(errors, &String.contains?(&1, "requires the authorization_code grant"))
  end

  test "rejects mappings for protocol-reserved claims" do
    for claim <- ~w(iss auth_time at_hash azp) do
      data = Map.put(@valid, "claims", %{claim => %{"source" => "email", "scope" => "email"}})
      assert {:error, errors} = Snapshot.new(data)
      assert Enum.any?(errors, &String.contains?(&1, "reserved by OpenID Connect"))
    end
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
