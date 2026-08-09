defmodule RobineId.Protocol.TokenAndKeyManagementTest do
  use ExUnit.Case, async: false

  alias RobineId.Protocol.Adapters.MemoryKeyStore

  test "issues RS256 tokens that are verifiable through JWKS" do
    issuer = "https://issuer-#{System.unique_integer([:positive])}.example.test"
    claims = %{"iss" => issuer, "sub" => "user-123", "aud" => "client-123", "nonce" => "n"}

    assert {:ok, token} =
             RobineId.Protocol.issue_id_token(claims, MemoryKeyStore, now: 100, lifetime: 60)

    assert {:ok, %{"keys" => [public_key]}} = RobineId.Protocol.jwks(issuer, MemoryKeyStore)

    jwk = JOSE.JWK.from_map(public_key)
    assert {true, jwt, jws} = JOSE.JWT.verify_strict(jwk, ["RS256"], token)
    assert jwt.fields["iss"] == issuer
    assert jwt.fields["iat"] == 100
    assert jwt.fields["exp"] == 160
    assert jws.fields["kid"] == public_key["kid"]
  end

  test "rotation publishes both the active and previous public key" do
    issuer = "https://rotation-#{System.unique_integer([:positive])}.example.test"
    claims = %{"iss" => issuer, "sub" => "subject", "aud" => "client"}

    assert {:ok, old_token} = RobineId.Protocol.issue_id_token(claims, MemoryKeyStore, [])
    assert {:ok, %{"keys" => [old_public]}} = RobineId.Protocol.jwks(issuer, MemoryKeyStore)

    assert {:ok, :rotated, new_kid} =
             RobineId.Protocol.rotate_signing_key(issuer, "rotation-2026-01", MemoryKeyStore)

    assert {:ok, :unchanged, ^new_kid} =
             RobineId.Protocol.rotate_signing_key(issuer, "rotation-2026-01", MemoryKeyStore)

    assert {:ok, %{"keys" => [new_public, retained_public]}} =
             RobineId.Protocol.jwks(issuer, MemoryKeyStore)

    assert new_public["kid"] == new_kid
    assert retained_public["kid"] == old_public["kid"]

    assert {true, _, _} =
             JOSE.JWT.verify_strict(JOSE.JWK.from_map(retained_public), ["RS256"], old_token)
  end

  test "requires standard identity claims" do
    assert {:error, {:invalid_claims, "aud is required"}} =
             RobineId.Protocol.issue_id_token(
               %{"iss" => "https://id.example.test", "sub" => "subject"},
               MemoryKeyStore,
               []
             )
  end

  test "encrypted key state survives a key-store restart" do
    directory =
      Path.join(System.tmp_dir!(), "robine-id-key-test-#{System.unique_integer([:positive])}")

    path = Path.join(directory, "keys.bin")
    File.mkdir!(directory)

    on_exit(fn ->
      File.rm(path)
      File.rm(path <> ".tmp")
      File.rmdir(directory)
    end)

    options = [name: :robine_id_persistence_test_store, path: path, secret: "test-secret"]
    assert {:ok, first_store} = MemoryKeyStore.start_link(options)
    assert {:ok, %{kid: kid}} = MemoryKeyStore.signing_key("persistent-issuer", first_store)
    assert {:ok, [public_before]} = MemoryKeyStore.public_keys("persistent-issuer", first_store)
    GenServer.stop(first_store)

    assert {:ok, second_store} = MemoryKeyStore.start_link(options)
    assert {:ok, %{kid: ^kid}} = MemoryKeyStore.signing_key("persistent-issuer", second_store)
    assert {:ok, [public_after]} = MemoryKeyStore.public_keys("persistent-issuer", second_store)
    assert public_after == public_before
    GenServer.stop(second_store)

    assert {:ok, stat} = File.stat(path)
    assert Bitwise.band(stat.mode, 0o777) == 0o600

    assert {:error, :invalid_key_store} =
             RobineId.Protocol.Adapters.EncryptedKeyFile.load(path, "wrong-secret")
  end
end
