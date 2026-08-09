defmodule RobineId.Protocol.Adapters.EncryptedKeyFile do
  @moduledoc "Atomic AES-256-GCM persistence for private signing-key state."

  @aad "robine-id-signing-keys-v1"
  @magic "RIDK1"

  def load(nil, _secret), do: {:ok, %{}}

  def load(path, secret) do
    case File.read(path) do
      {:ok, <<"RIDK1", iv::binary-size(12), tag::binary-size(16), ciphertext::binary>>} ->
        decrypt(ciphertext, tag, iv, secret)

      {:error, :enoent} ->
        {:ok, %{}}

      _ ->
        {:error, :invalid_key_store}
    end
  end

  def save(nil, _secret, _state), do: :ok

  def save(path, secret, state) do
    iv = :crypto.strong_rand_bytes(12)
    plaintext = :erlang.term_to_binary(state, compressed: 6)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(
        :aes_256_gcm,
        encryption_key(secret),
        iv,
        plaintext,
        @aad,
        true
      )

    temporary = path <> ".tmp"

    with :ok <- File.mkdir_p(Path.dirname(path)),
         :ok <- File.write(temporary, [@magic, iv, tag, ciphertext], [:binary]),
         :ok <- File.chmod(temporary, 0o600),
         :ok <- File.rename(temporary, path) do
      :ok
    else
      _ -> {:error, :key_store_write_failed}
    end
  end

  defp decrypt(ciphertext, tag, iv, secret) do
    case :crypto.crypto_one_time_aead(
           :aes_256_gcm,
           encryption_key(secret),
           iv,
           ciphertext,
           @aad,
           tag,
           false
         ) do
      :error -> {:error, :invalid_key_store}
      plaintext -> decode(plaintext)
    end
  end

  defp decode(plaintext) do
    # The term is decoded only after AES-GCM authentication succeeds. It is therefore
    # trusted local state, and JOSE's internal atoms may not be loaded yet in a fresh VM.
    case :erlang.binary_to_term(plaintext) do
      state when is_map(state) -> {:ok, state}
      _ -> {:error, :invalid_key_store}
    end
  rescue
    _ -> {:error, :invalid_key_store}
  end

  defp encryption_key(secret), do: :crypto.hash(:sha256, secret)
end
