defmodule RobineId.Protocol.Adapters.MemoryKeyStore do
  @moduledoc "Encrypted persistent RSA signing-key store; memory-only when no path is configured."
  use GenServer
  @behaviour RobineId.Protocol.Ports.KeyStore

  alias RobineId.Protocol.Adapters.EncryptedKeyFile

  def start_link(options) do
    GenServer.start_link(__MODULE__, options, name: Keyword.get(options, :name, __MODULE__))
  end

  @impl RobineId.Protocol.Ports.KeyStore
  def signing_key(issuer_id), do: signing_key(issuer_id, __MODULE__)
  def signing_key(issuer_id, server), do: GenServer.call(server, {:signing_key, issuer_id})

  @impl RobineId.Protocol.Ports.KeyStore
  def public_keys(issuer_id), do: public_keys(issuer_id, __MODULE__)
  def public_keys(issuer_id, server), do: GenServer.call(server, {:public_keys, issuer_id})

  @impl RobineId.Protocol.Ports.KeyStore
  def rotate(issuer_id, rotation_id), do: rotate(issuer_id, rotation_id, __MODULE__)

  def rotate(issuer_id, rotation_id, server),
    do: GenServer.call(server, {:rotate, issuer_id, rotation_id}, 30_000)

  @impl GenServer
  def init(options) do
    path = Keyword.get(options, :path, Application.get_env(:robine_id, :key_store_path))
    secret = Keyword.get(options, :secret, key_store_secret())

    case EncryptedKeyFile.load(path, secret) do
      {:ok, keys} -> {:ok, %{keys: keys, path: path, secret: secret}}
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl GenServer
  def handle_call({:signing_key, issuer_id}, _from, state) do
    {key, keys, changed?} = ensure_key(state.keys, issuer_id)
    state = persist_if_changed(%{state | keys: keys}, changed?)
    {:reply, {:ok, Map.take(key, [:kid, :jwk])}, state}
  end

  def handle_call({:public_keys, issuer_id}, _from, state) do
    {key, stored_keys, changed?} = ensure_key(state.keys, issuer_id)
    state = persist_if_changed(%{state | keys: stored_keys}, changed?)
    public_keys = [key | key.previous] |> Enum.map(&public_jwk/1)
    {:reply, {:ok, public_keys}, state}
  end

  def handle_call({:rotate, issuer_id, rotation_id}, _from, state) do
    {current, keys, created?} = ensure_key(state.keys, issuer_id)

    if current.rotation_id == rotation_id do
      state = persist_if_changed(%{state | keys: keys}, created?)
      {:reply, {:ok, :unchanged, current.kid}, state}
    else
      key =
        new_key([Map.drop(current, [:previous]) | current.previous])
        |> Map.put(:rotation_id, rotation_id)

      state = %{state | keys: Map.put(keys, issuer_id, key)} |> persist_if_changed(true)
      {:reply, {:ok, :rotated, key.kid}, state}
    end
  end

  defp ensure_key(keys, issuer_id) do
    case keys do
      %{^issuer_id => key} ->
        {key, keys, false}

      _ ->
        key = new_key([])
        {key, Map.put(keys, issuer_id, key), true}
    end
  end

  defp persist_if_changed(state, false), do: state

  defp persist_if_changed(state, true) do
    case EncryptedKeyFile.save(state.path, state.secret, state.keys) do
      :ok -> state
      {:error, reason} -> raise "signing key persistence failed: #{inspect(reason)}"
    end
  end

  defp key_store_secret do
    endpoint = Application.fetch_env!(:robine_id, RobineIdWeb.Endpoint)
    endpoint[:secret_key_base] || raise "secret_key_base is required for signing key persistence"
  end

  defp new_key(previous) do
    kid = :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)
    %{kid: kid, jwk: JOSE.JWK.generate_key({:rsa, 2048}), previous: previous, rotation_id: nil}
  end

  defp public_jwk(%{kid: kid, jwk: jwk}) do
    {_fields, map} = jwk |> JOSE.JWK.to_public() |> JOSE.JWK.to_map()
    Map.merge(map, %{"kid" => kid, "use" => "sig", "alg" => "RS256"})
  end
end
