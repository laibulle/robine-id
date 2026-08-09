defmodule RobineId.Protocol.Ports.KeyStore do
  @moduledoc "Port for issuer signing-key access and rotation."

  @callback signing_key(String.t()) ::
              {:ok, %{kid: String.t(), jwk: JOSE.JWK.t()}} | {:error, term()}
  @callback public_keys(String.t()) :: {:ok, [map()]} | {:error, term()}
  @callback rotate(String.t(), String.t()) :: {:ok, :rotated | :unchanged, String.t()}
end
