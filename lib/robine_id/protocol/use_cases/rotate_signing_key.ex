defmodule RobineId.Protocol.UseCases.RotateSigningKey do
  @moduledoc "Rotates an issuer signing key through the configured key-store port."
  def execute(issuer_id, rotation_id, key_store)
      when is_binary(rotation_id) and rotation_id != "",
      do: key_store.rotate(issuer_id, rotation_id)
end
