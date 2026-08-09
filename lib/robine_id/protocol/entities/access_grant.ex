defmodule RobineId.Protocol.Entities.AccessGrant do
  @moduledoc "Claims bound to an opaque bearer access token."

  @enforce_keys [:issuer, :subject, :client_id, :scope, :expires_at]
  defstruct @enforce_keys ++ [claims: %{}]

  @type t :: %__MODULE__{}
end
