defmodule RobineId.Protocol.Entities.AuthorizationGrant do
  @moduledoc "The data cryptographically bound to a short-lived authorization code."

  @enforce_keys [
    :issuer,
    :subject,
    :client_id,
    :redirect_uri,
    :scope,
    :nonce,
    :code_challenge,
    :expires_at
  ]
  defstruct @enforce_keys ++ [claims: %{}]

  @type t :: %__MODULE__{}
end
