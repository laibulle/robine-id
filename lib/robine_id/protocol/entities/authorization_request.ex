defmodule RobineId.Protocol.Entities.AuthorizationRequest do
  @moduledoc "Validated Authorization Code Flow request."

  @enforce_keys [
    :issuer_id,
    :client_id,
    :redirect_uri,
    :scope,
    :state,
    :nonce,
    :code_challenge,
    :code_challenge_method
  ]
  defstruct @enforce_keys ++ [locale: nil]

  @type t :: %__MODULE__{}
end
