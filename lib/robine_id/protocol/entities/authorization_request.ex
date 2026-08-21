defmodule RobineId.Protocol.Entities.AuthorizationRequest do
  @moduledoc "Validated Authorization Code Flow request."

  @enforce_keys [:issuer_id, :client_id, :redirect_uri, :scope]
  defstruct @enforce_keys ++
              [
                :state,
                :nonce,
                :code_challenge,
                :code_challenge_method,
                :locale,
                :display,
                :login_hint,
                :id_token_hint,
                :max_age,
                prompt: [],
                claims: %{}
              ]

  @type t :: %__MODULE__{}
end
