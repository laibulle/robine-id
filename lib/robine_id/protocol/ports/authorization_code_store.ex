defmodule RobineId.Protocol.Ports.AuthorizationCodeStore do
  @moduledoc "Port for issuing and atomically consuming opaque authorization codes."
  alias RobineId.Protocol.Entities.AuthorizationGrant

  @callback issue(AuthorizationGrant.t()) :: {:ok, String.t()}
  @callback consume(String.t()) :: {:ok, AuthorizationGrant.t()} | {:error, :invalid_grant}
end
