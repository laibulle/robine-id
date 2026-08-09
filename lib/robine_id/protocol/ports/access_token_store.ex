defmodule RobineId.Protocol.Ports.AccessTokenStore do
  @moduledoc "Port for opaque bearer-token lifecycle."
  alias RobineId.Protocol.Entities.AccessGrant

  @callback issue(AccessGrant.t()) :: {:ok, String.t()}
  @callback get(String.t()) :: {:ok, AccessGrant.t()} | {:error, :invalid_token}
  @callback revoke(String.t()) :: :ok
end
