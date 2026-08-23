defmodule RobineId.Identity.Ports.PasswordHasher do
  @moduledoc "Port for constant-time password verification."
  @callback verify(String.t(), String.t()) :: boolean()
  @callback hash(String.t()) :: String.t()
  @callback dummy_verify() :: false
end
