defmodule RobineId.Identity.Ports.UserRepository do
  @moduledoc "Port for resolving local identities."
  alias RobineId.Identity.Entities.User

  @callback get_by_identifier(String.t()) :: {:ok, User.t()} | {:error, :not_found | term()}
  @callback get_by_id(String.t()) :: {:ok, User.t()} | {:error, :not_found | term()}
end
