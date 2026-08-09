defmodule RobineId.Identity.Entities.User do
  @moduledoc "A local identity that can authenticate with Robine ID."

  @enforce_keys [:id, :identifier, :password_hash]
  defstruct [:id, :identifier, :password_hash, :name, :email, :claims]

  @type t :: %__MODULE__{}

  def from_config(
        %{"id" => id, "identifier" => identifier, "password_hash" => password_hash} = data
      )
      when is_binary(id) and is_binary(identifier) and is_binary(password_hash) do
    {:ok,
     %__MODULE__{
       id: id,
       identifier: identifier,
       password_hash: password_hash,
       name: data["name"],
       email: data["email"],
       claims: data["claims"] || %{}
     }}
  end

  def from_config(_), do: {:error, :invalid_user}
end
