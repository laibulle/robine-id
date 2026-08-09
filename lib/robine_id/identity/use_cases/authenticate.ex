defmodule RobineId.Identity.UseCases.Authenticate do
  @moduledoc "Authenticates without disclosing whether an identity exists."

  def execute(identifier, password, repository, password_hasher)
      when is_binary(identifier) and is_binary(password) do
    case repository.get_by_identifier(String.trim(identifier)) do
      {:ok, user} ->
        if password_hasher.verify(password, user.password_hash),
          do: {:ok, user},
          else: {:error, :invalid_credentials}

      {:error, :not_found} ->
        password_hasher.dummy_verify()
        {:error, :invalid_credentials}

      {:error, reason} ->
        {:error, reason}
    end
  end
end
