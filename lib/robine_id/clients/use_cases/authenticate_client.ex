defmodule RobineId.Clients.UseCases.AuthenticateClient do
  @moduledoc "Authenticates public and confidential token-endpoint clients."

  def execute(client_id, presented_secret, repository, secret_resolver) do
    method = if is_nil(presented_secret), do: "none", else: "client_secret_basic"
    execute(client_id, method, presented_secret, repository, secret_resolver)
  end

  def execute(client_id, authentication_method, presented_secret, repository, secret_resolver) do
    with {:ok, client} <- RobineId.Clients.get(client_id, repository) do
      authenticate(client, authentication_method, presented_secret, secret_resolver)
    else
      _ -> {:error, :invalid_client}
    end
  end

  defp authenticate(
         %{type: :public, authentication_method: "none"} = client,
         "none",
         nil,
         _resolver
       ),
       do: {:ok, client}

  defp authenticate(
         %{type: :confidential, authentication_method: method} = client,
         method,
         presented,
         resolver
       )
       when method in ["client_secret_basic", "client_secret_post"] and is_binary(presented) do
    with {:ok, expected} <- resolver.resolve(client.secret_reference),
         true <- same_secret?(presented, expected) do
      {:ok, client}
    else
      _ -> {:error, :invalid_client}
    end
  end

  defp authenticate(_, _, _, _), do: {:error, :invalid_client}

  defp same_secret?(presented, expected) when byte_size(presented) == byte_size(expected),
    do: Plug.Crypto.secure_compare(presented, expected)

  defp same_secret?(_, _), do: false
end
