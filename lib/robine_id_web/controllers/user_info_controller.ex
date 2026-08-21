defmodule RobineIdWeb.UserInfoController do
  use RobineIdWeb, :controller

  def show(conn, %{"issuer_id" => issuer_id} = params) do
    with {:ok, metadata} <-
           RobineId.Protocol.discovery(
             issuer_id,
             RobineId.Runtime.adapter(:configuration_store)
           ),
         {:ok, token} <- bearer_token(conn, params),
         {:ok, claims} <-
           RobineId.Protocol.user_info(
             token,
             RobineId.Runtime.adapter(:access_token_store),
             RobineId.Runtime.adapter(:user_repository),
             issuer: metadata["issuer"]
           ) do
      conn
      |> put_resp_header("cache-control", "no-store")
      |> put_resp_header("pragma", "no-cache")
      |> json(claims)
    else
      _ ->
        conn
        |> put_status(:unauthorized)
        |> put_resp_header("www-authenticate", ~s(Bearer error="invalid_token"))
        |> json(%{error: "invalid_token"})
    end
  end

  defp bearer_token(conn, params) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] when token != "" -> {:ok, token}
      [] -> body_token(conn, params)
      _ -> {:error, :invalid_token}
    end
  end

  defp body_token(%{method: "POST"} = conn, %{"access_token" => token})
       when is_binary(token) and token != "" do
    case get_req_header(conn, "content-type") do
      ["application/x-www-form-urlencoded" <> _parameters] -> {:ok, token}
      _ -> {:error, :invalid_token}
    end
  end

  defp body_token(_conn, _params), do: {:error, :invalid_token}
end
