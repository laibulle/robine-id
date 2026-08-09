defmodule RobineIdWeb.UserInfoController do
  use RobineIdWeb, :controller

  alias RobineId.Identity.Adapters.ConfigurationUserRepository
  alias RobineId.Protocol.Adapters.MemoryAccessTokenStore

  def show(conn, _params) do
    with {:ok, token} <- bearer_token(conn),
         {:ok, claims} <-
           RobineId.Protocol.user_info(
             token,
             MemoryAccessTokenStore,
             ConfigurationUserRepository,
             []
           ) do
      json(conn, claims)
    else
      _ ->
        conn
        |> put_status(:unauthorized)
        |> put_resp_header("www-authenticate", ~s(Bearer error="invalid_token"))
        |> json(%{error: "invalid_token"})
    end
  end

  defp bearer_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] when token != "" -> {:ok, token}
      _ -> {:error, :invalid_token}
    end
  end
end
