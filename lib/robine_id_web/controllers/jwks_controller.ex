defmodule RobineIdWeb.JwksController do
  use RobineIdWeb, :controller

  alias RobineId.Protocol.Adapters.MemoryKeyStore

  def show(conn, %{"issuer_id" => issuer_id}) do
    with {:ok, metadata} <-
           RobineId.Protocol.discovery(issuer_id, RobineId.Configuration.Adapters.MemoryStore),
         {:ok, jwks} <- RobineId.Protocol.jwks(metadata["issuer"], MemoryKeyStore) do
      conn
      |> put_resp_header("cache-control", "public, max-age=300")
      |> json(jwks)
    else
      {:error, :unknown_issuer} -> conn |> put_status(:not_found) |> json(%{error: "not_found"})
    end
  end
end
