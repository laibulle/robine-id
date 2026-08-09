defmodule RobineIdWeb.DiscoveryController do
  use RobineIdWeb, :controller

  alias RobineId.Configuration.Adapters.MemoryStore

  def show(conn, %{"issuer_id" => issuer_id}) do
    case RobineId.Protocol.discovery(issuer_id, MemoryStore) do
      {:ok, metadata} ->
        conn
        |> put_resp_header("cache-control", "public, max-age=300")
        |> json(metadata)

      {:error, :unknown_issuer} ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})
    end
  end
end
