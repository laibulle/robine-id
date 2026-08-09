defmodule RobineIdWeb.PageController do
  use RobineIdWeb, :controller

  def home(conn, _params) do
    store = RobineId.Configuration.Adapters.MemoryStore
    {:ok, snapshot} = RobineId.Configuration.active(store)
    issuer = List.first(snapshot.data["issuers"])
    {:ok, theme} = RobineId.Experience.theme(issuer["id"], nil, store)

    ready? =
      match?(
        {:ok, _},
        RobineId.Operations.readiness(store, [RobineId.Operations.Adapters.DatabaseHealth])
      )

    render(conn, :home,
      page_title: theme.product_name,
      theme: theme,
      issuer_id: issuer["id"],
      revision: snapshot.fingerprint,
      ready?: ready?
    )
  end

  def docs(conn, _params) do
    store = RobineId.Configuration.Adapters.MemoryStore
    {:ok, snapshot} = RobineId.Configuration.active(store)
    issuer = List.first(snapshot.data["issuers"])
    {:ok, theme} = RobineId.Experience.theme(issuer["id"], nil, store)

    render(conn, :docs,
      page_title: "Documentation",
      theme: theme,
      issuer_id: issuer["id"]
    )
  end
end
