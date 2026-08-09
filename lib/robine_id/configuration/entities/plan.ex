defmodule RobineId.Configuration.Entities.Plan do
  @moduledoc "A deterministic, non-mutating desired-state reconciliation plan."

  @resource_types ~w(issuers clients users)

  def build(nil, desired), do: build(%{}, desired)

  def build(current, desired) do
    operations =
      Enum.flat_map(@resource_types, fn type ->
        diff(type, current[type] || [], desired[type] || [])
      end)

    %{
      revision: desired_fingerprint(desired),
      operations: Enum.sort_by(operations, &{&1.resource_type, &1.id, &1.action})
    }
  end

  defp diff(type, current, desired) do
    current = Map.new(current, &{&1["id"], &1})
    desired = Map.new(desired, &{&1["id"], &1})

    creates_or_updates =
      Enum.map(desired, fn {id, value} ->
        action =
          case current[id] do
            nil -> :create
            ^value -> :unchanged
            _ -> :update
          end

        %{resource_type: type, id: id, action: action}
      end)

    removed =
      current
      |> Map.keys()
      |> Enum.reject(&Map.has_key?(desired, &1))
      |> Enum.map(&%{resource_type: type, id: &1, action: :disable})

    creates_or_updates ++ removed
  end

  defp desired_fingerprint(data) do
    {:ok, snapshot} = RobineId.Configuration.Entities.Snapshot.new(data)
    snapshot.fingerprint
  end
end
