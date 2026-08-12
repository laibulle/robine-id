defmodule RobineId.RuntimeTest do
  use ExUnit.Case, async: false

  setup do
    mode = Application.get_env(:robine_id, :mode)
    base_path = Application.get_env(:robine_id, :base_path)
    adapters = Application.get_env(:robine_id, :adapters)

    on_exit(fn ->
      restore(:mode, mode)
      restore(:base_path, base_path)
      restore(:adapters, adapters)
    end)

    :ok
  end

  test "normalizes embedded paths without changing standalone paths" do
    Application.put_env(:robine_id, :base_path, "/id/")
    assert RobineId.Runtime.path("/default/authorize") == "/id/default/authorize"

    Application.put_env(:robine_id, :base_path, "")
    assert RobineId.Runtime.path("/default/authorize") == "/default/authorize"
  end

  test "allows a host to replace adapters" do
    Application.put_env(:robine_id, :adapters, %{user_repository: __MODULE__})
    assert RobineId.Runtime.adapter(:user_repository) == __MODULE__

    assert RobineId.Runtime.adapter(:configuration_store) ==
             RobineId.Configuration.Adapters.MemoryStore
  end

  defp restore(key, nil), do: Application.delete_env(:robine_id, key)
  defp restore(key, value), do: Application.put_env(:robine_id, key, value)
end
