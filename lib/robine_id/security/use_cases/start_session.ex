defmodule RobineId.Security.UseCases.StartSession do
  @moduledoc "Starts a registered authenticated session."

  def execute(subject, maximum, registry) when is_binary(subject) and maximum > 0 do
    session_id = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
    :ok = registry.register(subject, session_id, maximum)
    {:ok, session_id}
  end
end
