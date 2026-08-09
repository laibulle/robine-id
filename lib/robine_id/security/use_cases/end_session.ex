defmodule RobineId.Security.UseCases.EndSession do
  @moduledoc "Revokes one authenticated session."

  def execute(subject, session_id, registry) when is_binary(subject) and is_binary(session_id),
    do: registry.revoke(subject, session_id)

  def execute(_, _, _), do: :ok
end
