defmodule RobineId.Security.UseCases.ValidateSession do
  @moduledoc "Validates idle, absolute, and registry session constraints."

  def execute(session, policy, registry, now \\ System.system_time(:second)) do
    started_at = session["session_started_at"] || session[:session_started_at]
    last_seen_at = session["session_last_seen_at"] || session[:session_last_seen_at]

    cond do
      is_nil(started_at) -> {:ok, timestamps(now)}
      now - started_at >= policy["absolute_timeout"] -> {:error, :absolute_timeout}
      now - last_seen_at >= policy["idle_timeout"] -> {:error, :idle_timeout}
      authenticated_but_inactive?(session, registry) -> {:error, :concurrent_session_revoked}
      true -> {:ok, %{session_last_seen_at: now}}
    end
  end

  defp authenticated_but_inactive?(session, registry) do
    subject = session["subject"] || session[:subject]
    session_id = session["authenticated_session_id"] || session[:authenticated_session_id]

    is_binary(subject) and
      (not is_binary(session_id) or not registry.active?(subject, session_id))
  end

  defp timestamps(now), do: %{session_started_at: now, session_last_seen_at: now}
end
