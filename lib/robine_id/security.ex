defmodule RobineId.Security do
  @moduledoc "Public facade for cross-cutting security policies."

  defdelegate check_rate_limit(key, limiter, options),
    to: RobineId.Security.UseCases.CheckRateLimit,
    as: :execute

  defdelegate validate_session(session, policy, registry, now),
    to: RobineId.Security.UseCases.ValidateSession,
    as: :execute

  defdelegate start_session(subject, maximum, registry),
    to: RobineId.Security.UseCases.StartSession,
    as: :execute

  defdelegate end_session(subject, session_id, registry),
    to: RobineId.Security.UseCases.EndSession,
    as: :execute
end
