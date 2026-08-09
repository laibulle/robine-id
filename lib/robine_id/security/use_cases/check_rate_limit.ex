defmodule RobineId.Security.UseCases.CheckRateLimit do
  @moduledoc "Applies a bounded authentication-attempt policy."

  def execute(key, limiter, options \\ []) do
    limit = Keyword.get(options, :limit, 5)
    window = Keyword.get(options, :window_seconds, 60)
    now = Keyword.get(options, :now, System.system_time(:second))
    limiter.check(key, limit, window, now)
  end
end
