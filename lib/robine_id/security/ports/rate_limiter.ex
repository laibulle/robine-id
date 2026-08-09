defmodule RobineId.Security.Ports.RateLimiter do
  @moduledoc "Port for atomic fixed-window rate limiting."
  @callback check(term(), pos_integer(), pos_integer(), integer()) ::
              {:ok, non_neg_integer()} | {:error, :rate_limited, pos_integer()}
end
