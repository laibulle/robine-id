defmodule RobineId.SecurityTest do
  use ExUnit.Case, async: false

  alias RobineId.Security.Adapters.MemoryRateLimiter
  alias RobineId.Security.Adapters.MemorySessionRegistry

  test "atomically limits attempts and resets after the configured window" do
    key = {:test, System.unique_integer([:positive])}

    assert {:ok, 1} =
             RobineId.Security.check_rate_limit(key, MemoryRateLimiter, limit: 2, now: 100)

    assert {:ok, 0} =
             RobineId.Security.check_rate_limit(key, MemoryRateLimiter, limit: 2, now: 101)

    assert {:error, :rate_limited, 58} =
             RobineId.Security.check_rate_limit(key, MemoryRateLimiter, limit: 2, now: 102)

    assert {:ok, 1} =
             RobineId.Security.check_rate_limit(key, MemoryRateLimiter, limit: 2, now: 160)
  end

  test "enforces idle and absolute session timeouts" do
    policy = %{"idle_timeout" => 10, "absolute_timeout" => 30, "max_concurrent" => 2}
    session = %{session_started_at: 100, session_last_seen_at: 105}

    assert {:ok, %{session_last_seen_at: 110}} =
             RobineId.Security.validate_session(session, policy, MemorySessionRegistry, 110)

    assert {:error, :idle_timeout} =
             RobineId.Security.validate_session(session, policy, MemorySessionRegistry, 115)

    assert {:error, :absolute_timeout} =
             RobineId.Security.validate_session(session, policy, MemorySessionRegistry, 130)
  end

  test "revokes the oldest session when the concurrent maximum is reached" do
    subject = "subject-#{System.unique_integer([:positive])}"
    assert {:ok, first} = RobineId.Security.start_session(subject, 1, MemorySessionRegistry)
    assert {:ok, second} = RobineId.Security.start_session(subject, 1, MemorySessionRegistry)

    policy = %{"idle_timeout" => 100, "absolute_timeout" => 200, "max_concurrent" => 1}
    base = %{subject: subject, session_started_at: 0, session_last_seen_at: 0}

    assert {:error, :concurrent_session_revoked} =
             RobineId.Security.validate_session(
               Map.put(base, :authenticated_session_id, first),
               policy,
               MemorySessionRegistry,
               1
             )

    assert {:ok, _updates} =
             RobineId.Security.validate_session(
               Map.put(base, :authenticated_session_id, second),
               policy,
               MemorySessionRegistry,
               1
             )
  end
end
