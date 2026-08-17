defmodule RobineId.RepoMigrationsTest do
  use RobineId.DataCase, async: false

  test "access token authentication context rejects impossible MFA state" do
    assert_raise Exqlite.Error, fn ->
      query!("""
      INSERT INTO access_tokens (
        token_hash, issuer, subject, client_id, scopes, claims,
        expires_at, created_at, auth_time, mfa_verified
      ) VALUES (
        X'01', 'https://issuer.example', 'subject', 'client', '[]', '{}',
        '2026-08-18T00:00:00Z', '2026-08-17T00:00:00Z', NULL, 1
      )
      """)
    end

    query!("""
    INSERT INTO access_tokens (
      token_hash, issuer, subject, client_id, scopes, claims,
      expires_at, created_at, auth_time, mfa_verified
    ) VALUES (
      X'02', 'https://issuer.example', 'subject', 'client', '[]', '{}',
      '2026-08-18T00:00:00Z', '2026-08-17T00:00:00Z', 1, 1
    )
    """)

    assert_raise Exqlite.Error, fn ->
      query!("UPDATE access_tokens SET auth_time = NULL WHERE token_hash = X'02'")
    end

    assert_raise Exqlite.Error, fn ->
      query!("UPDATE access_tokens SET auth_time = -1 WHERE token_hash = X'02'")
    end
  end

  defp query!(statement) do
    Ecto.Adapters.SQL.query!(Repo, statement, [])
  end
end
