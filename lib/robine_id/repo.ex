defmodule RobineId.Repo do
  use Ecto.Repo,
    otp_app: :robine_id,
    adapter: Ecto.Adapters.SQLite3
end
