import Config

config :robine_id, :key_store_path, nil
config :robine_id, :configuration_reload_interval, :disabled

# Configure your database
#
# The MIX_TEST_PARTITION environment variable can be used
# to provide built-in test partitioning in CI environment.
# Run `mix help test` for more information.
config :robine_id, RobineId.Repo,
  database:
    System.get_env("ROBINE_ID_TEST_DATABASE", Path.expand("../robine_id_test.db", __DIR__)),
  pool_size: 5,
  pool: Ecto.Adapters.SQL.Sandbox

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :robine_id, RobineIdWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "klZvcXhglITbVvKdGm+7h8BV6n+EGOOitEljsnxF0J3WqdT33aNmKg4ci7gvrPac",
  server: false

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Enable helpful, but potentially expensive runtime checks
config :phoenix_live_view,
  enable_expensive_runtime_checks: true

# Sort query params output of verified routes for robust url comparisons
config :phoenix,
  sort_verified_routes_query_params: true
