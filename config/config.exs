# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :robine_id, :configuration_path, Path.expand("robine_id.json", __DIR__)
config :robine_id, :configuration_reload_interval, 1_000
config :robine_id, :secure_cookies, config_env() == :prod
config :robine_id, :mode, :standalone

config :robine_id,
  ecto_repos: [RobineId.Repo],
  generators: [timestamp_type: :utc_datetime]

# Configure the endpoint
config :robine_id, RobineIdWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [html: RobineIdWeb.ErrorHTML, json: RobineIdWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: RobineId.PubSub,
  live_view: [signing_salt: "OxAC38C6"]

# Configure esbuild (the version is required)
config :esbuild,
  version: "0.25.4",
  robine_id: [
    args:
      ~w(js/app.js --bundle --target=es2022 --outdir=../priv/static/assets/js --external:/fonts/* --external:/images/* --alias:@=.),
    cd: Path.expand("../assets", __DIR__),
    env: %{"NODE_PATH" => [Path.expand("../deps", __DIR__), Mix.Project.build_path()]}
  ]

# Configure tailwind (the version is required)
config :tailwind,
  version: "4.3.0",
  robine_id: [
    args: ~w(
      --input=assets/css/app.css
      --output=priv/static/assets/css/app.css
    ),
    cd: Path.expand("..", __DIR__),
    env: %{"NODE_PATH" => [Path.expand("../deps", __DIR__), Mix.Project.build_path()]}
  ]

# Configure Elixir's Logger
config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id, :event, :outcome, :issuer_id, :client_id, :subject_id, :correlation_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
