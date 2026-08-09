import Config

default_configuration_path =
  case System.get_env("RELEASE_ROOT") do
    root when is_binary(root) -> Path.join(root, "config/robine_id.json")
    _ -> Path.expand("robine_id.json", __DIR__)
  end

configuration_path =
  System.get_env("ROBINE_ID_CONFIG", default_configuration_path)
  |> Path.expand()

config :robine_id, :configuration_path, configuration_path

if applications_path = System.get_env("ROBINE_ID_APPLICATIONS_DIR") do
  config :robine_id, :applications_path, Path.expand(applications_path)
end

if reload_interval = System.get_env("ROBINE_ID_RELOAD_INTERVAL") do
  case Integer.parse(reload_interval) do
    {milliseconds, ""} when milliseconds > 0 ->
      config :robine_id, :configuration_reload_interval, milliseconds

    _ ->
      raise "ROBINE_ID_RELOAD_INTERVAL must be a positive number of milliseconds"
  end
end

if config_env() == :prod and not File.regular?(configuration_path) do
  raise "ROBINE_ID_CONFIG does not point to a readable configuration file: #{configuration_path}"
end

if config_env() != :test and File.regular?(configuration_path) do
  configuration = configuration_path |> File.read!() |> Jason.decode!()
  storage = configuration["storage"] || %{}

  database_path =
    case storage["database_path"] do
      %{"provider" => "env", "key" => key} ->
        System.get_env(key) || raise "storage environment reference #{key} is unavailable"

      path when is_binary(path) ->
        if Path.type(path) == :absolute,
          do: path,
          else: Path.expand(path, Path.dirname(configuration_path))

      _ ->
        nil
    end

  if database_path do
    config :robine_id, RobineId.Repo,
      database: database_path,
      pool_size: storage["pool_size"] || 5
  end

  if signing_key_path = storage["signing_key_path"] do
    resolved_key_path =
      if Path.type(signing_key_path) == :absolute,
        do: signing_key_path,
        else: Path.expand(signing_key_path, Path.dirname(configuration_path))

    config :robine_id, :key_store_path, resolved_key_path
  end

  log_levels = %{"debug" => :debug, "info" => :info, "warning" => :warning, "error" => :error}

  if log_level = get_in(configuration, ["telemetry", "log_level"]) do
    config :logger, level: Map.fetch!(log_levels, log_level)
  end
end

# config/runtime.exs is executed for all environments, including
# during releases. It is executed after compilation and before the
# system starts, so it is typically used to load production configuration
# and secrets from environment variables or elsewhere. Do not define
# any compile-time configuration in here, as it won't be applied.
# The block below contains prod specific runtime configuration.

# ## Using releases
#
# If you use `mix release`, you need to explicitly enable the server
# by passing the PHX_SERVER=true when you start it:
#
#     PHX_SERVER=true bin/robine_id start
#
# Alternatively, you can use `mix phx.gen.release` to generate a `bin/server`
# script that automatically sets the env var above.
if System.get_env("PHX_SERVER") do
  config :robine_id, RobineIdWeb.Endpoint, server: true
end

config :robine_id, RobineIdWeb.Endpoint,
  http: [port: String.to_integer(System.get_env("PORT", "4001"))]

if config_env() == :dev do
  # Reload browser tabs when matching files change.
  config :robine_id, RobineIdWeb.Endpoint,
    live_reload: [
      web_console_logger: true,
      patterns: [
        # Static assets, except user uploads
        ~r"priv/static/(?!uploads/).*\.(js|css|png|jpeg|jpg|gif|svg)$"E,
        # Gettext translations
        ~r"priv/gettext/.*\.po$"E,
        # Router, Controllers, LiveViews and LiveComponents
        ~r"lib/robine_id_web/router\.ex$"E,
        ~r"lib/robine_id_web/(controllers|live|components)/.*\.(ex|heex)$"E
      ]
    ]
end

if config_env() == :prod do
  if database_path = System.get_env("DATABASE_PATH") do
    config :robine_id, RobineId.Repo,
      database: database_path,
      pool_size: String.to_integer(System.get_env("POOL_SIZE") || "5")
  end

  # The secret key base is used to sign/encrypt cookies and other secrets.
  # A default value is used in config/dev.exs and config/test.exs but you
  # want to use a different value for prod and you most likely don't want
  # to check this value into version control, so we use an environment
  # variable instead.
  secret_key_base =
    System.get_env("SECRET_KEY_BASE") ||
      raise """
      environment variable SECRET_KEY_BASE is missing.
      You can generate one by calling: mix phx.gen.secret
      """

  host = System.get_env("PHX_HOST") || "example.com"

  config :robine_id, :dns_cluster_query, System.get_env("DNS_CLUSTER_QUERY")

  config :robine_id, RobineIdWeb.Endpoint,
    url: [host: host, port: 443, scheme: "https"],
    http: [
      # Enable IPv6 and bind on all interfaces.
      # Set it to  {0, 0, 0, 0, 0, 0, 0, 1} for local network only access.
      # See the documentation on https://bandit.hexdocs.pm/Bandit.html#t:options/0
      # for details about using IPv6 vs IPv4 and loopback vs public addresses.
      ip: {0, 0, 0, 0, 0, 0, 0, 0}
    ],
    secret_key_base: secret_key_base

  # ## SSL Support
  #
  # To get SSL working, you will need to add the `https` key
  # to your endpoint configuration:
  #
  #     config :robine_id, RobineIdWeb.Endpoint,
  #       https: [
  #         ...,
  #         port: 443,
  #         cipher_suite: :strong,
  #         keyfile: System.get_env("SOME_APP_SSL_KEY_PATH"),
  #         certfile: System.get_env("SOME_APP_SSL_CERT_PATH")
  #       ]
  #
  # The `cipher_suite` is set to `:strong` to support only the
  # latest and more secure SSL ciphers. This means old browsers
  # and clients may not be supported. You can set it to
  # `:compatible` for wider support.
  #
  # `:keyfile` and `:certfile` expect an absolute path to the key
  # and cert in disk or a relative path inside priv, for example
  # "priv/ssl/server.key". For all supported SSL configuration
  # options, see https://plug.hexdocs.pm/Plug.SSL.html#configure/1
  #
  # We also recommend setting `force_ssl` in your config/prod.exs,
  # ensuring no data is ever sent via http, always redirecting to https:
  #
  #     config :robine_id, RobineIdWeb.Endpoint,
  #       force_ssl: [hsts: true]
  #
  # Check `Plug.SSL` for all available options in `force_ssl`.
end
