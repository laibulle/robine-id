defmodule RobineId.Runtime do
  @moduledoc """
  Runtime boundary shared by standalone releases and host applications.

  Embedded hosts select `:embedded` mode and may replace any adapter without
  introducing a compile-time dependency from Robine ID back to the host.
  """

  @defaults %{
    configuration_store: RobineId.Configuration.Adapters.MemoryStore,
    key_store: RobineId.Protocol.Adapters.MemoryKeyStore,
    authorization_code_store: RobineId.Protocol.Adapters.MemoryAuthorizationCodeStore,
    access_token_store: RobineId.Protocol.Adapters.MemoryAccessTokenStore,
    rate_limiter: RobineId.Security.Adapters.MemoryRateLimiter,
    session_registry: RobineId.Security.Adapters.MemorySessionRegistry,
    user_repository: RobineId.Identity.Adapters.ConfigurationUserRepository,
    password_hasher: RobineId.Identity.Adapters.BcryptPasswordHasher,
    client_repository: RobineId.Clients.Adapters.ConfigurationRepository,
    secret_resolver: RobineId.Clients.Adapters.EnvironmentSecretResolver,
    audit_sink: RobineId.Operations.Adapters.LoggerAuditSink,
    database_health: RobineId.Operations.Adapters.DatabaseHealth
  }

  def mode, do: Application.get_env(:robine_id, :mode, :standalone)
  def standalone?, do: mode() == :standalone
  def embedded?, do: mode() == :embedded

  def adapter(name) when is_atom(name) do
    overrides = Application.get_env(:robine_id, :adapters, %{})

    case Map.fetch(overrides, name) do
      {:ok, adapter} -> adapter
      :error -> default_adapter(name)
    end
  end

  def base_path do
    Application.get_env(:robine_id, :base_path, "")
    |> normalize_base_path()
  end

  def path(path) when is_binary(path) do
    base_path() <> "/" <> String.trim_leading(path, "/")
  end

  defp normalize_base_path(""), do: ""
  defp normalize_base_path("/"), do: ""
  defp normalize_base_path(path), do: "/" <> (path |> String.trim() |> String.trim("/"))

  defp default_adapter(:user_repository) do
    if standalone?(),
      do: RobineId.Identity.Adapters.ManagedUserRepository,
      else: RobineId.Identity.Adapters.ConfigurationUserRepository
  end

  defp default_adapter(name), do: Map.fetch!(@defaults, name)
end
