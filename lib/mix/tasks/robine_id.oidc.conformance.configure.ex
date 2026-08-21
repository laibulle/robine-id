defmodule Mix.Tasks.RobineId.Oidc.Conformance.Configure do
  @moduledoc """
  Generates the three static clients required by the OpenID Foundation Basic OP plan.

      mix robine_id.oidc.conformance.configure \
        --alias your-unique-alias \
        --applications-dir deploy/config/applications

  The alias becomes part of the conformance-suite callback URI. Existing files
  are preserved unless `--force` is supplied. Client secrets remain environment
  references and are never generated or written by this task.
  """
  use Mix.Task

  @shortdoc "Registers static clients for the OpenID Connect Basic OP conformance plan"

  @switches [alias: :string, applications_dir: :string, force: :boolean]

  @impl Mix.Task
  def run(arguments) do
    {options, remaining, invalid} = OptionParser.parse(arguments, strict: @switches)

    if remaining != [] or invalid != [] do
      Mix.raise("unexpected arguments; run mix help robine_id.oidc.conformance.configure")
    end

    alias_name = Keyword.get(options, :alias) || Mix.raise("--alias is required")
    validate_alias!(alias_name)

    directory =
      Keyword.get(options, :applications_dir) ||
        RobineId.Configuration.Adapters.ApplicationDirectoryLoader.applications_directory(
          Application.fetch_env!(:robine_id, :configuration_path)
        )

    callback = "https://www.certification.openid.net/test/a/#{alias_name}/callback"

    clients = [
      client(
        "robine-id-conformance-basic-1",
        "Basic OP primary",
        "client_secret_basic",
        callback,
        "ROBINE_ID_CONFORMANCE_BASIC_1_SECRET"
      ),
      client(
        "robine-id-conformance-basic-2",
        "Basic OP secondary",
        "client_secret_basic",
        callback,
        "ROBINE_ID_CONFORMANCE_BASIC_2_SECRET"
      ),
      client(
        "robine-id-conformance-post",
        "Basic OP secret-post",
        "client_secret_post",
        callback,
        "ROBINE_ID_CONFORMANCE_POST_SECRET"
      )
    ]

    File.mkdir_p!(directory)

    Enum.each(clients, fn client ->
      path = Path.join(directory, client["id"] <> ".json")
      write_client!(path, client, Keyword.get(options, :force, false))
      Mix.shell().info("wrote #{path}")
    end)

    Mix.shell().info("callback: #{callback}")
    Mix.shell().info("set the three ROBINE_ID_CONFORMANCE_*_SECRET environment variables")
  end

  defp client(id, name, method, callback, secret_environment_variable) do
    %{
      "schema_version" => 1,
      "kind" => "oidc_application",
      "id" => id,
      "name" => name,
      "type" => "confidential",
      "redirect_uris" => [callback],
      "scopes" => ["openid", "profile", "email", "address", "phone"],
      "grant_types" => ["authorization_code"],
      "authentication_method" => method,
      "pkce_required" => false,
      "nonce_required" => false,
      "secret_reference" => %{
        "provider" => "env",
        "key" => secret_environment_variable
      },
      "consent_required" => false
    }
  end

  defp write_client!(path, client, force?) do
    if File.exists?(path) and not force? do
      Mix.raise("#{path} already exists; pass --force to replace conformance client files")
    end

    File.write!(path, [Jason.encode_to_iodata!(client, pretty: true), "\n"])
  end

  defp validate_alias!(alias_name) do
    if not Regex.match?(~r/^[A-Za-z0-9._~-]{1,64}$/, alias_name) do
      Mix.raise("--alias must contain 1-64 URL-safe letters, digits, '.', '_', '~', or '-'")
    end
  end
end
