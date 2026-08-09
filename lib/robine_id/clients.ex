defmodule RobineId.Clients do
  @moduledoc "Public facade for relying-party clients."

  defdelegate get(client_id, repository), to: RobineId.Clients.UseCases.GetClient, as: :execute

  defdelegate consent_required?(client),
    to: RobineId.Clients.UseCases.GetConsentPolicy,
    as: :execute

  defdelegate authenticate(client_id, presented_secret, repository, secret_resolver),
    to: RobineId.Clients.UseCases.AuthenticateClient,
    as: :execute

  defdelegate authenticate(
                client_id,
                authentication_method,
                presented_secret,
                repository,
                secret_resolver
              ),
              to: RobineId.Clients.UseCases.AuthenticateClient,
              as: :execute
end
