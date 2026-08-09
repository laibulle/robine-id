defmodule RobineId.Protocol.UseCases.IssueAuthorizationCode do
  @moduledoc "Issues a short-lived code after successful authentication and consent."

  alias RobineId.Protocol.Entities.{AuthorizationGrant, AuthorizationRequest}

  def execute(%AuthorizationRequest{} = request, issuer, subject, store, options \\ [])
      when is_binary(subject) and subject != "" do
    now = Keyword.get(options, :now, System.system_time(:second))
    lifetime = Keyword.get(options, :lifetime, 60)

    grant = %AuthorizationGrant{
      issuer: issuer,
      subject: subject,
      client_id: request.client_id,
      redirect_uri: request.redirect_uri,
      scope: request.scope,
      nonce: request.nonce,
      code_challenge: request.code_challenge,
      expires_at: now + lifetime,
      claims: Keyword.get(options, :claims, %{})
    }

    store.issue(grant)
  end
end
