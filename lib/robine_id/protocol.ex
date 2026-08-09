defmodule RobineId.Protocol do
  @moduledoc "Public facade for OpenID Connect protocol operations."

  defdelegate discovery(issuer_id, configuration_store),
    to: RobineId.Protocol.UseCases.DiscoverProvider,
    as: :execute

  defdelegate validate_authorization_request(issuer_id, params, client_repository),
    to: RobineId.Protocol.UseCases.ValidateAuthorizationRequest,
    as: :execute

  defdelegate jwks(issuer_id, key_store), to: RobineId.Protocol.UseCases.GetJwks, as: :execute

  defdelegate rotate_signing_key(issuer_id, rotation_id, key_store),
    to: RobineId.Protocol.UseCases.RotateSigningKey,
    as: :execute

  defdelegate issue_id_token(claims, key_store, options),
    to: RobineId.Protocol.UseCases.IssueIdToken,
    as: :execute

  defdelegate issue_authorization_code(request, issuer, subject, code_store, options),
    to: RobineId.Protocol.UseCases.IssueAuthorizationCode,
    as: :execute

  defdelegate exchange_authorization_code(
                params,
                code_store,
                key_store,
                access_token_store,
                options
              ),
              to: RobineId.Protocol.UseCases.ExchangeAuthorizationCode,
              as: :execute

  defdelegate user_info(token, access_token_store, user_repository, options),
    to: RobineId.Protocol.UseCases.GetUserInfo,
    as: :execute

  defdelegate verify_id_token(token, issuer, key_store, options),
    to: RobineId.Protocol.UseCases.VerifyIdToken,
    as: :execute
end
