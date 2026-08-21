defmodule RobineId.Identity do
  @moduledoc "Public facade for user authentication."

  defdelegate authenticate(identifier, password, repository, password_hasher),
    to: RobineId.Identity.UseCases.Authenticate,
    as: :execute

  defdelegate map_claims(user, mappings, scopes),
    to: RobineId.Identity.UseCases.MapClaims,
    as: :execute

  defdelegate map_claims(user, mappings, scopes, requested_claims),
    to: RobineId.Identity.UseCases.MapClaims,
    as: :execute
end
