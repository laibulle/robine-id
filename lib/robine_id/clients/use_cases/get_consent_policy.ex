defmodule RobineId.Clients.UseCases.GetConsentPolicy do
  @moduledoc "Returns whether a client requires explicit consent."
  alias RobineId.Clients.Entities.Client

  def execute(%Client{consent_required: required}), do: required
end
