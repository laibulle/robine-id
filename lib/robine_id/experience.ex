defmodule RobineId.Experience do
  @moduledoc "Public facade for configured user experience."

  defdelegate theme(issuer_id, client_id, configuration_store),
    to: RobineId.Experience.UseCases.GetTheme,
    as: :execute

  defdelegate messages(theme, requested_locale),
    to: RobineId.Experience.UseCases.GetMessages,
    as: :execute
end
