defmodule RobineId.Configuration do
  @moduledoc "Public facade for declarative configuration."

  defdelegate load(path, loader), to: RobineId.Configuration.UseCases.Load, as: :execute

  defdelegate reconcile(snapshot, store),
    to: RobineId.Configuration.UseCases.Reconcile,
    as: :execute

  defdelegate active(store), to: RobineId.Configuration.UseCases.GetActive, as: :execute

  defdelegate preview(snapshot, store),
    to: RobineId.Configuration.UseCases.Preview,
    as: :execute

  defdelegate history(store), to: RobineId.Configuration.UseCases.GetHistory, as: :execute

  defdelegate issuer(issuer_id, store),
    to: RobineId.Configuration.UseCases.GetIssuer,
    as: :execute

  defdelegate record_failure(diagnostics, store),
    to: RobineId.Configuration.UseCases.RecordFailure,
    as: :execute
end
