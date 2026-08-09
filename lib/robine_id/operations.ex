defmodule RobineId.Operations do
  @moduledoc "Public facade for audit and operational events."

  defdelegate audit(event, attributes, sink),
    to: RobineId.Operations.UseCases.RecordAuditEvent,
    as: :execute

  defdelegate readiness(configuration_store, dependencies),
    to: RobineId.Operations.UseCases.CheckReadiness,
    as: :execute
end
