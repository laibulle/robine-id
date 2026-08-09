defmodule RobineId.Operations.Ports.AuditSink do
  @moduledoc "Port for security-relevant audit events."
  @callback record(atom(), map()) :: :ok
end
