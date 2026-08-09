defmodule RobineId.Operations.UseCases.RecordAuditEvent do
  @moduledoc "Records a bounded, explicitly non-secret audit event."

  @allowed_attributes ~w(outcome issuer_id client_id subject_id correlation_id reason)a

  def execute(event, attributes, sink) when is_atom(event) and is_map(attributes) do
    sanitized = Map.take(attributes, @allowed_attributes)
    sink.record(event, sanitized)
  end
end
