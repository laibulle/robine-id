defmodule RobineId.Operations.Adapters.LoggerAuditSink do
  @moduledoc "Structured Logger and telemetry audit adapter."
  @behaviour RobineId.Operations.Ports.AuditSink
  require Logger

  @impl true
  def record(event, attributes) do
    :telemetry.execute([:robine_id, :security, :event], %{count: 1}, %{
      event: event,
      outcome: attributes[:outcome] || :unknown
    })

    Logger.info("security_event", Map.to_list(Map.put(attributes, :event, event)))
    :ok
  end
end
