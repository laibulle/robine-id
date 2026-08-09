defmodule Mix.Tasks.RobineId.Keys.Rotate do
  use Mix.Task

  @shortdoc "Idempotently rotates an issuer signing key"

  @impl Mix.Task
  def run([issuer_id, rotation_id]) do
    Mix.Task.run("app.start")

    with {:ok, metadata} <-
           RobineId.Protocol.discovery(
             issuer_id,
             RobineId.Configuration.Adapters.MemoryStore
           ),
         {:ok, outcome, kid} <-
           RobineId.Protocol.rotate_signing_key(
             metadata["issuer"],
             rotation_id,
             RobineId.Protocol.Adapters.MemoryKeyStore
           ) do
      Mix.shell().info("#{outcome} issuer #{metadata["issuer"]} key #{kid}")
    else
      {:error, reason} -> Mix.raise("key rotation failed: #{inspect(reason)}")
    end
  end

  def run(_args), do: Mix.raise("usage: mix robine_id.keys.rotate ISSUER_ID ROTATION_ID")
end
