defmodule RobineId.Authorization do
  @moduledoc "Headless authorization facade for host-owned authentication interfaces."

  alias RobineId.Runtime

  def begin(issuer_id, params) do
    with {:ok, metadata} <- RobineId.Protocol.discovery(issuer_id, adapter(:configuration_store)),
         {:ok, request} <-
           RobineId.Protocol.validate_authorization_request(
             issuer_id,
             params,
             adapter(:client_repository)
           ),
         {:ok, client} <- RobineId.Clients.get(request.client_id, adapter(:client_repository)) do
      {:ok, %{request: request, client: client, issuer: metadata["issuer"]}}
    end
  end

  def authenticate(request, identifier, password, rate_limit_key) do
    with {:ok, _remaining} <-
           RobineId.Security.check_rate_limit(
             rate_limit_key,
             adapter(:rate_limiter),
             rate_limit_options()
           ),
         {:ok, user} <-
           RobineId.Identity.authenticate(
             identifier,
             password,
             adapter(:user_repository),
             adapter(:password_hasher)
           ),
         {:ok, client} <- RobineId.Clients.get(request.client_id, adapter(:client_repository)),
         {:ok, session_id} <-
           RobineId.Security.start_session(
             user.id,
             session_policy()["max_concurrent"],
             adapter(:session_registry)
           ) do
      auth_time = System.system_time(:second)
      {claims, id_token_claims} = claim_sets(user, request)

      {:ok,
       %{
         user: user,
         session_id: session_id,
         auth_time: auth_time,
         claims: claims,
         id_token_claims: id_token_claims,
         consent_required?: RobineId.Clients.consent_required?(client),
         client: client
       }}
    end
  end

  def approve(request, subject, claims),
    do: approve(request, subject, claims, %{}, System.system_time(:second))

  def approve(request, subject, claims, auth_time),
    do: approve(request, subject, claims, %{}, auth_time)

  def approve(request, subject, claims, id_token_claims, auth_time) do
    with {:ok, metadata} <-
           RobineId.Protocol.discovery(request.issuer_id, adapter(:configuration_store)),
         {:ok, code} <-
           RobineId.Protocol.issue_authorization_code(
             request,
             metadata["issuer"],
             subject,
             adapter(:authorization_code_store),
             code_options(request.issuer_id)
             |> Keyword.put(:claims, claims)
             |> Keyword.put(:id_token_claims, id_token_claims)
             |> Keyword.put(:auth_time, auth_time)
           ) do
      {:ok, append_query(request.redirect_uri, %{"code" => code, "state" => request.state})}
    end
  end

  def deny(request) do
    {:ok,
     append_query(request.redirect_uri, %{
       "error" => "access_denied",
       "error_description" => "The user denied the request",
       "state" => request.state
     })}
  end

  def end_session(subject, session_id) do
    RobineId.Security.end_session(subject, session_id, adapter(:session_registry))
  end

  defp claim_sets(user, request) do
    {:ok, snapshot} = RobineId.Configuration.active(adapter(:configuration_store))
    mappings = snapshot.data["claims"] || %{}

    requested_userinfo_claims =
      request.claims
      |> Map.get("userinfo", %{})
      |> Map.keys()

    requested_id_token_claims =
      request.claims
      |> Map.get("id_token", %{})
      |> Map.keys()

    {
      RobineId.Identity.map_claims(user, mappings, request.scope, requested_userinfo_claims),
      RobineId.Identity.map_claims(user, mappings, [], requested_id_token_claims)
    }
  end

  defp session_policy do
    {:ok, snapshot} = RobineId.Configuration.active(adapter(:configuration_store))
    get_in(snapshot.data, ["authentication", "session"]) || %{"max_concurrent" => 5}
  end

  defp rate_limit_options do
    {:ok, snapshot} = RobineId.Configuration.active(adapter(:configuration_store))
    policy = get_in(snapshot.data, ["authentication", "rate_limit"]) || %{}
    [limit: policy["attempts"] || 5, window_seconds: policy["window_seconds"] || 60]
  end

  defp code_options(issuer_id) do
    {:ok, issuer} = RobineId.Configuration.issuer(issuer_id, adapter(:configuration_store))
    [lifetime: get_in(issuer, ["token_policy", "authorization_code_lifetime"]) || 60]
  end

  defp append_query(uri, values) do
    parsed = URI.parse(uri)
    values = values |> Enum.reject(fn {_key, value} -> is_nil(value) end) |> Map.new()
    query = (parsed.query || "") |> URI.decode_query() |> Map.merge(values)
    %{parsed | query: URI.encode_query(query)} |> URI.to_string()
  end

  defp adapter(name), do: Runtime.adapter(name)
end
