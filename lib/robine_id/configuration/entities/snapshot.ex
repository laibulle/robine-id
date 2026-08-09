defmodule RobineId.Configuration.Entities.Snapshot do
  @moduledoc "Validated, immutable desired configuration state."

  @enforce_keys [:data, :fingerprint]
  defstruct [:data, :fingerprint]

  @type t :: %__MODULE__{data: map(), fingerprint: String.t()}

  @root_fields ~w(schema_version issuers clients users claims branding reconciliation authentication storage telemetry)
  @issuer_fields ~w(id url scopes token_policy claim_mappings branding)
  @client_fields ~w(id name type redirect_uris post_logout_redirect_uris scopes grant_types authentication_method pkce_required nonce_required secret_reference consent_required branding)
  @user_fields ~w(id identifier password_hash name email claims)
  @branding_fields ~w(product_name logo favicon primary_color font_family support_url privacy_url terms_url default_locale locales messages)

  @spec new(map()) :: {:ok, t()} | {:error, [String.t()]}
  def new(data) when is_map(data) do
    errors =
      []
      |> unknown_fields(data, @root_fields, "root")
      |> require_version(data)
      |> validate_issuers(data)
      |> validate_clients(data)
      |> validate_users(data)
      |> validate_branding(data)
      |> validate_claim_mappings(data)
      |> validate_reconciliation(data)
      |> validate_authentication(data)
      |> validate_storage(data)
      |> validate_telemetry(data)

    case errors do
      [] -> {:ok, %__MODULE__{data: data, fingerprint: fingerprint(data)}}
      errors -> {:error, Enum.reverse(errors)}
    end
  end

  def new(_), do: {:error, ["configuration root must be an object"]}

  defp require_version(errors, %{"schema_version" => 1}), do: errors
  defp require_version(errors, _), do: ["schema_version must be 1" | errors]

  defp validate_issuers(errors, %{"issuers" => issuers}) when is_list(issuers) do
    errors
    |> duplicates(issuers, "id", "issuer identifiers")
    |> Enum.concat(Enum.flat_map(issuers, &validate_issuer/1))
  end

  defp validate_issuers(errors, _), do: ["issuers must be a list" | errors]

  defp validate_issuer(%{"id" => id, "url" => url} = data)
       when is_binary(id) and is_binary(url) do
    errors =
      data
      |> unknown_field_errors(@issuer_fields, "issuer #{inspect(id)}")
      |> validate_token_policy(data["token_policy"], id)
      |> validate_nested_branding(data["branding"], "issuer #{inspect(id)} branding")

    case URI.new(url) do
      {:ok, %URI{scheme: "https", host: host}} when is_binary(host) ->
        errors

      {:ok, %URI{scheme: "http", host: host}}
      when host in ["localhost", "127.0.0.1", "::1"] ->
        errors

      _ ->
        ["issuer #{inspect(id)} has an invalid absolute URL" | errors]
    end
  end

  defp validate_issuer(_), do: ["every issuer requires string id and url fields"]

  defp validate_token_policy(errors, nil, _issuer_id), do: errors

  defp validate_token_policy(errors, policy, issuer_id) when is_map(policy) do
    allowed = ~w(authorization_code_lifetime id_token_lifetime access_token_lifetime clock_skew)
    errors = unknown_fields(errors, policy, allowed, "issuer #{inspect(issuer_id)} token_policy")

    Enum.reduce(allowed, errors, fn field, acc ->
      case policy[field] do
        nil ->
          acc

        value when is_integer(value) and value > 0 and value <= 86_400 ->
          acc

        _ ->
          ["issuer #{inspect(issuer_id)} token_policy #{field} must be between 1 and 86400" | acc]
      end
    end)
  end

  defp validate_token_policy(errors, _policy, issuer_id),
    do: ["issuer #{inspect(issuer_id)} token_policy must be an object" | errors]

  defp validate_clients(errors, %{"clients" => clients}) when is_list(clients) do
    errors
    |> duplicates(clients, "id", "client identifiers")
    |> Enum.concat(Enum.flat_map(clients, &validate_client/1))
  end

  defp validate_clients(errors, _), do: ["clients must be a list" | errors]

  defp validate_client(%{"id" => id, "redirect_uris" => uris} = data)
       when is_binary(id) and is_list(uris) and uris != [] do
    errors =
      data
      |> unknown_field_errors(@client_fields, "client #{inspect(id)}")
      |> validate_nested_branding(data["branding"], "client #{inspect(id)} branding")

    all_redirects = uris ++ (data["post_logout_redirect_uris"] || [])

    cond do
      not Enum.all?(all_redirects, &valid_redirect_uri?/1) ->
        ["client #{inspect(id)} contains an invalid redirect URI" | errors]

      match?({:error, _}, RobineId.Clients.Entities.Client.from_config(data)) ->
        {:error, {_type, message}} = RobineId.Clients.Entities.Client.from_config(data)
        ["client #{inspect(id)} #{message}" | errors]

      true ->
        errors
    end
  end

  defp validate_client(_), do: ["every client requires a string id and non-empty redirect_uris"]

  defp validate_users(errors, %{"users" => users}) when is_list(users) do
    errors
    |> duplicates(users, "id", "user identifiers")
    |> duplicates(users, "identifier", "user login identifiers")
    |> Enum.concat(Enum.flat_map(users, &validate_user/1))
  end

  defp validate_users(errors, %{"users" => _}), do: ["users must be a list" | errors]
  defp validate_users(errors, _), do: errors

  defp validate_user(%{"id" => id, "identifier" => identifier, "password_hash" => hash} = data)
       when is_binary(id) and is_binary(identifier) and is_binary(hash) do
    errors = unknown_field_errors(data, @user_fields, "user #{inspect(id)}")

    case Regex.run(~r/^\$2[aby]\$(\d{2})\$[.\/A-Za-z0-9]{53}$/, hash) do
      [_, cost] when cost >= "10" and cost <= "16" ->
        errors

      _ ->
        ["user #{inspect(id)} password_hash must be bcrypt with cost between 10 and 16" | errors]
    end
  end

  defp validate_user(_),
    do: ["every user requires string id, identifier, and password_hash fields"]

  defp validate_branding(errors, %{"branding" => branding}) when is_map(branding) do
    validate_nested_branding(errors, branding, "branding")
  end

  defp validate_branding(errors, %{"branding" => _}), do: ["branding must be an object" | errors]
  defp validate_branding(errors, _), do: errors

  defp validate_nested_branding(errors, nil, _location), do: errors

  defp validate_nested_branding(errors, branding, location) when is_map(branding) do
    errors = unknown_fields(errors, branding, @branding_fields, location)

    errors =
      case branding["primary_color"] do
        nil -> errors
        color when is_binary(color) -> validate_primary_color(errors, color)
        _ -> ["#{location} primary_color must be a CSS hex color" | errors]
      end

    validate_messages(errors, branding["messages"], location)
  end

  defp validate_nested_branding(errors, _branding, location),
    do: ["#{location} must be an object" | errors]

  defp validate_messages(errors, nil, _location), do: errors

  defp validate_messages(errors, messages, location) when is_map(messages) do
    if Enum.all?(messages, fn {locale, translations} ->
         is_binary(locale) and is_map(translations) and
           Enum.all?(translations, fn {key, value} -> is_binary(key) and is_binary(value) end)
       end) do
      errors
    else
      ["#{location} messages must contain locale objects with string values" | errors]
    end
  end

  defp validate_messages(errors, _messages, location),
    do: ["#{location} messages must be an object" | errors]

  defp validate_claim_mappings(errors, %{"claims" => mappings}) when is_map(mappings) do
    Enum.reduce(mappings, errors, fn {claim, mapping}, acc ->
      case {claim, mapping} do
        {reserved, _mapping} when reserved in ~w(iss sub aud iat exp nonce) ->
          ["claim #{inspect(claim)} is reserved by OpenID Connect" | acc]

        {_claim, %{"source" => source, "scope" => scope}}
        when is_binary(claim) and is_binary(source) and is_binary(scope) ->
          unknown_fields(acc, mapping, ["source", "scope"], "claim #{inspect(claim)}")

        _ ->
          ["claim #{inspect(claim)} requires string source and scope fields" | acc]
      end
    end)
  end

  defp validate_claim_mappings(errors, %{"claims" => _}),
    do: ["claims must be an object" | errors]

  defp validate_claim_mappings(errors, _), do: errors

  defp validate_primary_color(errors, "#" <> hex = color) when byte_size(hex) == 6 do
    with {red, ""} <- Integer.parse(String.slice(hex, 0, 2), 16),
         {green, ""} <- Integer.parse(String.slice(hex, 2, 2), 16),
         {blue, ""} <- Integer.parse(String.slice(hex, 4, 2), 16),
         true <- contrast_with_white(red, green, blue) >= 4.5 do
      errors
    else
      false ->
        ["branding primary_color #{color} has insufficient contrast with white text" | errors]

      _ ->
        ["branding primary_color must be a CSS hex color" | errors]
    end
  end

  defp validate_primary_color(errors, _),
    do: ["branding primary_color must be a CSS hex color" | errors]

  defp validate_reconciliation(errors, %{
         "reconciliation" => %{"deletion_policy" => policy} = reconciliation
       })
       when policy in ["disable", "retain", "delete"] do
    unknown_fields(errors, reconciliation, ["deletion_policy"], "reconciliation")
  end

  defp validate_reconciliation(errors, %{"reconciliation" => _}),
    do: ["reconciliation requires deletion_policy set to disable, retain, or delete" | errors]

  defp validate_reconciliation(errors, _), do: errors

  defp validate_authentication(errors, %{"authentication" => authentication})
       when is_map(authentication) do
    errors =
      unknown_fields(
        errors,
        authentication,
        ["session", "rate_limit", "methods"],
        "authentication"
      )

    errors =
      case authentication["methods"] do
        nil ->
          errors

        methods when is_list(methods) and methods != [] ->
          if Enum.all?(methods, &(&1 == "password")),
            do: errors,
            else: ["authentication methods contains an unsupported method" | errors]

        _ ->
          ["authentication methods must be a non-empty list" | errors]
      end

    errors
    |> validate_positive_fields(authentication["session"], "authentication session", [
      "idle_timeout",
      "absolute_timeout",
      "max_concurrent"
    ])
    |> validate_positive_fields(authentication["rate_limit"], "authentication rate_limit", [
      "attempts",
      "window_seconds"
    ])
  end

  defp validate_authentication(errors, %{"authentication" => _}),
    do: ["authentication must be an object" | errors]

  defp validate_authentication(errors, _), do: errors

  defp validate_positive_fields(errors, nil, _location, _fields), do: errors

  defp validate_positive_fields(errors, value, location, fields) when is_map(value) do
    errors = unknown_fields(errors, value, fields, location)

    Enum.reduce(fields, errors, fn field, acc ->
      case value[field] do
        number when is_integer(number) and number > 0 -> acc
        _ -> ["#{location} #{field} must be a positive integer" | acc]
      end
    end)
  end

  defp validate_positive_fields(errors, _value, location, _fields),
    do: ["#{location} must be an object" | errors]

  defp validate_storage(errors, %{"storage" => storage}) when is_map(storage) do
    errors =
      unknown_fields(
        errors,
        storage,
        ["database_path", "pool_size", "signing_key_path"],
        "storage"
      )

    errors =
      case storage["database_path"] do
        path when is_binary(path) and path != "" -> errors
        %{"provider" => "env", "key" => key} when is_binary(key) and key != "" -> errors
        _ -> ["storage database_path must be a path or typed env reference" | errors]
      end

    errors =
      case storage["pool_size"] do
        size when is_integer(size) and size > 0 -> errors
        _ -> ["storage pool_size must be a positive integer" | errors]
      end

    case storage["signing_key_path"] do
      nil -> errors
      path when is_binary(path) and path != "" -> errors
      _ -> ["storage signing_key_path must be a path" | errors]
    end
  end

  defp validate_storage(errors, %{"storage" => _}), do: ["storage must be an object" | errors]
  defp validate_storage(errors, _), do: errors

  defp validate_telemetry(errors, %{"telemetry" => telemetry}) when is_map(telemetry) do
    errors = unknown_fields(errors, telemetry, ["log_level"], "telemetry")

    case telemetry["log_level"] do
      nil -> errors
      level when level in ["debug", "info", "warning", "error"] -> errors
      _ -> ["telemetry log_level must be debug, info, warning, or error" | errors]
    end
  end

  defp validate_telemetry(errors, %{"telemetry" => _}),
    do: ["telemetry must be an object" | errors]

  defp validate_telemetry(errors, _), do: errors

  defp contrast_with_white(red, green, blue) do
    luminance =
      [red, green, blue]
      |> Enum.map(&(&1 / 255))
      |> Enum.map(fn channel ->
        if channel <= 0.04045,
          do: channel / 12.92,
          else: :math.pow((channel + 0.055) / 1.055, 2.4)
      end)
      |> then(fn [r, g, b] -> 0.2126 * r + 0.7152 * g + 0.0722 * b end)

    1.05 / (luminance + 0.05)
  end

  defp valid_redirect_uri?(uri) when is_binary(uri) do
    case URI.new(uri) do
      {:ok, %URI{scheme: "https", host: host, fragment: nil}} when is_binary(host) ->
        true

      {:ok, %URI{scheme: "http", host: host, fragment: nil}}
      when host in ["localhost", "127.0.0.1", "::1"] ->
        true

      _ ->
        false
    end
  end

  defp valid_redirect_uri?(_), do: false

  defp duplicates(errors, items, key, label) do
    values = Enum.map(items, &Map.get(&1, key))

    if length(values) == MapSet.size(MapSet.new(values)),
      do: errors,
      else: ["#{label} must be unique" | errors]
  end

  defp unknown_fields(errors, map, allowed, location) do
    unknown_field_errors(map, allowed, location) ++ errors
  end

  defp unknown_field_errors(map, allowed, location) do
    map
    |> Map.keys()
    |> Enum.reject(&(&1 in allowed))
    |> Enum.map(&"#{location} contains unknown field #{inspect(&1)}")
  end

  defp fingerprint(data) do
    data
    |> canonicalize()
    |> :erlang.term_to_binary()
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end

  defp canonicalize(map) when is_map(map) do
    map
    |> Enum.map(fn {key, value} -> {key, canonicalize(value)} end)
    |> Enum.sort()
  end

  defp canonicalize(list) when is_list(list) do
    list
    |> Enum.map(&canonicalize/1)
    |> Enum.sort()
  end

  defp canonicalize(value), do: value
end
