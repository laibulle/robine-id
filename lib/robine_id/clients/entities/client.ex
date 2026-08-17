defmodule RobineId.Clients.Entities.Client do
  @moduledoc "A validated OpenID Connect relying-party client."

  @enforce_keys [:id, :name, :type, :redirect_uris, :scopes, :grant_types, :authentication_method]
  defstruct [
    :id,
    :name,
    :type,
    :redirect_uris,
    :post_logout_redirect_uris,
    :resources,
    :scopes,
    :grant_types,
    :authentication_method,
    :pkce_required,
    :nonce_required,
    :secret_reference,
    :jwks,
    :consent_required,
    :introspection_allowed,
    :require_pushed_authorization_requests,
    :branding
  ]

  @type t :: %__MODULE__{}

  def from_config(data) when is_map(data) do
    type = data["type"] || "public"
    authentication_method = data["authentication_method"] || default_authentication(type)

    with :ok <- require_field(data, "id"),
         :ok <- require_field(data, "redirect_uris"),
         :ok <- validate_type(type),
         :ok <- validate_pkce_required(type, data),
         :ok <- validate_nonce_required(type, data),
         :ok <- validate_introspection(type, data),
         :ok <- validate_pushed_authorization_requirement(data),
         :ok <- validate_resources(data),
         :ok <- validate_grant_types(data),
         :ok <- validate_user_grants(data),
         :ok <- validate_service_grant(type, data),
         :ok <- validate_authentication(type, authentication_method, data) do
      {:ok,
       %__MODULE__{
         id: data["id"],
         name: data["name"] || data["id"],
         type: type_atom(type),
         redirect_uris: data["redirect_uris"],
         post_logout_redirect_uris: data["post_logout_redirect_uris"] || [],
         resources: data["resources"] || [],
         scopes: data["scopes"] || ["openid"],
         grant_types: data["grant_types"] || ["authorization_code"],
         authentication_method: authentication_method,
         pkce_required: Map.get(data, "pkce_required", true),
         nonce_required: Map.get(data, "nonce_required", true),
         secret_reference: data["secret_reference"],
         jwks: data["jwks"],
         consent_required: Map.get(data, "consent_required", true),
         introspection_allowed: Map.get(data, "introspection_allowed", false),
         require_pushed_authorization_requests:
           Map.get(data, "require_pushed_authorization_requests", false),
         branding: data["branding"] || %{}
       }}
    end
  end

  defp require_field(data, field) do
    if Map.has_key?(data, field), do: :ok, else: {:error, {:invalid_client, "missing #{field}"}}
  end

  defp validate_type(type) when type in ["public", "confidential"], do: :ok
  defp validate_type(_), do: {:error, {:invalid_client, "type must be public or confidential"}}

  defp validate_authentication("public", "none", _data), do: :ok

  defp validate_authentication(
         "confidential",
         method,
         %{"secret_reference" => reference} = data
       )
       when method in ["client_secret_basic", "client_secret_post"] do
    if Map.has_key?(data, "jwks"),
      do: {:error, {:invalid_client, "secret authentication cannot also configure jwks"}},
      else: validate_secret_reference(reference)
  end

  defp validate_authentication(
         "confidential",
         "private_key_jwt",
         %{"jwks" => jwks} = data
       ) do
    if Map.has_key?(data, "secret_reference"),
      do: {:error, {:invalid_client, "private_key_jwt cannot configure a secret reference"}},
      else: validate_jwks(jwks)
  end

  defp validate_authentication(_, _, _),
    do: {:error, {:invalid_client, "authentication method is incompatible with client type"}}

  defp validate_secret_reference(secret) when is_binary(secret) and secret != "", do: :ok

  defp validate_secret_reference(%{"provider" => "env", "key" => key})
       when is_binary(key) and key != "",
       do: :ok

  defp validate_secret_reference(_reference),
    do: {:error, {:invalid_client, "secret_reference must be a secret string or env reference"}}

  defp validate_jwks(%{"keys" => keys})
       when is_list(keys) and keys != [] and length(keys) <= 16 do
    key_ids = Enum.map(keys, &Map.get(&1, "kid"))

    if Enum.all?(keys, &valid_jwk?/1) and Enum.uniq(key_ids) == key_ids,
      do: :ok,
      else: {:error, {:invalid_client, "jwks must contain unique RSA signing keys"}}
  end

  defp validate_jwks(_jwks),
    do: {:error, {:invalid_client, "jwks must contain one to sixteen RSA signing keys"}}

  defp valid_jwk?(%{"kty" => "RSA", "kid" => kid, "n" => n, "e" => e} = key)
       when is_binary(kid) and byte_size(kid) in 1..256 and is_binary(n) and
              byte_size(n) in 342..1368 and is_binary(e) and byte_size(e) in 2..16 do
    with true <- key["use"] in [nil, "sig"],
         true <- key["alg"] in [nil, "RS256"],
         {:ok, modulus} <- Base.url_decode64(n, padding: false),
         {:ok, exponent} <- Base.url_decode64(e, padding: false) do
      byte_size(modulus) in 256..1024 and byte_size(exponent) in 1..8
    else
      _ -> false
    end
  end

  defp valid_jwk?(_key), do: false

  defp default_authentication("public"), do: "none"
  defp default_authentication(_), do: "client_secret_basic"

  defp validate_pkce_required("public", %{"pkce_required" => false}),
    do: {:error, {:invalid_client, "public clients must require PKCE"}}

  defp validate_pkce_required(_type, data) do
    case Map.get(data, "pkce_required", true) do
      value when is_boolean(value) -> :ok
      _ -> {:error, {:invalid_client, "pkce_required must be a boolean"}}
    end
  end

  defp validate_nonce_required("public", %{"nonce_required" => false}),
    do: {:error, {:invalid_client, "public clients must require a nonce"}}

  defp validate_nonce_required(_type, data) do
    case Map.get(data, "nonce_required", true) do
      value when is_boolean(value) -> :ok
      _ -> {:error, {:invalid_client, "nonce_required must be a boolean"}}
    end
  end

  defp validate_introspection("public", %{"introspection_allowed" => true}),
    do: {:error, {:invalid_client, "public clients cannot use token introspection"}}

  defp validate_introspection(_type, data) do
    case Map.get(data, "introspection_allowed", false) do
      value when is_boolean(value) -> :ok
      _ -> {:error, {:invalid_client, "introspection_allowed must be a boolean"}}
    end
  end

  defp validate_pushed_authorization_requirement(data) do
    case Map.get(data, "require_pushed_authorization_requests", false) do
      false ->
        :ok

      true ->
        if "authorization_code" in Map.get(data, "grant_types", ["authorization_code"]),
          do: :ok,
          else:
            {:error,
             {:invalid_client,
              "require_pushed_authorization_requests requires the authorization_code grant"}}

      _ ->
        {:error, {:invalid_client, "require_pushed_authorization_requests must be a boolean"}}
    end
  end

  defp validate_resources(data) do
    case Map.get(data, "resources", []) do
      resources when is_list(resources) and length(resources) <= 256 ->
        if Enum.all?(resources, &valid_resource?/1) and Enum.uniq(resources) == resources,
          do: :ok,
          else: {:error, {:invalid_client, "resources must be unique absolute HTTPS URIs"}}

      _ ->
        {:error, {:invalid_client, "resources must be a list"}}
    end
  end

  defp valid_resource?(resource) when is_binary(resource) and byte_size(resource) in 1..4096 do
    case URI.new(resource) do
      {:ok, %URI{scheme: "https", host: host, userinfo: nil, fragment: nil}}
      when is_binary(host) ->
        true

      {:ok, %URI{scheme: "http", host: host, userinfo: nil, fragment: nil}}
      when host in ["localhost", "127.0.0.1", "::1"] ->
        true

      _ ->
        false
    end
  end

  defp valid_resource?(_resource), do: false

  defp validate_grant_types(data) do
    case Map.get(data, "grant_types", ["authorization_code"]) do
      grants when is_list(grants) and grants != [] ->
        cond do
          Enum.any?(
            grants,
            &(&1 not in [
                "authorization_code",
                "refresh_token",
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:token-exchange",
                "urn:ietf:params:oauth:grant-type:device_code"
              ])
          ) ->
            {:error, {:invalid_client, "grant_types contains an unsupported grant"}}

          Enum.uniq(grants) != grants ->
            {:error, {:invalid_client, "grant_types must be unique"}}

          true ->
            :ok
        end

      _ ->
        {:error, {:invalid_client, "grant_types must be a non-empty list"}}
    end
  end

  defp validate_service_grant(type, data) do
    grants = Map.get(data, "grant_types", ["authorization_code"])

    cond do
      "client_credentials" in grants and type != "confidential" ->
        {:error, {:invalid_client, "client_credentials requires a confidential client"}}

      "urn:ietf:params:oauth:grant-type:token-exchange" in grants and
          (type != "confidential" or Map.get(data, "resources", []) == []) ->
        {:error,
         {:invalid_client,
          "token exchange requires a confidential client with at least one resource"}}

      true ->
        :ok
    end
  end

  defp validate_user_grants(data) do
    grants = Map.get(data, "grant_types", ["authorization_code"])
    scopes = Map.get(data, "scopes", ["openid"])

    if Enum.any?(
         grants,
         &(&1 in [
             "authorization_code",
             "urn:ietf:params:oauth:grant-type:device_code"
           ])
       ) and "openid" not in scopes do
      {:error, {:invalid_client, "user authorization grants require the openid scope"}}
    else
      :ok
    end
  end

  defp type_atom("public"), do: :public
  defp type_atom("confidential"), do: :confidential
end
