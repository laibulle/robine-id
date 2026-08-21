defmodule RobineId.Clients.Entities.Client do
  @moduledoc "A validated OpenID Connect relying-party client."

  @enforce_keys [
    :id,
    :name,
    :type,
    :redirect_uris,
    :scopes,
    :grant_types,
    :authentication_methods
  ]
  defstruct [
    :id,
    :name,
    :type,
    :redirect_uris,
    :post_logout_redirect_uris,
    :scopes,
    :grant_types,
    :authentication_method,
    :authentication_methods,
    :pkce_required,
    :nonce_required,
    :secret_reference,
    :consent_required,
    :branding
  ]

  @type t :: %__MODULE__{}

  def from_config(data) when is_map(data) do
    type = data["type"] || "public"
    authentication_methods = authentication_methods(data, type)

    with :ok <- require_field(data, "id"),
         :ok <- require_field(data, "redirect_uris"),
         :ok <- validate_type(type),
         :ok <- validate_pkce_required(type, data),
         :ok <- validate_nonce_required(type, data),
         :ok <- validate_authentication(type, authentication_methods, data) do
      {:ok,
       %__MODULE__{
         id: data["id"],
         name: data["name"] || data["id"],
         type: type_atom(type),
         redirect_uris: data["redirect_uris"],
         post_logout_redirect_uris: data["post_logout_redirect_uris"] || [],
         scopes: data["scopes"] || ["openid"],
         grant_types: data["grant_types"] || ["authorization_code"],
         authentication_method: List.first(authentication_methods),
         authentication_methods: authentication_methods,
         pkce_required: Map.get(data, "pkce_required", true),
         nonce_required: Map.get(data, "nonce_required", type == "public"),
         secret_reference: data["secret_reference"],
         consent_required: Map.get(data, "consent_required", true),
         branding: data["branding"] || %{}
       }}
    end
  end

  defp require_field(data, field) do
    if Map.has_key?(data, field), do: :ok, else: {:error, {:invalid_client, "missing #{field}"}}
  end

  defp validate_type(type) when type in ["public", "confidential"], do: :ok
  defp validate_type(_), do: {:error, {:invalid_client, "type must be public or confidential"}}

  defp validate_authentication("public", ["none"], _data), do: :ok

  defp validate_authentication("confidential", methods, %{"secret_reference" => reference})
       when is_list(methods) and methods != [] do
    if Enum.all?(methods, &(&1 in ["client_secret_basic", "client_secret_post"])) do
      validate_secret_reference(reference)
    else
      {:error, {:invalid_client, "unsupported authentication method"}}
    end
  end

  defp validate_authentication("confidential", _methods, _data),
    do:
      {:error,
       {:invalid_client, "confidential client authentication method requires a secret_reference"}}

  defp validate_authentication(_, _, _),
    do: {:error, {:invalid_client, "authentication method is incompatible with client type"}}

  defp authentication_methods(data, type) do
    case data do
      %{"authentication_methods" => methods} when is_list(methods) -> methods
      %{"authentication_method" => method} when is_binary(method) -> [method]
      _ -> [default_authentication(type)]
    end
  end

  defp validate_secret_reference(secret) when is_binary(secret) and secret != "", do: :ok

  defp validate_secret_reference(%{"provider" => "env", "key" => key})
       when is_binary(key) and key != "",
       do: :ok

  defp validate_secret_reference(_reference),
    do: {:error, {:invalid_client, "secret_reference must be a secret string or env reference"}}

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

  defp validate_nonce_required(type, data) do
    case Map.get(data, "nonce_required", type == "public") do
      value when is_boolean(value) -> :ok
      _ -> {:error, {:invalid_client, "nonce_required must be a boolean"}}
    end
  end

  defp type_atom("public"), do: :public
  defp type_atom("confidential"), do: :confidential
end
