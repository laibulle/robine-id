defmodule RobineId.Clients.Entities.Client do
  @moduledoc "A validated OpenID Connect relying-party client."

  @enforce_keys [:id, :name, :type, :redirect_uris, :scopes, :grant_types, :authentication_method]
  defstruct [
    :id,
    :name,
    :type,
    :redirect_uris,
    :post_logout_redirect_uris,
    :scopes,
    :grant_types,
    :authentication_method,
    :pkce_required,
    :nonce_required,
    :secret_reference,
    :consent_required,
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
         :ok <- validate_authentication(type, authentication_method, data) do
      {:ok,
       %__MODULE__{
         id: data["id"],
         name: data["name"] || data["id"],
         type: type_atom(type),
         redirect_uris: data["redirect_uris"],
         post_logout_redirect_uris: data["post_logout_redirect_uris"] || [],
         scopes: data["scopes"] || ["openid"],
         grant_types: data["grant_types"] || ["authorization_code"],
         authentication_method: authentication_method,
         pkce_required: Map.get(data, "pkce_required", true),
         nonce_required: Map.get(data, "nonce_required", true),
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

  defp validate_authentication("public", "none", _data), do: :ok

  defp validate_authentication("confidential", method, %{"secret_reference" => reference})
       when method in ["client_secret_basic", "client_secret_post"] do
    validate_secret_reference(reference)
  end

  defp validate_authentication(_, _, _),
    do: {:error, {:invalid_client, "authentication method is incompatible with client type"}}

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

  defp validate_nonce_required(_type, data) do
    case Map.get(data, "nonce_required", true) do
      value when is_boolean(value) -> :ok
      _ -> {:error, {:invalid_client, "nonce_required must be a boolean"}}
    end
  end

  defp type_atom("public"), do: :public
  defp type_atom("confidential"), do: :confidential
end
