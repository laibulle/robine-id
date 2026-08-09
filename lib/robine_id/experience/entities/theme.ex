defmodule RobineId.Experience.Entities.Theme do
  @moduledoc "Resolved, accessible presentation tokens."

  @enforce_keys [:product_name, :primary_color, :default_locale, :revision]
  defstruct [
    :product_name,
    :primary_color,
    :font_family,
    :logo,
    :favicon,
    :support_url,
    :privacy_url,
    :terms_url,
    :default_locale,
    :messages,
    :revision
  ]

  @type t :: %__MODULE__{}
end
