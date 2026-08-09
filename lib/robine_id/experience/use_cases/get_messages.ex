defmodule RobineId.Experience.UseCases.GetMessages do
  @moduledoc "Resolves stable UI message keys with per-message locale fallback."

  @defaults %{
    "sign_in.title" => "Welcome back",
    "sign_in.intro" => "Sign in to continue",
    "sign_in.identifier" => "Email",
    "sign_in.password" => "Password",
    "sign_in.submit" => "Continue",
    "consent.title" => "Allow access?",
    "consent.intro" => "This application would like permission to:",
    "consent.approve" => "Allow access",
    "consent.deny" => "Cancel"
  }

  def execute(theme, requested_locale) do
    configured = theme.messages || %{}
    default_messages = configured[theme.default_locale] || %{}
    requested_messages = configured[requested_locale] || %{}

    {:ok,
     @defaults
     |> Map.merge(default_messages)
     |> Map.merge(requested_messages)}
  end
end
