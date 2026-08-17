defmodule RobineId.ExperienceTest do
  use ExUnit.Case, async: true

  alias RobineId.Configuration.Entities.Snapshot
  alias RobineId.Experience.Entities.Theme
  alias RobineId.Test.Configuration.MemoryStore

  test "falls back message by message when a locale is incomplete" do
    theme = %Theme{
      product_name: "Robine ID",
      primary_color: "#176b70",
      default_locale: "en",
      revision: "test",
      messages: %{
        "en" => %{"sign_in.intro" => "Continue to the application"},
        "fr" => %{"sign_in.title" => "Heureux de vous revoir"}
      }
    }

    assert {:ok, messages} = RobineId.Experience.messages(theme, "fr")
    assert messages["sign_in.title"] == "Heureux de vous revoir"
    assert messages["sign_in.intro"] == "Continue to the application"
    assert messages["sign_in.submit"] == "Continue"
  end

  test "resolves global, issuer, then client branding with stable asset URLs" do
    data = %{
      "schema_version" => 1,
      "branding" => %{
        "product_name" => "Global",
        "primary_color" => "#1f43b0",
        "logo" => "/assets/global.svg"
      },
      "issuers" => [
        %{
          "id" => "main",
          "url" => "https://id.example.test",
          "branding" => %{"product_name" => "Issuer"}
        }
      ],
      "clients" => [
        %{
          "id" => "web",
          "redirect_uris" => ["https://app.example.test/callback"],
          "branding" => %{"product_name" => "Client"}
        }
      ]
    }

    {:ok, snapshot} = Snapshot.new(data)
    {:ok, :activated} = MemoryStore.activate(snapshot)
    assert {:ok, theme} = RobineId.Experience.theme("main", "web", MemoryStore)
    assert theme.product_name == "Client"
    assert theme.primary_color == "#1f43b0"
    assert theme.logo =~ "/assets/global.svg?rev="

    assert {:ok, same_theme} = RobineId.Experience.theme("main", "web", MemoryStore)
    assert same_theme.logo == theme.logo
  end

  test "rejects primary colors that cannot carry white button text" do
    data = %{
      "schema_version" => 1,
      "branding" => %{"primary_color" => "#ffffff"},
      "issuers" => [%{"id" => "main", "url" => "https://id.example.test"}],
      "clients" => [
        %{"id" => "web", "redirect_uris" => ["https://app.example.test/callback"]}
      ]
    }

    assert {:error, errors} = Snapshot.new(data)
    assert Enum.any?(errors, &String.contains?(&1, "insufficient contrast"))
  end
end
