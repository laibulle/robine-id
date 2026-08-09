defmodule RobineId.IdentityTest do
  use ExUnit.Case, async: true

  defmodule Repository do
    @behaviour RobineId.Identity.Ports.UserRepository
    alias RobineId.Identity.Entities.User

    @impl true
    def get_by_identifier("known@example.test") do
      {:ok,
       %User{
         id: "user",
         identifier: "known@example.test",
         password_hash: Bcrypt.hash_pwd_salt("correct", log_rounds: 4)
       }}
    end

    def get_by_identifier(_), do: {:error, :not_found}

    @impl true
    def get_by_id("user"), do: get_by_identifier("known@example.test")
    def get_by_id(_), do: {:error, :not_found}
  end

  test "authenticates valid credentials" do
    assert {:ok, user} =
             RobineId.Identity.authenticate(
               " known@example.test ",
               "correct",
               Repository,
               RobineId.Identity.Adapters.BcryptPasswordHasher
             )

    assert user.id == "user"
  end

  test "uses the same public error for unknown users and wrong passwords" do
    assert {:error, :invalid_credentials} =
             RobineId.Identity.authenticate(
               "known@example.test",
               "wrong",
               Repository,
               RobineId.Identity.Adapters.BcryptPasswordHasher
             )

    assert {:error, :invalid_credentials} =
             RobineId.Identity.authenticate(
               "missing@example.test",
               "wrong",
               Repository,
               RobineId.Identity.Adapters.BcryptPasswordHasher
             )
  end
end
