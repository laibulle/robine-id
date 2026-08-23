defmodule RobineId.Identity.Adapters.BcryptPasswordHasher do
  @moduledoc "Bcrypt password verification adapter."
  @behaviour RobineId.Identity.Ports.PasswordHasher

  @impl true
  def verify(password, hash), do: Bcrypt.verify_pass(password, hash)

  @impl true
  def hash(password), do: Bcrypt.hash_pwd_salt(password)

  @impl true
  def dummy_verify do
    Bcrypt.no_user_verify()
    false
  end
end
