defmodule RobineId.Identity.Accounts do
  @moduledoc "Self-service and administrative management of configured identities."

  import Ecto.Changeset

  alias RobineId.Identity.Adapters.{AccountOverrides, ConfigurationUserRepository}
  alias RobineId.Identity.Entities.User

  @profile_types %{
    name: :string,
    email: :string,
    current_password: :string,
    new_password: :string,
    password_confirmation: :string
  }
  @admin_types %{name: :string, email: :string, roles: :string, enabled: :boolean}
  @role_pattern ~r/^[a-z][a-z0-9:_-]{0,63}$/

  def list_users do
    with {:ok, users} <- ConfigurationUserRepository.list() do
      users
      |> Enum.map(&AccountOverrides.apply_including_disabled/1)
      |> collect_users()
    end
  end

  def get_user(id) do
    with {:ok, user} <- ConfigurationUserRepository.get_by_id(id) do
      AccountOverrides.apply_including_disabled(user)
    end
  end

  def profile_changeset(%User{} = user, attrs \\ %{}) do
    data = %{
      name: user.name || "",
      email: user.email || "",
      current_password: "",
      new_password: "",
      password_confirmation: ""
    }

    {data, @profile_types}
    |> cast(attrs, Map.keys(@profile_types))
    |> validate_required([:name, :email])
    |> validate_length(:name, min: 1, max: 160)
    |> validate_length(:email, max: 320)
    |> validate_format(:email, ~r/^[^\s@]+@[^\s@]+\.[^\s@]+$/)
  end

  def update_profile(%User{} = user, attrs, password_hasher) do
    changeset =
      user
      |> profile_changeset(attrs)
      |> validate_password_change(user, password_hasher)

    if changeset.valid? do
      new_password = get_field(changeset, :new_password)

      password_hash =
        if present?(new_password),
          do: password_hasher.hash(new_password),
          else: user.password_hash

      claims = Map.put(user.claims || %{}, "updated_at", System.system_time(:second))

      AccountOverrides.upsert(user, %{
        name: get_field(changeset, :name),
        email: get_field(changeset, :email),
        password_hash: password_hash,
        claims: claims
      })
    else
      {:error, %{changeset | action: :validate}}
    end
  end

  def admin_changeset(%User{} = user, attrs \\ %{}) do
    data = %{
      name: user.name || "",
      email: user.email || "",
      roles: Enum.join(user.roles, ", "),
      enabled: user.enabled
    }

    {data, @admin_types}
    |> cast(attrs, Map.keys(@admin_types))
    |> validate_required([:name, :email, :enabled])
    |> validate_length(:name, min: 1, max: 160)
    |> validate_length(:email, max: 320)
    |> validate_format(:email, ~r/^[^\s@]+@[^\s@]+\.[^\s@]+$/)
    |> validate_roles()
  end

  def update_by_admin(%User{} = actor, %User{} = target, attrs) do
    changeset =
      target
      |> admin_changeset(attrs)
      |> prevent_self_lockout(actor, target)

    if changeset.valid? do
      AccountOverrides.upsert(target, %{
        name: get_field(changeset, :name),
        email: get_field(changeset, :email),
        roles: parse_roles(get_field(changeset, :roles)),
        enabled: get_field(changeset, :enabled)
      })
    else
      {:error, %{changeset | action: :validate}}
    end
  end

  def admin?(%User{enabled: true, roles: roles}), do: "admin" in roles
  def admin?(_user), do: false

  defp validate_password_change(changeset, user, password_hasher) do
    new_password = get_field(changeset, :new_password)

    if present?(new_password) do
      changeset
      |> validate_required([:current_password, :password_confirmation])
      |> validate_length(:new_password, min: 12, max: 128)
      |> validate_password_confirmation()
      |> verify_current_password(user, password_hasher)
    else
      changeset
    end
  end

  defp validate_password_confirmation(changeset) do
    if get_field(changeset, :new_password) == get_field(changeset, :password_confirmation) do
      changeset
    else
      add_error(changeset, :password_confirmation, "does not match the new password")
    end
  end

  defp verify_current_password(changeset, user, password_hasher) do
    current_password = get_field(changeset, :current_password)

    if present?(current_password) and password_hasher.verify(current_password, user.password_hash) do
      changeset
    else
      add_error(changeset, :current_password, "is incorrect")
    end
  end

  defp validate_roles(changeset) do
    roles = changeset |> get_field(:roles, "") |> parse_roles()

    if roles == Enum.uniq(roles) and Enum.all?(roles, &Regex.match?(@role_pattern, &1)) do
      changeset
    else
      add_error(changeset, :roles, "must contain unique lowercase role identifiers")
    end
  end

  defp prevent_self_lockout(changeset, %User{id: id}, %User{id: id}) do
    roles = changeset |> get_field(:roles, "") |> parse_roles()

    changeset =
      if get_field(changeset, :enabled) == false,
        do: add_error(changeset, :enabled, "cannot disable your own account"),
        else: changeset

    if "admin" not in roles,
      do: add_error(changeset, :roles, "cannot remove your own admin role"),
      else: changeset
  end

  defp prevent_self_lockout(changeset, _actor, _target), do: changeset

  defp parse_roles(value) when is_binary(value) do
    value
    |> String.split(",", trim: true)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
  end

  defp collect_users(results) do
    Enum.reduce_while(results, {:ok, []}, fn
      {:ok, user}, {:ok, users} -> {:cont, {:ok, [user | users]}}
      {:error, reason}, _acc -> {:halt, {:error, reason}}
    end)
    |> case do
      {:ok, users} -> {:ok, Enum.reverse(users)}
      error -> error
    end
  end

  defp present?(value), do: is_binary(value) and String.trim(value) != ""
end
