defmodule Mix.Tasks.RobineId.Oidc.Conformance.ConfigureTest do
  use ExUnit.Case, async: false

  test "generates the three static Basic OP clients" do
    directory =
      Path.join(
        System.tmp_dir!(),
        "robine-id-conformance-#{System.unique_integer([:positive])}"
      )

    on_exit(fn -> File.rm_rf!(directory) end)

    Mix.Task.reenable("robine_id.oidc.conformance.configure")

    Mix.Task.run("robine_id.oidc.conformance.configure", [
      "--alias",
      "robine-id-test",
      "--applications-dir",
      directory
    ])

    files = directory |> File.ls!() |> Enum.sort()

    assert files == [
             "robine-id-conformance-basic-1.json",
             "robine-id-conformance-basic-2.json",
             "robine-id-conformance-post.json"
           ]

    post_client =
      directory
      |> Path.join("robine-id-conformance-post.json")
      |> File.read!()
      |> Jason.decode!()

    assert post_client["authentication_method"] == "client_secret_post"

    assert post_client["redirect_uris"] == [
             "https://www.certification.openid.net/test/a/robine-id-test/callback"
           ]

    assert get_in(post_client, ["secret_reference", "key"]) ==
             "ROBINE_ID_CONFORMANCE_POST_SECRET"

    root_path = Application.fetch_env!(:robine_id, :configuration_path)

    assert {:ok, composed} =
             RobineId.Configuration.Adapters.ApplicationDirectoryLoader.read(
               root_path,
               directory
             )

    assert {:ok, _snapshot} = RobineId.Configuration.Entities.Snapshot.new(composed)
  end
end
