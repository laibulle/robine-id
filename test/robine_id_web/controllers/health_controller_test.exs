defmodule RobineIdWeb.HealthControllerTest do
  use RobineIdWeb.ConnCase

  test "separates liveness and readiness", %{conn: conn} do
    assert %{"status" => "live"} = conn |> get(~p"/health/live") |> json_response(200)

    assert %{"status" => "ready", "revision" => revision} =
             build_conn() |> get(~p"/health/ready") |> json_response(200)

    assert byte_size(revision) == 64
  end
end
