defmodule RobineIdWeb.Router do
  use RobineIdWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug RobineIdWeb.Plugs.SessionPolicy
    plug :fetch_live_flash
    plug :put_root_layout, html: {RobineIdWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  scope "/", RobineIdWeb do
    pipe_through :browser

    get "/", PageController, :home
    get "/docs", PageController, :docs
    get "/:issuer_id/authorize", AuthorizationController, :new
    post "/:issuer_id/authorize", AuthorizationController, :create
    post "/:issuer_id/authorize/consent", AuthorizationController, :consent
    get "/:issuer_id/logout", LogoutController, :new
    post "/:issuer_id/logout", LogoutController, :create
  end

  scope "/", RobineIdWeb do
    pipe_through :api

    get "/health/live", HealthController, :live
    get "/health/ready", HealthController, :ready
    get "/:issuer_id/.well-known/openid-configuration", DiscoveryController, :show
    get "/:issuer_id/jwks.json", JwksController, :show
    post "/:issuer_id/token", TokenController, :create
    get "/:issuer_id/userinfo", UserInfoController, :show
  end

  # Other scopes may use custom stacks.
  # scope "/api", RobineIdWeb do
  #   pipe_through :api
  # end
end
