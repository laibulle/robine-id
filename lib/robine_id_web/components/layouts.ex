defmodule RobineIdWeb.Layouts do
  @moduledoc """
  This module holds layouts and related functionality
  used by your application.
  """
  use RobineIdWeb, :html

  # Embed all files in layouts/* within this module.
  # The default root.html.heex file contains the HTML
  # skeleton of your application, namely HTML headers
  # and other static content.
  embed_templates "layouts/*"

  @doc """
  Renders your app layout.

  This function is typically invoked from every template,
  and it often contains your application menu, sidebar,
  or similar.

  ## Examples

      <Layouts.app flash={@flash}>
        <h1>Content</h1>
      </Layouts.app>

  """
  attr :flash, :map, required: true, doc: "the map of flash messages"

  attr :current_scope, :map,
    default: nil,
    doc: "the current [scope](https://phoenix.hexdocs.pm/scopes.html)"

  slot :inner_block, required: true

  def app(assigns) do
    ~H"""
    <header class="navbar px-4 sm:px-6 lg:px-8">
      <div class="flex-1">
        <a href="/" class="flex-1 flex w-fit items-center gap-2">
          <img src={~p"/images/logo.svg"} width="36" />
          <span class="text-sm font-semibold">v{Application.spec(:phoenix, :vsn)}</span>
        </a>
      </div>
      <div class="flex-none">
        <ul class="flex flex-column px-1 space-x-4 items-center">
          <li>
            <a href="https://phoenixframework.org/" class="btn btn-ghost">Website</a>
          </li>
          <li>
            <a href="https://github.com/phoenixframework/phoenix" class="btn btn-ghost">GitHub</a>
          </li>
          <li>
            <.theme_toggle />
          </li>
          <li>
            <a href="https://phoenix.hexdocs.pm/overview.html" class="btn btn-primary">
              Get Started <span aria-hidden="true">&rarr;</span>
            </a>
          </li>
        </ul>
      </div>
    </header>

    <main class="px-4 py-20 sm:px-6 lg:px-8">
      <div class="mx-auto max-w-2xl space-y-4">
        {render_slot(@inner_block)}
      </div>
    </main>

    <.flash_group flash={@flash} />
    """
  end

  attr :flash, :map, required: true
  attr :current_user, :any, default: nil
  attr :theme, :any, required: true
  attr :title, :string, required: true
  slot :inner_block, required: true

  def portal(assigns) do
    ~H"""
    <div class="min-h-screen bg-[radial-gradient(circle_at_top_left,rgba(13,148,136,0.12),transparent_30rem),linear-gradient(to_bottom,#f8fafc,#f1f5f9)] text-slate-800">
      <header class="border-b border-slate-200/80 bg-white/85 backdrop-blur-xl">
        <nav
          class="mx-auto flex max-w-7xl items-center justify-between gap-5 px-5 py-4 sm:px-8"
          aria-label="Account navigation"
        >
          <a
            href={RobineId.Runtime.path("/")}
            class="flex items-center gap-3 font-bold tracking-tight text-slate-900 transition hover:text-teal-800"
          >
            <img :if={@theme.logo} src={@theme.logo} alt="" class="h-9 w-9 rounded-xl object-contain" />
            <img
              :if={!@theme.logo}
              src={RobineId.Runtime.path("/images/brand/robine-mark.png")}
              alt=""
              class="h-9 w-9 object-contain"
            />
            <span>{@theme.product_name}</span>
          </a>
          <div class="flex items-center gap-2 sm:gap-3">
            <a
              :if={@current_user}
              href={RobineId.Runtime.path("/account")}
              class="rounded-lg px-3 py-2 text-sm font-semibold text-slate-600 transition hover:bg-slate-100 hover:text-slate-900"
            >Account</a>
            <a
              :if={@current_user && RobineId.Identity.Accounts.admin?(@current_user)}
              href={RobineId.Runtime.path("/admin")}
              class="rounded-lg px-3 py-2 text-sm font-semibold text-slate-600 transition hover:bg-slate-100 hover:text-slate-900"
            >Admin</a>
            <.link
              :if={@current_user}
              href={RobineId.Runtime.path("/logout")}
              method="post"
              id="portal-sign-out"
              class="rounded-lg border border-slate-300 px-3 py-2 text-sm font-semibold text-slate-700 transition hover:border-slate-400 hover:bg-white"
            >Sign out</.link>
          </div>
        </nav>
      </header>

      <main class="mx-auto max-w-7xl px-5 py-10 sm:px-8 sm:py-14">
        {render_slot(@inner_block)}
      </main>

      <.flash_group flash={@flash} />
    </div>
    """
  end

  attr :theme, :any, required: true
  attr :labelledby, :string, required: true
  attr :eyebrow, :string, required: true
  slot :inner_block, required: true

  def auth(assigns) do
    ~H"""
    <main class="auth-shell" style={"--auth-primary: #{@theme.primary_color}"}>
      <section class="auth-card" aria-labelledby={@labelledby}>
        <img
          :if={@theme.logo}
          src={@theme.logo}
          alt={@theme.product_name}
          class="configured-logo"
        />
        <img
          :if={!@theme.logo}
          src={RobineId.Runtime.path("/images/brand/robine-mark.png")}
          alt=""
          class="auth-brand-logo"
        />
        <p class="eyebrow">{@eyebrow}</p>
        {render_slot(@inner_block)}
      </section>
    </main>
    """
  end

  @doc """
  Shows the flash group with standard titles and content.

  ## Examples

      <.flash_group flash={@flash} />
  """
  attr :flash, :map, required: true, doc: "the map of flash messages"
  attr :id, :string, default: "flash-group", doc: "the optional id of flash container"

  def flash_group(assigns) do
    ~H"""
    <div id={@id} aria-live="polite">
      <.flash kind={:info} flash={@flash} />
      <.flash kind={:error} flash={@flash} />
    </div>
    """
  end

  @doc """
  Provides dark vs light theme toggle based on themes defined in app.css.

  See <head> in root.html.heex which applies the theme before page load.
  """
  def theme_toggle(assigns) do
    ~H"""
    <div class="card relative flex flex-row items-center border-2 border-base-300 bg-base-300 rounded-full">
      <div class="absolute w-1/3 h-full rounded-full border-1 border-base-200 bg-base-100 brightness-200 left-0 [[data-theme=light]_&]:left-1/3 [[data-theme=dark]_&]:left-2/3 [[data-theme-source=system]_&]:!left-0 transition-[left]" />

      <button
        class="flex p-2 cursor-pointer w-1/3"
        data-phx-theme="system"
      >
        <.icon name="hero-computer-desktop-micro" class="size-4 opacity-75 hover:opacity-100" />
      </button>

      <button
        class="flex p-2 cursor-pointer w-1/3"
        data-phx-theme="light"
      >
        <.icon name="hero-sun-micro" class="size-4 opacity-75 hover:opacity-100" />
      </button>

      <button
        class="flex p-2 cursor-pointer w-1/3"
        data-phx-theme="dark"
      >
        <.icon name="hero-moon-micro" class="size-4 opacity-75 hover:opacity-100" />
      </button>
    </div>
    """
  end
end
