defmodule RobineIdWeb.AuthenticationComponents do
  @moduledoc "Shared authentication surfaces for OIDC and account sign-in."

  use RobineIdWeb, :html

  attr :theme, :any, required: true
  attr :form, :any, required: true
  attr :action, :string, required: true
  attr :form_id, :string, required: true
  attr :title, :string, required: true
  attr :intro, :string, required: true
  attr :context, :string, default: nil
  attr :identifier_label, :string, required: true
  attr :password_label, :string, required: true
  attr :submit_label, :string, required: true
  attr :privacy_note, :string, required: true
  attr :error, :string, default: nil
  attr :correlation_id, :string, default: nil

  def sign_in(assigns) do
    ~H"""
    <main class="auth-shell" style={"--auth-primary: #{@theme.primary_color}"}>
      <section class="auth-card" aria-labelledby={"#{@form_id}-title"}>
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
        <p class="eyebrow">{@theme.product_name}</p>
        <h1 id={"#{@form_id}-title"}>{@title}</h1>
        <p class="auth-intro">
          {@intro}
          <%= if @context do %>
            to <strong>{@context}</strong>
          <% end %>.
        </p>

        <div
          :if={@error}
          class="error-summary"
          role="alert"
          tabindex="-1"
          id={"#{@form_id}-errors"}
        >
          <strong>We couldn't sign you in</strong>
          <span>{@error}</span>
          <small :if={@correlation_id}>Reference <code>{@correlation_id}</code></small>
        </div>

        <.form for={@form} action={@action} id={@form_id} class="auth-form">
          <.input
            field={@form[:identifier]}
            type="email"
            label={@identifier_label}
            class="w-full rounded-xl border border-slate-300 bg-white px-4 py-3 text-slate-950 outline-none transition focus:border-[var(--auth-primary)] focus:ring-4 focus:ring-teal-700/10"
            autocomplete="username"
            inputmode="email"
            required
            autofocus
            aria-describedby={if @error, do: "#{@form_id}-errors"}
          />

          <.input
            field={@form[:password]}
            type="password"
            label={@password_label}
            class="w-full rounded-xl border border-slate-300 bg-white px-4 py-3 pr-14 text-slate-950 outline-none transition focus:border-[var(--auth-primary)] focus:ring-4 focus:ring-teal-700/10"
            autocomplete="current-password"
            required
            aria-describedby={if @error, do: "#{@form_id}-errors"}
          >
            <:suffix>
              <button
                type="button"
                class="reveal-password"
                data-password-toggle
                aria-label="Show password"
              >
                <span data-password-show-icon><.icon name="hero-eye" class="size-5" /></span>
                <span data-password-hide-icon hidden><.icon name="hero-eye-slash" class="size-5" /></span>
              </button>
            </:suffix>
          </.input>

          <button type="submit" class="primary-action">{@submit_label}</button>
        </.form>

        <p class="privacy-note">{@privacy_note}</p>
        <nav
          :if={@theme.privacy_url || @theme.terms_url || @theme.support_url}
          class="legal-links"
          aria-label="Help and legal"
        >
          <a :if={@theme.support_url} href={@theme.support_url}>Support</a>
          <a :if={@theme.privacy_url} href={@theme.privacy_url}>Privacy</a>
          <a :if={@theme.terms_url} href={@theme.terms_url}>Terms</a>
        </nav>
      </section>
    </main>
    """
  end
end
