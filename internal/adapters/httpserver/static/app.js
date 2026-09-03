document.addEventListener("click", (event) => {
  const toggle = event.target.closest("[data-password-toggle]")
  if (!toggle) return
  const input = toggle.parentElement.querySelector("input")
  const revealing = input.type === "password"
  input.type = revealing ? "text" : "password"
  toggle.textContent = revealing ? "Hide" : "Show"
  toggle.setAttribute("aria-label", revealing ? "Hide password" : "Show password")
})

document.addEventListener("htmx:afterSwap", (event) => {
  const alert = event.detail.target.querySelector("[role=alert]")
  if (alert) alert.focus()
})
