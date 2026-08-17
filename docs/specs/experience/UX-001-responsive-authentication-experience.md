# UX-001 — Responsive Authentication Experience

## Status

MVP target

## Summary

Robine ID provides a polished, fast, accessible authentication experience across mobile and desktop devices.

## Requirements

- Login, consent, protocol-error, logout, signed-out, and landing screens MUST share a coherent design system. Recovery and verification screens are outside the MVP.
- Primary authentication actions MUST remain usable at viewport widths from 320 pixels upward.
- Pages MUST meet WCAG 2.2 AA requirements, including keyboard navigation, visible focus, semantic labels, contrast, and reduced-motion support.
- Validation MUST be shown near the relevant field and summarized accessibly without clearing valid user input.
- Password fields MUST support reveal/hide controls and password-manager-compatible autocomplete metadata.
- Authentication pages MUST remain functional without client-side JavaScript unless a configured authentication method inherently requires it.
- A form-post authorization handoff MUST expose a visible labeled fallback button while also
  submitting automatically when the same-origin bundled script executes.
- The UI MUST avoid revealing whether an account exists except where an explicitly configured flow requires disclosure.
- User-visible protocol failures MUST provide a safe recovery action and a correlation identifier.
- Login inputs MUST use stable labels and `autocomplete="username"` and `autocomplete="current-password"` hints.
- Sensitive password values MUST never be rendered back after a failed submission.
- Overlong or empty credential values MUST use the same generic invalid-credential presentation;
  an overlong identifier MUST NOT be reflected back into the page.
- A valid OIDC `login_hint` SHOULD prefill the identifier without changing generic error behavior.
- Error summaries MUST use an announced alert role. HTTP status MUST remain meaningful independently of visual content.
- Consent MUST identify the client and explain every requested scope in plain language.
- Destructive or denying actions MUST be visually distinguishable from the primary approving action.
- Every form, key action, and error region MUST have a stable unique DOM identifier suitable for automated tests.
- Pages MUST have a unique descriptive title and one primary heading.
- Interactive targets SHOULD be at least 44 by 44 CSS pixels.
- Motion MUST be subtle and disabled when `prefers-reduced-motion` requests it. Forced-colors mode MUST preserve boundaries and focus.

## Supported Journeys

1. A valid authorization request renders login with issuer/client branding.
2. Invalid credentials preserve the identifier, clear the password, and show a generic error.
3. Rate limiting shows a generic retry message and returns `Retry-After`.
4. Required consent lists requested scopes and offers approve and deny actions.
5. Protocol errors remain on the provider when no redirect is trusted and expose a correlation reference.
6. Logout asks for confirmation and ends on either a local confirmation or validated client return URI.

JavaScript MAY enhance password visibility and transient loading feedback, but submitting login, consent, and logout MUST work without it.

## Acceptance Criteria

- Core authentication flows can be completed using only a keyboard and a screen reader.
- Layouts do not require horizontal scrolling at 320 CSS pixels under 200% zoom.
- Invalid form submission preserves non-sensitive input, moves focus to the error summary, and identifies every invalid field.
- Browser autofill and password managers can identify both login inputs.
- Consent approval and denial remain understandable without relying on color.

## Manual Verification

The release record MUST name the tested browser, viewport, assistive technology, and result for keyboard, screen-reader, 320-pixel, 200%-zoom, reduced-motion, and forced-colors checks listed in the specification index.
