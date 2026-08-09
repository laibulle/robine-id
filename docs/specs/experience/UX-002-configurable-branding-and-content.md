# UX-002 — Configurable Branding and Content

## Status

MVP target

## Summary

Operators can adapt Robine ID to their brand and audience entirely through configuration and static assets.

## Requirements

- Configuration MUST support product name, logo, favicon, primary color, font family, support link, privacy link, terms link, locale policy, and localized text overrides.
- Branding MAY be defined globally and overridden per issuer or client using deterministic precedence.
- Themes MUST preserve accessibility constraints; invalid or insufficient-contrast combinations MUST be rejected or replaced with safe values.
- Static asset references MUST be stable across an unchanged configuration.
- Text overrides MUST use stable message keys and MUST fall back to the configured default locale.
- Custom content MUST be escaped or sanitized according to its declared type.
- Missing optional assets MUST degrade to a complete default Robine ID theme.
- `primary_color` MUST be a six-digit CSS hexadecimal color and MUST achieve at least 4.5:1 contrast with white text.
- Links and asset references MUST be emitted only in the context for which they were configured.
- The default product name MUST be `Robine ID` and the default visual theme MUST remain complete without any operator-provided asset.
- The requested locale MUST use the first `ui_locales` value when supported; otherwise content MUST fall back to the configured default locale and then built-in English.
- Message overrides MUST be maps of stable string keys to plain string values. Markup supplied in messages MUST be escaped.
- Branding resolution MUST be performed independently for each request using the active configuration.

## Precedence

From lowest to highest priority, values resolve from built-in defaults, global branding, issuer branding, and client branding. A higher layer overrides only values it declares. Locale message maps merge by locale and key so an incomplete client translation can fall back to issuer, global, or default messages.

## Supported Message Keys

The MVP defines stable keys for the sign-in title, identifier label, password label, submit action, consent title, consent approval, and consent denial. New user-visible strings SHOULD receive stable keys before becoming configurable.

## Acceptance Criteria

- An operator can deploy a branded login experience without recompiling the application.
- Applying the same branding configuration repeatedly does not create new asset records or change generated URLs.
- An incomplete locale falls back per message without showing internal keys to users.
- An insufficient-contrast primary color prevents configuration activation with a precise diagnostic.
- Client branding overrides issuer and global values only for that client's authorization journey.

## Non-Goals

Uploading assets, arbitrary HTML/CSS injection, remote theme packages, a visual theme editor, and per-user themes are outside the MVP.
