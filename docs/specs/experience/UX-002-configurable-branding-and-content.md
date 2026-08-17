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
- Configured assets MUST use either an unambiguous absolute local path or HTTPS, except for
  loopback-only HTTP development. Local paths MUST reject authority prefixes, backslashes,
  whitespace, fragments, and literal or percent-encoded dot traversal.
- The active semantic configuration revision MUST be appended after any existing asset query
  parameters so a changed branding revision invalidates browser and CDN caches deterministically.
- Text overrides MUST use stable message keys and MUST fall back to the configured default locale.
- Custom content MUST be escaped or sanitized according to its declared type.
- Missing optional assets MUST degrade to a complete default Robine ID theme.
- Default visual assets MUST be embedded in the production runtime and MUST NOT require a writable
  or separately synchronized runtime asset directory.
- Embedded assets MUST return exact media types, bounded cache policy, content validators,
  conditional GET, and bodyless HEAD responses. The default crawler policy MUST disallow indexing.
- `primary_color` MUST be a six-digit CSS hexadecimal color and MUST achieve at least 4.5:1 contrast with white text.
- Links and asset references MUST be emitted only in the context for which they were configured.
- The default product name MUST be `Robine ID` and the default visual theme MUST remain complete without any operator-provided asset.
- The default theme MUST ship complete English and French message catalogs and advertise both
  locales when locale configuration is omitted.
- An explicit `ui_locales` parameter MUST take precedence. When it is absent, browser screens MUST
  use quality-ranked `Accept-Language` preferences, then the configured default locale. The parsed
  header MUST be bounded to 1 KiB, 32 candidates, eight retained tags, and 256 retained bytes;
  wildcards, zero-quality entries, malformed tags, and malformed weights MUST be ignored.
- The requested locale MUST use the first preference matched case-insensitively by bounded BCP 47
  lookup. A regional request such as `fr-FR` MUST progressively fall back to a configured `fr`;
  otherwise content MUST fall back to the configured default locale and then built-in English.
- A locale inferred for an authorization request MUST be persisted in its opaque browser
  transaction so login, TOTP, consent, and protocol-error screens cannot change language mid-flow.
- Every rendered HTML document MUST emit a valid `Content-Language` equal to its HTML `lang` value.
  Header derivation MUST reject malformed or non-language values, and JSON responses and redirects
  MUST NOT acquire a representation-language header from browser preferences.
- Message overrides MUST be maps of stable string keys to plain string values. Markup supplied in messages MUST be escaped.
- Branding resolution MUST be performed independently for each request using the active configuration.

## Precedence

From lowest to highest priority, values resolve from built-in locale catalogs, global branding,
issuer branding, and client branding. A higher layer overrides only values it declares. Locale
message maps merge by locale and key. At render time a requested-locale override falls back to the
configured default-locale override, then the built-in requested/default catalog and finally English,
so an incomplete translation never exposes an internal key.

## Supported Message Keys

The built-in catalog exposes stable keys for sign-in, TOTP, consent, device verification, scopes,
logout, signed-out, protocol-error, form-post handoff, navigation, and legal content. New
user-visible strings SHOULD receive stable keys before becoming configurable.

## Acceptance Criteria

- An operator can deploy a branded login experience without recompiling the application.
- Applying the same branding configuration repeatedly does not create new asset records or change generated URLs.
- An incomplete locale falls back per message without showing internal keys to users.
- A minimal configuration renders every login, TOTP, consent, device, logout, error, scope, and
  legal-navigation message in French for `ui_locales=fr` or `fr-FR`, with `lang="fr"`. The final
  form-post handoff remains French after consent and cross-instance transaction consumption.
- An insufficient-contrast primary color prevents configuration activation with a precise diagnostic.
- Client branding overrides issuer and global values only for that client's authorization journey.
- The complete default asset set is served identically by conventional Actix and Vercel routes.

## Non-Goals

Uploading assets, arbitrary HTML/CSS injection, remote theme packages, a visual theme editor, and per-user themes are outside the MVP.
