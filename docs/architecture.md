# Architecture

Robine ID applies a ports-and-adapters architecture with dependencies pointing inward.

```text
HTTP + HTMX ─┐
JSON config ─┼─> application use cases ─> domain entities
local files ─┤             │
S3 objects ──┘             └─> ports (interfaces)
```

`internal/domain` contains data and public error types only. `internal/application` coordinates protocol policy through interfaces from `internal/ports`. Adapters implement those ports, and `cmd/robine-id` is the only package that selects concrete implementations.

## Storage boundaries

`ports.BlobStore` provides three operations: read one object, atomically replace one object, and list a prefix. Both configuration composition and durable security state depend on this contract.

- `adapters/blob.Local` confines keys below one root and replaces files using write, sync, chmod, and rename.
- `adapters/blob.S3` maps keys below a configured prefix and uses complete `PutObject` replacements.
- `adapters/keystore.Encrypted` persists a versioned AES-256-GCM envelope without knowing which blob adapter is active.
- `adapters/accounts.Blob` persists managed account overrides without changing configured provisioning authority.

Protocol runtime state has separate narrow ports for authorization codes, access tokens, sessions, and rate limits. The built-in adapters are synchronized in-memory implementations. Shared database adapters can replace them at the composition root without touching HTTP or protocol use cases.

## HTTP boundary

The HTTP adapter owns routing, request parsing, encrypted browser cookies, CSRF validation, security headers, HTML rendering, and protocol response shapes. It delegates all identity and OIDC decisions to the provider application service.

HTMX is progressive enhancement: forms have ordinary methods and actions, while `hx-post`, `hx-target`, and `hx-swap` provide partial updates. External OIDC redirects use `HX-Redirect`; non-HTMX clients receive ordinary `303` responses.
