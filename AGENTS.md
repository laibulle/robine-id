# Robine ID contributor instructions

Robine ID is an OpenID Connect provider written in Go with server-rendered HTMX views.

## Required quality gate

- Run `make check` after every completed change.
- Total Go statement coverage must remain at or above 80%.
- Preserve race-detector cleanliness.

## Architecture

- Keep domain entities in `internal/domain` and use cases in `internal/application`.
- Declare infrastructure contracts in `internal/ports`.
- Keep HTTP, storage, crypto, configuration, and observability implementations in `internal/adapters`.
- Wire concrete adapters only in `cmd/robine-id`.
- Do not import an adapter from the domain or application packages.
- Keep secrets, credentials, tokens, codes, and raw identifiers out of logs.

## Go conventions

- Format with `gofmt` and keep `go vet ./...` clean.
- Accept `context.Context` at I/O boundaries.
- Use the standard library when it is sufficient.
- Keep interfaces small and owned by the consuming boundary.
- Wrap operational errors with context and expose only bounded protocol errors publicly.
- Use table-driven tests for validation matrices and `httptest` for HTTP behavior.

## HTMX and UI

- Authentication forms must remain functional without JavaScript.
- HTMX responses should return focused HTML fragments and use `HX-Redirect` for external OIDC redirects.
- Vendor browser dependencies; do not load scripts or styles from a CDN.
- Do not write inline scripts.
- Preserve stable DOM IDs, accessible labels, keyboard focus, reduced-motion behavior, and 320px layouts.

## Storage

- All file/object operations must go through `ports.BlobStore`.
- Local writes containing security state must be atomic and permission-restricted.
- S3-compatible writes must replace complete objects; never expose partial key state.
