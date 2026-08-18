# Robine ID contributor instructions

Robine ID is an OpenID Connect provider written in Rust. The HTTP server uses Actix Web, HTML is
rendered with Askama, mutable state is stored in PostgreSQL, and the same application can run as a
conventional server or through the Vercel Function entrypoint.

## Project guidelines

- Run `make preflight` after completing changes and fix every reported issue.
- Keep the server and Vercel transports behaviorally equivalent.
- Use the existing dependencies in `Cargo.toml` unless a new dependency is clearly necessary.
- Keep request parsing bounded, configuration strict, and diagnostics free of secret values.
- Preserve zeroizing handling for credentials, secrets, tokens, and decrypted key material.
- Persist shared protocol state in PostgreSQL; do not introduce process-local state that breaks
  multi-instance or serverless operation.
- Use Askama templates for server-rendered HTML and keep JavaScript in the Rust-served assets.
- Keep key controls accessible, responsive, and covered by focused rendering or HTTP tests.
- Generate SQL migrations in the root `migrations/` directory and make them safe to run once on a
  fresh PostgreSQL database.
- Start test services with the existing Compose/Make targets instead of introducing ad-hoc ports.
