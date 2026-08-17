# CONF-002 — Atomic and Idempotent Reconciliation

## Status

MVP target

## Summary

Robine ID reconciles declared configuration into runtime and persistent state atomically and idempotently.

## Requirements

- Reconciliation MUST compare desired state with effective state before making changes.
- Each resource MUST have a stable identity independent of list order or file layout.
- An unchanged desired state MUST result in a no-op.
- A reconciliation plan MUST be validated in full before mutations begin.
- Mutations for one configuration revision MUST be atomic; on failure, the previously active revision MUST remain usable.
- Apply operations serialized by the configuration store MUST converge on one effective result without duplicate resources.
- The server MUST record a non-secret revision fingerprint, timestamp, outcome, and safe diagnostics for apply attempts.
- Operators MUST be able to validate and preview a change without applying it.
- The running service MUST detect changes to the root or application documents and attempt a complete reload without restart.
- A reload MUST validate the complete composed revision before activation. Invalid or partially written files MUST leave the last valid revision active.
- Repeated observation of the same invalid inputs MUST NOT create unbounded duplicate failure events.
- An activated revision MUST immediately govern pending consent consumption. Disabling a user or
  client, or removing its authorization-code grant, redirect, scope, resource, authentication
  context, essential claim availability/value, or authorization-detail policy MUST invalidate the
  old pending authorization before any code or browser redirect is emitted. Non-essential mapped
  claims MUST be rebuilt from the active user and mapping definitions at consumption.
- An activated revision MUST also govern pending logout confirmation. A changed issuer URL,
  disabled issuer or client, removed issuer assignment, or removed post-logout redirect MUST drop
  the stale client redirect while local logout still completes.
- Pending Device Flow verification MUST immediately adopt the active client grant, scope, resource,
  offline-access, and rich-authorization policy before browser confirmation or token issuance.

## Acceptance Criteria

- Applying the same revision any number of times produces the same state and no duplicate side effects.
- A failure midway through an apply does not expose a partially updated configuration.
- Reordering equivalent declarations does not change the revision fingerprint or produce an update plan.
- A preview clearly identifies create, update, disable, delete, and unchanged operations.

## Revision Identity

The fingerprint MUST be a lowercase SHA-256 digest of a canonical representation of the validated document. Object key order and declaration list order MUST NOT affect it. Lists of objects with stable `id` fields are canonicalized by identifier; scalar list values are canonicalized consistently. A semantic change MUST produce a different fingerprint.

## Plan Semantics

A plan reports the candidate revision, whether it changes active state, resource operations, and diagnostics. Operations are `create`, `update`, `disable`, `delete`, and `unchanged`; removal behavior derives from `reconciliation.deletion_policy`. Preview MUST use the same validation and planning rules as apply.

## Activation Semantics

The Rust runtime activates one validated immutable snapshot through a serialized write lock. Readers
see either the previous or new snapshot, never an intermediate value. An equal fingerprint returns
`unchanged`. A failed load or validation does not call activation. Reconciliation outcomes and safe
diagnostics are emitted as structured operational events and counters; they reset on process
restart unless the deployment exports them to an external telemetry backend.

The default watcher interval is one second. It rebuilds the complete desired state rather than mutating one application in isolation, so duplicate IDs and cross-resource constraints are checked atomically. Removing an application file is a desired-state removal and follows the reconciliation plan on the next successful reload.

## Additional Acceptance Criteria

- The first valid apply activates one snapshot and records its fingerprint.
- An equivalent apply returns `unchanged` even when JSON object keys or identified resource lists are reordered.
- Invalid candidates leave the prior active snapshot readable.
- Preview never changes active revision or history.
- Effective configuration never exposes secret-bearing fields.

## MVP Limitation

Configuration activation remains local to each process. Shared protocol state is coordinated through
PostgreSQL, but a multi-instance deployment MUST use one immutable inline configuration revision or
the same read-only file authority for every node. Operators MUST roll a changed inline revision to
every node deliberately; conventional file-backed nodes watch and validate the shared documents
independently.
