# OIDC-017 — Pairwise Subject Identifiers

## Status

Implemented in the Rust runtime.

## Intent

An operator can prevent relying parties in different administrative sectors from correlating a
local identity through the OpenID Connect `sub` claim. Internal persistence continues to use the
stable local user ID; only protocol-facing subject claims are pseudonymized.

## Normative Requirements

- Clients MUST declare `subject_type` as `public` or `pairwise`; omission means `public`.
- A pairwise client MUST have one unambiguous sector. `sector_identifier` is a canonical lowercase
  hostname. When omitted, every registered redirect URI MUST have the same host and that host is
  the sector.
- Enabling any pairwise client MUST require the root
  `pairwise_subject_salt_reference` environment-secret reference. The resolved value MUST contain
  at least 32 bytes and MUST be redacted from effective configuration.
- Pairwise identifiers MUST be deterministic for the same issuer, sector, and local user, and MUST
  differ when any of those inputs changes. Robine ID derives them using domain-separated
  HMAC-SHA-256 and unpadded base64url encoding.
- The pairwise value MUST be used consistently in ID tokens, JWT access tokens, UserInfo responses,
  token introspection responses, ID-token-hint matching, essential `sub` claim evaluation, and
  back-channel logout tokens.
- Authorization codes, sessions, opaque access-token records, refresh-token families, and audit
  policy checks MUST retain the internal user ID. Client-credentials subjects and actor chains are
  service identifiers and MUST NOT be pseudonymized, including when a service identifier happens
  to equal a configured local user ID.
- A missing or weak runtime salt MUST fail subject generation without falling back to the public
  identifier.
- Discovery MUST advertise `pairwise` in `subject_types_supported` only when at least one configured
  client uses it.

## Configuration

The root document references the deployment secret:

```json
{
  "pairwise_subject_salt_reference": {
    "provider": "env",
    "key": "PAIRWISE_SUBJECT_SALT"
  }
}
```

The application declares its subject policy:

```json
{
  "subject_type": "pairwise",
  "sector_identifier": "apps.example.com"
}
```

Applications deliberately grouped under the same sector receive the same subject for a user and
issuer. Separate sectors cannot correlate that user through `sub`. Rotating the salt changes every
pairwise identifier, so operators MUST treat it as durable identity key material and back it up.

## Acceptance Evidence

- Configuration tests cover salt references, inferred and explicit sectors, invalid sector syntax,
  multi-host rejection, and effective-configuration redaction.
- Derivation tests cover stability and isolation by issuer, sector, and user.
- Protocol tests cover discovery gating.
- Rust token, UserInfo, introspection, hint, claims, and logout paths use one centralized derivation.
- `make release-smoke` performs a real pairwise authorization-code journey across two instances and
  verifies that ID token, UserInfo, and introspection expose the same non-public subject.

## Reference

[OpenID Connect Core 1.0, Pairwise Identifier Algorithm](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg)
