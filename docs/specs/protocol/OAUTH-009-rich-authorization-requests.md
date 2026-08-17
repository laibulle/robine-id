# OAUTH-009 — Rich Authorization Requests

Status: MVP target

## Purpose

Support RFC 9396 `authorization_details` so clients can request and downscope structured,
fine-grained permissions without encoding resource-specific rights into OAuth scopes.

## Requirements

- Operators MUST register bounded authorization-detail type definitions globally and explicitly
  enable each usable type per client. Discovery MUST expose only types reachable by a client of
  the selected issuer through `authorization_details_types_supported`.
- Authorization GET/POST, PAR, signed Request Objects, Device Authorization, Authorization Code,
  Refresh Token, Client Credentials, and Token Exchange requests MAY carry
  `authorization_details`. Query and form values are JSON strings; a signed Request Object MAY use
  a native JSON array.
- The value MUST be a non-empty array of at most 16 objects and at most 8192 serialized bytes. Each
  object MUST contain a registered string `type`, only configured fields, and all fields required by
  its type. Nested JSON depth, node count, strings, arrays, and objects MUST remain bounded.
- Common `actions`, `datatypes`, `privileges`, and `locations` members MUST be non-empty arrays of
  bounded strings. A requested location MUST exactly match a resource registered to the client.
- Unknown types, unknown fields, missing required fields, invalid shapes, and unauthorized values
  MUST fail with `invalid_authorization_details`.
- Fine-grained permissions MUST be persisted with authorization codes, device grants, access
  tokens, and refresh-token families. Consent MUST display their registered names and safely escaped
  payloads, even when ordinary consent is disabled for the client.
- A token request MAY select a conservative subset of its source grant. Scalars MUST remain equal;
  object fields and array members MAY only be removed. Any attempted expansion MUST fail without
  consuming a refresh token.
- Successful token responses, RFC 9068 JWT access tokens, and active introspection responses MUST
  include the effective `authorization_details`. Empty details MUST be omitted.
- Stored grants MUST become inactive when their detail type or client authorization is removed from
  the active configuration.
- Pending Device Flow confirmations MUST revalidate their stored details against the active type
  definitions and client allow-list before displaying or recording browser approval.

## Acceptance Criteria

- Configuration validation rejects duplicate, unknown, unbounded, or inconsistent type policies.
- Direct, PAR, JAR, and Device requests preserve and validate structured details.
- Consent and device confirmation render an escaped, readable description of requested details.
- Authorization Code, Device, Client Credentials, Refresh, and Token Exchange issuance preserve or
  safely reduce the original details.
- Token responses, JWT claims, and introspection agree on the effective details.
- Refresh-token expansion is rejected atomically and does not consume the token family.
