# OIDC-012 — ID Token Hint

## Status

MVP target

## Summary

Robine ID accepts a previously issued ID Token as an authorization-request hint about the
End-User's current or past authenticated session with a client.

## Requirements

- `id_token_hint` MUST be accepted by direct GET and form-serialized POST authorization requests,
  PAR, and signed Authorization Request Objects.
- An empty hint MUST be treated as omitted. A non-empty hint MUST be limited to 16 KiB before key
  or database work.
- The hint MUST be a signed RS256 ID Token issued by the selected Robine ID issuer using an active
  or retained signing key.
- The token audience MUST be the authorization request's validated `client_id`. A token issued to
  another relying party MUST be rejected with `invalid_request`.
- Expiration alone MUST NOT invalidate an otherwise authentic hint. The hint is not a credential and
  MUST NOT create a session, extend a session, or bypass current session, MFA, `max_age`, consent,
  claims, or application-policy checks.
- Silent authorization with `prompt=none` MAY omit the hint when the current session is otherwise
  sufficient. When a hint is present, the authenticated session subject MUST match its `sub` claim;
  otherwise the endpoint MUST return `login_required` without rendering interaction.
- During an interactive request, a missing or different current session MUST lead to normal
  authentication. The hint MUST NOT disclose an identifier or prove possession of the account.
- Native parameters outside a signed Request Object MUST either be absent or exactly match the
  corresponding signed `id_token_hint`; conflicts MUST be rejected.
- Invalid hints MUST only be returned to a redirect URI after the normal client and exact redirect
  trust boundary has been established.

## Acceptance Criteria

- A valid hint whose audience and subject match the client and current session permits silent SSO.
- A valid hint for another client is rejected as `invalid_request`.
- A valid hint for another subject returns `login_required` under `prompt=none`.
- A forged, wrong-issuer, unsupported-algorithm, or unknown-key hint is rejected.
- An expired but otherwise valid hint can identify an already authenticated matching subject.
- GET, POST, PAR, and JAR preserve the same hint value and reject conflicting signed/native values.

## Security Notes

An ID Token hint is untrusted request input until its issuer and signature are verified. Even after
verification it is only a routing hint: the browser session remains the sole SSO authority. Robine
ID does not prefill the login identifier from `sub`, avoiding account disclosure and coupling to a
particular subject identifier format.

## Standards

- OpenID Connect Core 1.0, sections 3.1.2.1 and 3.1.2.2.
