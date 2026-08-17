# OIDC-011 — Claims Parameter

Status: MVP target

## Purpose

Allow relying parties to express bounded, destination-specific OpenID Connect claim requests and
to require values that must be present before Robine ID issues an authorization code.

## Requirements

- Discovery MUST advertise `claims_parameter_supported` as `true`.
- Authorization GET, form POST, Pushed Authorization Requests, and signed Request Objects MUST
  preserve the same optional `claims` parameter. Conflicting outer and signed values MUST reject
  the Request Object.
- The decoded parameter MUST be a JSON object containing only optional `id_token` and `userinfo`
  objects. Each destination MAY request at most 64 bounded claim names.
- A claim request MUST be `null` or an object containing only `essential`, `value`, and `values`.
  `essential` MUST be Boolean; `value` and `values` are mutually exclusive; `values` MUST contain
  between one and sixteen bounded scalar JSON values. The serialized parameter MUST NOT exceed
  8192 bytes.
- An essential mapped claim is available only when its configured scope belongs to the selected
  issuer and is present in the authorization request. Essential built-in ID Token claims and the
  UserInfo `sub` claim remain available without an additional mapped scope.
- After authentication, every essential claim MUST exist in its requested destination. When
  `value` or `values` is present, the actual value MUST match one of the accepted values. A request
  that cannot be satisfied MUST return `access_denied` to the already validated redirect URI and
  MUST NOT create an authorization code.
- An essential ID Token `acr` constraint applies to fresh credentials and reusable sessions. The
  returned `acr` and `amr` MUST describe the context actually achieved. An essential MFA value may
  strengthen a client without `required_acr`; application policy may independently require MFA.
- Unknown or unavailable non-essential claims MAY be omitted. Claim mappings and requested scopes
  continue to bound user attributes, so the parameter cannot bypass application or issuer scope
  policy.
- Empty strings normalize to omission. Malformed JSON, unknown structural members, excessive
  depth/count/length, unsupported essential destinations, and invalid value shapes MUST return
  `invalid_request` without exposing credentials or configuration secrets.

## Acceptance Criteria

- Discovery reports claims-parameter support.
- Direct GET and POST requests, PAR, and JAR retain a valid parameter without reinterpretation.
- Malformed, oversized, structurally unknown, and contradictory requests fail closed.
- Password-only and MFA authentication contexts are distinguished for essential `acr` values.
- Essential mapped UserInfo values succeed only when the mapped scope and actual user value match.
- The production smoke journey requests essential MFA and receives an ID Token containing the
  matching `acr`, `amr`, and `auth_time` claims.
