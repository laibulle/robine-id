# OAUTH-005 — Demonstrating Proof of Possession

## Status

Rust production extension

## Summary

Robine ID implements RFC 9449 DPoP sender-constrained access and public-client refresh tokens.
Proof JWTs are validated at the endpoint where they are presented, and their identifiers are
registered atomically in PostgreSQL so replay is rejected across Actix and Vercel instances.

## Requirements

- Discovery MUST advertise `dpop_signing_alg_values_supported` with EdDSA, ES256, and RS256.
- A DPoP proof MUST be a bounded signed JWT with `typ=dpop+jwt`, an inline public asymmetric JWK,
  and an EdDSA, ES256, or RS256 signature over a matching Ed25519, P-256, or RSA public key. Private
  JWK parameters, cross-family parameters, algorithm confusion, and remote key references MUST be
  rejected.
- The proof MUST contain bounded `jti`, exact uppercase `htm`, exact canonical endpoint `htu`, and a
  recent `iat`. The `htu` value MUST NOT contain a query or fragment.
- A protected-resource proof MUST additionally contain `ath`, computed as the base64url SHA-256
  digest of the access token. Other proof claims are ignored unless a supported extension assigns
  them validation semantics.
- Every accepted `(jkt, jti)` MUST be registered once in PostgreSQL. A duplicate proof on the same
  or another instance MUST fail with `invalid_dpop_proof`.
- When `token_policy.dpop_nonce_required` is enabled, token, PAR, and DPoP-bound UserInfo proofs
  MUST contain a recently issued opaque nonce. Missing, expired, or mismatched values MUST produce
  `use_dpop_nonce` with exactly one `DPoP-Nonce` response header.
- Authorization-server and UserInfo nonce spaces MUST remain distinct. PostgreSQL MUST retain a
  bounded window of recent nonce digests per issuer, context, and key so concurrent requests and
  routing between instances do not desynchronize clients.
- Browser responses MUST expose `DPoP-Nonce`, and UserInfo MUST also expose `WWW-Authenticate`,
  through CORS. Responses carrying nonce state MUST remain uncacheable.
- Authorization requests MAY carry `dpop_jkt` directly, inside a signed request object, or through
  PAR. PAR MAY instead derive it from the DPoP header; both values MUST match when both are present.
- An authorization code carrying `dpop_jkt` MUST be exchangeable only with a proof from that key.
- Any token request carrying a valid proof MUST produce an access token bound to its JWK thumbprint
  and return `token_type=DPoP`; requests without a proof continue to produce bearer tokens.
- A public-client refresh token issued or rotated with DPoP MUST remain bound to the same key. A
  missing or mismatched proof MUST fail without consuming the refresh token. Confidential-client
  refresh tokens remain client-authenticated and are not sender-constrained by DPoP.
- UserInfo MUST accept a bound token only with the `DPoP` authorization scheme and a fresh matching
  proof containing the correct `ath`. A bound token used as Bearer MUST be rejected.
- Introspection MUST report `token_type=DPoP` and `cnf.jkt` for a bound access token.
- DPoP proof values, access tokens, JWK private material, and raw `jti` values MUST NOT be logged or
  persisted.
- Accepted-proof diagnostics MUST record only bounded endpoint/outcome categories; the JWK
  thumbprint, proof `jti`, and nonce MUST remain absent even at debug level.

## Acceptance Criteria

- Direct, JAR, and PAR authorization can bind a code to a DPoP key.
- Authorization Code, Refresh Token, and Client Credentials grants issue DPoP access tokens when a
  valid proof is supplied.
- Bound UserInfo succeeds across instances with a fresh `ath` proof and rejects Bearer use,
  mismatched keys, malformed proofs, and cross-instance replay.
- A bound public refresh token rejects a missing proof without being consumed and rotates only with
  its original key.
- With nonce enforcement enabled, a client can obtain a challenge from one instance and retry with
  the supplied nonce on another; authorization-server nonces MUST NOT satisfy UserInfo.
- Discovery and the Vercel adapter expose the same DPoP metadata and behavior as Actix.
- An automated tracing capture verifies that accepted UserInfo proof diagnostics contain the
  endpoint/outcome but none of the proof thumbprint, identifier, or nonce.

## Standards

- RFC 9449, OAuth 2.0 Demonstrating Proof of Possession.
- RFC 7638, JSON Web Key Thumbprint.

## Non-Goals

mTLS sender-constrained tokens, symmetric proof keys, and proof algorithms other than EdDSA, ES256,
and RS256 are outside this extension. JWT formatting and its `cnf.jkt` claim are defined by
OAUTH-007.
