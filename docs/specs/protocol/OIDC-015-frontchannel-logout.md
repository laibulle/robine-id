# OIDC-015 — Front-Channel Logout

## Status

MVP target

## Summary

Robine ID renders registered relying-party logout URIs in a bounded browser interstitial so RP
sessions can be cleared through the User Agent when an OpenID Provider session ends.

## Requirements

- Discovery MUST advertise `frontchannel_logout_supported` and
  `frontchannel_logout_session_supported` as `true`.
- A client MAY register one absolute `frontchannel_logout_uri` without credentials or a fragment.
  Its scheme, host, and effective port MUST equal those of at least one registered redirect URI.
  HTTPS is required except for loopback HTTP registered by a confidential client.
- `frontchannel_logout_session_required` MUST default to `false` and MUST NOT be enabled without a
  front-channel URI.
- When session parameters are required, the provider MUST retain the registered query and append
  both `iss` and `sid`; it MUST NOT send only one of them. When they are not required, neither is
  appended.
- Logout MUST construct at most one iframe URL for each unique associated RP session and render all
  frames in one interstitial response. Possible client-issuer combinations MUST be bounded to 32
  per configuration revision.
- The interstitial CSP MUST allow `frame-src` only for the exact set of registered callback origins.
  Frames MUST have a no-referrer policy and a sandbox limited to same-origin state plus scripts.
- The browser SHOULD continue after every iframe settles and MUST continue after a 1.5-second
  upper bound. A validated post-logout redirect remains the final destination.
- Without JavaScript, the iframe requests MUST still render and a normal continuation link MUST
  remain available.
- The interstitial and iframe callbacks MUST be non-cacheable. A failed or browser-blocked iframe
  MUST NOT restore the local OP session.

## Acceptance Criteria

- Configuration rejects a different redirect origin, public loopback HTTP, missing URI metadata,
  unsafe URLs, and unbounded callback combinations.
- Discovery truthfully publishes both capability flags.
- Existing query parameters are retained and `iss`/`sid` match the ID Token session.
- The rendered page contains all unique frames, a strict origin-only CSP, the validated final
  destination, and no inline script.
- RP-Initiated Logout uses the interstitial instead of an immediate redirect when at least one
  associated front-channel RP exists.
- The release smoke inspects the real interstitial and records a GET at a loopback RP listener.

## Limitations

Browser third-party-cookie and tracking-prevention policies can prevent an iframe from reaching RP
state. OIDC-014 Back-Channel Logout is the preferred complementary mechanism for deployments that
need delivery independent of browser privacy policy.

## Non-Goals

OpenID Connect Session Management `check_session_iframe`, top-level RP navigation, dynamic client
registration, and a guarantee that an RP actually cleared its state are outside this scope.
