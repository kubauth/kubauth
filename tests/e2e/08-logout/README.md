# 08-logout

RP-Initiated Logout (OIDC §3.1) including SsoSession invalidation.

## What it asserts

1. `OidcClient smoke-client` is READY.
2. Under `ssoMode=always`, login via Auth Code + PKCE creates a
   `kubauth_sso` cookie and a backing `SsoSession` CRD.
3. `GET /oauth2/logout?id_token_hint=<id_token>&post_logout_redirect_uri=<PLR>`
   returns `302/303` with `Location: <PLR>`.
4. A bare `GET /oauth2/logout` (no hint, no PLR) still returns `302/303`
   to the chart's configured default `postLogoutURL`.
5. **After logout, the `SsoSession` CRD is gone** — the handler calls
   `SsoSessionManager.Destroy(ctx)` which removes the CRD via the
   `KubeSsoStore.Delete` adapter.

## Mechanics

The test flips `oidc.sso.mode` to `always` for its duration via a
per-test `helm upgrade --reuse-values --set oidc.sso.mode=always` and
restores `never` in `finally`. Otherwise, with the chart default of
`never`, no `SsoSession` would be created and the CRD-deletion
assertion would be a no-op.

Login + logout run in the same pod so they share a cookie jar — the
logout call carries the `kubauth_sso` cookie that maps to the
`SsoSession` created by the login call.

## What it does NOT assert

- The `state` parameter echo back to the client (mandated by OIDC
  RP-Initiated Logout 1.0 §3, kubauth-side fix tracked under B7 in
  `COVERAGE-HISTORY.md`, validated by the conformance suite —
  `oidcc-rp-initiated-logout` plan, `CheckPostLogoutState SUCCESS`).
- Front-channel logout via iframe. Not in scope.
- Cross-app logout propagation (logout in client A invalidates the
  cookie that client B was riding for SSO). Could be a future test.

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/08-logout
```
