# 02-pkce-required

Negative test: a public OIDC client that omits `code_challenge` must be rejected.

## Why this test exists

OAuth 2.1 (RFC 7636 + best-practice draft) requires PKCE for **all** public
clients. kubauth ships with `oidc.enforcePKCE: true`, which rejects auth
requests missing `code_challenge`. Without this test, a regression that
disables PKCE enforcement would silently let public clients fall back to a
PKCE-less flow — exactly the threat OAuth 2.1 was written to prevent.

## What it asserts

1. A new public `OidcClient` (`pkce-required-test`) reaches `phase: READY`.
2. Walking `GET /oauth2/auth` then `POST /oauth2/login` (alice creds) **without**
   `code_challenge` yields a redirect to `redirect_uri` with:
   - `error=invalid_request`
   - `error_description` mentioning `code_challenge` / `PKCE`
   - **no** `code=...` query parameter (server must not emit a code)
3. The per-test `OidcClient` is cleaned up regardless of test outcome
   (`finally` block).

## What it does NOT assert

- The token endpoint behaviour without `code_verifier` — implied by §2 (no code
  is emitted, so there is nothing to exchange).
- `code_challenge_method=plain` rejection — server only advertises `S256` in
  discovery. Could be added as a third assertion if Hydra ever regresses.

## Why a per-test fixture, not a baseline OidcClient

`pkce-required-test` lives in `kubauth-system`, the chart's
`clientPrivilegedNamespace`. Adding it to `fixtures/oidcclients/` would pollute
the dev cluster baseline with a permanently-public client used only for one
negative test. Per-test apply + `finally`-block delete keeps the baseline
unchanged.

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/02-pkce-required
```
