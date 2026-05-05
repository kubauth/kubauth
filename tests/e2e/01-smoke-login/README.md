# 01-smoke-login

The simplest possible end-to-end check: kubauth issues an id_token to a confidential
client using the ROPC (Resource Owner Password Credentials) grant.

## What it proves

1. The OIDC server is up.
2. `OidcClient` reconciler works (status reaches `READY`).
3. `User` + `GroupBinding` are visible to the UCRD authority.
4. The merger chain (ucrd → audit) returns a valid identity.
5. The `/token` endpoint signs and returns an id_token.

## What it does NOT prove

- Browser flow (Authorization Code) — see `03-pkce-s256/`.
- Refresh token rotation — see `04-refresh-token/`.
- ID token signature validation against published JWKS — see `18-id-token-signature/`.
- Cross-app SSO — see `07-sso/`.

## Why ROPC

ROPC is deprecated in OAuth2.1 for human clients. **We use it here only because
it's the only flow that fits in 30 lines of bash without a browser.** Production
deployments must use Authorization Code + PKCE.

If we ever drop `allowPasswordGrant: true` from `kubauth-values.yaml`, this test
needs to be rewritten with a headless browser (or a Selenium-like driver).

## Run

```sh
make dev-up         # once
make e2e-smoke      # this test
```
