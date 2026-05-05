# 03-pkce-s256

Authorization Code flow with PKCE S256, walked headlessly with curl.

## Why this test exists

ROPC (`01-smoke-login`) only proves `/oauth2/token` works in isolation. **Real**
OIDC clients (kubelogin, oauth2-proxy, AppAuth-JS, NextAuth, …) all use
Authorization Code + PKCE. Without this test we have zero coverage of:

- the front channel (`/oauth2/auth`, `/oauth2/login`)
- session cookie handling (`kubauth_login`, `kubauth_sso`)
- the PKCE verifier ↔ challenge round-trip

## What it asserts

1. The `smoke-client` OidcClient is `READY`.
2. The 3-step Authorization Code flow completes:
   1. `GET /oauth2/auth` → 302 to `/oauth2/login` (cookie set)
   2. `POST /oauth2/login` (alice / alice-password) → 303 to
      `redirect_uri?code=…&state=…`
   3. `POST /oauth2/token` with code + `code_verifier` → JSON with id_token,
      access_token, refresh_token, token_type=bearer
3. The decoded id_token JWT payload contains the expected claims:
   - `sub: alice`
   - `aud: [smoke-client]`
   - `iss: https://kubauth-oidc-server.kubauth-system.svc:443`
   - `groups: [admins]`
   - `authority: ucrd`
   - `at_hash` present (binds the access_token to the id_token, OIDC §3.1.3.6)

## What it does NOT assert

- **JWT signature** — covered by `18-id-token-signature` (fetches `/jwks`,
  verifies the signature with PyJWT against the JWK matching the token's
  `kid`).
- **Refresh rotation** — covered by `04-refresh-token`.
- **PKCE rejection paths** — covered by `02-pkce-required`.

## PKCE pair used

The test uses the example pair from RFC 7636 §C, so anyone can verify by hand:

```text
verifier  = dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
challenge = E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM        # base64url(sha256(verifier))
```

## Run

```sh
make dev-up         # once
chainsaw test --config chainsaw.yaml e2e/03-pkce-s256
```
