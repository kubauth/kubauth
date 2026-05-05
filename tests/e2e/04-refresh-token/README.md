# 04-refresh-token

Refresh-token rotation + replay detection.

## Why this test exists

OAuth 2.1 mandates **refresh-token rotation**: every successful refresh issues
a new refresh_token and immediately invalidates the previous one. The previous
token, if reused, must yield `invalid_grant`. This is the only protection
against a stolen long-lived refresh token becoming a persistent backdoor.

kubauth wraps Hydra-vendored Fosite, which rotates by default — but a
mis-configuration or a regression in `cmd/oidc/fositepatch/` could silently
disable it. This test catches that.

## What it asserts

1. `smoke-client` OidcClient is `READY`.
2. Authorization Code + PKCE flow yields the initial token set with both
   `access_token` and `refresh_token` (= `RT1`).
3. Calling `POST /oauth2/token` with `grant_type=refresh_token` + `RT1`:
   - returns a fresh id_token, access_token, and refresh_token (= `RT2`)
   - `RT2 != RT1` (rotation)
   - `AT2 != AT1` (new access_token issued)
4. Reusing `RT1` after step 3 returns:
   - `error: invalid_grant`
   - description ideally mentioning "already used" (warning only — the test
     accepts variants of Hydra wording)

## What it does NOT assert

- Refresh after `refresh_token_lifespan` expires (would require a 30-min wait
  or chart override). Could be added later.
- Refresh on a revoked client / disabled user. See `13-disabled-user`.

## The `offline_access` scope

Hydra issues a refresh_token only when `offline_access` is in the requested
scope, hence the test passes `scope=openid+offline_access`.

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/04-refresh-token
```
