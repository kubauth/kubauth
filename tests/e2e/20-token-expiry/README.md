# 20-token-expiry

Confirm that `accessTokenLifespan` and `refreshTokenLifespan` are
actually enforced server-side, not merely advertised in the `exp` claim.

## Why this test exists

Other tests assert that `exp` is present in decoded payloads but never
wait for it to elapse. A regression where kubauth issued tokens with a
correct `exp` but no enforcement at `/oauth2/introspect` or
`/oauth2/token` would pass the rest of the suite.

## What it asserts

Per-test `OidcClient short-lived-client` with:

- `accessTokenLifespan: 5s`
- `refreshTokenLifespan: 15s`

Sequence:

1. ROPC → access token + refresh token issued.
2. Immediate `/oauth2/introspect` of the access token → `active: true`.
3. Sleep 8s.
4. `/oauth2/introspect` of the now-expired access token → `active: false`.
5. `/oauth2/token` with `grant_type=refresh_token` and the original RT →
   succeeds, returns a new AT and a rotated RT.
6. Sleep 17s.
7. `/oauth2/token` with `grant_type=refresh_token` and the rotated RT →
   `error: invalid_grant`.

Total runtime: ~30 s.

## Notes

- `offline_access` scope is required for the refresh token to be issued
  in the ROPC response (Fosite default).
- kubauth implements **rotation**: every refresh issues a new RT with a
  fresh lifespan and revokes the previous one. This test exercises
  expiry of the rotated RT — the original RT cannot be reused after
  rotation regardless of its remaining lifespan.

## What it does NOT assert

- `idTokenLifespan` — the id_token's `exp` claim is set but kubauth does
  not host an introspect-equivalent for id_tokens.
- Clock skew tolerance on the verifier side. RFC 6749 allows for a small
  leeway; we do not test it here.

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/20-token-expiry
```
