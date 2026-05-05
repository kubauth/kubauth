# 27-scope-filtering

`OidcClient.spec.scopes` is the universe of allowed scopes for that
client. A token request asking for a scope outside that universe must
either be rejected or filtered down — never silently granted.

## What it asserts

A per-test `OidcClient scope-restricted` is applied with
`scopes: [openid, email]` (no `groups`).

1. ROPC requesting `scope=openid email` → succeeds (200).
2. ROPC requesting `scope=openid email groups` → either:
   - **400** with body containing `invalid_scope` (Fosite default), OR
   - **200** with the response scope set NOT containing `groups`
     (kubauth filters down).

The test accepts either behaviour and pins it. A regression that
silently granted `groups` would fail the 200-branch check.

## What it does NOT assert

- The exact wording of the error description.
- Behaviour when the client requests **only** out-of-list scopes
  (would short-circuit before the password check).

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/27-scope-filtering
```
