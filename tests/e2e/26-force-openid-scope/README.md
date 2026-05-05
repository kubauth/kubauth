# 26-force-openid-scope

`OidcClient.spec.forceOpenIdScope: true` makes kubauth grant the
`openid` scope implicitly even when the request does not include it.

## What it asserts

Two confidential clients with identical specs **except**
`forceOpenIdScope`:

- `force-openid-yes`: `forceOpenIdScope: true`
- `force-openid-no`:  `forceOpenIdScope: false`

ROPC for alice with `scope=profile` (no `openid`):

- `force-openid-yes` → response includes `id_token` (kubauth granted
  `openid` implicitly via `scopehandler.go::HandleScopes`).
- `force-openid-no`  → response has no `id_token`, only `access_token`
  with `scope=profile`.

## What it does NOT assert

- The exact path through `fositepatch/scopehandler.go` — only the
  observable response shape.
- The case where `forceOpenIdScope` is unset entirely (defaults to
  `nil` → `false` per `IsForceOpenIdScope`). Add if needed.

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/26-force-openid-scope
```
