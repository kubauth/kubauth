# 07-sso

Single test that covers the full SSO behaviour: when the
`SsoSession` CRD is and is not persisted, and that the cross-app bypass
works under `mode=always`. Merged from the former `07-sso-cross-app`
and `17-sso-modes` (RT-2).

## What it asserts

| Step | mode     | remember | Expected                                  |
|------|----------|----------|-------------------------------------------|
| 1    | never    | on       | NO `SsoSession` CRD (`remember` ignored)  |
| 2    | onDemand | off      | NO `SsoSession` CRD                       |
| 3    | onDemand | on       | `SsoSession` CRD created                  |
| 4    | always   | —        | App A login leaves a `kubauth_sso` cookie that lets app B authorize without rendering a password form, and the resulting id_token has `sub=alice` |

## Source of truth

`SsoSession` **CRD** presence — not the cookie. SCS renews the
`kubauth_sso` cookie on every successful POST `/oauth2/login`
unconditionally, but `KubeSsoStore.CommitCtx` only persists an
`SsoSession` CRD when the SCS values map contains a non-empty
`ssoUser`. That happens iff:

```go
// cmd/oidc/oidcserver/handle-login.go
if s.SsoMode == SsoAlways || (s.SsoMode == SsoOnDemand && remember) {
    s.SsoSessionManager.Put(ctx, "ssoUser", user)
}
```

So the cookie alone is harmless — without a backing CRD, the SSO
bypass at `/oauth2/login` GET resolves to `nil` and the login form
renders normally.

## Mechanics

The test flips `oidc.sso.mode` between `never`, `onDemand`, and
`always` via per-step `helm upgrade --reuse-values --set …`. Three
upgrades total. `finally` restores `mode=never` so the rest of the
suite starts clean.

## What it does NOT assert

- `prompt=none` behaviour — kubauth does not currently honour the OIDC
  `prompt` parameter.
- Frontchannel/backchannel logout propagation across apps. Out of
  scope for v1.
- SSO cookie binding to a single browser/IP. Cookies are not bound.

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/07-sso
```
