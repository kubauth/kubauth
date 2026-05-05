# 28-multi-ns-oidcclient

OidcClient outside the chart's `oidc.clientPrivilegedNamespace` (the
default privileged namespace is `kubauth-system`) gets its
`client_id` prefixed by the namespace name.

## What it asserts

1. Apply `OidcClient nsapp` + `Secret nsapp-secret` in the `default`
   namespace (non-privileged).
2. After reconcile, `status.phase: READY` and `status.clientId:
   default-nsapp` (the prefix scheme implemented by
   `oidcclient_controller.go::buildClientId`).
3. ROPC with `default-nsapp:<secret>` returns an id_token.
4. ROPC with the bare `nsapp:<secret>` (no prefix) returns 4xx.

## What it does NOT assert

- A second prefix configuration (chart override of
  `oidc.clientPrivilegedNamespace`).
- The `spec.clientId` override path — when the spec sets `clientId`
  explicitly, kubauth uses that as-is (no prefix). Add a sub-test if
  this becomes load-bearing.
- The negative case where two non-privileged namespaces have an
  OidcClient with the same name (different namespace prefixes →
  different client_ids → no collision; but worth pinning).

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/28-multi-ns-oidcclient
```
