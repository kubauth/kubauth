# 16-upstream-reconcile

UpstreamProvider reconciler smoke against a real OIDC issuer. The full
federation sign-in flow (browser → upstream → callback → kubauth token)
is covered by `23-upstream-fed-flow`.

## What it asserts

1. `fixtures/mock-oidc/` (navikt/mock-oauth2-server) is reachable and
   serves OIDC discovery at
   `http://mock-oidc.mock-oidc-test.svc:8080/kubauth/.well-known/openid-configuration`.
2. `UpstreamProvider mock-upstream` reaches `status.phase: READY`.
3. `status.effectiveConfig` is populated by discovery — kubauth fetched
   the provider metadata and stored the `authorization_endpoint`,
   `token_endpoint`, `jwks_uri`, etc.

## What it does NOT assert

- The federated sign-in flow itself — see `23-upstream-fed-flow`.
- `clientSpecific` upstreams (filtered by `OidcClient.spec.upstreams`).
- TLS to the upstream — mock-oauth2-server speaks plain HTTP. Add a
  TLS-ed variant once cert-manager is wired into the mock.

## Mechanics

The mock issuer is namespaced (`mock-oidc-test`) so it does not pollute
`kubauth-system`. The chainsaw test brings it up via `apply` of
`fixtures/mock-oidc/{00-namespace,01-deployment}.yaml`, then applies the
UpstreamProvider + client_secret. Cleanup deletes the UpstreamProvider
but leaves the mock issuer running — it is cheap and reused by
`23-upstream-fed-flow`.

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/16-upstream-reconcile
```
