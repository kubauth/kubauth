# 29-clientspecific-upstream

`UpstreamProvider.spec.clientSpecific: true` makes an upstream
invisible to clients that do not list it explicitly via
`OidcClient.spec.upstreamProviders`.

## Setup

Two upstreams (both pointing at the mock OIDC server):

- `up-public`  — `clientSpecific: false` (default; visible globally)
- `up-private` — `clientSpecific: true`

Two relying clients:

- `cs-client-a` — no `upstreamProviders` list. Sees the global list,
  filtered: only `up-public`.
- `cs-client-b` — `upstreamProviders: [up-private]`. Sees only
  `up-private`.

## What it asserts

For each client, follow `/oauth2/auth` → `/oauth2/login`. Because each
client has exactly one upstream button computed,
`display-login.go::displayLoginResponse` auto-redirects to
`/upstream/go?upstreamProvider=<name>`. The `<name>` segment of that
URL tells us which upstream was selected.

Expectations:

- `cs-client-a` → `upstreamProvider=up-public` (clientSpecific=true
  upstream filtered out).
- `cs-client-b` → `upstreamProvider=up-private` (explicit list
  overrides the global filter).

## What it does NOT assert

- The HTML rendering when **multiple** upstream buttons are shown —
  the auto-redirect path covers single-button only. A multi-upstream
  scenario would require parsing the rendered HTML.
- The error path when an OidcClient lists an upstream name that does
  not exist.
- Behaviour with an `internal` upstream alongside the OIDC ones.

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/29-clientspecific-upstream
```
