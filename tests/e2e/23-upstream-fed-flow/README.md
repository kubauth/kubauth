# 23-upstream-fed-flow

Full upstream-OIDC federation: a user signs in via an external OIDC
provider, and kubauth issues its own `id_token` to the relying client.

## Why this test exists

`16-upstream-reconcile` only validates that an `UpstreamProvider` CR
reaches `READY` and that kubauth performed OIDC discovery against it.
It does NOT exercise the actual sign-in dance. This test does — it is
the primary deployment shape for federated kubauth setups.

## What it asserts

The federation chain, walked headlessly with `curl -L --max-redirs 4`:

```text
GET /oauth2/auth?...                       (smoke-client)
  -> 302 /oauth2/login?...                 (kubauth stashes authQuery)
  -> 302 /upstream/go?upstreamProvider=fed-upstream
                                            (single-upstream auto-redirect,
                                             see display-login.go)
  -> 302 mock /authorize?...               (mock-oauth2-server)
  -> 302 /upstream/callback?code=...&state=...
                                            (kubauth exchanges upstream
                                             code, builds User, with
                                             ssoMode=always completes
                                             original authorize)
  -> 302 http://localhost:9999/callback?code=<kubauth-code>
                                            (the kubauth code we want)
```

Then:

1. The redirected URL ends with the relying client's `redirect_uri`.
2. The `code` parameter is non-empty.
3. `POST /oauth2/token` with that code returns an `id_token`.
4. The decoded payload has `iss` equal to **kubauth's** issuer URL,
   not the upstream's.
5. The decoded payload has a non-empty `sub` (the upstream-mapped user).

## Mechanics

`--max-redirs 4` lets curl follow four redirects (`/oauth2/auth`,
`/oauth2/login`, `/upstream/go`, mock `/authorize`) and stop at the
fifth (which would attempt `localhost:9999/callback` and fail). The
`redirect_url` write-out field then carries the unfetched fifth
Location header, which contains the kubauth code.

The test sets `oidc.sso.mode=always` for its duration so kubauth
auto-completes the authorize after the upstream callback (no
`/upstream/welcome` form to drive). It restores `mode=never` in
`finally`.

The mock OIDC server (navikt/mock-oauth2-server) is configured with
`JSON_CONFIG={"interactiveLogin": false}` (in
`fixtures/mock-oidc/01-deployment.yaml`) so its `/authorize` skips the
HTML user-picker and auto-issues a code.

## What it does NOT assert

- Multi-upstream selection — kubauth's button-picker UI is bypassed by
  the single-upstream auto-redirect. Add a second `UpstreamProvider`
  for that test.
- `clientSpecific` upstream filtering (when an OidcClient lists allowed
  upstreams).
- The `/upstream/welcome` flow (rendered only with `ssoMode=onDemand`).
- Claim mapping correctness — we assert that `sub` is set, not its
  value. A future test can pin the mock issuer's claims and verify the
  mapping.
- Upstream signature verification — kubauth's go-oidc client validates
  the upstream `id_token` signature, but this test does not directly
  assert it (would require tampering with the mock to test rejection).

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/23-upstream-fed-flow
```
