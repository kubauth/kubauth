# 19-discovery-shape

Assert that `/.well-known/openid-configuration` advertises the standard
set of fields an OIDC RP needs. A regression here breaks every external
relying party silently — none of the other tests would catch it because
they all hit kubauth at hard-coded endpoint URLs, not through discovery.

## What it asserts

1. `GET /.well-known/openid-configuration` returns `200`.
2. The JSON body contains every field expected by an OIDC RP:
   - `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`,
     `userinfo_endpoint`, `introspection_endpoint`, `end_session_endpoint`
   - `response_types_supported`, `grant_types_supported`,
     `id_token_signing_alg_values_supported`, `scopes_supported`,
     `code_challenge_methods_supported`, `claims_supported`
3. `issuer` matches the chart-configured value exactly.
4. `code_challenge_methods_supported` includes `S256` (public clients
   depend on it).
5. `id_token_signing_alg_values_supported` advertises at least one strong
   algorithm (`RS256`, `ES256`, or `PS256`).
6. `authorization_code` is in `grant_types_supported`.
7. `openid` is in `scopes_supported`.
8. `authorization_endpoint` URL is under the issuer.
9. The advertised `authorization_endpoint` is reachable (any non-5xx).

## What it does NOT assert

- Field-by-field semantic correctness (e.g. that every endpoint actually
  responds to its documented HTTP methods). Out of scope here — that is
  the job of the OpenID Conformance Suite.
- The exact set of advertised values (e.g. that exactly RS256 is the
  only signing alg). Adding ES256 in a future release should not require
  changing this test.

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/19-discovery-shape
```
