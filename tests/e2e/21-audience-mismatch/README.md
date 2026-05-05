# 21-audience-mismatch

Verify that `/oauth2/introspect` and `/userinfo` apply credential and
payload checks. Surfaces an open question on cross-client introspection.

## What it asserts

1. A confidential client introspecting its own real token →
   `active: true`.
2. Wrong client password on `/oauth2/introspect` → `401`.
3. Garbage token from a valid client → `active: false`.
4. Garbage Bearer at `/userinfo` → `401`.
5. **Reports** (does not fail on) cross-client introspection: client B
   introspecting a token issued to client A.

## Open question — cross-client introspect is permissive

Today, when client B authenticates to `/oauth2/introspect` and submits a
token issued to client A, kubauth returns `active: true` with the full
payload (sub, scope, exp, aud, etc.). Step 5 of this test reports this
state without failing.

This is the **default behavior** of the underlying Hydra/Fosite stack.
RFC 7662 §2.1 does not strictly mandate that the introspection endpoint
filter results by token audience or by the introspecting client's
identity, so this is not a spec violation.

It is, however, a defense-in-depth concern in multi-tenant setups: a
confidential client that is granted introspection access can learn `sub`
and `scope` of any user logged in via any other client on the same
issuer. Whether kubauth should filter (e.g. only return `active: true`
when the token's `aud` matches the introspecting client) is a design
decision for the project.

When that decision is made:

- if the answer is "filter by audience" → step 5 will fail, and the
  test should be updated to assert `active: false` (the stricter
  behavior).
- if the answer is "current behavior is intended" → this section can be
  removed and step 5 reduced to a single sanity check.

## What it does NOT assert

- Audience verification at `/userinfo` — the spec is `/userinfo` accepts
  any valid bearer for the user the token was issued to, regardless of
  the calling party. Cross-client `/userinfo` is not a security concern.
- `id_token`'s `aud` claim correctness — that is covered by
  `18-id-token-signature` (which uses `verify_aud=True`).

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/21-audience-mismatch
```
