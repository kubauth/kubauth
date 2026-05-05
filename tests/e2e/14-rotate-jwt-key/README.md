# 14-rotate-jwt-key

JWT signing-key rotation: replacing the secret + restarting the deployment
must invalidate all previously-issued tokens, and the new tokens carry a new
`kid`.

## Why this test exists

kubauth currently has **single-key signing** — no overlap window where two
`kid`s coexist (cf. `findings.md` S6). Any rotation is hard-cut: every token
issued before becomes immediately invalid. This test guards against:

- a regression where the new signing material isn't picked up after restart
- a regression where `/jwks` continues to advertise the old `kid` (information
  leak + token-replay risk)
- a regression where `/userinfo` still validates against the old key

## What it asserts

1. Get token A; capture its `kid` (KID_A).
2. `KID_A` is in `/jwks`.
3. Generate fresh RSA-2048 + a new `kid`, replace the
   `kubauth-system/kubauth-oidc-jwt-key` Secret.
4. `kubectl rollout restart deploy/kubauth`, wait for ready.
5. Get token B; assert `kid != KID_A` and `kid == NEW_KID`.
6. `/jwks` advertises `NEW_KID` and **not** `KID_A`.
7. `/userinfo` with token A returns `401`.
8. `/userinfo` with token B returns 200 with alice's claims.

## Side effects (heads-up)

- The cluster ends with the rotated key. `make dev-up` keeps it as-is
  (`kubauth-install.sh` only generates a new key when the secret is absent).
- `kubectl rollout restart` resets in-memory state of the OIDC pod (BFA queue,
  Fosite stores). Other tests run after this should not assume continuity of
  in-memory state — but our chainsaw tests are designed to be order-independent.
- chainsaw's `cleanup` and `delete` timeouts in `chainsaw.yaml` are bumped to
  90 s to absorb pod-deletion grace periods exercised here.

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/14-rotate-jwt-key
```
