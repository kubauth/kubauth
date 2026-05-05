# 09-lockout-bfa

Brute-force protection — `internal/handlers/protector/bfa.go`.

## kubauth's BFA model (read this first)

BFA is **delay-based**, not lockout-based:

- After `freeFailure` attempts, every additional failure adds `penaltyByFailure`
  to the response delay.
- The penalty is capped at `maxPenalty`.
- Correct credentials still work after the penalty timer drains — the goal is
  to slow down credential-stuffing attackers, not to DoS legitimate users.

This is intentional. Permanent lockouts are themselves a DoS surface (an attacker
who knows your username can lock you out by hammering wrong passwords).

## What it asserts

1. `OidcClient smoke-client` is READY.
2. Six consecutive failed ROPC attempts on `alice-bfa` (an unknown user — the
   merger must not leak whether the user exists; failure counts the same):
   - all return `400`
   - the **6th** attempt is at least 2 seconds slower than the **1st** (the
     penalty timer has engaged)
3. A correct ROPC for `alice` still succeeds afterwards.

The 2 s floor accommodates timer jitter; expected real spread on a quiet
cluster is closer to 4–5 s on the 6th attempt.

## What it does NOT assert

- Exact `freeFailure` / `maxPenalty` / `penaltyByFailure` values. Tested only
  qualitatively (delay grows). Adjust if the chart exposes those flags and we
  want fine-grained coverage.
- BFA across pod restart. Today the state lives in memory (cf. `findings.md`
  S4); a restart resets it. Once persisted, add a regression test.

## Cluster setup

Requires `merger.server.bfaProtection: true` in `fixtures/kubauth-values.yaml`.

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/09-lockout-bfa
```
