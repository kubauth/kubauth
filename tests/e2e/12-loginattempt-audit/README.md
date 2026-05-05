# 12-loginattempt-audit

Each authentication attempt is recorded as a `LoginAttempt` CR in the
`kubauth-audit` namespace by the audit authority.

## What it asserts

1. `OidcClient smoke-client` is READY.
2. Three failed ROPC attempts using **unique** unknown logins:
   `audit-test-<chainsaw-test-namespace-suffix>-1/2/3`.
3. After a 3 s settle window, exactly three `LoginAttempt` CRs exist in
   `kubauth-audit` whose `spec.user.login` matches our prefix, each with
   `spec.status: userNotFound`.
4. The `finally` block removes our LAs (the chart's audit cleaner handles
   long-lived TTL anyway).

## Why unique logins per test run

`LoginAttempt` resource names embed both `<login>` and a timestamp. Reusing a
fixed login across runs eventually produces collisions. By suffixing with the
chainsaw test namespace name (auto-generated, unique per run), the test is
order-independent and CI-safe.

## What it does NOT assert

- The `passwordChecked` and `passwordFail` paths. Both are observable via
  alice's BFA-affected attempts, but pulling alice into this test would couple
  it to BFA timing. Reserved for a follow-up.
- The audit cleaner TTL. Set in the chart (`recordLifetime`).

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/12-loginattempt-audit
```
