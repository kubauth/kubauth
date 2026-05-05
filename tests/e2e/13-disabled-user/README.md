# 13-disabled-user

`User.spec.disabled: true` blocks every authentication for that user — even
with the correct password.

## What it asserts

1. A new User with `disabled: true` and the well-known bcrypt hash for
   `alice-password` (so the credential is *correct*) is applied.
2. ROPC with that user + correct password returns:
   - `error: invalid_grant`
   - `error_description` **must not** contain the word `disabled`
     (anti-enumeration: the surface must look identical to a wrong-password
     attempt).
3. The audit chain produces a `LoginAttempt` in `kubauth-audit` with:
   - `spec.user.login: disabled-user-test`
   - `spec.status: disabled`

   Operators need this in audit even though end users can't tell the difference
   externally.
4. Cleanup: removes the User, the LA, and the curl pod.

## Why anti-enumeration matters

Returning a distinct error for disabled accounts (`account_disabled`, etc.)
lets an attacker enumerate which usernames exist *and* which are currently
locked — a stepping stone for targeted social-engineering. Hydra's stock
`invalid_grant` keeps the surface flat.

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/13-disabled-user
```
