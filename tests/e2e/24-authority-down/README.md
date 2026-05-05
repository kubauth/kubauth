# 24-authority-down

Pin the **observed** behaviour when a non-critical authority's
backing service is unreachable, and document the discrepancy with the
documented `critical: false` semantics.

## Setup

`fixtures/kubauth-values.yaml` declares two authorities:

```yaml
merger:
  idProviders:
    - name: ucrd
      critical: true
    - name: ldap
      critical: false
```

Per the merger source code (`merger/provider/provider.go::GetUserDetail`),
when a non-critical provider returns an HTTP error, the merger logs
and SKIPS it (returns `UserDetail` with `Status=Undefined`). The
caller (`merger/authenticator/authenticator.go`) then continues with
the remaining providers.

So in theory, with LDAP down:

- alice (UCRD-only) → succeeds (`ucrd` answers, `ldap` is skipped)
- carol (LDAP-only) → fails (`ldap` is skipped, `ucrd` does not know
  her, → `userNotFound`)

## What this test asserts (today's reality)

When the LDAP server is scaled to 0:

- alice → HTTP 500 with `error: server_error`
- carol → HTTP 500 with `error: server_error`

Both users get `server_error`, regardless of which authority knows
them. This contradicts the documented `critical: false` semantics.
The error originates from the LDAP authority binary failing its
HTTP-level call to the merger and surfacing as a generic 500.

This test is a **pin** — it asserts the current behaviour so a future
fix toggles it. When kubauth honours `critical: false`, the
assertions in step `ldap-down-current-behaviour` will fail with
`BEHAVIOUR CHANGED` and the test should be updated to:

- alice → HTTP 200
- carol → non-200

See `COVERAGE.md` backlog item B3 (or wherever the linked issue lands).

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/24-authority-down
```
