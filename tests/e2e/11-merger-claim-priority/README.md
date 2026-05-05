# 11-merger-claim-priority

Two authorities respond for the same login (`carol`). The merger composes the
id_token claims per the per-field `*Authority` flags configured in
`fixtures/kubauth-values.yaml`.

## Cluster prerequisites

- LDAP carol (`fixtures/ldap/`):
  - email `carol@example.test`, uid `2001`, group `engineers`
- UCRD carol (per-test fixture `user.yaml`):
  - email `carol-ucrd@example.test`, uid `5001`, no group binding

`kubauth-values.yaml`:

| Authority | credentialAuthority | claimAuthority | groupAuthority | nameAuthority | emailAuthority | groupPattern |
|---|---|---|---|---|---|---|
| ucrd | ✅ | ✅ | ✅ | ✅ | ✅ | `%s` |
| ldap | ✅ | ❌ | ✅ | ✅ | ✅ | `ldap-%s` |

## Documented merge result

ROPC with the **UCRD** password (`alice-password` reused) returns claims:

| Claim | Source | Value |
|---|---|---|
| `authority` | (= which authority validated the credential) | `ucrd` |
| `sub` | `metadata.name` | `carol` |
| `email` | UCRD wins (claimAuthority) | `carol-ucrd@example.test` |
| `emails[]` | union of both | `[carol-ucrd@example.test, carol@example.test]` |
| `name` | UCRD wins (nameAuthority + first in chain) | `Carol from UCRD` |
| `uid` | UCRD | `5001` |
| `groups` | LDAP only contributes (UCRD has no GroupBinding) | `[ldap-engineers]` |

## What it does NOT assert

- Order swap (LDAP first) — the chart-level chain is fixed in
  `kubauth-values.yaml`. A separate test could prove order matters by
  reversing the providers.
- A login that LDAP validates but UCRD doesn't — covered by `10-ldap-authority`.

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/11-merger-claim-priority
```
