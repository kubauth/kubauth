# 25-groupbinding

GroupBinding flow: a `Group` + `GroupBinding` mapping a user to a group
adds the group to the user's id_token `groups[]` claim; deleting the
binding removes it.

## What it asserts

1. Apply `Group qa-team` and `GroupBinding alice-qa-team` (binding
   alice to qa-team).
2. ROPC for alice with `scope=openid profile email groups` →
   `id_token.groups[]` contains `qa-team`.
3. Delete the GroupBinding.
4. ROPC again → `id_token.groups[]` no longer contains `qa-team`.

## What it does NOT assert

- The reconciler's exact timing — a 3 s sleep is used between CRD
  changes and the next ROPC. If the reconciler regresses to be slow,
  this test may flake.
- The `comment` field on Group, the `Status` subresource, ordering of
  groups[] in the claim.

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/25-groupbinding
```
