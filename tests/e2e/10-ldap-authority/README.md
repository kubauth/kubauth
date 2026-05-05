# 10-ldap-authority

ROPC for an LDAP-only user succeeds, and the merger tags the id_token with
`authority: ldap` plus the configured group pattern.

## What it asserts

1. The OpenLDAP fixture (`fixtures/ldap/`) is up.
2. `OidcClient smoke-client` is READY.
3. ROPC for `carol` (lives only in OpenLDAP, not in any User CRD) returns
   200 with an id_token whose claims contain:
   - `authority: ldap`
   - `sub: carol`
   - `email: carol@example.test`
   - `groups: [ldap-engineers]` (merger `groupPattern: "ldap-%s"` applied to
     LDAP group `engineers`)

## What it does NOT assert

- LDAP TLS — the test uses `insecureNoSSL: true`. A separate test should
  cover ldaps:// once cert-manager wires a CA into the LDAP server.
- StartTLS, mTLS to LDAP. Out of scope for v1.

## Cluster prerequisites

- `make dev-up` deploys `fixtures/ldap/` (OpenLDAP + LDIF carol/engineers).
- `kubauth-values.yaml` enables `ldap.enabled: true` and adds `ldap` to
  `merger.idProviders`.

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/10-ldap-authority
```
