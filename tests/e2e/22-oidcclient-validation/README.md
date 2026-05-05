# 22-oidcclient-validation

Exercise the OidcClient defaulting and reconciler-level validation that
rejects unusable specs.

## Scope

This test covers **reconciler-level** validation of OidcClient (and
the defaulting webhook). The `OidcClient` and `UpstreamProvider`
validation webhooks are still skeletons:

```go
// cmd/oidc/webhooks/oidcclient_webhook.go
func (v *OidcClientCustomValidator) ValidateCreate(...) {
    // TODO(user): fill in your validation logic upon object creation.
    return nil, nil
}
```

So the validation that actually fires today lives in the OidcClient
reconciler and surfaces as `status.phase: ERROR` with a
`status.message`. This test exercises that path.

When the webhook gains real validation logic (backlog **B1** in
`tests/COVERAGE.md`), split this test: `22-oidcclient-validation`
keeps the reconciler checks; a new `22-oidcclient-webhook` covers
admission rejection at apply time.

## What it asserts

### Defaulting webhook (which IS implemented)

Apply an OidcClient without `accessTokenLifespan`,
`refreshTokenLifespan`, `idTokenLifespan`. After the defaulter runs,
each is set to `1h`.

### Reconciler validation: confidential client with no secret

`public: false` + empty `secrets` → `status.phase: ERROR` with a
message mentioning "secret".

### Reconciler validation: public client with a secret

`public: true` + `secrets: [...]` → `status.phase: ERROR` with a
message mentioning "public".

## What it does NOT assert

- Webhook-level admission rejection (skeleton today). Add when the
  webhook gains real validation logic.
- Other invariants the spec implies but the reconciler does not
  currently enforce: empty `redirectURIs`, non-https URI for
  confidential clients, unknown grant type, etc.

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/22-oidcclient-validation
```
