# 05-resource-server

Resource-server endpoints: `/userinfo` (OIDC §5.3) and
`/oauth2/introspect` (RFC 7662). Merged from the former
`05-userinfo` + `06-introspection` (RT-1) — same shape, single token
issue, single curl pod.

## What it asserts

One Auth-Code + PKCE login with scope
`openid profile email groups` issues an access token. The test then
exercises:

### `/userinfo`

1. `GET /userinfo` with a valid Bearer → `200`, claims include
   `sub=alice`, `email=alice@example.test`, `groups=[admins]`,
   `name=Alice Smith`.
2. `GET /userinfo` without any `Authorization` header → `401`.
3. `GET /userinfo` with a garbage Bearer → `401`.

### `/oauth2/introspect`

1. POST with valid token + Basic client auth → `200`,
   `active=true`, `sub=alice`, `client_id=smoke-client`,
   `username=alice`.
2. POST with a garbage token + Basic client auth → `200`,
   `active=false`, no `sub` leakage.
3. POST with a valid token but no client auth → `401`.

## What it does NOT assert

- Cross-client introspect behaviour (kubauth is permissive — covered
  separately in `21-audience-mismatch`).
- Expired-token behaviour at these endpoints (`20-token-expiry`).
- id_token signature (`18-id-token-signature`).

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/05-resource-server
```
