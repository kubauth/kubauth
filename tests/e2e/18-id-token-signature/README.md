# 18-id-token-signature

Verify the cryptographic signature of an `id_token` issued by kubauth
against the keys advertised at `/jwks`.

## Why this test exists

Every other test in the suite decodes the JWT payload with `base64 -d`
and trusts the result. None verify the signature. A regression that
shipped tokens with `alg: none`, with a wrong-key signature, or with no
signature at all would pass the rest of the suite. This test closes that
gap.

## What it asserts

1. ROPC against `smoke-client` returns an `id_token`.
2. `/.well-known/openid-configuration` advertises a `jwks_uri`.
3. Fetching `jwks_uri` returns at least one JWK with a `kid` matching
   the token's header `kid`.
4. The token's `alg` is **not** `none` and is present in its header.
5. PyJWT verifies the signature against the public key derived from the
   matching JWK, with `verify_aud=True` and `verify_exp=True`.
6. The decoded `sub` claim is `alice`.

## Mechanics

The Python verifier (`verifier-cm.yaml`) is shipped as a ConfigMap so we
do not have to wrestle with YAML block-scalar / shell-heredoc / Python
indentation interactions in a chainsaw script block. The chainsaw step
applies the ConfigMap, runs a `python:3.12-slim` pod with the ConfigMap
mounted at `/verifier/`, and `pip install`s `pyjwt[crypto]` + `requests`
at startup (about 5 s).

## What it does NOT assert

- Multiple signing keys advertised simultaneously (see `14-rotate-jwt-key`
  for rotation, but not the multi-key window).
- ECDSA keys — kubauth currently uses RSA only. If support for ES256 is
  added, extend `verify.py` to handle `ECAlgorithm.from_jwk`.
- Algorithm downgrade attacks (e.g. token claiming `alg: HS256` and a
  wrong-key — would need an extra negative test).

## Run

```sh
make dev-up
chainsaw test --config chainsaw.yaml e2e/18-id-token-signature
```
