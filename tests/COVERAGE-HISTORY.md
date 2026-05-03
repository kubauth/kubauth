# Coverage history

Audit log of completed backlog items. Live state is in
[COVERAGE.md](COVERAGE.md). Items move into this file once they ship,
keyed by the original `CT-N` (new test) / `RT-N` (refactor) ID and the
SHA of the closing commit.

---

## CT-1 — Verify id_token signature against `/jwks`  ·  P0

**Why** — Every test decoded the JWT payload with `base64 -d` and
trusted the result. None verified the signature. A regression that
shipped tokens with `alg: none`, with a wrong-key signature, or with
no signature would have passed the rest of the suite.

**Acceptance (delivered)**

- `e2e/18-id-token-signature/` runs in ~10 s.
- Acquires an `id_token` via the existing smoke-login flow.
- Fetches `/jwks` over the cluster service URL.
- Verifies the signature with PyJWT against the JWK matching the
  token header `kid`.
- Rejects `alg: none` and missing `alg`.

**Surface unlocked** — `/jwks` endpoint, signing-key correctness,
`kid` pinning.

---

## CT-2 — Discovery document shape  ·  P1

**Why** — A regression in `/.well-known/openid-configuration` would
break every external OIDC RP silently.

**Acceptance (delivered)**

- `e2e/19-discovery-shape/` asserts the standard discovery fields,
  the configured issuer, S256 PKCE advertisement, presence of a
  strong signing alg, presence of `authorization_code` grant and
  `openid` scope, that the advertised `authorization_endpoint` is
  under the issuer and reachable.

---

## CT-3 — Token expiry enforcement  ·  P0

**Why** — Tests asserted `exp` was present in the payload but never
waited for expiry to confirm rejection.

**Acceptance (delivered)**

- `e2e/20-token-expiry/` runs in ~30 s.
- Per-test `OidcClient` with `accessTokenLifespan: 5s`,
  `refreshTokenLifespan: 15s`.
- Asserts: fresh `/oauth2/introspect` shows `active: true`;
  post-expiry shows `active: false`; rotated refresh-token rejected
  with `invalid_grant` after the refresh lifespan elapses.

---

## CT-4 — Audience cross-client rejection  ·  P0  ·  ◐ partial

**Why** — A token issued to client A could be used at
`/oauth2/introspect` with client B credentials.

**Acceptance (delivered, partial)**

- `e2e/21-audience-mismatch/` covers the verifiable parts:
  - real client + real token → `active: true`.
  - bad client password → `401`.
  - garbage token → `active: false`.
  - garbage Bearer at `/userinfo` → `401`.
- The original assertion (cross-client rejection) was **not** added:
  kubauth's introspection is permissive (Hydra default). The test
  documents this as an open design question; the strict version of
  the assertion is logged as backlog item B2 in `COVERAGE.md`.

---

## CT-5 — Webhook admission rejection (re-scoped)  ·  P0  ·  ◐ re-scoped

**Why** — `oidcclient_webhook.go` and `upstreamprovider_webhook.go`
are skeletons (`ValidateCreate` returns `nil, nil`). Webhook-level
rejection cannot be tested until kubauth implements validation logic.

**Re-scoped to** `e2e/22-oidcclient-validation/` which exercises:

- the defaulting webhook (1 h default lifespans applied when omitted)
- reconciler-level validation (`public=false` without secrets,
  `public=true` with secrets) producing `status.phase: ERROR` with
  the right message.

The original webhook-admission assertion is logged as backlog item
B1 in `COVERAGE.md`, blocked on the upstream change.

---

## CT-6 — Full upstream-OIDC federation flow  ·  P1

**Why** — `16-upstream-reconcile` only validated the reconciler. The
actual federated sign-in (button click → upstream → callback →
kubauth issues its own id_token) was the primary user-facing flow
for federated setups and had zero coverage.

**Acceptance (delivered)**

- `e2e/23-upstream-fed-flow/` runs in ~33 s.
- Uses `fixtures/mock-oidc/` (navikt/mock-oauth2-server with
  `interactiveLogin: false`) as the upstream.
- Walks the full chain headlessly with `curl -L --max-redirs 4`:
  `/oauth2/auth` → `/oauth2/login` → `/upstream/go` → mock
  `/authorize` → `/upstream/callback` → relying client `redirect_uri`
  with kubauth's own code.
- Exchanges the code at `/oauth2/token`, decodes the resulting
  id_token, asserts `iss` is kubauth's issuer (not the upstream)
  and `sub` is non-empty.

**Surface unlocked** — `/upstream/go`, `/upstream/callback`, and
under `ssoMode=always`, `completeUpstreamAuthorize`.

---

## RT-1 — Merge `05-userinfo` + `06-introspection` → `05-resource-server`  ·  P2

**Why** — Both validated "endpoint X returns claims for a valid
token" — same shape, same setup. Merging eliminated one redundant
token issue.

**Delivered** — `05-resource-server/` covers `/userinfo` and
`/oauth2/introspect` with one Auth-Code+PKCE login, three positive
assertions and four negatives.

---

## RT-2 — Merge `07-sso-cross-app` + `17-sso-modes` → `07-sso`  ·  P2

**Why** — `17` was almost a subset of `07`. A single test with four
sub-cases is clearer and saves one helm-upgrade cycle.

**Delivered** — `07-sso/` walks the matrix:

- `mode=never + remember=on` → no SsoSession.
- `mode=onDemand + remember=off` → no SsoSession.
- `mode=onDemand + remember=on` → SsoSession created.
- `mode=always` → app A login enables app B SSO bypass; resulting
  id_token has `sub=alice`.

---

## RT-3 — Rename `16-upstream-oidc-fed` → `16-upstream-reconcile`  ·  P2

**Why** — The previous name suggested federation was tested. It was
not — only reconcile-to-READY. Renaming was honest. The full
federation flow lives in `23-upstream-fed-flow` (CT-6).

**Delivered** — directory rename + README rewrite + cross-references
updated.

---

## RT-4 — Tighten `08-logout` to assert SsoSession deletion  ·  P1

**Why** — Logout previously only asserted the redirect URL. A
regression where the SsoSession CRD survived logout would have
silently left the SSO cookie usable.

**Delivered** — `08-logout/` now flips `oidc.sso.mode=always` for
its duration, logs in, performs RP-initiated logout, then asserts
that `kubectl get ssosessions -n kubauth-system` returns zero
results within 10 s. Login and logout share a cookie jar in one
pod so the cookie binds to the session being destroyed.

---

## RT-5 — Tighten `12-loginattempt-audit` to assert CR contents  ·  P2

**Why** — The test only asserted CR creation. It did not check
timestamp, status, or `spec.user.uid`.

**Delivered** — `12-loginattempt-audit/` now also:

- Asserts `spec.when` is within ±5 s of the test window.
- Asserts `spec.user.login` matches the request login.
- Adds a successful ROPC for alice and asserts
  `spec.status: passwordChecked` and `spec.user.uid: 1001`.

---

## A1 — Authority failure modes  ·  P1  ·  ◐ pinned (revealed kubauth bug)

**Why** — Verify what happens when an authority is unreachable.

**Delivered (with finding)** — `e2e/24-authority-down/` runs the
scenario and revealed that with LDAP scaled to 0, every
`/oauth2/token` returns `500 server_error` — even users that exist
only in UCRD (the critical authority). This contradicts the
documented `critical: false` semantic on the LDAP authority. The
test pins the observed behaviour so a future fix toggles it. The
discrepancy is filed as backlog item B3 in `COVERAGE.md`.

---

## A2 — GroupBinding flow  ·  P1

**Why** — `groups[]` claim was exercised only as a side effect of the
seeded `alice-admins` GroupBinding.

**Delivered** — `e2e/25-groupbinding/`:

- Apply Group `qa-team` and GroupBinding `alice-qa-team`.
- ROPC for alice → `groups[]` includes `qa-team`.
- Delete the GroupBinding → next ROPC drops `qa-team`.

---

## A3 — `forceOpenIdScope`  ·  P2

**Why** — Flag existed in the spec, was untested.

**Delivered** — `e2e/26-force-openid-scope/`:

- Two OidcClients identical except `forceOpenIdScope`.
- ROPC against each with `scope=profile` (no `openid`).
- `forceOpenIdScope: true` → response includes `id_token`.
- `forceOpenIdScope: false` → response has no `id_token`.

---

## A4 — scope filtering  ·  P2

**Why** — `OidcClient.spec.scopes` was supposed to be the universe of
allowed scopes; behaviour was untested.

**Delivered** — `e2e/27-scope-filtering/`:

- OidcClient with `scopes: [openid, email]` (no `groups`).
- Allowed-only request → 200.
- Out-of-list scope (`groups`) → 400 `invalid_scope` (Fosite default,
  which kubauth ships).
- The test accepts either rejection or filtering and pins whichever
  kubauth does today.

---

## A5 — multi-namespace OidcClient  ·  P2

**Why** — Namespace-prefix code path existed but was never tested.

**Delivered** — `e2e/28-multi-ns-oidcclient/`:

- OidcClient `nsapp` applied in the `default` namespace.
- `status.clientId: default-nsapp` (the prefix scheme implemented by
  `oidcclient_controller.go::buildClientId`).
- ROPC with the prefixed client_id → succeeds.
- ROPC with the bare name → 4xx.

---

## B8-partial — `prompt=none` and `prompt=login` honoured at `/oauth2/login`  ·  P1  ·  OIDC Core 1.0 §3.1.2.1

**Why** — kubauth's `handleLogin` GET branch ignored the `prompt`
query parameter. Two consequences:

- `prompt=none`: when the client says "do not interact with the
  user, just confirm a session", kubauth was rendering the login
  form anyway. Spec says: must return `login_required` to the
  redirect_uri instead.
- `prompt=login`: when the client says "force re-authentication
  even if a session exists", kubauth was auto-completing via the
  existing SSO session. Spec says: must show the login form again.

**Effect on conformance**

- `oidcc-prompt-none-not-logged-in` (oidcc-basic): INTERRUPTED FAILED → FINISHED PASSED.
- ~7 cascade modules in `oidcc-rp-initiated-logout-certification`
  that issue a follow-up `prompt=none` after logout: would also
  benefit, **but** B8 (the SSO session not being terminated by
  logout) is the still-open root cause that gates them. The
  prompt=none plumbing is now in place; what remains is to make
  logout actually destroy the session.

**Delivered**

- `cmd/oidc/oidcserver/handle-login.go::handleLogin` now parses
  the `prompt` parameter (space-delimited), honours `none` and
  `login`. Other values (`consent`, `select_account`) are silently
  ignored — kubauth has no consent UI, and there's only one user
  per session.
- The bypass-via-SSO branch is gated on `!promptLogin`.
- A new branch returns `fosite.ErrLoginRequired` via
  `WriteAuthorizeError` when we'd otherwise render the login page
  AND `prompt=none` is set.
- `tests/conformance/config/oidcc-basic.json` browser block — the
  inner "Submit kubauth login form" task is marked `optional: true`
  so prompt=none paths (which legitimately skip the form) don't
  trip the HtmlUnit driver with "WebRunner unexpected url for task".

**Outcome** — oidcc-basic: 22/35 reaching FINISHED with PASSED or
WARNING (was 19), 15 PASSED (was 12). The remaining red modules
are kubauth feature gaps tracked individually as B9-B14 in
`COVERAGE.md`. B8 (the rp-logout root cause) is **still open** —
this commit only addresses the prompt parameter handling.

---

## B6-polish — refine id_token claim filter (drop `rat`, allow `authority`+`uid`)  ·  P1

**Why** — the initial B6 filter (closed earlier) treated all kubauth
claims uniformly: anything not in OIDC §5.4 was dropped. Two
problems surfaced:

- **`rat` (hydra/fosite "requested at")** was let through via the
  `alwaysAllowedClaims` bucket "to keep working with existing
  clients". The OpenID Conformance Suite flagged it as
  non-requested → WARNING on every id-token-bearing module.
- **`authority` and `uid`** are kubauth-specific extensions that
  the chainsaw e2e suite (`03-pkce-s256`, `10-ldap-authority`,
  `11-merger-claim-priority`) and downstream tooling rely on. With
  the original filter they were dropped under
  `scope=openid` only → 3 chainsaw failures.

**Delivered** in `cmd/oidc/fositepatch/scope_filter.go`:

- `rat` removed from `alwaysAllowedClaims`. Strict RPs no longer
  get the WARNING; the value remains observable via
  `/oauth2/introspect` for clients that genuinely need it.
- `authority` added — informational, says which IdP authenticated
  the user (ucrd / ldap / ...). Kept as a kubauth extension; the
  conformance suite WARNs on it but doesn't fail.
- `uid` added — POSIX numeric uid, used by downstream tooling
  that maps OIDC sub → host user. Same kubauth extension status.

Plus on the chainsaw side: `tests/e2e/03-pkce-s256/chainsaw-test.yaml`
now requests `scope=openid+groups` explicitly (the test was
relying on kubauth's pre-B6 behaviour of always emitting `groups`
regardless of scope; the request should be honest about what it
needs).

**Outcome** — chainsaw 26/26 PASS. Conformance oidcc-basic:
WARNINGs no longer trip on `rat`; remaining WARNINGs are all the
benign `VerifyScopesReturnedInUserInfoClaims` (kubauth's user
model doesn't carry every optional `profile` claim).

---

## B7 — RP-initiated logout dropped `state`  ·  P1  ·  RFC: OIDC RP-Initiated Logout 1.0 §3

**Why** — `cmd/oidc/oidcserver/handle-logout.go` did
`http.Redirect(w, r, postLogoutURL, 302)` straight to the URL with
no query-string augmentation. OIDC RP-Initiated Logout 1.0 §3 says:
"If the `state` parameter is included in the request, the OP MUST
add it to the URL of the response when redirecting to the
`post_logout_redirect_uri`."

**Effect on conformance** — every module of
`oidcc-rp-initiated-logout-certification` that exercised the state
echo (the main `oidcc-rp-initiated-logout` test plus
`-only-state`, `-no-state`, `-query-added-...`) failed at
`CheckPostLogoutState`.

**Delivered** — `handle-logout.go` parses the request query, lifts
`state` (when present), and merges it into the `postLogoutURL`
before redirecting. Pre-existing query parameters on the post-logout
URL are preserved; on a malformed configured URL the helper falls
back to a safe append rather than dropping `state` silently.

**Outcome** — confirmed by the conformance suite log:
`CheckPostLogoutState: state passed to post logout redirect uri matches request` SUCCESS.
The remaining `oidcc-rp-initiated-logout-*` failures are tracked
separately as backlog B8 (SSO session not destroyed).

---

## B6 — id_token leaked every user claim regardless of scope  ·  P1  ·  OIDC §5.4

**Why** — `cmd/oidc/oidcserver/oidcserver.go::newSession` populated
both `IDTokenClaims_.Extra` and `JWTClaims_.Extra` from
`user.Claims` — the full authenticator-side claim set
(`name, email, emails, groups, uid, authority, rat`). OIDC Core 1.0
§5.4 requires that profile/email/address/phone claims appear in the
id_token only when the matching scope is granted.

**Effect on conformance** — every id-token-bearing module of
`oidcc-basic-certification` ended in `FINISHED WARNING` on
`EnsureIdTokenDoesNotContainNonRequestedClaims`.

**Delivered**

- New `cmd/oidc/fositepatch/scope_filter.go`:
  - `claimsByScope` table (standard scopes from OIDC §5.4 plus the
    kubauth-specific `groups` scope).
  - `alwaysAllowedClaims` for protocol-level Extra entries
    (`azp, nonce, at_hash, c_hash, acr, amr, auth_time, sid`).
    `rat` deliberately excluded — strict RPs flag it as
    non-requested; the value remains observable via
    `/oauth2/introspect` for clients that genuinely need it.
  - `FilterExtraClaimsByScope` mutates an Extra map in place.
  - `scopeFilteringIDTokenStrategy` wraps the default
    `OpenIDConnectTokenStrategy`, filters the session before
    delegating to `GenerateIDToken`.
- `compose2.go`: wires the wrapped strategy into the
  `compose.CommonStrategy.OIDCTokenStrategy` slot for both the
  HMAC and JWT access-token modes.
- `handle-user-info.go`: restored the scope-filtered claim
  selection (the original implementation was commented-out at
  lines 66-89). Now reuses `fositepatch.AllowedIDTokenClaimsFor`
  so id_token and userinfo follow the same scope→claim mapping.
  `sub` is always added back from the top-level `IDTokenClaims_.Subject`.

**Outcome** — `oidcc-basic`'s WARNINGs no longer trip on leaked
claims. The 7 remaining WARNINGs are now benign
`VerifyScopesReturnedInUserInfoClaims` notes (kubauth's user model
doesn't carry every optional `profile` claim — informational, not
a spec violation).

---

## B5 — userinfo rejected lowercase `bearer` scheme  ·  P0  ·  RFC 7235

**Why** — `cmd/oidc/oidcserver/handle-user-info.go` checked
`strings.HasPrefix(authz, "Bearer ")` exactly. RFC 7235 §2.1
specifies that the auth scheme name is **case-insensitive**; the
OpenID Conformance Suite (and other clients) sends `bearer` in
lowercase, which kubauth rejected with 401 `missing bearer token`.

**Effect on conformance** — every `oidcc-basic` module that calls
`/userinfo` (the bulk of the plan) failed at
`EnsureHttpStatusCodeIs200`. Surfaced once `oidcc-basic` was wired up.

**Delivered**

- `handle-user-info.go`: prefix check uses `strings.EqualFold` over
  `Bearer` (length-bounded). Token extraction switched from
  `TrimPrefix` to slice-from-prefix-length (no semantic change but
  symmetric with the new check).
- Image rebuilt (tag `conformance`, in the local kind registry at
  `localhost:5001/kubauth/exec/kubauth`); helm upgraded over all five
  components (oidc, merger, ucrd, audit, ldap) for the conformance
  test cluster.
- E2e suite re-validated; the existing `05-resource-server` test
  uses the standard `Bearer` casing, unaffected.

**Outcome** — `oidcc-basic` jumped from "every userinfo module
failed" to 13 PASSED + 7 WARNING (warnings tracked as B6).

---

## B4 — cert-manager empty-subject certs blocking conformance  ·  P1

**Why** — `tests/fixtures/cluster-issuer.yaml` was a `selfSigned`
ClusterIssuer and the chart's Certificate templates omit
`commonName`. cert-manager therefore issued kubauth's server cert
with an **empty Subject DN** — RFC-compliant (SAN covers hostname
matching) but rejected by strict JVM TLS clients. The OpenID
Conformance Suite's discovery step failed with
`Failed to parse server certificates`, blocking every plan.

**Delivered (option (a) — local fix, no upstream change)**

- `tests/fixtures/cluster-issuer.yaml` rewritten as a 3-resource
  manifest:
  1. `kubauth-tests-bootstrap` — selfSigned ClusterIssuer used
     only to sign the CA cert.
  2. `kubauth-tests-ca` Certificate (in `cert-manager` namespace)
     with `isCA: true`, `commonName: kubauth-tests-ca`,
     `duration: 87600h`, RSA 2048.
  3. `kubauth-tests-selfsigned` ClusterIssuer (kept under the same
     legacy name so the chart's `issuerRef` is unchanged), now of
     type `ca` referencing the secret produced by the CA cert.
- `tests/scripts/kubauth-install.sh` extended:
  - `apply_cluster_issuer` now waits for the CA Certificate to
    reach `Ready` before proceeding (otherwise downstream certs
    queue forever).
  - New `patch_certificate_common_names` step (called after
    `helm_install_kubauth`) patches each Certificate the chart
    created (`kubauth-oidc-server`, `kubauth-oidc-webhooks`,
    `kubauth-ucrd-webhooks`) with `commonName: <cert-name>`,
    deletes the underlying secrets to force re-issue, and bounces
    the kubauth Deployment.

**Outcome**

- Every kubauth server cert now carries a non-empty Subject DN
  (e.g. `CN = kubauth-oidc-server`).
- `oidcc-config-certification-test-plan` driven via the suite's
  REST API: status `FINISHED`, result `PASSED`. JSON report
  captured under
  `tests/conformance/results/oidcc-config-rwxF57HHEI7jEnS.json`.
- E2e suite re-validated 26/26.

---

## A6 — `clientSpecific` upstream filtering  ·  P2

**Why** — `UpstreamProvider.spec.clientSpecific` existed in the
spec but the filtering logic in `display-login.go` was never
exercised.

**Delivered** — `e2e/29-clientspecific-upstream/`:

- Two UpstreamProviders pointing at the mock issuer (`up-public`
  with `clientSpecific=false`, `up-private` with
  `clientSpecific=true`).
- Two OidcClients: `cs-client-a` (no upstream list) and `cs-client-b`
  (`upstreamProviders: [up-private]`).
- For each, follow `/oauth2/auth` → `/oauth2/login` → 302
  `/upstream/go?upstreamProvider=<name>` and assert the right
  upstream is selected.

---

## G1 — Go unit tests for `internal/misc/expandenv`  ·  pure-logic

**Delivered** — `internal/misc/expandenv_test.go`, 13 tests.

- Empty input, no-variables passthrough, single + multiple variables.
- Lone `$` passes through literally (documented divergence from
  `os.ExpandEnv`).
- `MissingVariableError` returned for undefined vars, includes the
  variable name and line number.
- Variable names accept `[a-zA-Z0-9_]`; invalid chars fall back to
  literal passthrough.
- `MissingVariableError.Error()` formatting pinned.

**Surfaced bug** — adjacent variables (`${A}${B}`) leave the second
unexpanded because the parser stays in `STATE_IN_VAR` after a closing
`}`. Pinned by `TestExpandEnv_AdjacentVariables_PinsCurrentBuggyBehaviour`.
One-line fix candidate (`state = STATE_NOMINAL`) deferred to keep this
PR strictly tests-only.

---

## G2 — Go unit tests for `internal/misc/loadconfig`  ·  pure-logic

**Delivered** — `internal/misc/loadconfig_test.go`, 7 tests.

- Parses YAML into struct; returns absolute path even on read error.
- Env-expansion runs *before* YAML parse — verified end-to-end.
- Missing env var surfaces as a `MissingVariableError` from
  `ExpandEnv`.
- File-not-found path.
- Strict YAML mode rejects unknown fields (silent-typo guard).
- Empty file is not an error (decoder hits `io.EOF`).
- Relative path is resolved to absolute.

---

## G4 — Go unit tests for `internal/httpclient`  ·  httptest

**Delivered** — `internal/httpclient/httpclient_test.go`, 24 tests.

- `New` URL/scheme validation (malformed, ftp://, http://, https://).
- CA loading errors: empty PEM, garbage PEM, invalid base64,
  base64-decoding-to-non-PEM, missing CA file. Plain `http://` skips
  CA loading entirely.
- `appendCaFromPEM` rejects empty input and PEM with no CERTIFICATE
  block.
- `Do` returns `*UnauthorizedError` on 401, `*NotFoundError` on 404
  (with URL in message), generic `error` on 500. Connection-refused
  surfaces as a wrapped error.
- Headers: Content-Type propagated; Basic auth + Bearer token set
  correctly; no `Authorization` if `HttpAuth` not configured.
- BaseURL + path joining preserves the path verbatim.
- Error type messages (`UnauthorizedError`, `NotFoundError`) pinned.
