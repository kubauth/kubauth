# Test coverage & open backlog

Single source of truth for the test scope. Update on every PR that
adds, retires, or changes a test.

For *how to run* the suite, see [README.md](README.md).
For *contributing rules*, see [CONTRIBUTING.md](CONTRIBUTING.md).
For the **history of completed backlog items**, see
[COVERAGE-HISTORY.md](COVERAGE-HISTORY.md).

GitHub renders a floating table of contents from the `##` headings —
click the menu icon at the top-left of this file in the GH UI.

---

## TL;DR

| Type                      | Tests | Status                                                       |
|---------------------------|-------|--------------------------------------------------------------|
| Chainsaw e2e              | 26 + 1 stub | all green; covers full surface (auth, sessions, IdP, federation, security, CRDs) |
| Chainsaw regression       | 0     | dir scaffolded; populate when a fixed bug deserves a watch   |
| OIDF Conformance — plans  | 3     | `oidcc-config` ✓ PASSED; `oidcc-basic` 22/35 PASS+WARN; `oidcc-rp-logout` 1 PASSED + 4 FINISHED FAILED + 6 INTERRUPTED (see B8, B15) |
| Go unit tests             | 48    | seed on 5 pure-logic packages; 15 packages on backlog (G1..G15) — see [Go unit tests](#go-unit-tests--inside-each-package) |

**Open backlog**:

- 3 chainsaw items (B1, B2, B3) and 8 conformance items
  (B8, B9, B10, B11, B12, B13, B14, B15) — each scoped to a specific
  kubauth feature gap.
- 15 Go unit-test items (G1..G15) — packages without `*_test.go`
  yet. G1..G4 are quick wins; G5..G10 share fixture infrastructure;
  G11..G14 each need their own mocking layer. See
  [Backlog — Go unit tests](#backlog--go-unit-tests).

Closed items are recorded in [COVERAGE-HISTORY.md](COVERAGE-HISTORY.md).

---

## Conventions

| Symbol | Meaning |
|---|---|
| ✓ | Covered |
| ◐ | Partially covered (see notes) |
| ✗ | Not covered |
| ⭐⭐⭐ | High pertinence — regressing this is critical |
| ⭐⭐ | Medium pertinence — useful but not load-bearing |
| ⭐ | Low pertinence — minimal signal |

| Priority | Meaning |
|---|---|
| **P0** | Security, correctness — fix before next release |
| **P1** | Major feature uncovered — fix this quarter |
| **P2** | Nice to have — fix when convenient |

---

## Chainsaw e2e — `tests/e2e/`

Run with `make e2e` (full) or `make e2e-smoke` (just `01-smoke-login`).

### Coverage at a glance

```text
              ┌─────────────────────────────────────────────────┐
              │                  KUBAUTH                        │
              ├─────────────────────────────────────────────────┤
   discovery  │  /.well-known/openid-configuration  ✓ 19        │
              │  /jwks                              ✓ 18        │
              ├─────────────────────────────────────────────────┤
   auth core  │  ROPC                               ✓ 01        │
              │  authorization-code + PKCE S256     ✓ 03        │
              │  PKCE enforcement (negative)        ✓ 02        │
              │  refresh + rotation + replay        ✓ 04        │
              │  id_token signature verification    ✓ 18        │
              │  exp expiry enforcement             ✓ 20        │
              │  audience cross-client rejection    ◐ 21 (B2)   │
              ├─────────────────────────────────────────────────┤
   resource   │  /userinfo                          ✓ 05        │
   server     │  /oauth2/introspect                 ✓ 05        │
              │  scope filtering                    ✓ 27        │
              │  forceOpenIdScope                   ✓ 26        │
              ├─────────────────────────────────────────────────┤
   sessions   │  RP-initiated logout (redirect)     ✓ 08        │
              │  SsoSession deletion on logout      ✓ 08        │
              │  SSO cookie cross-app               ✓ 07        │
              │  ssoMode × remember matrix          ✓ 07        │
              ├─────────────────────────────────────────────────┤
   IdP        │  UCRD authority                     ✓ 01        │
   backends   │  LDAP authority                     ✓ 10        │
              │  merger composition                 ✓ 11        │
              │  authority down (critical=*)        ◐ 24 (B3)   │
              ├─────────────────────────────────────────────────┤
   upstream   │  Provider reconcile (smoke)         ✓ 16        │
   federation │  Full browser fed flow              ✓ 23        │
              │  clientSpecific filter              ✓ 29        │
              ├─────────────────────────────────────────────────┤
   security   │  BFA lockout                        ✓ 09        │
              │  disabled user                      ✓ 13        │
              │  JWT signing-key rotation           ✓ 14        │
              │  audit (LoginAttempt) shape         ✓ 12        │
              ├─────────────────────────────────────────────────┤
   admin /    │  Group CRD direct test              ◐ 25        │
   CRDs       │  GroupBinding flow                  ✓ 25        │
              │  Reconciler-level validation        ✓ 22        │
              │  Webhook admission rejection        ✗ (B1)      │
              │  multi-namespace OidcClient         ✓ 28        │
              ├─────────────────────────────────────────────────┤
   API        │  kubectl OIDC auth against k8s API  ✗ (15 stub) │
              └─────────────────────────────────────────────────┘
```

### Tests in the suite

| ID | Test | Surface | Status | Pertinence |
|---|---|---|---|---|
| 01 | smoke-login | ROPC + token + id_token payload | ✓ | ⭐⭐⭐ |
| 02 | pkce-required | enforcePKCE chart flag (negative) | ✓ | ⭐⭐⭐ |
| 03 | pkce-s256 | code+PKCE S256 happy path | ✓ | ⭐⭐⭐ |
| 04 | refresh-token | rotation + replay rejection | ✓ | ⭐⭐⭐ |
| 05 | resource-server | `/userinfo` + `/oauth2/introspect` | ✓ | ⭐⭐ |
| 07 | sso | mode × remember matrix + cross-app bypass | ✓ | ⭐⭐⭐ |
| 08 | logout | RP-initiated logout *with* `id_token_hint` + SsoSession deletion + post-logout `prompt=none` cookie replay (happy path only — hint-less / bad-hint / bad-PLR paths are uncovered, see B8 / B15) | ✓ | ⭐⭐⭐ |
| 09 | lockout-bfa | brute-force protection | ✓ | ⭐⭐⭐ |
| 10 | ldap-authority | LDAP IdP + merger group prefix | ✓ | ⭐⭐⭐ |
| 11 | merger-claim-priority | per-field authority flags | ✓ | ⭐⭐⭐ |
| 12 | loginattempt-audit | LoginAttempt CR contents | ✓ | ⭐⭐ |
| 13 | disabled-user | `User.spec.disabled: true` blocks auth | ✓ | ⭐⭐ |
| 14 | rotate-jwt-key | JWT signing-key rotation | ✓ | ⭐⭐⭐ |
| 15 | kubectl-flow-complet | (stub — TODO scope doc only) | — | — |
| 16 | upstream-reconcile | UpstreamProvider reconcile to READY | ✓ | ⭐⭐ |
| 18 | id-token-signature | id_token RSA signature against /jwks | ✓ | ⭐⭐⭐ |
| 19 | discovery-shape | `/.well-known/openid-configuration` shape | ✓ | ⭐⭐⭐ |
| 20 | token-expiry | `accessTokenLifespan` + `refreshTokenLifespan` | ✓ | ⭐⭐⭐ |
| 21 | audience-mismatch | introspect cred + payload checks | ◐ | ⭐⭐ |
| 22 | oidcclient-validation | defaulting + reconciler rejections | ✓ | ⭐⭐ |
| 23 | upstream-fed-flow | full federation flow | ✓ | ⭐⭐⭐ |
| 24 | authority-down | pin observed behaviour when LDAP is unreachable | ◐ | ⭐⭐ |
| 25 | groupbinding | Group + GroupBinding → groups[] claim | ✓ | ⭐⭐ |
| 26 | force-openid-scope | `forceOpenIdScope` issues id_token without explicit `openid` | ✓ | ⭐⭐ |
| 27 | scope-filtering | `OidcClient.scopes` rejects/filters out-of-list scopes | ✓ | ⭐⭐ |
| 28 | multi-ns-oidcclient | `client_id` namespace prefix outside privileged ns | ✓ | ⭐⭐ |
| 29 | clientspecific-upstream | `UpstreamProvider.clientSpecific` filtering | ✓ | ⭐⭐ |

Notes on partial coverage (◐):

- **21-audience-mismatch** — covers credential and payload checks at
  `/oauth2/introspect`. Does **not** assert that a token issued to
  client A is rejected when client B introspects it (kubauth is
  permissive, Hydra default). See B2 below.
- **24-authority-down** — pins the observed behaviour: with
  `critical:false` LDAP, both alice and carol return `server_error`
  when the LDAP backend is down. The expected behaviour is a
  documented bug (B3) — the test asserts what kubauth actually does,
  to flip once fixed.
- **15-kubectl-flow-complet** — stub. Out of scope (apiserver
  `--oidc-*` flags + RBAC needed on kind), see [Out of scope](#out-of-scope).

### Backlog — chainsaw e2e

#### B1 — Webhook admission rejection · P0 · blocked on kubauth

**What blocks it** — `cmd/oidc/webhooks/oidcclient_webhook.go`
`ValidateCreate` and `ValidateUpdate` return `nil, nil` (skeleton).
Same for `upstreamprovider_webhook.go`. The webhook is registered
but does nothing.

**Kubauth fix** — implement validation for at least: empty
`redirectURIs`, non-https URI for confidential clients, unknown
grant type, missing `issuerURL` for `UpstreamProvider type=oidc`,
mutual exclusivity of `certificateAuthority.{configMap,secret}`.
The runtime equivalents already live in `controller.go`; mirror
them at admission.

**Test once unblocked** — new `e2e/22b-oidcclient-webhook/` (or
extend `22-oidcclient-validation`). Apply invalid CRs and assert
`kubectl apply` fails with HTTP 4xx and a `denied by` message *at
apply time*, not after a reconcile loop. ~2 h.

#### B2 — Cross-client introspect filtering · P2 · open design question

**What blocks it** — design call. Today `/oauth2/introspect` accepts
any authenticated client to introspect any token. RFC 7662 doesn't
forbid this. Whether kubauth should filter by audience is a
threat-model decision.

**Decide one of**:

- (a) **Status quo** — keep permissive. Update
  `21-audience-mismatch/README.md` to drop the open question.
- (b) **Filter by audience** — patch `/oauth2/introspect` to return
  `active=false` when the introspecting client's id ≠ token `aud`.
  Tighten step 5 of `21-audience-mismatch` (~30 min).

#### B3 — `critical: false` should not surface server_error · P1

**What blocks it** — behavioural bug or doc mismatch in the merger.
With `merger.idProviders = [ucrd (critical:true), ldap (critical:false)]`,
scaling LDAP to 0 causes every `/oauth2/token` to return
`500 server_error`, even for users that exist only in UCRD.

**Currently pinned by** — `e2e/24-authority-down/`. Both alice and
carol return `server_error` when LDAP is down; expected once fixed:
alice → 200, carol → non-200.

**Kubauth fix path** — trace what HTTP status the LDAP authority
returns to the merger when its backend is unreachable. Either
(a) confirm 5xx and check why the merger doesn't skip it under
`critical:false`, or (b) have the LDAP authority return
`UserDetail{Status=Undefined}` instead of an error.

**Test flip** — invert the assertions in `24-authority-down/chainsaw-test.yaml`
step `ldap-down-current-behaviour` (~10 min). Update the README.

---

## Chainsaw regression — `tests/regression/`

Run with `make e2e-regression`.

**Empty.** Convention: one directory per fixed bug we never want to
see come back. Populate as bugs get fixed in subsequent PRs.

### Backlog — chainsaw regression

(none — gets populated retroactively as bugs are fixed.)

---

## OIDF Conformance — `tests/conformance/`

Run with `make conformance-{config,basic,rp-logout,all}`. Reports
captured under `tests/conformance/results/<plan>/`.

| Plan | What it asserts | Modules | Best result | Latest report |
|---|---|---|---|---|
| `oidcc-config-certification-test-plan` | Discovery JSON shape, JWKS reachability, supported alg list, claim/scope advertisements, **RFC 6749 / 6750 error response shapes** | 1 | ✓ PASSED | [`results/oidcc-config/`](conformance/results/oidcc-config/) |
| `oidcc-basic-certification-test-plan` | Full auth-code flow (`/authorize` → login → `/token` → id_token validation, claim presence, signature, expiry), **OAuth2 grant edge cases** (auth-code reuse, malformed JWT, etc.) | 35 | 22/35 reach FINISHED with PASSED or WARNING (15 PASSED + 7 WARNING) | [`results/oidcc-basic/summary.txt`](conformance/results/oidcc-basic/summary.txt) |
| `oidcc-rp-initiated-logout-certification-test-plan` | End-session endpoint advertisement, `id_token_hint` validation, `post_logout_redirect_uri` matching, `state` echo | 11 | 1 PASSED + 4 FINISHED FAILED + 6 INTERRUPTED FAILED (see B8 + B15) | [`results/oidcc-rp-initiated-logout/summary.txt`](conformance/results/oidcc-rp-initiated-logout/summary.txt) |

The 7 oidcc-basic WARNINGs are all benign
`VerifyScopesReturnedInUserInfoClaims` notes (kubauth's user model
doesn't carry every optional `profile` claim — informational, not a
spec violation). The id_token-claim-leak warning (B6) is gone.

### Backlog — OIDF Conformance

The 13 remaining red oidcc-basic modules and the 8 still-red
oidcc-rp-logout modules sort into 5 distinct kubauth feature gaps,
each tracked as its own backlog entry below. Two of the items
(B9, B14) also explain part of why oidcc-rp-logout cascades.

#### B8 — `/oauth2/logout` doesn't terminate the session when called without `id_token_hint` · P1

**Symptom** — after `/oauth2/logout` (with no `id_token_hint`,
or with only `state` / `post_logout_redirect_uri`), a follow-up
`/oauth2/auth?prompt=none` returns a code instead of
`error=login_required`. The SSO session survived the logout call.

**What 08-logout does and doesn't cover** — the chainsaw test
exercises only the *with-hint* path (`/oauth2/logout?id_token_hint=…&post_logout_redirect_uri=…&state=…`)
and asserts that path correctly: the cookie replay returns
`login_required`. The bare-logout assertion in 08-logout only
checks the `302/303` redirect, not session termination — that's
the gap this bug lives in.

**Affected modules** (4, all FINISHED FAILED on `make conformance-rp-logout`):
`oidcc-rp-initiated-logout-no-params`,
`-no-post-logout-redirect-uri`, `-no-state`, `-only-state`. Each
trips `EnsureErrorFromAuthorizationEndpointResponse` and
`RejectAuthCodeInAuthorizationEndpointResponse`.

**Kubauth fix path** — `cmd/oidc/oidcserver/handle-logout.go`
should destroy the SSO session on every successful logout call,
not only when an `id_token_hint` is provided and validated. RFC
spec lets the OP ask for confirmation before logging out without
a hint, but kubauth doesn't render a confirmation page either —
silently leaving the session live is the worst of both worlds.

**Test once unblocked** — extend `08-logout` to cover the four
hint-less cases (no params, only state, only PLR, hint-less +
state) with the same cookie-replay assertion. Today's chainsaw
"bare logout" check would then become a real session-termination
check.

#### B9 — `address` / `phone` scopes not modelled · P2 · oidcc-basic

**Affected modules** — `oidcc-scope-address`, `oidcc-scope-phone`,
`oidcc-scope-all` (which exercises every scope, including the two
above).

**Symptom** — `CheckIfAuthorizationEndpointError`: "the authorization
was expected to succeed, but the server returned an error from the
authorization endpoint." The conformance-client doesn't include
`address` / `phone` in its `OidcClient.spec.scopes`, so kubauth
correctly rejects the request — but even if those scopes were
allowed, the kubauth `User` CR has no `address` / `phone_number`
fields to populate the corresponding claims.

**What kubauth needs to do**

- Decision call: are `address` / `phone` in scope for kubauth, or
  is kubauth's User model intentionally minimal?
- If yes:
  - Extend `User.spec` with `address`, `phone_number`, `phone_number_verified`.
  - Wire those into the merger / authority output.
  - Add `address`, `phone` to `claimsByScope` in
    `cmd/oidc/fositepatch/scope_filter.go` (already provisioned
    there — they map to nothing today because the User CR lacks
    the fields).
  - Add the scopes to `tests/fixtures/oidcclients/conformance-client.yaml`.
- If no: document as out of scope, drop the suite-side expectation
  (no kubauth-side fix needed; conformance-client just stays
  without those scopes and the modules will continue to fail).

**Effort** — significant if accepted (User model change → CRD
migration). Skip if not.

#### B10 — `id_token_hint` not honoured in `/oauth2/auth` · P2 · oidcc-basic

**Affected modules** — `oidcc-id-token-hint`, plus several
`oidcc-rp-initiated-logout-*` cascade modules.

**Symptom** — same `CheckIfAuthorizationEndpointError`. Kubauth
ignores the `id_token_hint` param: the spec says the OP SHOULD
treat it as a hint about which subject the RP expects, and MAY
short-circuit the login if the hint matches the active session.

**What kubauth needs to do** — in `handle-authorize.go` /
`handle-login.go`:

1. Parse `id_token_hint` from the auth query.
2. Verify its signature against the active JWKS.
3. If it decodes and `sub` matches a live SSO session → complete
   the auth flow directly (similar to the existing `ssoUser`
   short-circuit).
4. If it doesn't match → ignore (still continue with login).

**Effort** — ~2-4 h. Reuse the existing JWKS fetcher and the
`ssoUser` complete path.

#### B11 — `max_age` parameter not enforced · P2 · oidcc-basic

**Affected modules** — `oidcc-max-age-1`, `oidcc-max-age-10000`.

**Symptoms**

- `oidcc-max-age-1`: INTERRUPTED at the runner timeout. Suite
  waits for a forced re-auth that never comes.
- `oidcc-max-age-10000` (FINISHED FAILED) trips
  `CheckIdTokenAuthTimeClaimsSameIfPresent`: "the id_tokens contain
  different auth_time claims, but must contain the same auth_time."
  → kubauth regenerates `auth_time` per id_token. It should be
  stable for the lifetime of the SSO session.

**What kubauth needs to do**

- Persist `auth_time` on the SSO session (it's the timestamp of
  the user-interactive login, not of the token issuance).
- On every `/oauth2/auth` with `max_age=N`: compare `now - auth_time`.
  If `> N`, force a fresh login (clear the SSO session bypass).
  If `<= N`, complete the flow and emit the **same** `auth_time`
  in the resulting id_token.

**Effort** — ~3 h. Touches `handle-login.go` (the SSO bypass
branch) and `oidcserver.go::newSession` (use a passed-in
auth_time instead of `time.Now()`).

#### B12 — `request=` parameter (request object) not supported · P2 · oidcc-basic

**Affected modules** — `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported`,
`oidcc-ensure-request-object-with-redirect-uri`,
`oidcc-ensure-registered-redirect-uri` (the "unregistered URI"
test fails because kubauth never reads its registered list when a
request object is present).

**Symptom** — the conformance suite passes `request=<JWT>` in the
auth query; kubauth ignores it and falls through. The test then
either fails open or times out.

**Resolution** — pick one:

- (a) **Reject explicitly**: when `request` (or `request_uri`) is
  present in `/oauth2/auth`, reply with
  `request_not_supported` / `request_uri_not_supported` (per OIDC
  Core 1.0 §6). Tells the suite "we don't support this" cleanly.
- (b) **Implement properly**: parse the JWT, validate signature,
  merge its claims onto the request. Larger feature.

(a) is probably the right answer for kubauth (the spec lets OPs
opt out as long as they advertise so via discovery
metadata — `request_parameter_supported: false`).

**Effort for (a)** — ~30 min: add a check at the top of
`handle-authorize.go`, plus advertise
`request_parameter_supported: false` in
`handle-oidc-configuration.go`.

#### B13 — Multi-flow conformance tests don't progress · P2 · runner-side

**Affected modules** — `oidcc-prompt-login`, `oidcc-prompt-none-logged-in`.

**Why** — these tests run **two** auth flows back-to-back. The
in-cluster runner's `try_implicit_submit` auto-trigger only
remembers ONE `implicit_submit.path` per test; when the second
flow generates a new one, the trigger fires the first one a second
time → "Got an HTTP request to '...' that wasn't expected" → the
suite interrupts the test.

**Fix** — runner-side: track *every* `implicit_submit.path` seen
and POST each one only once. Already partially done in
`scripts/conformance-run.sh::poll_implicit_submits`; needs to be
wired in the `run_module` polling loop. ~30 min.

#### B14 — `oidcc-rp-initiated-logout-no-{post-logout-redirect-uri,state}` need a logout success page · P2 · oidcc-rp-logout

**Affected modules** — the two rp-logout sub-tests that omit
`post_logout_redirect_uri` (the suite then expects the OP to
display its own "you have been logged out" HTML page).

**What kubauth does today** — when no `post_logout_redirect_uri`
and no client default, redirects to the global default URL.
That's RFC-compliant behaviour, but the suite's specific assertion
expects an HTML response with a confirmation message.

**Resolution** — render a minimal "logged out" template at
`/oauth2/logout` when neither query param nor client default
provides a redirect target. Add to `resources/templates/`. ~1 h.

> **Note** — the two modules listed here (`-no-post-logout-redirect-uri`,
> `-only-state`) also trip B8 (session not terminated). Re-validate
> B14 once B8 is fixed: it's possible the "HTML success page" need
> disappears once the session is actually destroyed.

#### B15 — `/oauth2/logout` accepts unvalidated `id_token_hint` and unregistered `post_logout_redirect_uri` · P1 · oidcc-rp-logout

**Symptoms** (all from the latest `make conformance-rp-logout` run):

| Module | What kubauth lets through |
|---|---|
| `oidcc-rp-initiated-logout-bad-id-token-hint` | accepts a structurally invalid id_token_hint and redirects to the registered PLR anyway |
| `oidcc-rp-initiated-logout-modified-id-token-hint` | accepts an id_token_hint with a tampered signature and redirects |
| `oidcc-rp-initiated-logout-no-id-token-hint` | redirects to PLR with no hint at all (no validation possible) |
| `oidcc-rp-initiated-logout-bad-post-logout-redirect-uri` | redirects to a PLR that's NOT in the client's registered `redirectURIs` |
| `oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri` | accepts a PLR with extra query parameters appended (no exact-match enforcement) |
| `oidcc-rp-initiated-logout` (canonical) | cascade-fails on the same root cause (`bad-id-token-hint` is part of its flow) |

All 6 land in INTERRUPTED FAILED on `make conformance-rp-logout`.

**Spec violations** — OIDC RP-Initiated Logout 1.0 §3:

- "If a `post_logout_redirect_uri` is supplied, the OP MUST verify
  that it matches one of the redirection URIs registered for the
  client."
- "The `id_token_hint` parameter, when present, SHOULD be used as
  a hint about which RP-initiated logout flow to follow ... the
  signature MUST be validated."

**Kubauth fix path** — `cmd/oidc/oidcserver/handle-logout.go`:

1. Validate `id_token_hint` (signature + expiry + audience) before
   trusting any of its claims. Reject with `400 invalid_request`
   if validation fails.
2. Match `post_logout_redirect_uri` against the client's
   `OidcClient.spec.redirectURIs` (exact match, no query-string
   tolerance). Reject with `400 invalid_request` if no match.
3. If no `id_token_hint` and no PLR provided, fall back to the
   global default — but still validate that the PLR (if provided)
   is registered.

**Test once unblocked** — re-run `make conformance-rp-logout`:
expect the 6 modules above to flip green (FINISHED PASSED or
WARNING). Add chainsaw assertions in `08-logout` for each of the
five negative cases above (modified hint, bad hint, no hint, bad
PLR, query-added PLR).

**Effort** — ~3-4 h (the validation paths are straightforward;
matching `redirectURIs` mirrors what `/oauth2/auth` already does).

---

## Go unit tests — inside each package

Live next to the Go source they cover (Go convention), not in this
folder. Run with `go test ./...` from the repo root. Current seed
coverage focuses on pure-logic packages — anything mockable without
spinning up a real OIDC server, k8s API, or LDAP backend.

| Package | What's covered | Tests |
|---|---|---|
| `internal/misc` | `MergeMaps` (recursive), `DedupAndSort`, `AppendIfNotPresent`, `BoolPtr{True,False}`, `ShortenString`, `CountTrue` | 12 |
| `cmd/oidc/fositepatch` | `AllowedIDTokenClaimsFor` (scope→claim mapping, alwaysAllowed set, `rat` exclusion), `FilterExtraClaimsByScope` (drops unauthorised + mutates contract) | 13 |
| `cmd/oidc/oidcserver` | `mapUpstreamClaimsToUserClaims` (Login fallback chain, claims copy isolation, error paths) | 12 |
| `cmd/oidc/sessioncodec` | `JSONCodec.Encode/Decode` round-trip, empty-bytes path, nil-values normalisation, invalid-JSON error | 6 |
| `cmd/merger/authenticator` | `priority` ordering of `proto.Status` (the merger's tie-break contract: `Disabled` outranks all, `PasswordChecked`/`PasswordFail` tie) | 5 |

### Backlog — Go unit tests

Each row is a kubauth package not yet covered by any `*_test.go`.
The **Fixture** column says what infrastructure has to land first
— "pure" = no fixtures needed (low cost), the rest mark the
mocking layer required before tests can be written. The
**Exercised by** column shows what already covers the surface
end-to-end, so a missing Go unit test isn't a blind spot — it's
slower feedback than it could be.

Order is rough cost (cheapest first).

| ID | Package | Surface | Fixture | Exercised by |
|---|---|---|---|---|
| G1 | `internal/misc/expandenv` | env-var expansion | pure | — |
| G2 | `internal/misc/loadconfig` | YAML config loader | tempfile | — |
| G3 | `internal/handlers/protector/bfa` | brute-force protection | pure (after clock injection) | chainsaw 09 |
| G4 | `internal/httpclient` | HTTP client wrapper | httptest | — |
| G5 | `cmd/oidc/oidcserver/handle-*.go` | 12 OIDC handlers (auth, token, userinfo, logout, callback, jwks, discovery, login, upstream-{welcome,go,callback}, ...) | httptest + fosite mocks + fake k8s | chainsaw 01-08, 18-21, 26-27 + OIDF conformance |
| G6 | `cmd/oidc/upstreams` | OAuth federation flows | httptest mock IdP + fosite session | chainsaw 16, 23, 29 |
| G7 | `cmd/oidc/sessionstore` | KubeSSOStore (CRD-backed `scs.Store`) | controller-runtime fake client | chainsaw 07, 08 |
| G8 | `cmd/oidc/oidcstorage` | KubauthClient store | fake k8s client | chainsaw 22 |
| G9 | `cmd/oidc/fositepatch/scopehandler.go` | scope filter at fosite layer | fosite Requester mocks | chainsaw 27 |
| G10 | `cmd/oidc/fositepatch/flow_resource_owner.go` | ROPC flow handler | fosite mocks | chainsaw 01 |
| G11 | `cmd/oidc/webhooks` | OidcClient / UpstreamProvider admission | admission.Request fixtures | — (ties to B1 — webhook is a stub today) |
| G12 | `cmd/ucrd/authenticator` | UCRD-backed authenticator | fake k8s + GroupBinding fixtures | chainsaw 01, 25 |
| G13 | `cmd/ucrd/webhooks` | UCRD admission | admission.Request fixtures | — |
| G14 | `cmd/ldap/authenticator` | LDAP backend | stub LDAP server (glauth or in-process) | chainsaw 10 |
| G15 | `cmd/audit/cleaner` | LoginAttempt CR cleaner | fake k8s client | chainsaw 12 |

**Where the next chunk of effort goes**: G1–G4 are quick wins
(pure or near-pure, no fixture work) — bundle them in one PR.
G5–G10 share the same fixture stack (fosite mocks + httptest +
fake k8s); writing the helpers once unlocks all six. G11/G12/G13
share admission.Request fixtures. G14 alone needs an LDAP stub.

---

## Out of scope

The following are deliberately not tested by any harness in this
repo. Each row is genuinely uncovered today — the "Where it would
go" column is aspirational.

| Surface | Where it would go | Why not here |
|---|---|---|
| Performance, load, concurrency | (none planned) | Different tooling (k6, vegeta). |
| Fuzzing | (none planned) | `go-fuzz` / native Go 1.18 fuzz. |
| End-user kubectl OIDC flow against the K8s API | `tests/e2e/15-kubectl-flow-complet/` (stub) | Requires kind apiserver `--oidc-*` flags + RBAC. Deferred. |

For surfaces that *are* covered but in a different harness than you
might expect (e.g. RFC 6749/6750 error shapes, OAuth2 grant edge
cases), see the [OIDF Conformance](#oidf-conformance--testsconformance)
section's "What it asserts" column.

---

## Maintenance rules

1. **Every new chainsaw test in `tests/e2e/`** gets a row in
   [Tests in the suite](#tests-in-the-suite) in the same PR.
2. **Every backlog item completed** moves to
   `COVERAGE-HISTORY.md` (with the closing commit SHA), and the
   matching `✗`/`◐` becomes `✓` in the diagram.
3. **Every test retired** is removed from its section. No ghost rows.
4. **Backlog item placement** — file under the test type that the
   item primarily affects:
   - blocked on kubauth code, would create or change a chainsaw e2e
     → "Backlog — chainsaw e2e" (`B<N>`)
   - surfaced by a conformance plan, blocks a green run → "Backlog —
     OIDF Conformance" (`B<N>`, same series — chainsaw and conformance
     share the `B` namespace because items often cross between them)
   - missing Go `*_test.go` for a kubauth package → "Backlog — Go
     unit tests" (`G<N>`)
   Cross-cutting items get a primary section + a one-line cross-ref.
5. **No TODO without a backlog ID.** Either it's `B<N>` / `G<N>`
   here, or it doesn't belong.
6. **TL;DR table** is recomputed by hand on every PR that changes
   counts. Keep it under 6 rows.
