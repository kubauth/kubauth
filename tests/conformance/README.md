# OpenID Conformance Suite — kubauth

Spec-conformance harness for kubauth's OIDC server. Drives the
official OpenID Foundation
[conformance-suite][conformance-suite] against `kubauth-oidc-server`
and captures pass/fail per profile under `results/`.

[conformance-suite]: https://gitlab.com/openid/conformance-suite

---

## Status

The suite deploys in-cluster as a 3-pod Deployment (mongo + Java
server + nginx). Plans are driven end-to-end via the suite's REST API
through `make conformance-<plan>`. Reports land under `results/<plan>/`.

| Plan | Modules | Best result | Latest run |
|---|---|---|---|
| `oidcc-config-certification-test-plan`         | 1  | ✓ PASSED | [`results/oidcc-config/`](results/oidcc-config/) |
| `oidcc-basic-certification-test-plan`          | 35 | 19/35 reach FINISHED with PASSED or WARNING (12 PASSED + 7 WARNING; warnings are now benign — claim leaks fixed via B6, see [Open work](#open-work) for the rest) | [`results/oidcc-basic/summary.txt`](results/oidcc-basic/summary.txt) |
| `oidcc-rp-initiated-logout-certification-test-plan` | 11 | 1 PASSED + 4 FINISHED FAILED + 6 INTERRUPTED FAILED; failures cluster around B8 (4 modules) and B15 (6 modules) — see [Open work](#open-work) | [`results/oidcc-rp-initiated-logout/summary.txt`](results/oidcc-rp-initiated-logout/summary.txt) |

Re-run any plan with `make conformance-<plan>`; the previous run's
JSON is overwritten in `results/<plan>/`.

## Layout

```text
conformance/
├── README.md                            # this file
├── config/
│   ├── oidcc-config.json                # plan config: discovery + metadata
│   ├── oidcc-basic.json                 # plan config: auth-code flow
│   └── oidcc-rp-initiated-logout.json   # plan config: RP-initiated logout
└── results/
    ├── oidcc-config/                    # one dir per plan, one log+info pair per module
    ├── oidcc-basic/
    └── oidcc-rp-initiated-logout/

fixtures/conformance/                    # in-cluster manifests
├── 00-namespace.yaml
├── 01-mongo.yaml
├── 02-server.yaml
└── 03-nginx.yaml

fixtures/oidcclients/conformance-client.yaml  # OidcClient used by every plan
                                              # (separate from smoke-client; pre-registers
                                              # the suite's redirect/post-logout URIs)
```

## Why in-cluster

Both kubauth (the OP under test) and the conformance suite (acting as
the test RP) live in the same kind cluster. They reach each other via
cluster DNS:

- Suite → kubauth: `https://kubauth-oidc-server.kubauth-system.svc:443`
- Suite WebRunner → suite (its own callback): the conformance-server pod
  has a `hostAliases` entry mapping `localhost.emobix.co.uk` to the
  conformance-nginx Service ClusterIP (pinned at `10.96.255.10`),
  so the embedded HtmlUnit driver can follow OP redirects back to the
  suite without leaving the cluster.

The only thing that crosses the cluster boundary is the user's
browser when watching a run live — `make conformance-portforward`.

## Boot the suite

```sh
make conformance-up                     # 3-pod deploy + CA copy
make conformance-portforward &          # in another shell, leaves the API reachable on host
```

`localhost.emobix.co.uk` resolves to `127.0.0.1`. The suite was built
to expect this hostname (its bundled TLS cert SAN matches it). Accept
the TLS warning the first time.

## Run plans headlessly

```sh
make conformance-config                 # always green
make conformance-basic                  # toggles enforcePKCE off for the run
make conformance-rp-logout              # toggles enforcePKCE off for the run
make conformance-all                    # all three, sequentially
```

Each target calls `scripts/conformance-run.sh`, which:

1. POSTs the plan config to `/api/plan?planName=...&variant=...`
2. for every module in the plan: POSTs `/api/runner?test=...&plan=...`
3. polls `/api/info/{testId}` until `FINISHED` or `INTERRUPTED`
4. when a module sits at `WAITING` because the suite's
   `implicitCallback` page can't auto-POST under HtmlUnit (Bootstrap5
   parse error in the suite's own UI), POSTs the `implicit_submit.path`
   ourselves to unblock progression
5. captures `/api/log/...` and `/api/info/...` under `results/<plan>/`
6. exits non-zero unless every module reached `FINISHED` with
   `PASSED` or `WARNING`

`make conformance-basic` and `conformance-rp-logout` are wrapped in
`scripts/with-pkce-disabled.sh`, which patches the kubauth Deployment
to `--enforcePKCE=false`, runs the inner command, and restores the
previous value on exit (even on error/Ctrl-C). The basic and
rp-logout plans don't add PKCE to authorize requests; with
`enforcePKCE=true` (the test cluster default) they get `invalid_request`
back from kubauth.

The wrapper also bounces `conformance-server` after kubauth rolls,
to flush the suite's JVM-level network state (DNS cache + Apache
HttpClient connection pool — both keep entries pointing at the
defunct kubauth pod IP across rollouts, surfacing as `Connect timed
out` on the suite's first call of the next plan). The bounce only
happens on the OFF transition; the restore at the end runs no plans,
so a stale pool there is harmless.

Override `SUITE_URL=...` if you don't use the default port-forward.

## Run a plan via the UI (manual)

```sh
make conformance-portforward
open https://localhost.emobix.co.uk:8443/
```

In the suite UI: Create test plan → pick the certification plan →
paste the matching `config/<plan>.json` → Start. Watch the live log.
On completion, export the result JSON manually if you want a copy
under `results/`.

## Tear down

```sh
make conformance-down
```

Drops the namespace and everything under it.

## What each plan covers

| Plan | What it asserts |
|---|---|
| `oidcc-config` | Discovery JSON shape, JWKS reachability, supported alg list, claim/scope advertisements. Static, no browser flow. |
| `oidcc-basic`  | Full auth-code flow: `/authorize` → login → `/token` → `id_token` validation, claim presence, signature, expiry. Drives the kubauth login form via the `browser` block. |
| `oidcc-rp-initiated-logout` | End-session endpoint advertisement, `id_token_hint` validation, `post_logout_redirect_uri` matching, `state` echo. |

## Open work

### `oidcc-basic` — finish what's still red/yellow

The plan currently reaches **19/35** modules in `FINISHED` state
with PASSED or WARNING (12 PASSED + 7 WARNING + 1 SKIPPED). The
remaining 15 split into 4 buckets:

#### Warning content (after B6)

The 7 modules now in `FINISHED WARNING` no longer trip on claim
leakage — that's been fixed (see `tests/COVERAGE-HISTORY.md` B6).
The remaining warnings are
`VerifyScopesReturnedInUserInfoClaims`: kubauth's user model only
carries `name, email, groups`, so a `profile` scope request gets
back `name` but not `family_name`, `given_name`, `birthdate`, etc.
That's a kubauth feature gap, not an RFC violation — the suite
warns rather than fails.

#### `INTERRUPTED FAILED` — feature-gap modules

| Module | Likely root cause |
|---|---|
| `oidcc-response-type-missing` | kubauth doesn't reject `response_type` absent with the error shape the suite expects |
| `oidcc-scope-{address,phone,all}` | kubauth doesn't advertise/honour `address`, `phone` scopes |
| `oidcc-ensure-registered-redirect-uri` | redirect-uri matching strictness mismatch |
| `oidcc-ensure-post-request-succeeds` | `/oauth2/auth` over POST not implemented |
| `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` | `request` parameter handling |
| `oidcc-ensure-request-object-with-redirect-uri` | same |

Each is a small, isolated kubauth feature. Pull the per-module log
under `results/oidcc-basic/<module>-<id>.json` to see the exact
expectation.

#### `WAITING` — multi-step flows the auto-trigger doesn't catch

| Module | Why |
|---|---|
| `oidcc-prompt-login`, `oidcc-prompt-none-logged-in` | Need `prompt` parameter handling on kubauth |
| `oidcc-max-age-{1,10000}` | `max_age` re-auth gate |
| `oidcc-id-token-hint` | `id_token_hint` short-circuit |

These tests issue a second auth flow in the same session. The
`browser` block triggers once; the second flow never finds a
matcher to drive it. Add a second-flow matcher in
`config/oidcc-basic.json` if/when kubauth supports the parameter
they exercise.

#### `FINISHED FAILED` — implementation issues

| Module | Symptom |
|---|---|
| `oidcc-prompt-none-not-logged-in` | kubauth returns the login form when it should return `login_required` immediately |

### `oidcc-rp-initiated-logout` — what's still red

The 10 red modules split into two distinct kubauth gaps. Both
tracked in `tests/COVERAGE.md`.

**B8 — session not terminated when `id_token_hint` is absent.** 4
modules trip `EnsureErrorFromAuthorizationEndpointResponse`: after
a hint-less `/oauth2/logout` (no params, only state, only PLR,
PLR+state), a follow-up `/oauth2/auth?prompt=none` returns a code
instead of `error=login_required`. The chainsaw test `08-logout`
covers the *with-hint* path correctly (SsoSession deletion + cookie
replay returns `login_required`) but only checks the redirect, not
session termination, on the bare-logout path — that's the gap.

**B15 — `/oauth2/logout` accepts unvalidated `id_token_hint` and
unregistered `post_logout_redirect_uri`.** 6 modules (including
the canonical `oidcc-rp-initiated-logout`) end INTERRUPTED with
"OP has incorrectly called the registered post_logout_redirect_uri":
kubauth redirects to the PLR even when the id_token_hint is
syntactically invalid, signature-tampered, or absent, and even when
the PLR isn't in the client's registered `redirectURIs` (or has
extra query params appended).

Latest run on `make conformance-rp-logout`: 1 PASSED (discovery),
4 FINISHED FAILED (B8 cluster), 6 INTERRUPTED FAILED (B15 cluster).

### `oidcc-implicit`, `oidcc-hybrid`, `fapi-*`

Out of scope: kubauth doesn't ship implicit/hybrid grant types
(deprecated by OAuth 2.1) and isn't a FAPI OP.
