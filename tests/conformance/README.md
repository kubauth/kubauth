# OpenID Conformance Suite — kubauth

Spec-conformance harness for kubauth's OIDC server. Drives the
official OpenID Foundation
[conformance-suite][conformance-suite] against `kubauth-oidc-server`
and captures pass/fail per profile under `results/`.

[conformance-suite]: https://gitlab.com/openid/conformance-suite

---

## Status

The suite deploys in-cluster as a 3-pod Deployment (mongo + Java
server + nginx). Plans are driven end-to-end via the suite's REST API.
Reports land under `results/<plan>/`.

Two ways in:

- **`make conformance`** (from the repo root or `tests/`) is autonomous:
  from only Docker it brings up kind + cert-manager + a working-tree
  kubauth + the suite, runs the plan(s), classifies every module against
  an allowlist, prints a roll-up, and tears down. See
  [Autonomous run](#autonomous-run-make-conformance).
- **`make conformance-<plan>`** are the low-level per-plan targets; they
  assume you already ran `make dev-up` + `make conformance-up` + a
  port-forward (see [Boot the suite](#boot-the-suite)).

| Plan | Modules | Expected baseline (provisional) | Latest run |
|---|---|---|---|
| `oidcc-config-certification-test-plan`         | 1  | 1 green (PASSED) / 0 expected-fail | [`results/oidcc-config/`](results/oidcc-config/) |
| `oidcc-basic-certification-test-plan`          | 35 | ~24 green / ~11 expected-fail. Green = PASSED + WARNING + SKIPPED (warnings are benign profile-claim notes, see [Open work](#open-work)); the expected-fails map to B9-B13 | [`results/oidcc-basic/summary.txt`](results/oidcc-basic/summary.txt) |
| `oidcc-rp-initiated-logout-certification-test-plan` | 11 | 1 green (PASSED) / ~10 expected-fail (FINISHED FAILED + INTERRUPTED), clustering on B8 + B15 (see [Open work](#open-work)) | [`results/oidcc-rp-initiated-logout/summary.txt`](results/oidcc-rp-initiated-logout/summary.txt) |

> **Counts are provisional.** The per-plan green / expected-fail numbers
> above (and throughout [Open work](#open-work)) are carried over from the
> pre-autonomous harness and have **not** yet been reproduced by a real
> `make conformance` run on this branch. They are **recomputed on the
> first real run** (locally or via the [CI workflow](#ci)) from
> `results/<plan>/summary.txt`; update this table and the allowlists then.
> What is authoritative today is the *set* of expected-fail modules and
> their B-number mapping, encoded per plan in
> [`expected/<plan>.yaml`](expected/) and enforced by the 3-bucket gate
> (below) — the aggregate counts are a hand-off estimate until the first
> green-on-known-state run.

Re-run any plan with `make conformance-<plan>`; the previous run's JSON
is overwritten in `results/<plan>/`.

## Autonomous run (`make conformance`)

One command, no pre-existing cluster, only Docker assumed:

```sh
make conformance                  # default: PLAN=config (the fast canary)
make conformance PLAN=basic       # one of: config | basic | rp-logout | all
make conformance-full             # shorthand for PLAN=all
make conformance PLAN=all KEEP=1  # keep the cluster up afterwards (debug)
make conformance REUSE=1          # reuse an existing cluster (skip kind-up/teardown)
```

The orchestrator (`scripts/conformance-orchestrate.sh`) runs the whole
pipeline and always tears down on exit (even on failure or Ctrl-C),
unless `KEEP=1`:

1. preflight (docker/kind/kubectl/helm/curl/python3/openssl)
2. `make dev-up` (kind + registry + cert-manager + working-tree kubauth
   image + helm install + cert patch + the conformance OidcClient seed)
3. `make conformance-up` (mongo + server + nginx, with the CA copy + the
   pinned nginx ClusterIP)
4. a backgrounded `kubectl port-forward` to the suite API, reaped by a
   trap, waited on until the API answers
5. the plan target(s) (`PLAN=all` runs `make conformance-all`, which
   toggles `enforcePKCE` off once for the whole sequence; single plans
   run their own target). `oidcc-basic` / `oidcc-rp-initiated-logout`
   need PKCE off; `oidcc-config` does not.
6. a per-plan + cross-plan roll-up; exit 0 iff every plan is OK
7. teardown (`make dev-down`)

The default is `PLAN=config` (1 module, always green, proves the whole
bring-up + REST path) until `basic` / `rp-logout` are routinely reviewed.

## CI

The harness runs in CI via
[`.github/workflows/conformance.yml`](../../.github/workflows/conformance.yml).
It is **not** a per-PR gate: a from-zero run is heavy (JVM ~5 min cold
start, multi-Gi suite pods, several large public image pulls), so the
workflow triggers only on:

- `workflow_dispatch` (on-demand) and
- a nightly `schedule` (04:00 UTC).

Each job installs kind / kubectl / helm at the `.tool-versions` pins
(`hack/ci-install-tools.sh`; Go comes from `actions/setup-go`, Docker is
preinstalled on the runner) and then runs `make conformance`, which owns
the entire from-zero chain *and* the teardown — there is no separate
cluster-up / cluster-down step.

Gating, on first landing:

- **`oidcc-config`** is the required signal (one always-green module that
  proves the whole bring-up + REST path). Its 3-bucket verdict
  (0 unexpected) gates the workflow.
- **`oidcc-basic`** and **`oidcc-rp-initiated-logout`** run
  informationally (`continue-on-error`) until their allowlists have been
  reviewed against a real CI run, then get promoted to gating.

The job's pass/fail is the orchestrator exit code = the allowlist verdict,
so a fresh regression OR a now-fixed-but-still-listed module both fail it.
Teardown always runs in CI for a clean slate; `KEEP=1` is a local-debug
escape hatch only.

## The 3-bucket gate

A raw conformance run is all-or-nothing red: kubauth has documented OIDC
gaps (B8-B15), so plans never go fully green. Instead, every module is
sorted against a committed, hand-curated allowlist
(`expected/<plan>.yaml`, matched on **module name** because testIds are
random per run):

| Bucket | Definition |
|---|---|
| **GREEN** | `FINISHED` with `PASSED`, `WARNING`, or `SKIPPED`. WARNING and SKIPPED count as green on purpose (kubauth's minimal user model warns on some `profile` claims; `oidcc-refresh-token` skips). |
| **EXPECTED-FAIL** | not green, AND listed in the allowlist with a matching `state` (and `result`, when the entry pins one). |
| **UNEXPECTED** | green-but-listed (a fix landed - drop it from the allowlist) OR not-green-and-not-listed (a regression). |

The gate exits 0 **iff** the UNEXPECTED bucket is empty across all plans,
so it fails on **both** drift directions: a fresh regression and a
now-passing module that is still allowlisted. The allowlist is never
generated from a run (that would launder regressions into the baseline);
seed it by hand from `results/<plan>/modules.txt` cross-referenced to the
`B`-numbers in [`../COVERAGE.md`](../COVERAGE.md), then commit. Each
allowlist entry carries a `ref:` pointing at the COVERAGE.md backlog id.

The classifier is `scripts/conformance-classify.py`; its logic is
covered by a cluster-free unit test:

```sh
make conformance-classify-test        # ~sub-second, no kind needed
```

## Layout

```text
conformance/
├── README.md                            # this file
├── config/
│   ├── oidcc-config.json                # plan config: discovery + metadata
│   ├── oidcc-basic.json                 # plan config: auth-code flow
│   └── oidcc-rp-initiated-logout.json   # plan config: RP-initiated logout
├── expected/                            # committed expected-failures allowlists
│   ├── oidcc-config.yaml                #   (matched on module name; drive the gate)
│   ├── oidcc-basic.yaml
│   └── oidcc-rp-initiated-logout.yaml
└── results/                             # gitignored run output (not committed)
    ├── oidcc-config/                    # one dir per plan, one log+info pair per module,
    ├── oidcc-basic/                     #   plus modules.txt (raw) + summary.txt (buckets)
    └── oidcc-rp-initiated-logout/

scripts/                                 # the harness
├── conformance-orchestrate.sh           # `make conformance`: from-zero run + teardown
├── conformance-run.sh                   # drive one plan via REST + apply the 3-bucket gate
├── conformance-classify.py             # the classifier (results + allowlist -> buckets)
└── conformance-classify-test.sh         # cluster-free unit test for the classifier

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

On the pre-autonomous harness the plan reached roughly **24/35** modules
green (`FINISHED` with PASSED, WARNING, or SKIPPED) — about 15 PASSED + 8
WARNING + 1 SKIPPED — leaving ~11 expected-fail (all allowlisted in
`expected/oidcc-basic.yaml`, mapped to B9-B13). These counts are
provisional (see the [Status](#status) caveat) and get recomputed from
`results/oidcc-basic/summary.txt` on the first real run. The not-green
modules split into the buckets below.

#### Warning content (after B6)

The modules now in `FINISHED WARNING` no longer trip on claim
leakage - that's been fixed (see `tests/COVERAGE-HISTORY.md` B6).
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

**B8 - session not terminated when `id_token_hint` is absent.** 4
modules trip `EnsureErrorFromAuthorizationEndpointResponse` (2 land
FINISHED FAILED, 2 INTERRUPTED): after a hint-less `/oauth2/logout`
(no params, only state, only PLR, PLR+state), a follow-up
`/oauth2/auth?prompt=none` returns a code instead of
`error=login_required`. The chainsaw test `08-logout` covers the
*with-hint* path correctly (SsoSession deletion + cookie replay
returns `login_required`) but only checks the redirect, not session
termination, on the bare-logout path - that's the gap.

**B15 — `/oauth2/logout` accepts unvalidated `id_token_hint` and
unregistered `post_logout_redirect_uri`.** 6 modules (including
the canonical `oidcc-rp-initiated-logout`) end INTERRUPTED with
"OP has incorrectly called the registered post_logout_redirect_uri":
kubauth redirects to the PLR even when the id_token_hint is
syntactically invalid, signature-tampered, or absent, and even when
the PLR isn't in the client's registered `redirectURIs` (or has
extra query params appended).

Provisional baseline (see the [Status](#status) caveat; recomputed from
`results/oidcc-rp-initiated-logout/summary.txt` on the first real run):
1 PASSED (discovery), then ~10 expected-fail, split as 4 B8 modules + 6
B15 modules. All are allowlisted in
`expected/oidcc-rp-initiated-logout.yaml`.

### `oidcc-implicit`, `oidcc-hybrid`, `fapi-*`

Out of scope: kubauth doesn't ship implicit/hybrid grant types
(deprecated by OAuth 2.1) and isn't a FAPI OP.
