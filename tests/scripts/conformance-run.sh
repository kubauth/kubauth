#!/usr/bin/env bash
#
# Drive an OpenID Conformance Suite plan end-to-end via its REST API.
#
# Iterates every module in the plan: starts each test, polls until
# FINISHED, captures the log + info JSON. For tests that block waiting
# on the suite's "implicit submit" page (response_mode=query auto-POST,
# which HtmlUnit can't render due to the embedded Bootstrap5 CDN
# script), POSTs the implicit URL ourselves to unblock progression.
#
# Prerequisites (handled by the caller):
#   - Cluster up, kubauth installed (make dev-up).
#   - Conformance suite deployed (make conformance-up).
#   - Suite UI/API reachable at $SUITE_URL (default
#     https://localhost.emobix.co.uk:8443; use
#     `make conformance-portforward` in another shell).
#   - For oidcc-basic: enforcePKCE must be off (see with-pkce-disabled.sh).
#
# Usage:
#   conformance-run.sh <plan-name> <variant-json|none> <config-file>
#
# Examples:
#   conformance-run.sh oidcc-config-certification-test-plan none \
#     conformance/config/oidcc-config.json
#
#   conformance-run.sh oidcc-basic-certification-test-plan \
#     '{"server_metadata":"discovery","client_registration":"static_client"}' \
#     conformance/config/oidcc-basic.json
#
# Every module is then classified into 3 buckets against the plan's
# expected-failures allowlist (conformance/expected/<plan-stem>.yaml):
#
#   GREEN          FINISHED with PASSED | WARNING | SKIPPED.
#   EXPECTED-FAIL  not green AND listed in the allowlist with a matching
#                  state (and result, when the entry pins one).
#   UNEXPECTED     green-but-listed (a fix landed, drop it from the list)
#                  OR not-green-and-not-listed (a regression).
#
# The gate fails on BOTH drift directions. The allowlist is hand-curated
# and never generated from a run (that would launder regressions into the
# baseline). See conformance/README.md and conformance/expected/.
#
# Outputs (under tests/conformance/results/<plan-stem>/):
#   <module>-<testId>.json        full log (from /api/log)
#   <module>-<testId>-info.json   status + result (from /api/info)
#   modules.txt                   raw "<module> <state> <result>" per module
#   summary.txt                   the 3-bucket TL;DR + any UNEXPECTED detail
#
# When CONFORMANCE_ROLLUP names a file, the plan's one-line TL;DR is also
# appended there (the orchestrator uses it to build the cross-plan roll-up).
#
# Exit codes:
#   0  the UNEXPECTED bucket is empty for this plan
#   1  one or more UNEXPECTED modules (regression or stale baseline)
#   2  usage / setup error

set -euo pipefail

# shellcheck source=lib/env.sh
source "$(dirname "$0")/lib/env.sh"

require_bin curl
require_bin python3

readonly SUITE_URL="${SUITE_URL:-https://localhost.emobix.co.uk:8443}"
readonly RESULTS_BASE="${KUBAUTH_TESTS_ROOT}/conformance/results"
readonly EXPECTED_BASE="${KUBAUTH_TESTS_ROOT}/conformance/expected"
CLASSIFY="$(dirname "$0")/conformance-classify.py"
readonly CLASSIFY
readonly POLL_TIMEOUT_SECONDS="${POLL_TIMEOUT_SECONDS:-90}"
readonly POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-2}"
# INTERRUPTED is not always terminal: the suite occasionally finalises a
# module INTERRUPTED -> FINISHED via a late async callback (a browser submit
# that lands just after we observed the interruption). Settle-poll for this
# long before recording, so modules.txt captures the terminal state instead
# of a transient one that makes the gate drift between runs.
readonly SETTLE_TIMEOUT_SECONDS="${SETTLE_TIMEOUT_SECONDS:-10}"

usage() {
  sed -n '3,30p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

[[ $# -eq 3 ]] || usage

readonly PLAN="$1"
readonly VARIANT="$2"     # "none" or compact JSON like {"server_metadata":"discovery"}
readonly CONFIG="$3"

[[ -f "$CONFIG" ]] || die "config file not found: $CONFIG"

# URL-encode a JSON variant string with python3.
url_encode_variant() {
  python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "$1"
}

# Suite curl with self-signed cert tolerated.
suite_curl() { curl -sk "$@"; }

# Pick a JSON field with python3.
jget() {
  python3 -c '
import json, sys
path = sys.argv[1].split(".")
d = json.load(sys.stdin)
for p in path:
    if p == "":
        continue
    if isinstance(d, list):
        d = d[int(p)]
    else:
        d = d.get(p) if d is not None else None
print("" if d is None else d)
' "$1"
}

# Read the alias from the config file (used to assemble implicit-submit URLs).
config_alias() {
  python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["alias"])' "$CONFIG"
}

# Find every `implicit_submit.path` in the test log and POST any
# we haven't already submitted. Tests with multiple auth flows
# (oidcc-rp-initiated-logout's main test, prompt=login, max_age,
# id_token_hint, etc.) emit one implicit URL per flow — POSTing
# only the first is not enough.
#
# Tracks already-submitted paths via the file referenced by
# $1 (caller-supplied per-test state). Echoes 1 if at least one
# new submit was posted in this call, 0 otherwise.
poll_implicit_submits() {
  local test_id="$1"
  local alias_v="$2"
  local seen_file="$3"
  local n=0
  local paths
  paths="$(suite_curl "${SUITE_URL}/api/log/${test_id}" \
    | python3 -c '
import json, sys
for e in json.load(sys.stdin):
    iu = e.get("implicit_submit")
    if iu and iu.get("path"):
        print(iu["path"])
' 2>/dev/null || true)"
  if [[ -z "$paths" ]]; then
    echo "0"
    return
  fi
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    if ! grep -qxF "$p" "$seen_file" 2>/dev/null; then
      log "    triggering implicit submit: /test/a/${alias_v}/${p}"
      suite_curl -X POST "${SUITE_URL}/test/a/${alias_v}/${p}" >/dev/null
      printf '%s\n' "$p" >> "$seen_file"
      n=$((n + 1))
    fi
  done <<<"$paths"
  echo "$n"
}

# Run a single module. Echoes "<module> <status> <result>".
#
# If the test sits at WAITING past POLL_TIMEOUT_SECONDS it is force-
# terminated via DELETE /api/runner/{id}. Otherwise the next module
# in the same plan trips the suite's alias-conflict check and is
# rejected ("Stopping test due to alias conflict").
run_module() {
  local plan_id="$1" module="$2" alias_v="$3" results_dir="$4"

  local run test_id
  run="$(suite_curl -X POST "${SUITE_URL}/api/runner?test=${module}&plan=${plan_id}")"
  test_id="$(echo "$run" | jget id)"
  if [[ -z "$test_id" ]]; then
    echo "${module}  ERROR_START  -"
    return
  fi

  # Per-test scratch file tracking which implicit_submit URLs we've
  # already POSTed (multi-flow tests emit several).
  local seen_file
  seen_file="$(mktemp -t conformance-implicit-XXXXXX)"
  trap 'rm -f "$seen_file"' RETURN

  local elapsed=0
  local status="?" result="?"
  while ((elapsed < POLL_TIMEOUT_SECONDS)); do
    suite_curl "${SUITE_URL}/api/info/${test_id}" -o /tmp/info.json
    status="$(jget status </tmp/info.json)"
    result="$(jget result </tmp/info.json)"
    case "$status" in
      FINISHED|INTERRUPTED) break ;;
    esac
    if ((elapsed >= 4)); then
      poll_implicit_submits "$test_id" "$alias_v" "$seen_file" >/dev/null
    fi
    sleep "$POLL_INTERVAL_SECONDS"
    elapsed=$((elapsed + POLL_INTERVAL_SECONDS))
  done

  # Settle a self-reported INTERRUPTED: re-poll briefly in case the suite
  # finalises it to FINISHED (the late-callback race described at
  # SETTLE_TIMEOUT_SECONDS). A genuinely interrupted test stays INTERRUPTED
  # and we just spend the settle budget once. Skipped for the WAITING path
  # below, which force-terminates and is terminal by construction.
  if [[ "$status" == "INTERRUPTED" ]]; then
    local settle=0 settle_status
    while ((settle < SETTLE_TIMEOUT_SECONDS)); do
      sleep "$POLL_INTERVAL_SECONDS"
      settle=$((settle + POLL_INTERVAL_SECONDS))
      suite_curl "${SUITE_URL}/api/info/${test_id}" -o /tmp/info.json
      settle_status="$(jget status </tmp/info.json)"
      if [[ "$settle_status" == "FINISHED" ]]; then
        status="$settle_status"
        result="$(jget result </tmp/info.json)"
        break
      fi
    done
  fi

  # Force-terminate if still WAITING (otherwise next module hits an
  # alias conflict). DELETE returns 200 even when the test has
  # already finished, so we always send it for safety.
  if [[ "$status" != "FINISHED" && "$status" != "INTERRUPTED" ]]; then
    suite_curl -X DELETE "${SUITE_URL}/api/runner/${test_id}" >/dev/null
    # Re-poll the final status now that the test was cancelled.
    suite_curl "${SUITE_URL}/api/info/${test_id}" -o /tmp/info.json
    status="$(jget status </tmp/info.json)"
    result="$(jget result </tmp/info.json)"
  fi

  # Capture artefacts.
  suite_curl "${SUITE_URL}/api/log/${test_id}"  > "${results_dir}/${module}-${test_id}.json"
  suite_curl "${SUITE_URL}/api/info/${test_id}" > "${results_dir}/${module}-${test_id}-info.json"

  echo "${module}  ${status}  ${result:-?}"
}

main() {
  local plan_stem
  plan_stem="$(basename "$CONFIG" .json)"
  local results_dir="${RESULTS_BASE}/${plan_stem}"
  mkdir -p "$results_dir"

  local variant_query=""
  if [[ "$VARIANT" != "none" ]]; then
    variant_query="&variant=$(url_encode_variant "$VARIANT")"
  fi

  log "creating plan: $PLAN"
  local plan_id
  plan_id="$(suite_curl -X POST -H 'Content-Type: application/json' \
    --data-binary @"$CONFIG" \
    "${SUITE_URL}/api/plan?planName=${PLAN}${variant_query}" | jget id)"
  [[ -n "$plan_id" ]] || die "plan creation failed (no id returned)"
  log "plan id: $plan_id"

  # Enumerate modules in plan.
  local modules
  modules="$(suite_curl "${SUITE_URL}/api/plan/${plan_id}" \
    | python3 -c 'import json,sys; print(" ".join(m["testModule"] for m in json.load(sys.stdin)["modules"]))')"
  local count
  count="$(echo "$modules" | wc -w | tr -d ' ')"
  # Fail closed on an empty enumeration. A wrong plan name/variant, a suite-version
  # bump that renamed the plan, or a mid-run abort would otherwise yield an empty
  # modules.txt that the classifier reads as 0 green / 0 xfail / 0 unexpected -> exit 0,
  # laundering a total failure green.
  [[ "$count" -gt 0 ]] || die "plan '${PLAN}' enumerated 0 modules (wrong plan/variant or suite drift)"
  log "running ${count} module(s)"

  local alias_v
  alias_v="$(config_alias)"

  # Raw per-module results (one "<module> <state> <result>" per line).
  # This is the classifier's input, NOT the human summary.
  local modules_file="${results_dir}/modules.txt"
  : > "$modules_file"

  for module in $modules; do
    log "  ${module}"
    local line
    line="$(run_module "$plan_id" "$module" "$alias_v" "$results_dir")"
    echo "$line" >> "$modules_file"
  done

  # 3-bucket gate. The allowlist is matched on module name; its path is
  # the plan-config stem under conformance/expected/. A missing allowlist
  # is a setup error (every wired plan must have one; config's is empty).
  local allowlist="${EXPECTED_BASE}/${plan_stem}.yaml"
  [[ -f "$allowlist" ]] || die "no allowlist for plan '${plan_stem}' at ${allowlist} (create it; use 'expected_failures: []' for an all-green plan)"
  [[ -f "$CLASSIFY" ]]  || die "classifier not found at ${CLASSIFY}"

  # Classify. The classifier prints the TL;DR line + any UNEXPECTED detail
  # to stdout and exits non-zero iff the UNEXPECTED bucket is non-empty.
  # Capture its verdict without letting `set -e` abort before we record it.
  local summary="${results_dir}/summary.txt"
  local classify_out rc=0
  set +e
  classify_out="$(python3 "$CLASSIFY" "$PLAN" "$modules_file" "$allowlist")"
  rc=$?
  set -e

  if ((rc == 2)); then
    printf '%s\n' "$classify_out" >&2
    die "allowlist classification failed (parse error) for ${allowlist}"
  fi

  # Persist + echo the human summary.
  {
    echo "suite ${CONFORMANCE_SUITE_VERSION:-unknown}"
    printf '%s\n' "$classify_out"
  } > "$summary"
  log
  log "3-bucket summary at ${summary}"
  cat "$summary"

  # Feed the cross-plan roll-up (orchestrator sets CONFORMANCE_ROLLUP).
  if [[ -n "${CONFORMANCE_ROLLUP:-}" ]]; then
    printf '%s\n' "$classify_out" | head -1 >> "$CONFORMANCE_ROLLUP"
  fi

  if ((rc != 0)); then
    err "plan '${PLAN}' has UNEXPECTED modules (regression or stale baseline) - see above"
    return 1
  fi
  ok "plan '${PLAN}' matches its known state (0 unexpected)"
}

main "$@"
