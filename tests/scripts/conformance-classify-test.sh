#!/usr/bin/env bash
#
# Unit test for conformance-classify.py - the 3-bucket gate.
#
# No live conformance suite is involved: every case feeds a synthetic
# results file + a synthetic allowlist and asserts (a) the printed
# bucket counts and (b) the exit code. The gate must fail on BOTH drift
# directions, so the suite covers:
#   - a clean baseline (all green or all expected) -> exit 0
#   - a fresh regression (new non-green, not listed) -> exit 1
#   - a now-passing listed module (green-but-listed) -> exit 1
#   - a listed module whose state/result moved (state drift) -> exit 1
#   - a listed module that vanished from the run -> exit 1
#   - result-token noise (?/-) matched on state alone -> exit 0
#   - an optional-state entry matched in either terminal state -> exit 0
#   - a state-omitted module that turns green still flagged -> exit 1
#   - empty allowlist with a failure -> exit 1
#   - a malformed allowlist -> exit 2 (loud parse error)
#
# Run: tests/scripts/conformance-classify-test.sh
# Exit 0 iff every assertion holds.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CLASSIFY="${HERE}/conformance-classify.py"
WORK="$(mktemp -d -t conformance-classify-test-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0

# assert_case <name> <results-file> <allowlist-file> <want-exit> \
#             <want-green> <want-xfail> <want-unexpected>
#
# want-green / want-xfail / want-unexpected may be '-' to skip that
# count check (used for the parse-error case where no summary prints).
assert_case() {
  local name="$1" rf="$2" af="$3" want_exit="$4"
  local want_g="$5" want_x="$6" want_u="$7"
  local out rc
  set +e
  out="$(python3 "$CLASSIFY" "$name" "$rf" "$af" 2>&1)"
  rc=$?
  set -e

  local ok=1
  if [[ "$rc" != "$want_exit" ]]; then
    ok=0
    echo "FAIL [$name] exit: want $want_exit got $rc"
  fi

  if [[ "$want_g" != "-" ]]; then
    # Parse the TL;DR line: "<plan>: <g> green / <x> xfail / <u> unexpected -> ..."
    local g x u
    g="$(printf '%s\n' "$out" | sed -n 's/.* \([0-9][0-9]*\) green .*/\1/p' | head -1)"
    x="$(printf '%s\n' "$out" | sed -n 's/.*green \/ *\([0-9][0-9]*\) xfail .*/\1/p' | head -1)"
    u="$(printf '%s\n' "$out" | sed -n 's/.*xfail \/ *\([0-9][0-9]*\) unexpected .*/\1/p' | head -1)"
    if [[ "$g" != "$want_g" || "$x" != "$want_x" || "$u" != "$want_u" ]]; then
      ok=0
      echo "FAIL [$name] counts: want g=$want_g x=$want_x u=$want_u; got g=${g:-?} x=${x:-?} u=${u:-?}"
    fi
  fi

  if [[ "$ok" == 1 ]]; then
    pass=$((pass + 1))
    echo "ok   [$name]"
  else
    fail=$((fail + 1))
    echo "---- [$name] output ----"
    printf '%s\n' "$out" | sed 's/^/     /'
    echo "------------------------"
  fi
}

# ── Shared fixtures ─────────────────────────────────────────────────────────

# A representative allowlist: two listed failures, one with a pinned
# result, one matched on state alone (result omitted).
cat >"${WORK}/allow.yaml" <<'YAML'
plan: synthetic-plan
suite: release-vX
expected_failures:
  - module: mod-finished-fail
    state: FINISHED
    result: FAILED
    reason: "documented gap A"
    ref: "COVERAGE.md#bAA"
  - module: mod-interrupted-noresult
    state: INTERRUPTED
    reason: "documented gap B"
    ref: "COVERAGE.md#bBB"
YAML

# Empty allowlist (oidcc-config style).
cat >"${WORK}/allow-empty.yaml" <<'YAML'
plan: synthetic-config
suite: release-vX
expected_failures: []
YAML

# Malformed allowlist: unknown entry key -> must fail to parse.
cat >"${WORK}/allow-bad.yaml" <<'YAML'
plan: synthetic-bad
suite: release-vX
expected_failures:
  - module: whatever
    state: FINISHED
    bogus_key: nope
YAML

# Allowlist exercising OPTIONAL state: one entry pins a result but no
# state (matches that result in any non-green terminal state), one pins
# neither (matches the module in any non-green state at all).
cat >"${WORK}/allow-stateless.yaml" <<'YAML'
plan: synthetic-stateless
suite: release-vX
expected_failures:
  - module: mod-racy-fail
    result: FAILED
    reason: "racy terminal state, always FAILED"
    ref: "COVERAGE.md#bCC"
  - module: mod-racy-anystate
    reason: "known gap, any non-green terminal state"
    ref: "COVERAGE.md#bDD"
YAML

# ── Case 1: clean baseline. 2 green, 2 listed-and-failing as expected. ───────
cat >"${WORK}/r-clean.txt" <<'TXT'
# comment line ignored
mod-green-passed              FINISHED   PASSED
mod-green-warning            FINISHED   WARNING
mod-finished-fail            FINISHED   FAILED
mod-interrupted-noresult     INTERRUPTED   -
TXT
assert_case "clean-baseline" "${WORK}/r-clean.txt" "${WORK}/allow.yaml" 0 2 2 0

# ── Case 2: SKIPPED counts as green. ────────────────────────────────────────
cat >"${WORK}/r-skipped.txt" <<'TXT'
mod-skipped                  FINISHED   SKIPPED
mod-finished-fail            FINISHED   FAILED
mod-interrupted-noresult     INTERRUPTED   ?
TXT
assert_case "skipped-is-green" "${WORK}/r-skipped.txt" "${WORK}/allow.yaml" 0 1 2 0

# ── Case 3: fresh regression - a new non-green module not in the list. ───────
cat >"${WORK}/r-regression.txt" <<'TXT'
mod-green-passed             FINISHED   PASSED
mod-finished-fail            FINISHED   FAILED
mod-interrupted-noresult     INTERRUPTED   -
mod-brand-new                FINISHED   FAILED
TXT
assert_case "fresh-regression" "${WORK}/r-regression.txt" "${WORK}/allow.yaml" 1 1 2 1

# ── Case 4: now-passing listed module (green-but-listed) -> unexpected. ──────
# This is the "a fix landed, drop it from the baseline" direction.
cat >"${WORK}/r-nowpass.txt" <<'TXT'
mod-green-passed             FINISHED   PASSED
mod-finished-fail            FINISHED   PASSED
mod-interrupted-noresult     INTERRUPTED   -
TXT
assert_case "now-passing-listed" "${WORK}/r-nowpass.txt" "${WORK}/allow.yaml" 1 1 1 1

# ── Case 5: state drift - listed FINISHED/FAILED but observed INTERRUPTED. ───
cat >"${WORK}/r-statedrift.txt" <<'TXT'
mod-green-passed             FINISHED   PASSED
mod-finished-fail            INTERRUPTED   FAILED
mod-interrupted-noresult     INTERRUPTED   -
TXT
assert_case "state-drift" "${WORK}/r-statedrift.txt" "${WORK}/allow.yaml" 1 1 1 1

# ── Case 6: a listed module vanished from the run -> stale entry. ────────────
cat >"${WORK}/r-vanished.txt" <<'TXT'
mod-green-passed             FINISHED   PASSED
mod-finished-fail            FINISHED   FAILED
TXT
# mod-interrupted-noresult is missing -> 1 green, 1 xfail, 1 unexpected(stale)
assert_case "vanished-listed" "${WORK}/r-vanished.txt" "${WORK}/allow.yaml" 1 1 1 1

# ── Case 7: result-token noise matched on state alone (no pinned result). ────
# mod-interrupted-noresult pins no result; INTERRUPTED with any of -/?/FAILED
# must all count as expected-fail.
cat >"${WORK}/r-noise.txt" <<'TXT'
mod-interrupted-noresult     INTERRUPTED   FAILED
mod-finished-fail            FINISHED   FAILED
TXT
assert_case "result-noise-state-match" "${WORK}/r-noise.txt" "${WORK}/allow.yaml" 0 0 2 0

# ── Case 8: empty allowlist + a failure -> unexpected. ───────────────────────
cat >"${WORK}/r-config-fail.txt" <<'TXT'
oidcc-server                 FINISHED   FAILED
TXT
assert_case "empty-allow-with-failure" "${WORK}/r-config-fail.txt" "${WORK}/allow-empty.yaml" 1 0 0 1

# ── Case 9: empty allowlist + all green -> OK (the config happy path). ────────
cat >"${WORK}/r-config-ok.txt" <<'TXT'
oidcc-server                 FINISHED   PASSED
TXT
assert_case "empty-allow-all-green" "${WORK}/r-config-ok.txt" "${WORK}/allow-empty.yaml" 0 1 0 0

# ── Case 10: malformed allowlist -> hard parse error (exit 2). ───────────────
assert_case "malformed-allowlist" "${WORK}/r-clean.txt" "${WORK}/allow-bad.yaml" 2 - - -

# ── Case 11: optional state matches a FINISHED failure. ──────────────────────
cat >"${WORK}/r-stateless-finished.txt" <<'TXT'
mod-green-passed             FINISHED   PASSED
mod-racy-fail                FINISHED   FAILED
mod-racy-anystate            INTERRUPTED   -
TXT
assert_case "stateless-matches-finished" "${WORK}/r-stateless-finished.txt" "${WORK}/allow-stateless.yaml" 0 1 2 0

# ── Case 12: the SAME entries match the opposite terminal state. ─────────────
cat >"${WORK}/r-stateless-interrupted.txt" <<'TXT'
mod-green-passed             FINISHED   PASSED
mod-racy-fail                INTERRUPTED   FAILED
mod-racy-anystate            FINISHED   FAILED
TXT
assert_case "stateless-matches-interrupted" "${WORK}/r-stateless-interrupted.txt" "${WORK}/allow-stateless.yaml" 0 1 2 0

# ── Case 13: a state-omitted module that turns green is still flagged. ───────
cat >"${WORK}/r-stateless-nowpass.txt" <<'TXT'
mod-racy-fail                FINISHED   PASSED
mod-racy-anystate            INTERRUPTED   -
TXT
assert_case "stateless-still-catches-green" "${WORK}/r-stateless-nowpass.txt" "${WORK}/allow-stateless.yaml" 1 0 1 1

# ── Summary ─────────────────────────────────────────────────────────────────
echo
echo "classifier unit test: ${pass} passed, ${fail} failed"
[[ "$fail" -eq 0 ]]
