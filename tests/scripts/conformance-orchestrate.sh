#!/usr/bin/env bash
#
# Autonomous, from-zero OIDC conformance run.
#
# Assuming only Docker, this drives the whole pipeline end to end and
# tears it down again (design note section 2):
#
#   1. preflight        docker/kind/kubectl/helm/curl/python3/openssl
#   2. dev-up           kind + registry + cert-manager + working-tree
#                       kubauth image + helm install + cert patch
#                       (delegates to `make dev-up`, which carries the
#                        local image vars + the CA ClusterIssuer + the
#                        conformance OidcClient seed)
#   3. conformance-up   mongo + server + nginx (3-pod suite) + waits
#   4. port-forward     backgrounded host port-forward to the suite API,
#                       reaped by a trap; wait until the API answers
#   5. run plan(s)      with-pkce-disabled wrapping conformance-run.sh
#                       per plan; each plan classifies its modules into
#                       green / expected-fail / unexpected
#   6. summarize        per-plan TL;DR roll-up + OVERALL verdict
#   7. teardown (trap)  kill the port-forward; `make dev-down`
#                       (kind delete + registry rm). KEEP=1 skips it.
#
# Exit 0 iff every plan reports 0 unexpected modules (the cross-plan
# 3-bucket verdict). Any plan with an UNEXPECTED module (regression or
# stale baseline) fails the whole run.
#
# Environment:
#   PLAN=<config|basic|rp-logout|all>   plan set to run (default: config)
#   KEEP=1                              skip teardown (leave cluster up)
#   REUSE=1                             skip kind-up/teardown, reuse an
#                                       existing cluster (fast local loop)
#   SUITE_URL=...                       override the suite API base URL
#
# Usage: conformance-orchestrate.sh    (normally via `make conformance`)

set -euo pipefail

# shellcheck source=lib/env.sh
source "$(dirname "$0")/lib/env.sh"

# `make` runs from the tests/ root (tests/Makefile). Resolve it once.
readonly TESTS_MAKE_DIR="${KUBAUTH_TESTS_ROOT}"

readonly SUITE_URL="${SUITE_URL:-https://localhost.emobix.co.uk:8443}"
readonly PF_LOCAL_PORT="${PF_LOCAL_PORT:-8443}"
# `:-` fires on unset OR empty, so an empty value forwarded by make
# (PLAN= with no value) still falls back to the default here.
readonly PLAN="${PLAN:-config}"
readonly KEEP="${KEEP:-0}"
readonly REUSE="${REUSE:-0}"

# Roll-up file: each plan appends its one-line TL;DR (conformance-run.sh
# honours CONFORMANCE_ROLLUP). Lives under tests/.tmp (gitignored).
readonly ROLLUP="${TMP_DIR}/conformance-rollup.txt"

# Port-forward bookkeeping (file scope, not local: the EXIT trap reads
# PF_PID after main returns; a local would be out of scope under set -u).
PF_PID=""
PF_LOG=""

# ── Preflight ────────────────────────────────────────────────────────────────
preflight() {
  log "preflight: checking required tools"
  local t
  for t in docker kind kubectl helm curl python3 openssl; do
    require_bin "$t"
  done
  ok "preflight passed"
}

# ── Teardown (trap) ──────────────────────────────────────────────────────────
# Always reap the port-forward. Delete the cluster unless KEEP=1 or REUSE=1.
teardown() {
  local rc=$?
  set +e
  if [[ -n "$PF_PID" ]] && kill -0 "$PF_PID" 2>/dev/null; then
    log "stopping port-forward (pid ${PF_PID})"
    kill "$PF_PID" 2>/dev/null
    wait "$PF_PID" 2>/dev/null
  fi
  [[ -n "$PF_LOG" && -f "$PF_LOG" ]] && rm -f "$PF_LOG"

  if [[ "$KEEP" == "1" ]]; then
    warn "KEEP=1 - leaving the cluster up. Tear down with: make -C tests dev-down"
  elif [[ "$REUSE" == "1" ]]; then
    log "REUSE=1 - leaving the reused cluster up"
  else
    log "tearing down the cluster"
    make -C "$TESTS_MAKE_DIR" dev-down || warn "dev-down failed - clean up manually"
  fi
  exit "$rc"
}

# ── Bring-up ─────────────────────────────────────────────────────────────────
bring_up() {
  if [[ "$REUSE" == "1" ]]; then
    log "REUSE=1 - skipping kind-up; expecting an existing cluster + kubauth"
    # Still (idempotently) ensure kubauth + the suite are installed.
    make -C "$TESTS_MAKE_DIR" dev-up
  else
    log "bringing up cluster + kubauth (make dev-up)"
    make -C "$TESTS_MAKE_DIR" dev-up
  fi

  log "deploying the conformance suite (make conformance-up)"
  make -C "$TESTS_MAKE_DIR" conformance-up
}

# ── Port-forward (backgrounded) ──────────────────────────────────────────────
start_port_forward() {
  PF_LOG="$(mktemp -t conformance-pf-XXXXXX.log)"
  log "starting backgrounded port-forward ${PF_LOCAL_PORT}:8443 -> svc/conformance-nginx"
  # Bypass the env.sh log() wrappers for the child; just background kubectl.
  kubectl -n conformance port-forward svc/conformance-nginx \
    "${PF_LOCAL_PORT}:8443" >"$PF_LOG" 2>&1 &
  PF_PID=$!
  log "port-forward pid ${PF_PID} (log: ${PF_LOG})"

  # Wait until the suite REST API answers. localhost.emobix.co.uk
  # resolves to 127.0.0.1; the suite ships a cert whose SAN matches it,
  # but we tolerate the self-signed chain anyway (-k). `/api/runner/available`
  # is a lightweight always-present suite endpoint.
  local _
  for _ in $(seq 1 60); do
    if ! kill -0 "$PF_PID" 2>/dev/null; then
      err "port-forward died early - log follows:"
      cat "$PF_LOG" >&2 || true
      die "port-forward could not be established"
    fi
    if curl -sk -o /dev/null --max-time 3 "${SUITE_URL}/api/runner/available"; then
      ok "suite API reachable at ${SUITE_URL}"
      return 0
    fi
    sleep 2
  done
  err "suite API not reachable at ${SUITE_URL} after ~120s - port-forward log:"
  cat "$PF_LOG" >&2 || true
  die "giving up waiting for the suite API"
}

# ── Plan runner ──────────────────────────────────────────────────────────────
# Map the friendly PLAN value to the make target(s) to run.
#
# The `all` case runs the single `conformance-all` target rather than
# looping config/basic/rp-logout here: conformance-all wraps the whole
# sequence in ONE with-pkce-disabled (toggling PKCE off once, restoring
# once). Looping the per-plan targets ourselves would toggle PKCE per
# plan and re-trigger the documented rp-logout TLS-readiness race (see
# the conformance-all comment in tests/Makefile). Either way each plan's
# conformance-run.sh applies the 3-bucket gate and appends its TL;DR to
# CONFORMANCE_ROLLUP.
plan_targets() {
  case "$PLAN" in
    config)             echo "conformance-config" ;;
    basic)              echo "conformance-basic" ;;
    rp-logout)          echo "conformance-rp-logout" ;;
    all|full)           echo "conformance-all" ;;
    *)
      die "unknown PLAN='${PLAN}' (use: config | basic | rp-logout | all)"
      ;;
  esac
}

run_plans() {
  mkdir -p "$TMP_DIR"
  : > "$ROLLUP"

  local targets overall_rc=0 t
  targets="$(plan_targets)"
  log "running plan target(s): ${targets}"

  # Export the roll-up path so each conformance-run.sh appends its
  # one-line TL;DR. The plans are run via their make targets so the
  # PKCE toggle / suite-bounce wrappers stay in one place (tests/Makefile).
  export CONFORMANCE_ROLLUP="$ROLLUP"
  export SUITE_URL

  for t in $targets; do
    log "── plan: make ${t} ──"
    if ! make -C "$TESTS_MAKE_DIR" "$t"; then
      overall_rc=1
      warn "plan target '${t}' reported UNEXPECTED modules"
    fi
  done

  echo
  echo "================ conformance roll-up ================"
  echo "suite ${CONFORMANCE_SUITE_VERSION:-unknown}"
  if [[ -s "$ROLLUP" ]]; then
    cat "$ROLLUP"
  else
    echo "(no plan produced a summary line)"
    overall_rc=1
  fi
  if ((overall_rc == 0)); then
    echo "OVERALL: OK (0 unexpected)"
  else
    echo "OVERALL: FAIL (unexpected modules present - see per-plan detail above)"
  fi
  echo "===================================================="

  return "$overall_rc"
}

# ── kubauth discovery readiness ───────────────────────────────────────────────
# `helm install ... rollout status` returns when kubauth's :8110/readyz is green,
# which does NOT guarantee the OIDC TLS server (:6801, behind svc :443) is bound or
# that kube-proxy has swapped the Service endpoint to the new pod. Probe from inside
# the conformance-server pod (the exact path the suite uses: cluster DNS + Service
# ClusterIP) so EVERY plan waits for kubauth to actually answer discovery — including
# the default config plan, which is not wrapped by with-pkce-disabled.sh (that wrapper
# carries the same probe for the basic/rp-logout paths after its PKCE rollout).
wait_kubauth_discovery() {
  log "waiting for kubauth discovery to be reachable from the suite"
  local _
  for _ in $(seq 1 30); do
    if kubectl -n conformance exec deploy/conformance-server -c server -- \
         timeout 3 curl -sfk -o /dev/null \
         "https://kubauth-oidc-server.${NS_KUBAUTH}.svc:443/.well-known/openid-configuration" \
         >/dev/null 2>&1; then
      ok "kubauth discovery reachable from the suite"
      return 0
    fi
    sleep 2
  done
  die "kubauth discovery not reachable from the suite after ~60s"
}

main() {
  preflight
  # EXIT runs teardown on normal exit; the INT/TERM handlers exit explicitly so a
  # Ctrl-C / kill interrupts any blocking foreground command and still fires EXIT
  # (teardown is idempotent). Without these, an interactive SIGINT can skip teardown
  # and leak the kind cluster on some bash versions.
  trap teardown EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  bring_up
  wait_kubauth_discovery
  start_port_forward
  run_plans
}

main "$@"
