#!/usr/bin/env bash
#
# Run a command with `--enforcePKCE=false` on the kubauth Deployment,
# then restore the previous setting (whatever it was) on exit — even on
# error, Ctrl-C, or kill.
#
# Why: The OpenID Conformance Suite's `oidcc-basic-certification-test-plan`
# expects PKCE to be optional (the basic profile dates back to before
# PKCE was mandated). kubauth ships with `enforcePKCE: true` in the
# test cluster (see fixtures/kubauth-values.yaml) — best practice for
# real deployments, but the suite refuses to send a `code_challenge`
# from inside its basic plan and kubauth replies `invalid_request`.
#
# Toggling the flag for the duration of the run keeps the e2e suite
# (which exercises `02-pkce-required`) intact while letting the
# conformance plan complete.
#
# Usage:
#   with-pkce-disabled.sh <command> [args...]
#
# Examples:
#   with-pkce-disabled.sh make conformance-basic
#   with-pkce-disabled.sh tests/scripts/conformance-run.sh ...

set -euo pipefail

# shellcheck source=lib/env.sh
source "$(dirname "$0")/lib/env.sh"

require_bin kubectl
require_bin python3

# Find the index of `--enforcePKCE=...` in the kubauth oidc container args.
find_pkce_arg_index() {
  kubectl -n "$NS_KUBAUTH" get deploy kubauth \
    -o jsonpath='{.spec.template.spec.containers[0].args}' \
    | python3 -c '
import json, sys
args = json.load(sys.stdin)
for i, a in enumerate(args):
    if a.startswith("--enforcePKCE="):
        print(i); sys.exit(0)
sys.exit(2)
'
}

# Read the current value (true|false) of `--enforcePKCE`.
current_pkce_value() {
  kubectl -n "$NS_KUBAUTH" get deploy kubauth \
    -o jsonpath='{.spec.template.spec.containers[0].args}' \
    | python3 -c '
import json, sys
args = json.load(sys.stdin)
for a in args:
    if a.startswith("--enforcePKCE="):
        print(a.split("=", 1)[1]); sys.exit(0)
sys.exit(2)
'
}

# Patch arg index $1 with `--enforcePKCE=$2`.
set_pkce() {
  local idx="$1" val="$2"
  kubectl -n "$NS_KUBAUTH" patch deployment kubauth --type=json \
    -p "[{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/args/${idx}\",\"value\":\"--enforcePKCE=${val}\"}]" \
    >/dev/null
  kubectl -n "$NS_KUBAUTH" rollout status deployment kubauth --timeout=120s >/dev/null

  # `rollout status` returns when the new pod's readiness probe (oidc
  # :8110/readyz, plain HTTP) is green. That's *not* enough for the
  # conformance suite, which connects through the Service ClusterIP
  # (kubauth-oidc-server:443 → targetPort 6801, the OIDC TLS server).
  # Two distinct races bite the suite right after rollout-status:
  #   1. TLS server :6801 binds a couple of seconds *after* :8110/readyz
  #      goes green — readiness probe doesn't gate it.
  #   2. kube-proxy iptables hasn't yet swapped the Service endpoint to
  #      the new pod IP — packets still hit the old pod, which has
  #      already closed :6801 during graceful shutdown → ECONNREFUSED.
  #
  # Probing via the apiserver's service-proxy (`get --raw .../proxy/...`)
  # bypasses kube-proxy and only catches race (1), so the suite still
  # gets `Connect refused` on its first call. Probe instead from inside
  # the conformance-server pod, exactly the path the suite uses (cluster
  # DNS + Service ClusterIP), so we wait for *both* races to settle.
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if kubectl -n conformance exec deploy/conformance-server -c server -- \
         timeout 3 curl -sfk -o /dev/null \
         "https://kubauth-oidc-server.${NS_KUBAUTH}.svc:443/.well-known/openid-configuration" \
         >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  warn "kubauth /.well-known/openid-configuration not reachable from conformance-server after rollout — caller may flake"
}

# Bounce the OpenID conformance-server pod so its JVM-level network state
# is cleared before the next plan runs. Required after kubauth rolls,
# because:
#
#   1. JVM positive DNS cache is unbounded by default (no SecurityManager
#      → cache policy = forever). Once the JVM has resolved
#      `kubauth-oidc-server.kubauth-system.svc`, it sticks with that IP
#      across kubauth rollouts.
#   2. Apache HttpClient (used by the suite) keeps a connection pool
#      keyed by hostname:port. After kubauth rolls, the pool reuses a
#      keep-alive connection to the now-gone old pod IP. Even with a
#      bounded DNS TTL, pool reuse bypasses re-resolution and the call
#      surfaces as `Connect timed out` on the suite's first
#      GetDynamicServerConfiguration of the next plan.
#
# We can't reach into the suite to flush its pool from outside, and the
# OIDF suite isn't designed to outlive OP configuration changes. A pod
# restart is the standard, supported way to refresh it. We only do this
# on the OFF transition (just before plans run); the restore at the end
# of the wrapped command runs no plans, so a stale pool there is harmless.
bounce_conformance_server_if_present() {
  if ! kubectl -n conformance get deploy conformance-server >/dev/null 2>&1; then
    log "conformance-server not deployed — skipping JVM pool flush"
    return 0
  fi
  log "bouncing conformance-server to flush JVM DNS cache + HTTP pool"
  kubectl -n conformance rollout restart deploy/conformance-server >/dev/null
  kubectl -n conformance rollout status deploy/conformance-server --timeout=180s >/dev/null
}

main() {
  if (($# == 0)); then
    err "no command supplied"
    echo "usage: $0 <command> [args...]" >&2
    exit 2
  fi

  # Intentionally NOT `local`: the EXIT trap below references `idx`
  # and `prev`, and traps run in the main shell after `main` returns
  # — local variables are out of scope by then. With `set -u` (env.sh
  # default), an out-of-scope reference fires `unbound variable` and
  # the restore is skipped, leaving the cluster with PKCE off. Keep
  # them at file scope.
  idx="$(find_pkce_arg_index)"
  prev="$(current_pkce_value)"
  log "current --enforcePKCE=${prev} at args[${idx}]"

  if [[ "$prev" == "false" ]]; then
    log "PKCE already disabled — running command without toggling"
    exec "$@"
  fi

  # Restore on any exit (success, failure, signal). Trap body is
  # double-quoted so `${idx}` and `${prev}` are baked in at install
  # time -- extra safety even if someone later re-introduces `local`
  # on idx/prev. Disable SC2064 (warns about non-deferred expansion)
  # because the early expansion is exactly what we want here.
  # shellcheck disable=SC2064
  trap "
    log 'restoring --enforcePKCE=${prev}'
    set_pkce '${idx}' '${prev}' || warn 'failed to restore --enforcePKCE -- manual fix needed'
  " EXIT

  log "disabling enforcePKCE for the duration of: $*"
  set_pkce "${idx}" "false"
  ok "kubauth rolled with --enforcePKCE=false"

  # Now that kubauth has rolled, refresh the conformance suite so it
  # doesn't try to talk to a defunct kubauth pod IP via cached state.
  # Skipped automatically if conformance-server isn't deployed (e.g.
  # someone uses this wrapper for non-conformance tooling).
  bounce_conformance_server_if_present

  # Run the command. Trap fires regardless of its exit code.
  "$@"
}

main "$@"
