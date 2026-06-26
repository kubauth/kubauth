#!/usr/bin/env bash
#
# Install the cluster prerequisites kubauth depends on:
#   - cert-manager (TLS for the webhooks + OIDC HTTPS)
#
# cert-manager is also installed by hack/kind-with-registry.sh (the shared
# bring-up), so this step is normally a no-op on a freshly-booted cluster; it
# stays here so the suite can install prereqs against a cluster that was brought
# up some other way. Idempotent: skips when the namespace already exists.
#
# Flux is intentionally NOT installed: kubauth does not depend on it and the
# conformance harness does not exercise FluxCD-driven installs.

set -euo pipefail

# shellcheck source=lib/env.sh
source "$(dirname "$0")/lib/env.sh"

require_bin kubectl

install_cert_manager() {
  if kubectl get ns "$NS_CERT_MANAGER" >/dev/null 2>&1; then
    log "cert-manager namespace exists — skipping install"
    return
  fi
  log "installing cert-manager $CERT_MANAGER_VERSION"
  kubectl apply -f \
    "https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.yaml"
  kubectl -n "$NS_CERT_MANAGER" rollout status deploy/cert-manager --timeout=180s
  kubectl -n "$NS_CERT_MANAGER" rollout status deploy/cert-manager-webhook --timeout=180s
  kubectl -n "$NS_CERT_MANAGER" rollout status deploy/cert-manager-cainjector --timeout=180s
}

main() {
  install_cert_manager
  ok "prereqs installed"
}

main "$@"
