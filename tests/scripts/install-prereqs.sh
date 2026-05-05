#!/usr/bin/env bash
#
# Install the cluster prerequisites kubauth depends on:
#   - cert-manager (TLS for webhook + OIDC HTTPS)
#   - flux (only the CRDs source-controller / helm-controller need)
#
# Idempotent: skips already-installed components.

set -euo pipefail

# shellcheck source=lib/env.sh
source "$(dirname "$0")/lib/env.sh"

require_bin kubectl
require_bin helm

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

install_flux() {
  # Kubauth itself does not need Flux. We install it here to make the test cluster
  # representative of a real OKDP-style deployment that uses Flux to push kubauth.
  # Drop this step the day this suite does not exercise FluxCD-driven installs.
  if kubectl get ns "$NS_FLUX" >/dev/null 2>&1; then
    log "flux namespace exists — skipping install"
    return
  fi
  if ! command -v flux >/dev/null 2>&1; then
    warn "flux CLI not installed — skipping (set up later)"
    return
  fi
  log "installing flux"
  flux install --components=source-controller,helm-controller,kustomize-controller
}

main() {
  install_cert_manager
  install_flux
  ok "prereqs installed"
}

main "$@"
