#!/usr/bin/env bash
#
# Tear down the Kind cluster and the local registry container.

set -euo pipefail

# shellcheck source=lib/env.sh
source "$(dirname "$0")/lib/env.sh"

require_bin docker
require_bin kind

delete_cluster() {
  if kind get clusters | grep -qx "$CLUSTER_NAME"; then
    log "deleting cluster '$CLUSTER_NAME'"
    kind delete cluster --name "$CLUSTER_NAME"
  else
    log "cluster '$CLUSTER_NAME' already absent"
  fi
}

delete_registry() {
  if docker inspect "$REGISTRY_NAME" >/dev/null 2>&1; then
    log "removing registry container"
    docker rm -f "$REGISTRY_NAME" >/dev/null
  else
    log "registry container already absent"
  fi
}

main() {
  delete_cluster
  delete_registry
  ok "torn down"
}

main "$@"
