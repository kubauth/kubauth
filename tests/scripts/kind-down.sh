#!/usr/bin/env bash
#
# Tear down the local Kind cluster + OCI registry.
#
# Mirrors main's `make dev-down` (there is no hack/ teardown script to delegate
# to): delete the single shared cluster and remove the registry container by the
# names defined in hack/lib.sh (sourced via env.sh). Idempotent.

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
    log "removing registry container '$REGISTRY_NAME'"
    docker rm -f -v "$REGISTRY_NAME" >/dev/null
  else
    log "registry container '$REGISTRY_NAME' already absent"
  fi
}

main() {
  delete_cluster
  delete_registry
  ok "torn down"
}

main "$@"
