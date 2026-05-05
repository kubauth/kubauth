#!/usr/bin/env bash
#
# Boot a Kind cluster wired to a local OCI registry.
#
# Idempotent: rerunning the script reuses an existing cluster and registry.
# Pattern follows https://kind.sigs.k8s.io/docs/user/local-registry/

set -euo pipefail

# shellcheck source=lib/env.sh
source "$(dirname "$0")/lib/env.sh"

require_bin docker
require_bin kind
require_bin kubectl

ensure_registry() {
  if docker inspect "$REGISTRY_NAME" >/dev/null 2>&1; then
    if [[ "$(docker inspect -f '{{.State.Running}}' "$REGISTRY_NAME")" != "true" ]]; then
      log "registry container exists but stopped — restarting"
      docker start "$REGISTRY_NAME" >/dev/null
    else
      log "registry already running"
    fi
    return
  fi
  log "creating registry container :$REGISTRY_PORT"
  docker run -d --restart=always \
    -p "127.0.0.1:${REGISTRY_PORT}:5000" \
    --network bridge \
    --name "$REGISTRY_NAME" \
    registry:2 >/dev/null
}

ensure_cluster() {
  if kind get clusters | grep -qx "$CLUSTER_NAME"; then
    log "cluster '$CLUSTER_NAME' already exists"
    return
  fi
  log "creating cluster '$CLUSTER_NAME' (image $KIND_NODE_IMAGE)"
  cat <<EOF | kind create cluster --name "$CLUSTER_NAME" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: ${KIND_NODE_IMAGE}
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry]
      config_path = "/etc/containerd/certs.d"
EOF
}

# Tell containerd in the Kind node where to find the local registry.
configure_node_registry() {
  local registry_dir="/etc/containerd/certs.d/localhost:${REGISTRY_PORT}"
  local node
  for node in $(kind get nodes --name "$CLUSTER_NAME"); do
    docker exec "$node" mkdir -p "$registry_dir"
    docker exec -i "$node" tee "$registry_dir/hosts.toml" >/dev/null <<EOF
[host."http://${REGISTRY_NAME}:5000"]
EOF
  done
}

# Connect registry to the kind network so the cluster can pull from it.
connect_registry_to_kind_network() {
  if [[ "$(docker inspect -f='{{json .NetworkSettings.Networks.'"$REGISTRY_HOST_NETWORK"'}}' "$REGISTRY_NAME")" == "null" ]]; then
    log "connecting registry to '$REGISTRY_HOST_NETWORK' docker network"
    docker network connect "$REGISTRY_HOST_NETWORK" "$REGISTRY_NAME"
  fi
}

# Document the registry inside the cluster (best practice — see Kind docs).
publish_registry_configmap() {
  cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:${REGISTRY_PORT}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF
}

main() {
  ensure_registry
  ensure_cluster
  configure_node_registry
  connect_registry_to_kind_network
  publish_registry_configmap
  ok "cluster '$CLUSTER_NAME' ready, registry at localhost:${REGISTRY_PORT}"
}

main "$@"
