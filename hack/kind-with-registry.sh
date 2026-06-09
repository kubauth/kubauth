#!/usr/bin/env bash
# Copyright (c) Kubotal 2026.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Idempotently bring up the local kubauth dev cluster: a Kind cluster wired to a
# local OCI registry, plus cert-manager and the kubauth CRDs. This is the
# DEV-environment bootstrap — it does NOT install the kubauth application
# (helm + fixtures); that belongs to the e2e suite (a separate increment).
#
# One cluster serves both the host and the devcontainer: under
# Docker-outside-of-Docker the Kind nodes run on the host daemon, reachable from
# the host (localhost) and from the devcontainer (host.docker.internal).

set -o errexit
set -o nounset
set -o pipefail

# Shared helpers, config, and per-developer overrides (dev.env).
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# Operate from the repository root so relative paths (config/crd, Makefile) work.
cd "${REPO_ROOT}"

# Retry a network-dependent command up to 3 times with a back-off.
retry() {
  local n=1 max=3 delay=5
  while true; do
    if "$@"; then
      return 0
    elif (( n >= max )); then
      err "command '$*' failed after ${n} attempts."
      return 1
    else
      warn "command '$*' failed — retrying in ${delay}s (attempt ${n}/${max})..."
      sleep "${delay}"
      ((n++))
    fi
  done
}

# ── 0. Pre-flight checks ─────────────────────────────────────────────────────
log "running pre-flight environment checks..."

if ! docker info >/dev/null 2>&1; then
  die "the Docker daemon is not running or not reachable. Start Docker and retry."
fi

require_bin kind
require_bin kubectl
require_bin helm
require_bin make

# Is our registry already running? Computed once and reused: lets us skip the
# port probe when we already hold the port, and skip re-creating the container.
reg_running="false"
if [ "$(docker inspect -f '{{.State.Running}}' "${REGISTRY_NAME}" 2>/dev/null || true)" = "true" ]; then
  reg_running="true"
fi

# Check the registry host port is free before binding it. Under
# Docker-outside-of-Docker the registry publishes on the host's loopback
# (127.0.0.1:${REGISTRY_PORT}), so the Docker daemon — not an in-container TCP
# probe, which inspects the wrong network namespace — is the only reliable
# authority. We reuse the pinned registry image as a throwaway bind-probe (no
# extra dependency); a non-conflict error (e.g. image pull) is ignored here and
# left for the real 'docker run' below to surface and retry.
if [ "${reg_running}" = "false" ]; then
  probe_err="$(docker run --rm --entrypoint /bin/true \
    -p "127.0.0.1:${REGISTRY_PORT}:${REGISTRY_PORT}" "${REGISTRY_IMAGE}" 2>&1 >/dev/null || true)"
  if printf '%s' "${probe_err}" | grep -q 'port is already allocated'; then
    err "host port ${REGISTRY_PORT} is already in use on this machine."
    err "pick a free port via KUBAUTH_REGISTRY_PORT in dev.env, then re-run."
    err "(if a previous kubauth registry is still bound, run 'make dev-down' first.)"
    exit 1
  fi
fi

ok "pre-flight checks passed."

# ── 1. Local OCI registry ────────────────────────────────────────────────────
if [ "${reg_running}" = "false" ]; then
  log "creating OCI registry container '${REGISTRY_NAME}' on :${REGISTRY_PORT}..."
  # Internal listen port == published port so the containerd routing (below)
  # resolves a single, consistent port number.
  retry docker run \
    -d --restart=always -p "127.0.0.1:${REGISTRY_PORT}:${REGISTRY_PORT}" --network bridge \
    -e "REGISTRY_HTTP_ADDR=:${REGISTRY_PORT}" \
    --name "${REGISTRY_NAME}" \
    "${REGISTRY_IMAGE}"
else
  log "registry container '${REGISTRY_NAME}' is already running."
fi

log "waiting for the OCI registry to be responsive..."
reg_ready=false
for _ in $(seq 1 30); do
  if docker exec "${REGISTRY_NAME}" wget -q --spider "http://localhost:${REGISTRY_PORT}/v2/" >/dev/null 2>&1; then
    reg_ready=true
    break
  fi
  sleep 1
done
[ "${reg_ready}" = "true" ] || die "registry started but did not answer on :${REGISTRY_PORT} within 30s."
ok "OCI registry is ready."

# ── 2. Kind cluster ──────────────────────────────────────────────────────────
if ! kind get clusters | grep -qx "${CLUSTER_NAME}"; then
  log "creating Kind cluster '${CLUSTER_NAME}' (node image ${KIND_NODE_IMAGE})..."
  # Inline config so KIND_NODE_IMAGE + REGISTRY_PORT (from lib.sh / dev.env) flow
  # straight in. config_path enables per-registry hosts.toml (written in step 5).
  retry kind create cluster --name "${CLUSTER_NAME}" --wait 5m --config=- <<EOF
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
else
  log "Kind cluster '${CLUSTER_NAME}' already exists."
fi

# Refresh the kubeconfig context. 'kind create cluster' writes the 'kind-<name>'
# context only on creation, so a pre-existing cluster — or a freshly rebuilt
# devcontainer with an empty kubeconfig — would leave nothing for the
# '--context kind-<name>' flags below to resolve. 'kind export kubeconfig' is
# idempotent; the patch just after repoints the server to host.docker.internal.
kind export kubeconfig --name "${CLUSTER_NAME}"

# From the devcontainer the apiserver is reachable via host.docker.internal, and
# the serving cert validates against the SAN '${CLUSTER_NAME}-control-plane'.
log "patching kubeconfig for devcontainer access..."
api_port="$(docker port "${CLUSTER_NAME}-control-plane" 6443/tcp | head -1 | awk -F: '{print $2}')"
kubectl config set-cluster "kind-${CLUSTER_NAME}" \
  --server="https://host.docker.internal:${api_port}" \
  --tls-server-name="${CLUSTER_NAME}-control-plane"

# ── 3. Wire the registry to the cluster network ──────────────────────────────
if [ "$(docker inspect -f '{{json .NetworkSettings.Networks.kind}}' "${REGISTRY_NAME}")" = "null" ]; then
  log "connecting registry '${REGISTRY_NAME}' to the 'kind' docker network..."
  retry docker network connect "kind" "${REGISTRY_NAME}"
fi

# ── 4. Route localhost:${REGISTRY_PORT} to the registry on each node ─────────
log "configuring containerd registry routing on Kind nodes..."
for node in $(kind get nodes --name "${CLUSTER_NAME}"); do
  docker exec "${node}" mkdir -p "/etc/containerd/certs.d/localhost:${REGISTRY_PORT}"
  docker exec -i "${node}" sh -c "cat > /etc/containerd/certs.d/localhost:${REGISTRY_PORT}/hosts.toml" <<EOF
server = "http://${REGISTRY_NAME}:${REGISTRY_PORT}"

[host."http://${REGISTRY_NAME}:${REGISTRY_PORT}"]
  capabilities = ["pull", "resolve"]
  skip_verify = true
EOF
done

# ── 5. cert-manager (kubauth's webhooks + OIDC HTTPS depend on it) ───────────
if kubectl --context "kind-${CLUSTER_NAME}" get namespace cert-manager >/dev/null 2>&1; then
  log "cert-manager already installed — skipping."
else
  log "installing cert-manager ${CERT_MANAGER_VERSION}..."
  retry kubectl --context "kind-${CLUSTER_NAME}" apply -f \
    "https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.yaml"
fi

# ── 6. Wait for cert-manager to be available ─────────────────────────────────
log "waiting for cert-manager to be available..."
for d in cert-manager cert-manager-webhook cert-manager-cainjector; do
  kubectl --context "kind-${CLUSTER_NAME}" -n cert-manager rollout status "deploy/${d}" --timeout=180s
done

ok "kubauth dev cluster ready."
echo "  Cluster context : kind-${CLUSTER_NAME}" >&2
echo "  Local registry  : localhost:${REGISTRY_PORT} (host) / host.docker.internal:${REGISTRY_PORT} (devcontainer)" >&2
echo "  Next            : 'make install' to add the kubauth CRDs, then deploy via helm / run the controller." >&2
