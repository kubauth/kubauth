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
# CI tool installer for the conformance workflow.
#
# Installs kind, kubectl, and helm at EXACTLY the versions pinned in
# .tool-versions, so CI uses the same single source of truth as local dev
# (hack/check-tools.sh) without a separate tool-manager (no mise on main).
# Go comes from actions/setup-go (go-version-file: .tool-versions); docker
# is preinstalled on GitHub-hosted ubuntu runners. Installs into a dir on
# PATH (defaults to /usr/local/bin) for linux/amd64.
#
# Idempotent: a tool already present at the pinned version is left as-is.

set -o errexit
set -o nounset
set -o pipefail

# Shared helpers + tool_version() (reads .tool-versions). Also defines
# log/ok/warn/err/die.
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

readonly BIN_DIR="${BIN_DIR:-/usr/local/bin}"
readonly OS="linux"
readonly ARCH="amd64"

# `sudo` when not already root (GitHub runners write /usr/local/bin via sudo).
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  SUDO="sudo"
fi

# need <tool> <pinned>: true if <tool> is absent or not at the pinned version.
need() {
  local tool="$1" pinned="$2" have
  command -v "$tool" >/dev/null 2>&1 || return 0
  case "$tool" in
    kind)    have="$(kind version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)" ;;
    kubectl) have="$(kubectl version --client 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)" ;;
    helm)    have="$(helm version --template='{{.Version}}' 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)" ;;
  esac
  [ "$have" != "$pinned" ]
}

install_kind() {
  local v="$1"
  log "installing kind v${v}"
  curl -fsSL -o /tmp/kind \
    "https://github.com/kubernetes-sigs/kind/releases/download/v${v}/kind-${OS}-${ARCH}"
  $SUDO install -m 0755 /tmp/kind "${BIN_DIR}/kind"
  rm -f /tmp/kind
}

install_kubectl() {
  local v="$1"
  log "installing kubectl v${v}"
  curl -fsSL -o /tmp/kubectl \
    "https://dl.k8s.io/release/v${v}/bin/${OS}/${ARCH}/kubectl"
  $SUDO install -m 0755 /tmp/kubectl "${BIN_DIR}/kubectl"
  rm -f /tmp/kubectl
}

install_helm() {
  local v="$1"
  log "installing helm v${v}"
  curl -fsSL -o /tmp/helm.tgz \
    "https://get.helm.sh/helm-v${v}-${OS}-${ARCH}.tar.gz"
  tar -xzf /tmp/helm.tgz -C /tmp "${OS}-${ARCH}/helm"
  $SUDO install -m 0755 "/tmp/${OS}-${ARCH}/helm" "${BIN_DIR}/helm"
  rm -rf /tmp/helm.tgz "/tmp/${OS}-${ARCH}"
}

main() {
  local kind_v kubectl_v helm_v
  kind_v="$(tool_version kind)"
  kubectl_v="$(tool_version kubectl)"
  helm_v="$(tool_version helm)"

  [ -n "$kind_v" ]    || die ".tool-versions has no 'kind' pin"
  [ -n "$kubectl_v" ] || die ".tool-versions has no 'kubectl' pin"
  [ -n "$helm_v" ]    || die ".tool-versions has no 'helm' pin"

  if need kind "$kind_v";       then install_kind "$kind_v";       else ok "kind v${kind_v} already present"; fi
  if need kubectl "$kubectl_v"; then install_kubectl "$kubectl_v"; else ok "kubectl v${kubectl_v} already present"; fi
  if need helm "$helm_v";       then install_helm "$helm_v";       else ok "helm v${helm_v} already present"; fi

  ok "tool install complete:"
  kind version    || true
  kubectl version --client || true
  helm version    || true
}

main "$@"
