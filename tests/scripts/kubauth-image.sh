#!/usr/bin/env bash
#
# Build the kubauth container image from the working tree and load it
# into the test Kind cluster.
#
# Mirrors what `.github/workflows/e2e.yml` does in CI:
#
#   docker build -t local/kubauth:<tag> -f Dockerfile .
#   kind load docker-image local/kubauth:<tag> --name kubauth-e2e
#
# After this script runs, `kubauth-install.sh` invoked with
#   KUBAUTH_IMAGE_REPO=local/kubauth
#   KUBAUTH_IMAGE_TAG=<tag>
#   KUBAUTH_IMAGE_PULL_POLICY=Never
# will helm-install kubauth using the image we just built — i.e. with
# whatever's in your working tree, not the published quay.io image.
#
# Idempotent: docker uses its build cache; kind load is a no-op when the
# digest already matches what's in the kind node.
#
# Usage:
#   kubauth-image.sh                 # tag = "dev"
#   KUBAUTH_LOCAL_TAG=foo kubauth-image.sh
#
# Env vars (read):
#   KUBAUTH_LOCAL_TAG  — image tag to apply (default: "dev").

set -euo pipefail

# shellcheck source=lib/env.sh
source "$(dirname "$0")/lib/env.sh"

require_bin docker
require_bin kind

readonly TAG="${KUBAUTH_LOCAL_TAG:-dev}"
readonly IMAGE="local/kubauth:${TAG}"
# Dockerfile lives at the kubauth repo root, one level above tests/.
# Split declaration and assignment per SC2155 (cd's exit status is
# otherwise masked by readonly's).
REPO_ROOT="$(cd "${KUBAUTH_TESTS_ROOT}/.." && pwd)"
readonly REPO_ROOT

log "building ${IMAGE} from ${REPO_ROOT}/Dockerfile"
docker build -t "${IMAGE}" -f "${REPO_ROOT}/Dockerfile" "${REPO_ROOT}"

log "loading ${IMAGE} into kind cluster ${CLUSTER_NAME}"
kind load docker-image "${IMAGE}" --name "${CLUSTER_NAME}"

ok "image ${IMAGE} ready in kind"
