#!/usr/bin/env bash
#
# Bring up the local Kind cluster + OCI registry for the test suite.
#
# One kind stack only: this delegates to the repo's single source of truth,
# hack/kind-with-registry.sh (cluster "kubauth", registry "kubauth-registry"
# on :5001). That script is idempotent and also installs cert-manager + the
# kubauth CRDs, so the conformance harness, `make dev-up`, and the devcontainer
# all share the exact same cluster. Do NOT reintroduce a separate "kubauth-e2e"
# cluster here.

set -euo pipefail

# shellcheck source=lib/env.sh
source "$(dirname "$0")/lib/env.sh"

# REPO_ROOT and the hack/ helpers come from hack/lib.sh (sourced by env.sh).
exec bash "${REPO_ROOT}/hack/kind-with-registry.sh" "$@"
