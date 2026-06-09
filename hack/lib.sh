#!/usr/bin/env bash
# Shared helpers + configuration for hack/ scripts. Source this file; do not
# execute it.
# shellcheck disable=SC2034  # config vars are consumed by scripts that source this file

# Repo root resolved from this file's location (hack/ sits directly under root).
_hack_lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${_hack_lib_dir}/.." && pwd)"
TOOL_VERSIONS_FILE="${TOOL_VERSIONS_FILE:-${REPO_ROOT}/.tool-versions}"

# Load per-developer overrides from dev.env if present (git-ignored). Values are
# auto-exported so child processes inherit them. An absent file is a no-op; this
# never fails. Same file on the host and in the devcontainer (repo is mounted).
DEV_ENV_FILE="${DEV_ENV_FILE:-${REPO_ROOT}/dev.env}"
if [ -f "${DEV_ENV_FILE}" ]; then
    set -a
    # shellcheck disable=SC1090
    . "${DEV_ENV_FILE}"
    set +a
fi

# tool_version <name>: print the version pinned for <name> in .tool-versions
# (matched on the exact first field). Empty output if the tool is absent.
tool_version() {
    awk -v t="$1" '$1 == t { print $2 }' "${TOOL_VERSIONS_FILE}"
}

# ── Local dev cluster + registry configuration ──────────────────────────────
# One cluster serves the host AND the devcontainer (Docker-outside-of-Docker:
# kind runs on the host daemon, reachable from both). The e2e suite (a separate
# increment) is expected to reuse the same cluster/registry names.
CLUSTER_NAME="${KUBAUTH_CLUSTER_NAME:-kubauth}"
REGISTRY_NAME="${KUBAUTH_REGISTRY_NAME:-kubauth-registry}"
REGISTRY_PORT="${KUBAUTH_REGISTRY_PORT:-5001}"
REGISTRY_IMAGE="${KUBAUTH_REGISTRY_IMAGE:-registry:2.8.3}"
# Kind node image. v1.31.4 is the arm64 / Mac-M-series-stable image kubauth
# settled on (v1.34 was flaky during early Kind 0.31 testing). Revisit once a
# newer node image proves stable on Apple Silicon.
KIND_NODE_IMAGE="${KUBAUTH_KIND_NODE_IMAGE:-kindest/node:v1.31.4}"
# Cluster prerequisites (installed into the cluster, not CLI tools).
CERT_MANAGER_VERSION="${KUBAUTH_CERT_MANAGER_VERSION:-v1.16.2}"

# ── Logging helpers ──────────────────────────────────────────────────────────
# Output goes to stderr so a script's stdout stays reserved for its real product
# (e.g. a value captured via command substitution).
log()  { printf '\033[0;36m[kubauth-dev]\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[0;32m[kubauth-dev] \xE2\x9C\x94\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[0;33m[kubauth-dev] \xE2\x9A\xA0\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[0;31m[kubauth-dev] \xE2\x9C\x98\033[0m %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

# require_bin <name>: fail with a clear message if <name> is not on PATH.
require_bin() {
    command -v "$1" >/dev/null 2>&1 || die "required tool '$1' is not installed in PATH"
}
