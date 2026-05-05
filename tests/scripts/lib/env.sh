# shellcheck shell=bash
# shellcheck disable=SC2034  # vars are consumed by scripts that source this file
#
# Shared environment — sourced by every script.
# Single source of truth for names, ports, paths, versions.
#
# Usage:
#   # shellcheck source=lib/env.sh
#   source "$(dirname "$0")/lib/env.sh"
#
# All variables read-only after sourcing.

# Resolve repo root regardless of where the script is called from.
KUBAUTH_TESTS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly KUBAUTH_TESTS_ROOT

# ── Cluster ────────────────────────────────────────────────────────────────
readonly CLUSTER_NAME="kubauth-e2e"
# Use a battle-tested arm64-compatible node image. v1.34 was unstable on Mac M-series
# during early Kind 0.31 testing — bump only after smoke runs green for a week.
# Skew with kubectl 1.34 (mise.toml) is supported (kubectl ±1 minor).
readonly KIND_NODE_IMAGE="kindest/node:v1.31.4"

# ── Local OCI registry ─────────────────────────────────────────────────────
readonly REGISTRY_NAME="kubauth-e2e-registry"
readonly REGISTRY_PORT=5001
readonly REGISTRY_HOST_NETWORK="kind"

# ── Namespaces ─────────────────────────────────────────────────────────────
readonly NS_KUBAUTH="kubauth-system"
readonly NS_UPSTREAMS="kubauth-upstreams"
readonly NS_USERS="kubauth-users"
readonly NS_FLUX="flux-system"
readonly NS_CERT_MANAGER="cert-manager"

# ── Kubauth versions to install ────────────────────────────────────────────
# Kept in one place so we can bump in a single line.
readonly KUBAUTH_BRANCH="v0.3.0-upstream"
readonly KC_BRANCH="v0.2.1"
readonly KUBAUTH_APISERVER_BRANCH="main"
readonly KUBAUTH_KUBECONFIG_BRANCH="main"

# ── Paths ──────────────────────────────────────────────────────────────────
# In-tree layout: this suite lives at kubauth/tests/. KUBAUTH_REPO is the
# parent (the kubauth repo root). The chart lives at $KUBAUTH_REPO/helm/kubauth.
readonly KUBAUTH_REPO="${KUBAUTH_TESTS_ROOT}/.."
readonly FIXTURES_DIR="${KUBAUTH_TESTS_ROOT}/fixtures"
readonly TMP_DIR="${KUBAUTH_TESTS_ROOT}/.tmp"

# ── External dependencies versions ─────────────────────────────────────────
readonly FLUX_VERSION="2.4.0"
readonly CERT_MANAGER_VERSION="v1.16.2"

# ── Logging helpers ────────────────────────────────────────────────────────
# Prefix every line with the script's name so multi-script logs stay readable.
__log_prefix() { basename "${BASH_SOURCE[2]:-${BASH_SOURCE[1]}}" .sh; }

# All log output goes to stderr so a script's stdout is reserved for
# its actual product (e.g. a result line that the caller captures via
# command substitution). Without this conformance-run.sh's per-module
# summary line gets mixed with progress logs.
log()  { printf '\033[0;36m[%s]\033[0m %s\n' "$(__log_prefix)" "$*" >&2; }
ok()   { printf '\033[0;32m[%s] ✔\033[0m %s\n' "$(__log_prefix)" "$*" >&2; }
warn() { printf '\033[0;33m[%s] ⚠\033[0m %s\n' "$(__log_prefix)" "$*" >&2; }
err()  { printf '\033[0;31m[%s] ✘\033[0m %s\n' "$(__log_prefix)" "$*" >&2; }

# Fail loudly with a one-line reason.
die() { err "$*"; exit 1; }

# Require a binary on PATH or die.
require_bin() {
  local bin="$1"
  command -v "$bin" >/dev/null 2>&1 || die "missing binary: $bin (install it and retry)"
}
