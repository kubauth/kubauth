# shellcheck shell=bash
# shellcheck disable=SC2034  # vars are consumed by scripts that source this file
#
# Shared environment — sourced by every test script.
#
# Single kind stack: this file DEFERS to the repo's hack/lib.sh for everything
# that defines the local dev cluster (cluster name, registry name/port/image,
# kind node image, cert-manager version) plus the require_bin / die helpers.
# The conformance harness, the dev cluster, and the devcontainer therefore all
# share ONE cluster/registry. Do NOT reintroduce a second "kubauth-e2e" stack.
#
# What stays here = test-suite-specific only: namespaces, fixture/tmp paths, the
# pinned OIDC conformance suite version, and a per-script log prefix override.
#
# Usage:
#   # shellcheck source=lib/env.sh
#   source "$(dirname "$0")/lib/env.sh"

# Resolve the tests/ root regardless of where the caller runs from.
KUBAUTH_TESTS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly KUBAUTH_TESTS_ROOT

# ── Defer to the single source of truth: hack/lib.sh ─────────────────────────
# hack/ sits at the repo root (tests/ is a subdir of the kubauth repo). lib.sh
# provides: CLUSTER_NAME (kubauth), REGISTRY_NAME (kubauth-registry),
# REGISTRY_PORT (5001), REGISTRY_IMAGE, KIND_NODE_IMAGE, CERT_MANAGER_VERSION,
# REPO_ROOT, tool_version, require_bin, die, and base log/ok/warn/err helpers.
# It also auto-loads per-developer overrides from dev.env. We re-derive its
# path from KUBAUTH_TESTS_ROOT so it resolves no matter the caller's cwd.
# shellcheck source=../../../hack/lib.sh
source "${KUBAUTH_TESTS_ROOT}/../hack/lib.sh"

# ── Namespaces (test-suite specific) ─────────────────────────────────────────
readonly NS_KUBAUTH="kubauth-system"
readonly NS_UPSTREAMS="kubauth-upstreams"
readonly NS_USERS="kubauth-users"
readonly NS_CERT_MANAGER="cert-manager"

# ── Kubauth versions to install ──────────────────────────────────────────────
# Kept in one place so a bump is a single line.
readonly KUBAUTH_BRANCH="v0.3.0-upstream"
readonly KC_BRANCH="v0.2.1"
readonly KUBAUTH_APISERVER_BRANCH="main"
readonly KUBAUTH_KUBECONFIG_BRANCH="main"

# ── OIDC Conformance Suite version (single source of truth) ──────────────────
# Injected into fixtures/conformance/02-server.yaml + 03-nginx.yaml at apply
# time (see Makefile `conformance-up`), so the tag lives in exactly one place.
# Bumping it can change which modules pass -> re-baseline the expected/ allowlist.
# EXPORTED (readonly -x): envsubst runs as a child process and only substitutes
# variables present in its environment, so a plain `readonly` would render an
# empty tag. Keep the -x.
declare -rx CONFORMANCE_SUITE_VERSION="release-v5.1.43"

# ── Paths ────────────────────────────────────────────────────────────────────
# In-tree layout: this suite lives at kubauth/tests/. KUBAUTH_REPO is the parent
# (the kubauth repo root, == hack/lib.sh's REPO_ROOT). Chart at $KUBAUTH_REPO/helm/kubauth.
readonly KUBAUTH_REPO="${KUBAUTH_TESTS_ROOT}/.."
readonly FIXTURES_DIR="${KUBAUTH_TESTS_ROOT}/fixtures"
readonly TMP_DIR="${KUBAUTH_TESTS_ROOT}/.tmp"

# ── Logging helpers (per-script-prefix override) ─────────────────────────────
# hack/lib.sh already defines log/ok/warn/err/die (fixed "[kubauth-dev]" prefix,
# all on stderr). We override the four progress helpers here to prefix each line
# with the *calling script's* name, which keeps the conformance harness's
# multi-script output readable (kind-up -> prereqs -> image -> install -> run).
# Like hack/lib.sh, output stays on stderr so a script's stdout remains reserved
# for its real product (e.g. conformance-run.sh's captured per-module summary).
# die() is inherited from hack/lib.sh (it calls err, so it picks up this prefix).
__log_prefix() { basename "${BASH_SOURCE[2]:-${BASH_SOURCE[1]}}" .sh; }
log()  { printf '\033[0;36m[%s]\033[0m %s\n' "$(__log_prefix)" "$*" >&2; }
ok()   { printf '\033[0;32m[%s] ✔\033[0m %s\n' "$(__log_prefix)" "$*" >&2; }
warn() { printf '\033[0;33m[%s] ⚠\033[0m %s\n' "$(__log_prefix)" "$*" >&2; }
err()  { printf '\033[0;31m[%s] ✘\033[0m %s\n' "$(__log_prefix)" "$*" >&2; }
