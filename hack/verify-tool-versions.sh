#!/usr/bin/env bash
# Verify the Go MAJOR.MINOR version is consistent across the three places it is
# pinned: .tool-versions, go.mod's `go` directive, and the devcontainer
# Dockerfile base image. Keep them in lock-step. Run via 'make verify-tool-versions'.
set -euo pipefail

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# Silently succeed if .tool-versions is absent (nothing to verify).
[ -f "${TOOL_VERSIONS_FILE}" ] || exit 0

minor() { awk -F. '{ print $1"."$2 }'; }

tool_go_full="$(tool_version golang)"
tool_go_minor="$(printf '%s' "$tool_go_full" | minor)"
go_mod_minor="$(grep -E '^go [0-9]+\.[0-9]+' "${REPO_ROOT}/go.mod" | awk '{print $2}' | minor)"

fail=0

if [ "$tool_go_minor" != "$go_mod_minor" ]; then
    echo "ERROR: Go MAJOR.MINOR mismatch: .tool-versions=$tool_go_minor vs go.mod=$go_mod_minor" >&2
    fail=1
fi

# Devcontainer base image, e.g. 'FROM …/devcontainers/go:dev-1.26-bookworm'.
dockerfile="${REPO_ROOT}/.devcontainer/Dockerfile"
if [ -f "$dockerfile" ]; then
    df_go_minor="$(grep -oE 'devcontainers/go:[^[:space:]]*' "$dockerfile" | grep -oE '[0-9]+\.[0-9]+' | head -n1)"
    if [ -n "$df_go_minor" ] && [ "$df_go_minor" != "$tool_go_minor" ]; then
        echo "ERROR: Go MAJOR.MINOR mismatch: Dockerfile base=$df_go_minor vs .tool-versions=$tool_go_minor" >&2
        fail=1
    fi
fi

[ "$fail" -eq 0 ] || exit 1
echo "Go version consistent (${tool_go_minor}): .tool-versions=$tool_go_full, go.mod & Dockerfile aligned"
