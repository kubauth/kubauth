#!/usr/bin/env bash
# Check locally installed dev tools against the versions pinned in .tool-versions.
# Reported only when something is off, with three levels:
#   - missing            -> ERROR   (script exits non-zero)
#   - installed < pinned -> WARNING (you may hit bugs already fixed upstream)
#   - installed > pinned -> NOTICE  (usually fine; the pin simply lags)
#   - exact match        -> silent
# No 'set -e': probing absent tools is expected.

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

if [ ! -f "${TOOL_VERSIONS_FILE}" ]; then
    echo "❌ ERROR: .tool-versions file not found!" >&2
    exit 1
fi

failed=0

semver() { grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1; }
minor()  { awk -F. '{ print $1"."$2 }'; }

# compare <a> <b> -> prints eq | lt | gt (semver-aware via sort -V).
compare() {
    [ "$1" = "$2" ] && { echo eq; return; }
    if [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ]; then echo lt; else echo gt; fi
}

# report <label> <pinned> <installed>
report() {
    local label="$1" pinned="$2" installed="$3"
    [ -z "$pinned" ] && return 0                       # not pinned -> nothing to check
    if [ -z "$installed" ]; then
        echo "❌ ERROR   ${label}: not installed (pinned ${pinned})" >&2
        failed=1
        return
    fi
    case "$(compare "$installed" "$pinned")" in
        lt) echo "⚠️  WARNING ${label}: ${installed} installed < ${pinned} pinned" >&2 ;;
        gt) echo "ℹ️  NOTICE  ${label}: ${installed} installed > ${pinned} pinned" >&2 ;;
        eq) : ;;                                        # exact match -> silent
    esac
}

# Go is special: compare MAJOR.MINOR only (the patch floats with the base image,
# frozen at runtime by GOTOOLCHAIN=local).
report go "$(tool_version golang | minor)" "$(go version 2>/dev/null | awk '{print $3}' | sed 's/go//' | minor)"

report kubectl    "$(tool_version kubectl)"    "$(kubectl version --client 2>/dev/null | semver)"
report helm       "$(tool_version helm)"       "$(helm version --template='{{.Version}}' 2>/dev/null | semver)"
report kind       "$(tool_version kind)"       "$(kind version 2>/dev/null | semver)"
report kustomize  "$(tool_version kustomize)"  "$(kustomize version 2>/dev/null | semver)"
report k9s        "$(tool_version k9s)"        "$(k9s version 2>/dev/null | semver)"
report pre-commit "$(tool_version pre-commit)" "$(pre-commit --version 2>/dev/null | semver)"

exit "$failed"
