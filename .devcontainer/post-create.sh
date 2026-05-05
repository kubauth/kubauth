#!/usr/bin/env bash
#
# Run once when the devcontainer is first built.
# Idempotent: safe to re-run after a rebuild without --no-cache.

set -euo pipefail

cd /workspaces/kubauth

mise trust mise.toml
mise install
mise list

mise exec -- pre-commit install --install-hooks

echo
echo "Devcontainer ready. Try:"
echo "  make help"
echo "  make dev-up         # boot Kind + cert-manager + kubauth"
echo "  make e2e-smoke      # run the smoke test"
