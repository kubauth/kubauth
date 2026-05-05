#!/usr/bin/env bash
#
# Run on every container start.
#
# VS Code Dev Containers injects ~/.docker/config.json with a credsStore
# pointing at `dev-containers-<uuid>` — a credential helper binary meant
# to forward host docker auth into the container. The helper isn't
# actually installed inside this image, so the injection breaks every
# `docker pull` (even of public images: docker calls the helper before
# deciding it doesn't need auth, and the missing binary errors with
# "error getting credentials - err: exit status 255").
#
# With Docker-in-Docker the inner daemon doesn't share state with the
# host anyway, so the credential forwarding is moot — stripping the
# credsStore costs nothing.
#
# Idempotent: only rewrites if a `dev-containers-` credsStore is present.

set -euo pipefail

if [[ -f "$HOME/.docker/config.json" ]] \
   && grep -q 'dev-containers-' "$HOME/.docker/config.json" 2>/dev/null; then
  echo '{}' > "$HOME/.docker/config.json"
  echo "[post-start] stripped broken VS Code credsStore from ~/.docker/config.json"
fi
