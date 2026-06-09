# .devcontainer/Dockerfile
FROM mcr.microsoft.com/devcontainers/go:dev-1.26-bookworm

# Freeze the Go toolchain for determinism: the floating dev-1.26 base provides
# the latest 1.26 patch, and GOTOOLCHAIN=local forbids a silent auto-upgrade
# beyond what go.mod's `go 1.26.2` directive asks for.
ENV GOTOOLCHAIN=local

# System packages needed by the dev scripts (hack/) and the kubauth toolchain.
# shellcheck is for the editor extension + manual use; the pre-commit gate uses
# its own pinned copy.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    make \
    ca-certificates \
    jq \
    openssl \
    shellcheck \
    python3 \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Note: '--mount=type=bind' mounts .tool-versions ephemerally so version pins
# don't bloat image layers or leave residual files. Architecture is detected
# dynamically via 'dpkg --print-architecture' (standard on this Debian base).

# 1. Install kubectl and verify its official SHA256 checksum
RUN --mount=type=bind,source=.tool-versions,target=/tmp/.tool-versions \
    KUBECTL_VERSION=$(awk '/^kubectl/ {print $2}' /tmp/.tool-versions) \
    && ARCH=$(dpkg --print-architecture) \
    && curl -fsSL -o /usr/local/bin/kubectl "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/${ARCH}/kubectl" \
    && curl -fsSL "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/${ARCH}/kubectl.sha256" -o /tmp/kubectl.sha256 \
    && echo "$(cat /tmp/kubectl.sha256)  /usr/local/bin/kubectl" | sha256sum -c - \
    && chmod +x /usr/local/bin/kubectl \
    && rm -f /tmp/kubectl.sha256

# 2. Install Helm and verify its official SHA256 checksum
RUN --mount=type=bind,source=.tool-versions,target=/tmp/.tool-versions \
    HELM_VERSION=$(awk '/^helm/ {print $2}' /tmp/.tool-versions) \
    && ARCH=$(dpkg --print-architecture) \
    && cd /tmp \
    && curl -fsSL -O "https://get.helm.sh/helm-v${HELM_VERSION}-linux-${ARCH}.tar.gz" \
    && curl -fsSL -O "https://get.helm.sh/helm-v${HELM_VERSION}-linux-${ARCH}.tar.gz.sha256sum" \
    && sha256sum -c "helm-v${HELM_VERSION}-linux-${ARCH}.tar.gz.sha256sum" \
    && tar -xzf "helm-v${HELM_VERSION}-linux-${ARCH}.tar.gz" \
    && mv "linux-${ARCH}/helm" /usr/local/bin/helm \
    && chmod +x /usr/local/bin/helm \
    && rm -rf "helm-v${HELM_VERSION}-linux-${ARCH}.tar.gz" "helm-v${HELM_VERSION}-linux-${ARCH}.tar.gz.sha256sum" "linux-${ARCH}"

# 3. Install Kind and verify its official SHA256 checksum
RUN --mount=type=bind,source=.tool-versions,target=/tmp/.tool-versions \
    KIND_VERSION=$(awk '/^kind/ {print $2}' /tmp/.tool-versions) \
    && ARCH=$(dpkg --print-architecture) \
    && cd /tmp \
    && curl -fsSL -O "https://github.com/kubernetes-sigs/kind/releases/download/v${KIND_VERSION}/kind-linux-${ARCH}" \
    && curl -fsSL -O "https://github.com/kubernetes-sigs/kind/releases/download/v${KIND_VERSION}/kind-linux-${ARCH}.sha256sum" \
    && sha256sum -c "kind-linux-${ARCH}.sha256sum" \
    && mv "kind-linux-${ARCH}" /usr/local/bin/kind \
    && chmod +x /usr/local/bin/kind \
    && rm -f "kind-linux-${ARCH}.sha256sum"

# 4. Install k9s and verify its official SHA256 checksum
# checksums.sha256 covers all platforms; we extract the matching line (same
# pattern as a multi-platform checksums file).
RUN --mount=type=bind,source=.tool-versions,target=/tmp/.tool-versions \
    K9S_VERSION=$(awk '/^k9s/ {print $2}' /tmp/.tool-versions) \
    && ARCH=$(dpkg --print-architecture) \
    && cd /tmp \
    && curl -fsSL -O "https://github.com/derailed/k9s/releases/download/v${K9S_VERSION}/k9s_Linux_${ARCH}.tar.gz" \
    && curl -fsSL -O "https://github.com/derailed/k9s/releases/download/v${K9S_VERSION}/checksums.sha256" \
    && EXPECTED_SHA=$(grep "  k9s_Linux_${ARCH}.tar.gz$" checksums.sha256) \
    && [ -n "$EXPECTED_SHA" ] \
    && echo "$EXPECTED_SHA" | sha256sum -c - \
    && tar -xzf "k9s_Linux_${ARCH}.tar.gz" k9s \
    && mv k9s /usr/local/bin/k9s \
    && chmod +x /usr/local/bin/k9s \
    && rm -rf "k9s_Linux_${ARCH}.tar.gz" checksums.sha256

# 5. Install kustomize and verify its official SHA256 checksum
# Release tags are URL-encoded as 'kustomize%2FvX.Y.Z'; checksums.txt covers all
# platforms, so we extract the matching line.
RUN --mount=type=bind,source=.tool-versions,target=/tmp/.tool-versions \
    KUSTOMIZE_VERSION=$(awk '/^kustomize/ {print $2}' /tmp/.tool-versions) \
    && ARCH=$(dpkg --print-architecture) \
    && cd /tmp \
    && curl -fsSL -O "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv${KUSTOMIZE_VERSION}/kustomize_v${KUSTOMIZE_VERSION}_linux_${ARCH}.tar.gz" \
    && curl -fsSL -O "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv${KUSTOMIZE_VERSION}/checksums.txt" \
    && EXPECTED_SHA=$(grep "  kustomize_v${KUSTOMIZE_VERSION}_linux_${ARCH}.tar.gz$" checksums.txt) \
    && [ -n "$EXPECTED_SHA" ] \
    && echo "$EXPECTED_SHA" | sha256sum -c - \
    && tar -xzf "kustomize_v${KUSTOMIZE_VERSION}_linux_${ARCH}.tar.gz" \
    && mv kustomize /usr/local/bin/kustomize \
    && chmod +x /usr/local/bin/kustomize \
    && rm -rf "kustomize_v${KUSTOMIZE_VERSION}_linux_${ARCH}.tar.gz" checksums.txt

# 6. Install pre-commit in an isolated virtualenv (avoids PEP 668 conflicts).
# Hook tools (shellcheck, yamllint, markdownlint, gitleaks) are fetched and
# pinned by pre-commit itself from .pre-commit-config.yaml on first run.
RUN --mount=type=bind,source=.tool-versions,target=/tmp/.tool-versions \
    PRECOMMIT_VERSION=$(awk '/^pre-commit/ {print $2}' /tmp/.tool-versions) \
    && python3 -m venv /opt/precommit \
    && /opt/precommit/bin/pip install --no-cache-dir "pre-commit==${PRECOMMIT_VERSION}" \
    && ln -sf /opt/precommit/bin/pre-commit /usr/local/bin/pre-commit \
    && pre-commit --version

# kustomize and controller-gen are NOT baked here: the Makefile installs them on
# demand (go-install-tool, pinned in the Makefile) into ./bin. Go comes from the
# base image. Run as root — see the rationale in devcontainer.json (kind#3196).
