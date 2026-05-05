# syntax=docker/dockerfile:1.7
#
# Devcontainer base image for kubauth-tests.
#
# Strategy: thin layer on top of the standard Microsoft devcontainer image
# (Debian + a non-root `vscode` user). Tools themselves come from `mise.toml`
# at post-create time — keeps this Dockerfile stable across version bumps.

FROM mcr.microsoft.com/devcontainers/base:debian-12

ARG USER=vscode

# ─── System packages we need before mise can run ───────────────────────────
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        gnupg \
        jq \
        make \
        openssl \
        pipx \
        python3 \
        unzip \
 && rm -rf /var/lib/apt/lists/*

# Make pipx-installed binaries available to all users (mise uses pipx to fetch
# Python tools like yamllint). Without PATH wiring, mise install fails for
# pipx-backed tools.
ENV PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/opt/pipx/bin \
    PATH=/opt/pipx/bin:$PATH
RUN install -d -m 0777 ${PIPX_HOME} ${PIPX_BIN_DIR}

# ─── Install mise system-wide so every shell sees it ───────────────────────
# Pin the mise version itself — bumps land in PRs, not silently.
ARG MISE_VERSION=2026.4.5
RUN curl -fsSL https://mise.run | MISE_VERSION="v${MISE_VERSION}" sh \
 && mv /root/.local/bin/mise /usr/local/bin/mise \
 && chmod +x /usr/local/bin/mise

# Activate mise for both bash and zsh. Done at image level so that subsequent
# layers (and the running container) have the right env without a manual step.
RUN echo 'eval "$(mise activate bash)"' >> /etc/bash.bashrc \
 && echo 'eval "$(mise activate zsh)"'  >> /etc/zsh/zshrc

# Pre-create the XDG dirs mise + many other tools expect under the user's HOME.
# Without this, the named volume that mounts at .local/share/mise can't be
# initialised (volume comes up as root-owned), and mise's state dir doesn't
# exist at all → 'mise trust' fails with EACCES.
RUN install -d -o ${USER} -g ${USER} \
        /home/${USER}/.local/bin \
        /home/${USER}/.local/share \
        /home/${USER}/.local/share/mise \
        /home/${USER}/.local/state \
        /home/${USER}/.local/state/mise \
        /home/${USER}/.cache

USER ${USER}
WORKDIR /workspaces
