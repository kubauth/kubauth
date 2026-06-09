# Kubauth Local Dev Environment (Devcontainer)

Pre-configured with the system packages, Go toolchain, and Kubernetes utilities
needed to develop kubauth and bring up a local cluster.

## Architecture Overview

The environment uses a **Docker-outside-of-Docker (DooD)** setup:

1. **Dev Container**: your tools and terminal run inside a Debian-based
   container, as **root** (see _Why root?_ below).
2. **Host Docker Daemon**: the container talks to the host's Docker daemon via a
   mounted socket — it does **not** run its own daemon.
3. **Local OCI Registry**: a containerized registry (`kubauth-registry`,
   `registry:2.8.3`) runs as a **sibling container on the host daemon**. Its
   port is published on the host at `127.0.0.1:5001` (default; configurable via
   `dev.env`). Kind nodes pull from it over the shared `kind` network.
4. **Local Kind Cluster**: a Kubernetes cluster named `kubauth` is created with
   Kind. It runs directly on the host daemon, so **one cluster is reachable from
   both the host and the devcontainer at the same time** — the main reason DooD
   is preferred here over Docker-in-Docker.

### Why root?

Kind's control plane fails to come up in a **non-root** devcontainer over
Docker-outside-of-Docker — the kubelet cannot set up the QOS cgroup hierarchy.
Running as root is the documented workaround. See
[kind#3196](https://github.com/kubernetes-sigs/kind/issues/3196). Because the
container is root and the Go cache volumes mount root-owned, no `chown` step is
needed.

## Mounted Caches

Persistent named Docker volumes cache Go modules and build output across
container rebuilds:

- `kubauth-gomodcache` → `/home/vscode/go/pkg/mod`
- `kubauth-gobuildcache` → `/home/vscode/.cache/go-build`

## Tooling

Versions are pinned in [`.tool-versions`](../.tool-versions) (the single source
of truth for the baked tools). `kubectl`, `helm`, `kind`, and `k9s` are downloaded and
verified against their official **SHA256 checksums** at image build time; Go
comes from the base image (`go:dev-1.26-bookworm`, patch floats, frozen at
runtime by `GOTOOLCHAIN=local`); `pre-commit` is a version-pinned pip install in
an isolated venv.

Where the other versions live:

- **kustomize / controller-gen** — pinned in the [`Makefile`](../Makefile)
  (`go-install-tool`, installed on demand into `./bin`).
- **shellcheck / yamllint / markdownlint / gitleaks** — pinned by
  [`.pre-commit-config.yaml`](../.pre-commit-config.yaml); pre-commit fetches and
  caches them itself (the `shellcheck` apt package is only an editor convenience).
- **chainsaw + e2e tooling** — added with the e2e suite (a separate increment).

> Note: this repo intentionally does **not** use `mise`/`asdf` to install tools
> at runtime. The devcontainer bakes them into the image (reproducible,
> checksum-verified, offline-capable) — fitting for a security/OIDC product.

## Reachability (host vs devcontainer)

The Kind apiserver and the registry are reachable from inside the devcontainer
via **`host.docker.internal`** (Docker Desktop natively; a `host-gateway` alias
on Linux via `runArgs`). The kubeconfig is patched to use it at `make dev-up`
time. From the **host shell**, use `localhost` instead — `localhost:5001` for the
registry, and the kubeconfig context `kind-kubauth` for the cluster.

## Quality gate (pre-commit)

A `pre-commit` hook is wired automatically (via `postCreateCommand`). It runs
whitespace/EOL fixers, **shellcheck**, **yamllint**, **markdownlint**,
**gitleaks** (secret scanning — important for an OIDC server), and enforces
**Conventional Commits** on the commit message.

## Quick Start (in your editor)

1. Open this repository in any Dev Containers-capable editor and let it
   reopen/start in the container.
2. Open a terminal inside the container and run `make dev-up` — brings up the
   registry, the Kind cluster, cert-manager, and the kubauth CRDs (idempotent).
3. Tear down with `make dev-down`.

> `make dev-up` provisions a cluster ready for **developing** kubauth (cluster +
> cert-manager + CRDs). Deploying the full kubauth application (helm chart +
> fixtures) and the chainsaw/conformance suites is the job of the e2e increment.

## Running it without an IDE (Dev Containers CLI)

```bash
# install the CLI once (Node.js must be available on your host)
npm install -g @devcontainers/cli

# build + start the container from the repo root
devcontainer up --workspace-folder .

# run anything inside it
devcontainer exec --workspace-folder . make dev-up
devcontainer exec --workspace-folder . make test
```

> Give Docker enough RAM/CPU — the local stack (Kind + cert-manager + registry)
> needs headroom to come up.

## Customizing your environment (`dev.env`)

Per-developer overrides live in a git-ignored `dev.env` at the repo root. Copy
the template and edit it:

```bash
cp dev.env.example dev.env
```

`dev.env` is sourced by the `hack/` scripts, by the Makefile, and by the
container shell — so it applies identically **on the host and inside the
devcontainer**. With no `dev.env`, the documented defaults are used.

Available settings include `KUBAUTH_REGISTRY_PORT` (default `5001`; change it if
it collides with another product's dev registry — KuboCD also defaults to 5001).
After changing the port, run `make dev-down` before `make dev-up`.

## Troubleshooting

- **Docker socket permissions**: if `docker` commands fail with "permission
  denied" inside the container, make sure the host Docker daemon is running and
  your user can access `/var/run/docker.sock`.
- **Registry port conflict**: `make dev-up` runs a pre-flight check that fails
  fast — naming the port — if the registry's host port (`5001` by default) is
  already taken. Set a different `KUBAUTH_REGISTRY_PORT` in `dev.env`, then
  re-run. If the holder is a leftover kubauth registry, run `make dev-down`
  first.
