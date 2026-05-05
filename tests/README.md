# Kubauth E2E Testing

End-to-end + OIDC conformance tests for the **kubauth** OIDC server. This
suite lives in-tree at `tests/` so every PR that touches `cmd/`, `api/`,
`helm/` or `tests/` is gated by it.

[![e2e](https://github.com/kubauth/kubauth/actions/workflows/e2e.yml/badge.svg)](https://github.com/kubauth/kubauth/actions/workflows/e2e.yml)
[![e2e-lint](https://github.com/kubauth/kubauth/actions/workflows/e2e-lint.yml/badge.svg)](https://github.com/kubauth/kubauth/actions/workflows/e2e-lint.yml)

## What's inside

| Layer | Tool | Where |
|---|---|---|
| End-to-end | [Chainsaw](https://kyverno.github.io/chainsaw/) | `e2e/` |
| OIDC conformance | [OpenID Conformance Suite](https://gitlab.com/openid/conformance-suite) | `conformance/` |
| Regression | Chainsaw | `regression/` (one dir per fixed bug) |

Unit tests live **alongside the Go packages** at the kubauth root (`*_test.go`),
not here.

## Quick start (devcontainer-first)

```sh
gh repo clone kubauth/kubauth
code kubauth                     # → "Reopen in Container"

# inside the container:
make dev-up                      # Kind + cert-manager + kubauth (helm install)
make e2e-smoke                   # smoke test (~30 s)
```

`make help` (at the repo root) lists every test-related target under the
`E2E Testing` block; they all proxy into `tests/Makefile`.

→ Full setup, contributing rules, branch workflow: [CONTRIBUTING.md](CONTRIBUTING.md).
→ Coverage map and backlog of pending tests: [COVERAGE.md](COVERAGE.md).

## Layout

```text
kubauth/                        ← repo root (Go source, helm chart, Dockerfile)
├── .devcontainer/                VS Code devcontainer (Go + e2e tooling)
├── .github/workflows/
│   ├── e2e.yml                     CI: kind + chainsaw (~9-12 min)
│   └── e2e-lint.yml                CI: pre-commit on tests/
├── mise.toml                     pinned tool versions (root, walks up from tests/)
├── .pre-commit-config.yaml       repo-wide hooks
├── helm/kubauth/                 the chart under test
└── tests/                        ← this folder
    ├── Makefile                  entry point — every target self-documents (`make help`)
    ├── chainsaw.yaml             Chainsaw global config
    ├── scripts/                  one script = one verb, idempotent, set -euo pipefail
    │   ├── lib/env.sh                single source of truth (names, ports, paths)
    │   ├── kind-up.sh                Kind + local OCI registry
    │   ├── kind-down.sh              clean teardown
    │   ├── install-prereqs.sh        cert-manager
    │   └── kubauth-install.sh        ClusterIssuer + JWT key + helm install kubauth
    ├── fixtures/                 YAML manifests applied during dev-up
    │   ├── cluster-issuer.yaml         CA-based ClusterIssuer (selfSigned bootstrap → CA cert with commonName → ca-typed issuer the chart uses)
    │   ├── kubauth-values.yaml         helm values for the test cluster
    │   ├── users/                       User CRs (alice, …)
    │   ├── groups/                      Group + GroupBinding CRs
    │   ├── oidcclients/                 OidcClient CRs (smoke client, …)
    │   ├── ldap/                        OpenLDAP test server
    │   └── mock-oidc/                   navikt/mock-oauth2-server (for UpstreamProvider tests)
    ├── e2e/                      one dir per scenario (NN-kebab-intent)
    ├── regression/               one dir per fixed bug
    └── conformance/              OpenID Conformance Suite (in-cluster deploy + REST runner)
        ├── config/                 plan configs (oidcc-config, oidcc-basic, oidcc-rp-initiated-logout)
        └── results/                JSON reports per plan (committed)
```

## Versions pinned

| Tool | Version | Source |
|---|---|---|
| kubectl | 1.34.0 | `mise.toml` |
| kind | 0.31.0 | `mise.toml` |
| helm | 3.20.2 | `mise.toml` |
| chainsaw | 0.2.14 | `mise.toml` |
| shellcheck | 0.11.0 | `mise.toml` |
| yamllint | 1.36.1 | `mise.toml` |

Bump in PRs only — diff visible.

## Design rules

These are not optional. Every contribution respects them.

1. **Each script does one thing.** No god-scripts.
2. **Idempotent.** Running `kind-up.sh` twice is safe.
3. **`set -euo pipefail`** at the top of every bash script. shellcheck strict.
4. **No magic strings.** Cluster name, registry name, namespaces — all in `scripts/lib/env.sh`.
5. **No hidden state.** If a step needs a file or running container, it checks for it.
6. **Errors are loud.** Non-zero exit, one-line reason. Never swallow.
7. **Targets in the Makefile are short.** Heavy lifting goes in scripts.
8. **Test names are intent-driven.** `01-smoke-login`, not `01-test`.
9. **Conventional commits enforced** by `pre-commit` (`commit-msg` hook).
10. **Devcontainer-first.** If it doesn't work in the devcontainer, the design is wrong.
