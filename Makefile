#    Copyright (c) Kubotal 2025.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.


# Image and chart registry — Must be set via dev.env or from environment.
# Intentionally empty in this makefile, as we want user to set REGISTRY
# explicitly. Targets that need it depend on `check-registry`, which fails with
# a clear message when it is unset.
REGISTRY ?=

# The official publishing registry. NEVER a default here: it is only used by
# check-registry as a guard, which refuses to target it outside CI (GitHub
# Actions sets CI=true) unless FORCE_OFFICIAL=1 is passed explicitly. This
# protects published artifacts from an accidental local `make docker-push`.
OFFICIAL_REGISTRY := quay.io/kubauth

# Per-developer local dev-env overrides (git-ignored): REGISTRY, cluster/registry
# names, KUBAUTH_REGISTRY_PORT… An absent file is a no-op. The hack/ scripts
# source the same file on the shell side (hack/lib.sh), so dev.env applies
# identically either way.
-include dev.env

# Product versions — code-bound. Declared with ':=' AFTER the include so a
# dev.env value can't silently change what you build/publish; the CLI/CI still
# can (command-line assignments beat makefile ':='), e.g.
#   make docker APP_VERSION=v0.3.1
# But, doing this break the GIT <-> <effectiveCode> link
APP_VERSION := 0.3.0-snapshot
HELM_KUBAUTH_VERSION := 0.3.0-snapshot
HELM_KUBAUTH_USERS_VERSION := 0.3.0-snapshot
HELM_KUBAUTH_UPSTREAM_PROVIDERS_VERSION := 0.3.0-snapshot

IMG_REPO := $(REGISTRY)/exec/kubauth

HELM_DOCKER_REPO := $(REGISTRY)/charts

# Local dev cluster + registry names (kept in sync with the defaults in
# hack/lib.sh). Override in dev.env if they collide with another stack.
KUBAUTH_CLUSTER_NAME ?= kubauth
KUBAUTH_REGISTRY_NAME ?= kubauth-registry

# To authenticate for pushing in quay repo (img) (Use encrypted password):
# docker login quay.io

# To authenticate for pushing in quay repo (helm):
# helm registry login quay.io

# To authenticate for pushing in github repo:
# echo $GITHUB_TOKEN | docker login ghcr.io -u $USER_NAME --password-stdin


BUILD_TS ?= $(shell date -u +%Y%m%d.%H%M%S)

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
#SHELL = /usr/bin/env bash -o pipefail
#.SHELLFLAGS = -ec

#.PHONY: all
#all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: check-registry
check-registry: ## Fail if REGISTRY is unset, or if it targets the official registry outside CI
	@if [ -z "$(strip $(REGISTRY))" ]; then \
		echo "ERROR: REGISTRY is not set."; \
		echo "Set it in dev.env, export it in your environment, or pass it on the command line, e.g.:"; \
		echo "    make $(or $(MAKECMDGOALS),<target>) REGISTRY=quay.io/my-organization"; \
		exit 1; \
	fi
	@if [ "$(strip $(REGISTRY))" = "$(OFFICIAL_REGISTRY)" ] && [ -z "$$CI" ] && [ "$(FORCE_OFFICIAL)" != "1" ]; then \
		echo "ERROR: refusing to target the official registry ($(OFFICIAL_REGISTRY)) outside CI."; \
		echo "This guard protects published artifacts from an accidental local push."; \
		echo "Use your own registry in dev.env. If you really mean it:"; \
		echo "    make $(or $(MAKECMDGOALS),<target>) FORCE_OFFICIAL=1"; \
		exit 1; \
	fi

.PHONY: display
display:  ## Display current config values
	@echo "---------"
	@echo "REGISTRY: $(REGISTRY)"
	@echo "APP_VERSION: $(APP_VERSION)"
	@echo "HELM_KUBAUTH_VERSION: $(HELM_KUBAUTH_VERSION)"
	@echo "BUILD_TS: $(BUILD_TS)"
	@echo "---------"

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="boilerplate.go.txt" paths="./..."

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) apply -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

##@ Local Development Environment

.PHONY: dev-up
dev-up: ## Bring up local Kind cluster + registry + cert-manager + kubauth CRDs (idempotent)
	@bash ./hack/kind-with-registry.sh

.PHONY: dev-down
dev-down: ## Tear down the local Kind cluster and OCI registry
	@kind delete cluster --name $(KUBAUTH_CLUSTER_NAME) || true
	@docker rm -f -v $(KUBAUTH_REGISTRY_NAME) || true

.PHONY: check-tools
check-tools: ## Check locally-installed tools match .tool-versions
	@bash ./hack/check-tools.sh

.PHONY: verify-tool-versions
verify-tool-versions: ## Verify .tool-versions and go.mod agree on the Go version
	@bash ./hack/verify-tool-versions.sh


##@ Build

.PHONY: build
build:  build-kubauth  ## Build kubauth binaries with dependencies

.PHONY: build-kubauth
build-kubauth: generate ## Build kubauth binary.
	CGO_ENABLED=0 go build -ldflags '-X kubauth/internal/global.Version=$(APP_VERSION) -X kubauth/internal/global.BuildTs=$(BUILD_TS)' -o bin/kubauth main.go

.PHONY: test
test: ## Run the Go unit tests
	CGO_ENABLED=0 go test ./...

##@ Docker

.PHONY: docker
docker: display docker-build docker-push  ## Build controller docker image and push

.PHONY: docker-build
docker-build: check-registry generate ## Build docker image with the manager.
	$(CONTAINER_TOOL) build --build-arg VERSION=$(APP_VERSION) --build-arg BUILD_TS=$(BUILD_TS) -t $(IMG_REPO):$(APP_VERSION)  .

.PHONY: docker-push
docker-push: check-registry ## Push docker image with the manager.
	$(CONTAINER_TOOL) push $(IMG_REPO):$(APP_VERSION)


.PHONY: docker-ubuntu
docker-ubuntu: display docker-ubuntu-build docker-ubuntu-push  ## Build controller docker image using Ubuntu 22.04  and push

.PHONY: docker-ubuntu-build
docker-ubuntu-build: check-registry generate ## Build docker image using Ubuntu 22.04 as base
	$(CONTAINER_TOOL) build --build-arg RUNTIME_BASE=ubuntu:22.04 --build-arg VERSION=$(APP_VERSION) --build-arg BUILD_TS=$(BUILD_TS) -t $(IMG_REPO):$(APP_VERSION)-ubuntu  .

.PHONY: docker-ubuntu-push
docker-ubuntu-push: check-registry ## Push docker image using Ubuntu 22.04  with the manager.
	$(CONTAINER_TOOL) push $(IMG_REPO):$(APP_VERSION)-ubuntu



# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - have enabled BuildKit. More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image to your registry
# To adequately provide solutions that are compatible with multiple platforms, you should consider using this option.
#PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
PLATFORMS ?= linux/arm64,linux/amd64
.PHONY: docker-buildx
docker-buildx:  check-registry display ## Build and push docker image for the manager for cross-platform support
	- $(CONTAINER_TOOL) buildx create --name kubauth-builder --driver=docker-container
	$(CONTAINER_TOOL) buildx build --builder kubauth-builder --push --platform=$(PLATFORMS) --build-arg VERSION=$(APP_VERSION) --build-arg BUILD_TS=$(BUILD_TS) --tag $(IMG_REPO):$(APP_VERSION) -f Dockerfile .
	- $(CONTAINER_TOOL) buildx rm kubauth-builder


##@ Helm

.PHONY: crds
crds: manifests kustomize ## Generate crds file into helm chart
	$(KUSTOMIZE) build config/crd -o helm/kubauth/crds/crds.yaml

# ----------------------
.PHONY: charts
charts: chart-kubauth chart-kubauth-users chart-kubauth-upstream-providers	## Build all charts
# ----------------------

define CHART_KUBAUTH_YAML
# File generated by Makefile
apiVersion: v2
name: kubauth
version: $(HELM_KUBAUTH_VERSION)
appVersion: $(APP_VERSION)
description: "Kubauth, the Kubernetes authentication system"
keywords:
  - kubauth
  - authentication
  - oidc
  - ldap
  - kubectl
sources:
  - https://github.com/kubauth/kubauth
maintainers:
  - name: kubauth
    url: https://github.com/kubauth
endef
export CHART_KUBAUTH_YAML

# The generated Chart.yaml is registry-free on purpose: the default image
# repository lives in values.yaml (overridable at install time), so this
# target needs no REGISTRY and the committed Chart.yaml never drifts with a
# developer's dev.env.
.PHONY: chart-kubauth-yaml
chart-kubauth-yaml: ## Generate the helm/kubauth/Chart.yaml
	echo "$$CHART_KUBAUTH_YAML" >./helm/kubauth/Chart.yaml

.PHONY: chart-kubauth
chart-kubauth: check-registry chart-kubauth-yaml crds ## Build and push oidc server helm chart
	cd ./helm && helm package -d ./../tmp kubauth && helm push ./../tmp/kubauth-${HELM_KUBAUTH_VERSION}.tgz oci://${HELM_DOCKER_REPO}

# ----------------------

define CHART_KUBAUTH_USERS_YAML
# File generated by Makefile
apiVersion: v2
name: kubauth-users
version: $(HELM_KUBAUTH_USERS_VERSION)
appVersion: $(APP_VERSION)
description: "Kubauth, the Kubernetes authentication system. Users deployment"
keywords:
  - kubauth
  - authentication
  - oidc
  - ldap
  - kubectl
sources:
  - https://github.com/kubauth/kubauth
maintainers:
  - name: kubauth
    url: https://github.com/kubauth
endef
export CHART_KUBAUTH_USERS_YAML

.PHONY: chart-kubauth-users-yaml
chart-kubauth-users-yaml: ## Generate the helm/kubauth-users/Chart.yaml
	echo "$$CHART_KUBAUTH_USERS_YAML" >./helm/kubauth-users/Chart.yaml

.PHONY: chart-kubauth-users
chart-kubauth-users: check-registry chart-kubauth-users-yaml crds ## Build and push oidc users helm chart
	cd ./helm && helm package -d ./../tmp kubauth-users && helm push ./../tmp/kubauth-users-${HELM_KUBAUTH_USERS_VERSION}.tgz oci://${HELM_DOCKER_REPO}

# ----------------------

define CHART_KUBAUTH_UPSTREAM_PROVIDERS_YAML
# File generated by Makefile
apiVersion: v2
name: kubauth-upstream-providers
version: $(HELM_KUBAUTH_UPSTREAM_PROVIDERS_VERSION)
appVersion: $(APP_VERSION)
description: "Kubauth, the Kubernetes authentication system. Upstreams provider deployments"
keywords:
  - kubauth
  - authentication
  - oidc
  - ldap
  - kubectl
sources:
  - https://github.com/kubauth/kubauth
maintainers:
  - name: kubauth
    url: https://github.com/kubauth
endef
export CHART_KUBAUTH_UPSTREAM_PROVIDERS_YAML

.PHONY: chart-kubauth-upstream-providers-yaml
chart-kubauth-upstream-providers-yaml: ## Generate the helm/kubauth-upstream-providers/Chart.yaml
	echo "$$CHART_KUBAUTH_UPSTREAM_PROVIDERS_YAML" >./helm/kubauth-upstream-providers/Chart.yaml

.PHONY: chart-kubauth-upstream-providers
chart-kubauth-upstream-providers: check-registry chart-kubauth-upstream-providers-yaml crds ## Build and push oidc upstream providers helm chart
	cd ./helm && helm package -d ./../tmp kubauth-upstream-providers && helm push ./../tmp/kubauth-upstream-providers-${HELM_KUBAUTH_UPSTREAM_PROVIDERS_VERSION}.tgz oci://${HELM_DOCKER_REPO}


##@ Dependencies

## Tool Binaries
KUBECTL ?= kubectl
KIND ?= kind
# controller-gen runs via the go.mod 'tool' directive (no per-arch binary in
# ./bin that would break across host/devcontainer — a Mac-built binary can't run
# in the Linux container). kustomize is baked (checksum-verified) into the
# devcontainer and pinned in .tool-versions; on a native host, install it
# yourself (versions live in .tool-versions / go.mod, not here).
KUSTOMIZE ?= kustomize
CONTROLLER_GEN ?= go tool controller-gen

# No-op targets so existing prerequisites (e.g. 'manifests: controller-gen',
# 'install: ... kustomize') still resolve now that both tools come from
# 'go tool' / PATH rather than a download into ./bin.
.PHONY: controller-gen kustomize
controller-gen kustomize:
