# kubauth e2e suite — entry point.
#
# Conventions:
#   - one target = one verb. No "do everything" target.
#   - heavy lifting lives in scripts/, not here.
#   - every target self-documents via the `## comment` (see `make help`).

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

# ─── Paths ────────────────────────────────────────────────────────────────
SCRIPTS := scripts

# Chart path exported so the install script can locate the chart without
# hardcoding the layout. In-tree: tests/ is a subdirectory of kubauth, so the
# chart is at ../helm/kubauth.
export KUBAUTH_CHART ?= $(realpath ..)/helm/kubauth

# ─── Self-documenting help ────────────────────────────────────────────────
.PHONY: help
help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ─── Cluster lifecycle ────────────────────────────────────────────────────
.PHONY: kind-up
kind-up: ## Create the Kind cluster + local registry.
	@$(SCRIPTS)/kind-up.sh

.PHONY: kind-down
kind-down: ## Delete the Kind cluster + registry.
	@$(SCRIPTS)/kind-down.sh

.PHONY: prereqs
prereqs: ## Install cert-manager (no flux — kubauth does not depend on it).
	@$(SCRIPTS)/install-prereqs.sh

.PHONY: image
image: ## Build kubauth image from the working tree and load it into kind.
	@$(SCRIPTS)/kubauth-image.sh

.PHONY: install
install: ## Install kubauth into the cluster (uses chart defaults; honours KUBAUTH_IMAGE_* if set).
	@$(SCRIPTS)/kubauth-install.sh

# `dev-up` is the contract documented in CONTRIBUTING.md: bring the
# cluster up with kubauth built from your working tree (not the
# published quay.io image). Mirrors what .github/workflows/e2e.yml does.
#
# Make exports these to recipe shells when set; the values are only
# assigned during dev-up's chain (target-specific variables, below),
# so `make install` invoked directly keeps the chart's default image
# while `make dev-up` swaps in the freshly-built local one.
export KUBAUTH_IMAGE_REPO
export KUBAUTH_IMAGE_TAG
export KUBAUTH_IMAGE_PULL_POLICY

.PHONY: dev-up
dev-up: KUBAUTH_IMAGE_REPO := local/kubauth
dev-up: KUBAUTH_IMAGE_TAG := dev
dev-up: KUBAUTH_IMAGE_PULL_POLICY := Never
dev-up: kind-up prereqs image install ## Full bring-up: kind-up + prereqs + image (working tree) + install.
	@echo "Cluster ready (kubauth built from working tree). Run 'make conformance' next."

.PHONY: dev-down
dev-down: kind-down ## Full teardown.

# ─── Conformance ──────────────────────────────────────────────────────────
# The OpenID Foundation Conformance Suite runs IN-CLUSTER as a 3-pod
# Deployment (mongo + server + nginx) under the `conformance` ns.
# Plans are driven from the suite's UI (port-forwarded to localhost).

.PHONY: conformance-up
conformance-up: ## Deploy the OpenID Conformance Suite into the kind cluster.
	@command -v envsubst >/dev/null || { echo "envsubst not installed (gettext) — needed to inject the suite version"; exit 1; }
	@# 00 (namespace) + 01 (mongo) carry no templated fields — apply as-is.
	@kubectl apply -f fixtures/conformance/00-namespace.yaml
	@# Copy kubauth's self-signed CA into the conformance namespace so
	@# the suite's JVM truststore (built by an initContainer) trusts
	@# kubauth when the plan calls /.well-known/openid-configuration.
	@kubectl -n kubauth-system get secret kubauth-oidc-server-cert \
		-o jsonpath='{.data.ca\.crt}' | base64 -d > /tmp/kubauth-ca.crt
	@kubectl -n conformance create secret generic kubauth-ca-trust \
		--from-file=ca.crt=/tmp/kubauth-ca.crt \
		--dry-run=client -o yaml | kubectl apply -f -
	@rm -f /tmp/kubauth-ca.crt
	@kubectl apply -f fixtures/conformance/01-mongo.yaml
	@# The conformance-nginx Service pins a fixed ClusterIP (10.96.255.10)
	@# so the conformance-server pod can resolve `localhost.emobix.co.uk`
	@# to it via hostAliases (see fixtures/conformance/02-server.yaml).
	@# ClusterIP is immutable on update — if the live Service has a
	@# different IP (older install, or first-run race), drop it so the
	@# apply below recreates it with the desired IP.
	@if kubectl -n conformance get svc conformance-nginx >/dev/null 2>&1; then \
		current="$$(kubectl -n conformance get svc conformance-nginx -o jsonpath='{.spec.clusterIP}')" ; \
		if [ "$$current" != "10.96.255.10" ]; then \
			echo "  conformance-nginx has ClusterIP=$$current, expected 10.96.255.10 — recreating" ; \
			kubectl -n conformance delete svc conformance-nginx --wait=true ; \
		fi ; \
	fi
	@# 02 (server) + 03 (nginx) pin the suite image tag via
	@# $${CONFORMANCE_SUITE_VERSION}, single-sourced in scripts/lib/env.sh.
	@# Substitute ONLY that var (explicit allowlist) and apply.
	@source $(SCRIPTS)/lib/env.sh ; \
		envsubst '$${CONFORMANCE_SUITE_VERSION}' < fixtures/conformance/02-server.yaml | kubectl apply -f - ; \
		envsubst '$${CONFORMANCE_SUITE_VERSION}' < fixtures/conformance/03-nginx.yaml  | kubectl apply -f -
	@kubectl -n conformance rollout status deploy/mongo              --timeout=120s
	@kubectl -n conformance rollout status deploy/conformance-server --timeout=300s
	@kubectl -n conformance rollout status deploy/conformance-nginx  --timeout=120s
	@echo
	@echo "Suite ready. To open the UI:"
	@echo "  kubectl -n conformance port-forward svc/conformance-nginx 8443:8443"
	@echo "  open https://localhost.emobix.co.uk:8443/"

.PHONY: conformance-down
conformance-down: ## Tear down the OpenID Conformance Suite from the cluster.
	@kubectl delete namespace conformance --ignore-not-found

.PHONY: conformance-portforward
conformance-portforward: ## Port-forward the suite UI to https://localhost.emobix.co.uk:8443.
	@kubectl -n conformance port-forward svc/conformance-nginx 8443:8443

# Plan runners — drive the suite via its REST API. All targets assume
# `make conformance-up` already ran AND the suite UI/API is reachable
# at $$SUITE_URL (defaults to https://localhost.emobix.co.uk:8443; run
# `make conformance-portforward` in another shell to make it so).
#
# Layout: each plan has its own `conformance/config/<plan>.json` and
# its results land under `conformance/results/<plan>/`.
.PHONY: conformance-config
conformance-config: ## Run oidcc-config-certification-test-plan via the REST API.
	@$(SCRIPTS)/conformance-run.sh \
		oidcc-config-certification-test-plan \
		none \
		conformance/config/oidcc-config.json

.PHONY: conformance-basic
conformance-basic: ## Run oidcc-basic-certification-test-plan (toggles enforcePKCE off for the run).
	@$(SCRIPTS)/with-pkce-disabled.sh \
		$(SCRIPTS)/conformance-run.sh \
		oidcc-basic-certification-test-plan \
		'{"server_metadata":"discovery","client_registration":"static_client"}' \
		conformance/config/oidcc-basic.json

.PHONY: conformance-rp-logout
conformance-rp-logout: ## Run oidcc-rp-initiated-logout-certification-test-plan (toggles enforcePKCE off).
	@$(SCRIPTS)/with-pkce-disabled.sh \
		$(SCRIPTS)/conformance-run.sh \
		oidcc-rp-initiated-logout-certification-test-plan \
		'{"response_type":"code","client_registration":"static_client"}' \
		conformance/config/oidcc-rp-initiated-logout.json

.PHONY: conformance-all
conformance-all: ## Run every wired conformance plan in sequence (continues on per-plan failures).
	@# Each individual plan exits non-zero when a module didn't reach
	@# FINISHED with PASSED/WARNING — that's by design (lets CI gate
	@# on a plan's regression). For `conformance-all`, we want to see
	@# how every plan went regardless, so we don't make-prereq-chain
	@# them. The summary at the bottom recaps per-plan exit codes.
	@#
	@# Wrap the whole sequence in `with-pkce-disabled` so PKCE is
	@# toggled ONCE at the start and restored ONCE at the end. The
	@# inner conformance-{basic,rp-logout} targets each have their
	@# own with-pkce-disabled wrapper, but it short-circuits when the
	@# flag is already off, so the inner wrappers become no-ops here.
	@# Without this, conformance-all caused four kubauth restarts
	@# (off-restore for basic, off-restore for rp-logout); the conformance
	@# suite then occasionally raced kubauth's TLS readiness on the
	@# first module of rp-logout and got Connect-refused.
	@$(SCRIPTS)/with-pkce-disabled.sh sh -c '\
	  rc_config=0; rc_basic=0; rc_rp=0; \
	  $(MAKE) --no-print-directory conformance-config       || rc_config=$$?; \
	  $(MAKE) --no-print-directory conformance-basic        || rc_basic=$$?; \
	  $(MAKE) --no-print-directory conformance-rp-logout    || rc_rp=$$?; \
	  echo; \
	  echo "===== conformance-all per-plan exit codes ====="; \
	  echo "  config         : $$rc_config"; \
	  echo "  basic          : $$rc_basic"; \
	  echo "  rp-init-logout : $$rc_rp"; \
	  echo "Reports under tests/conformance/results/<plan>/summary.txt"; \
	  if [ $$rc_config -ne 0 ] || [ $$rc_basic -ne 0 ] || [ $$rc_rp -ne 0 ]; then \
	    exit 1; \
	  fi'

# ─── Autonomous from-zero conformance ──────────────────────────────────────
# `make conformance` owns the entire pipeline from an empty machine
# (only Docker assumed): kind + registry + cert-manager, build & load the
# working-tree kubauth image, helm install + cert patch, deploy the OIDF
# suite, run the plan(s) behind a backgrounded + trap-reaped port-forward,
# classify each module green / expected-fail / unexpected against
# conformance/expected/<plan>.yaml, print a roll-up, then tear down.
#
# Unlike the conformance-{config,basic,rp-logout} targets above (which
# assume a human already ran dev-up + conformance-up + a port-forward),
# this target has ZERO prerequisites. Exit 0 iff every plan reports 0
# unexpected modules.
#
#   PLAN=config      (default) only the always-green discovery plan
#   PLAN=basic       oidcc-basic behind its allowlist
#   PLAN=rp-logout   oidcc-rp-initiated-logout behind its allowlist
#   PLAN=all         all three (same as `make conformance-full`)
#   KEEP=1           skip teardown (leave the cluster up for debugging)
#   REUSE=1          reuse an existing cluster (skip kind-up + teardown)
#
# Export the knobs so they reach the orchestrator's environment whether
# they arrive as env vars or as command-line make variables (the script
# reads them from the environment, defaulting empty/unset itself).
export PLAN
export KEEP
export REUSE
.PHONY: conformance
conformance: ## From-zero autonomous conformance run + teardown (PLAN=config|basic|rp-logout|all, KEEP=1, REUSE=1).
	@$(SCRIPTS)/conformance-orchestrate.sh

.PHONY: conformance-full
conformance-full: ## `make conformance` over all three plans (config + basic + rp-logout).
	@PLAN=all $(SCRIPTS)/conformance-orchestrate.sh

# Cluster-free unit test for the 3-bucket classifier (the allowlist gate
# logic). Runs on synthetic data in a few hundred ms, no kind required —
# safe to run in any CI lane, unlike the full `conformance` target.
.PHONY: conformance-classify-test
conformance-classify-test: ## Unit-test the 3-bucket allowlist classifier (no cluster).
	@$(SCRIPTS)/conformance-classify-test.sh

# ─── Lint / hygiene ───────────────────────────────────────────────────────
.PHONY: shellcheck
shellcheck: ## Lint shell scripts.
	@command -v shellcheck >/dev/null || { echo "shellcheck not installed"; exit 1; }
	@shellcheck $(SCRIPTS)/*.sh $(SCRIPTS)/lib/*.sh

.PHONY: yamllint
yamllint: ## Lint YAML fixtures.
	@command -v yamllint >/dev/null || { echo "yamllint not installed"; exit 1; }
	@yamllint -s fixtures/

.PHONY: lint
lint: shellcheck yamllint ## Lint everything.
