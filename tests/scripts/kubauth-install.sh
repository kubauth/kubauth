#!/usr/bin/env bash
#
# Install kubauth into the test cluster.
#
# Steps (each idempotent):
#   1. ensure namespaces exist
#   2. apply self-signed ClusterIssuer
#   3. create JWT signing key Secret (random, regenerated on demand)
#   4. helm install/upgrade the kubauth chart from the local source repo
#   5. wait for all 5 deployments to be ready

set -euo pipefail

# shellcheck source=lib/env.sh
source "$(dirname "$0")/lib/env.sh"

require_bin kubectl
require_bin helm
require_bin openssl

ensure_namespaces() {
  local ns
  for ns in "$NS_KUBAUTH" "$NS_UPSTREAMS" "$NS_USERS"; do
    if ! kubectl get ns "$ns" >/dev/null 2>&1; then
      log "creating namespace $ns"
      kubectl create namespace "$ns"
    fi
  done
}

apply_cluster_issuer() {
  log "applying CA-based ClusterIssuer"
  kubectl apply -f "${FIXTURES_DIR}/cluster-issuer.yaml"
  # The CA-typed ClusterIssuer can only sign once its backing CA cert
  # has been issued by the bootstrap selfSigned issuer. Wait for it,
  # otherwise downstream Certificates queue forever and the helm
  # rollout below times out on cert-mounted secrets.
  log "waiting for kubauth-tests-ca certificate to be Ready"
  kubectl -n cert-manager wait --for=condition=Ready \
    certificate/kubauth-tests-ca --timeout=120s
}

# JWT signing key — generated locally, never reused across clusters.
ensure_jwt_signing_key() {
  if kubectl -n "$NS_KUBAUTH" get secret jwt-signing-key >/dev/null 2>&1; then
    log "JWT signing key secret already exists"
    return
  fi
  log "generating JWT signing key (RSA 2048)"
  mkdir -p "$TMP_DIR"
  local key="${TMP_DIR}/jwt-signing.key"
  openssl genrsa -out "$key" 2048 2>/dev/null
  kubectl -n "$NS_KUBAUTH" create secret generic jwt-signing-key \
    --from-file=tls.key="$key"
  rm -f "$key"
}

# Kubauth helm chart lives in the source repo. We test what the upstream chart ships.
require_chart_present() {
  local chart_dir="${KUBAUTH_REPO}/helm/kubauth"
  if [[ ! -f "${chart_dir}/Chart.yaml" ]]; then
    die "kubauth chart not found at ${chart_dir} — make sure ${KUBAUTH_REPO} is checked out on branch ${KUBAUTH_BRANCH}"
  fi
}

helm_install_kubauth() {
  log "helm upgrade --install kubauth"
  # When KUBAUTH_IMAGE_REPO + KUBAUTH_IMAGE_TAG are set, override every
  # container's image. KUBAUTH_IMAGE_PULL_POLICY defaults to IfNotPresent.
  local sets=()
  if [[ -n "${KUBAUTH_IMAGE_REPO:-}" && -n "${KUBAUTH_IMAGE_TAG:-}" ]]; then
    log "overriding all kubauth container images: ${KUBAUTH_IMAGE_REPO}:${KUBAUTH_IMAGE_TAG} (pullPolicy=${KUBAUTH_IMAGE_PULL_POLICY:-IfNotPresent})"
    local component
    for component in oidc merger ucrd audit ldap; do
      sets+=("--set" "${component}.image.repository=${KUBAUTH_IMAGE_REPO}")
      sets+=("--set" "${component}.image.tag=${KUBAUTH_IMAGE_TAG}")
      sets+=("--set" "${component}.image.pullPolicy=${KUBAUTH_IMAGE_PULL_POLICY:-IfNotPresent}")
    done
  fi
  helm upgrade --install kubauth \
    "${KUBAUTH_REPO}/helm/kubauth" \
    --namespace "$NS_KUBAUTH" \
    --values "${FIXTURES_DIR}/kubauth-values.yaml" \
    "${sets[@]}" \
    --wait \
    --timeout 10m
}

# Apply User/Group/GroupBinding/OidcClient fixtures used by every smoke test.
# Uses kapply_with_webhook_retry so a webhook that hasn't quite finished
# binding its TLS socket post-restart doesn't fail the install.
apply_seed_fixtures() {
  log "applying seed fixtures (users, groups, oidcclients)"
  if ls "${FIXTURES_DIR}"/users/*.yaml >/dev/null 2>&1; then
    kapply_with_webhook_retry -n "$NS_USERS" -f "${FIXTURES_DIR}/users/"
  fi
  if ls "${FIXTURES_DIR}"/groups/*.yaml >/dev/null 2>&1; then
    kapply_with_webhook_retry -n "$NS_USERS" -f "${FIXTURES_DIR}/groups/"
  fi
  if ls "${FIXTURES_DIR}"/oidcclients/*.yaml >/dev/null 2>&1; then
    kapply_with_webhook_retry -n "$NS_KUBAUTH" -f "${FIXTURES_DIR}/oidcclients/"
  fi
}

# Patch every Certificate the chart created with a `commonName`
# matching the cert's name. cert-manager does not derive commonName
# from dnsNames automatically, so without this step every server cert
# carries an empty Subject DN — strict TLS clients (notably the
# OpenID Conformance Suite's JVM) refuse to parse them. Idempotent;
# re-applies the patch and forces a re-issue.
patch_certificate_common_names() {
  log "patching kubauth Certificates with commonName (cert-manager does not auto-derive)"
  local cert
  for cert in kubauth-oidc-server kubauth-oidc-webhooks kubauth-ucrd-webhooks; do
    if kubectl -n "$NS_KUBAUTH" get certificate "$cert" >/dev/null 2>&1; then
      kubectl -n "$NS_KUBAUTH" patch certificate "$cert" --type=merge \
        -p "{\"spec\":{\"commonName\":\"${cert}\"}}" >/dev/null
    fi
  done
  # Force re-issue by deleting the underlying secrets — cert-manager
  # picks up the spec change and produces fresh certs with non-empty
  # Subject DN.
  kubectl -n "$NS_KUBAUTH" delete secret \
    kubauth-oidc-server-cert kubauth-oidc-webhooks kubauth-ucrd-webhooks \
    --ignore-not-found >/dev/null 2>&1 || true

  # Wait for cert-manager to mark each Certificate Ready again. We
  # check the Certificate (not the Secret) because the Certificate's
  # Ready condition only flips to True after the new Secret has been
  # written AND its content matches the spec. Faster runners have
  # been flaky here when the script only watched one of the three.
  log "waiting for re-issued certificates to be Ready"
  for cert in kubauth-oidc-server kubauth-oidc-webhooks kubauth-ucrd-webhooks; do
    kubectl -n "$NS_KUBAUTH" wait --for=condition=Ready \
      "certificate/${cert}" --timeout=120s
  done

  kubectl -n "$NS_KUBAUTH" rollout restart deployment kubauth >/dev/null
  kubectl -n "$NS_KUBAUTH" rollout status deployment kubauth --timeout=180s
}

# Retry `kubectl apply -f` against a transient webhook timeout.
# `rollout status` returns when the deployment's readiness probe
# (oidc /healthz on :8110) passes, but the webhook TLS sockets
# served by other containers in the same pod (ucrd:9443,
# oidc-webhook:9443) bind a couple of seconds later. CI runners
# have been flaky during that window — `kubectl apply` of a
# CR whose admission webhook isn't serving yet returns
# "context deadline exceeded" with no automatic retry. This
# wrapper retries up to ~30 s.
kapply_with_webhook_retry() {
  local i out
  for i in $(seq 1 15); do
    if out="$(kubectl apply "$@" 2>&1)"; then
      [[ -n "$out" ]] && printf '%s\n' "$out"
      return 0
    fi
    if printf '%s' "$out" | grep -q "context deadline exceeded\|failed calling webhook\|no endpoints available"; then
      log "  webhook not yet serving (attempt ${i}/15) — retrying in 2 s"
      sleep 2
      continue
    fi
    # Genuine non-webhook error → surface and fail.
    printf '%s\n' "$out" >&2
    return 1
  done
  err "kubectl apply kept failing on webhook timeout after 15 retries"
  return 1
}

# OpenLDAP test fixture — only deployed when present in fixtures/ldap/.
# Required by e2e/10-ldap-authority and e2e/11-merger-claim-priority.
deploy_ldap_fixture() {
  local dir="${FIXTURES_DIR}/ldap"
  if [[ ! -d "$dir" ]]; then
    log "no fixtures/ldap/ — skipping OpenLDAP fixture"
    return
  fi
  log "applying OpenLDAP fixture (namespace: ldap-test)"
  kubectl apply -f "$dir/"
  kubectl -n ldap-test rollout status deploy/openldap --timeout=180s
}

main() {
  require_chart_present
  ensure_namespaces
  apply_cluster_issuer
  ensure_jwt_signing_key
  deploy_ldap_fixture           # before helm so the LDAP authority can connect on first start
  helm_install_kubauth
  patch_certificate_common_names
  apply_seed_fixtures
  ok "kubauth installed in namespace $NS_KUBAUTH"
}

main "$@"
