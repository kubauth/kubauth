# 15-kubectl-flow-complet

**Status: TODO — not yet implemented.** Documenting the scope here so we
know exactly what to build when this test lands.

## Goal

End-to-end validation that a kubauth-issued id_token can be used by kubectl
to authenticate against a kube-apiserver, with RBAC bound to the kubauth
identity (sub, groups).

## What it should assert

1. Configure the kind API server with:
   - `--oidc-issuer-url=https://kubauth-oidc-server.kubauth-system.svc:443`
   - `--oidc-client-id=kubectl`
   - `--oidc-username-claim=sub`
   - `--oidc-groups-claim=groups`
   - `--oidc-ca-file=<kubauth CA>`
2. Apply an `OidcClient kubectl` (public, code+PKCE, redirect to `localhost`).
3. Apply RBAC: `User: alice` → `Role: pod-reader` in `default`.
4. Get an id_token for alice via the auth-code+login flow on the `kubectl`
   client (or ROPC for shortcut, since this test is about API auth, not the
   browser dance).
5. Build a kubeconfig with:

   ```yaml
   users:
     - name: alice
       user:
         auth-provider:
           name: oidc
           config:
             idp-issuer-url: https://kubauth-oidc-server.kubauth-system.svc:443
             client-id: kubectl
             id-token: <id_token>
             refresh-token: <refresh_token>
             idp-certificate-authority-data: <base64 CA>
   ```

6. `kubectl get pods` against the kind API succeeds for `alice`.
7. `kubectl get nodes` is **rejected** (alice has no permission on nodes).

## Why it isn't built yet

The kind API-server flags require recreating the cluster with a custom
`kubeadmConfigPatches` block in `scripts/kind-up.sh`. That's a one-time
infrastructure change — small in code, but it shifts every other test's
boot path. Deferred while the rest of the suite focuses on kubauth's own
surface (OIDC endpoints, CRDs, merger, audit) without involving the
kube-apiserver as a relying party.

## Implementation sketch

```yaml
# scripts/kind-up.sh — extra block
nodes:
  - role: control-plane
    image: ${KIND_NODE_IMAGE}
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        apiServer:
          extraArgs:
            oidc-issuer-url: https://kubauth-oidc-server.kubauth-system.svc:443
            oidc-client-id: kubectl
            oidc-username-claim: sub
            oidc-groups-claim: groups
            oidc-ca-file: /etc/kubernetes/pki/kubauth-ca.crt
          extraVolumes:
            - name: kubauth-ca
              hostPath: /var/run/kubauth/ca.crt
              mountPath: /etc/kubernetes/pki/kubauth-ca.crt
              readOnly: true
              pathType: File
extraMounts:
  - hostPath: /tmp/kubauth-ca.crt
    containerPath: /var/run/kubauth/ca.crt
```

The kubauth CA needs to be exported from cert-manager into a host file
before kind boots, but cert-manager itself runs inside kind. Possible
patterns: boot kind with an empty CA, install kubauth, fetch the issued
CA, then restart the control-plane; or use a webhook-based authenticator
that does not require a static CA file.

## When to build

Once the test surface genuinely needs kube-apiserver-side validation,
or when an end-user kubectl OIDC flow regresses and we need a guard.
