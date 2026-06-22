/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package fositepatch

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"kubauth/api/kubauth/v1alpha1"
	"kubauth/cmd/oidc/oidcstorage"

	"github.com/ory/hydra/v2/fosite"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// --- Smoke: provider construction ----------------------------------------

func TestComposeAllEnabled_ReturnsProvider_HMAC(t *testing.T) {
	store := newTestStore(t, &fakeAuthenticator{}, true)
	p := ComposeAllEnabled(newTestConfig(), store, newTestKey(t), false)
	if p == nil {
		t.Fatal("ComposeAllEnabled returned nil provider (HMAC access tokens)")
	}
}

func TestComposeAllEnabled_ReturnsProvider_JWT(t *testing.T) {
	store := newTestStore(t, &fakeAuthenticator{}, true)
	p := ComposeAllEnabled(newTestConfig(), store, newTestKey(t), true)
	if p == nil {
		t.Fatal("ComposeAllEnabled returned nil provider (JWT access tokens)")
	}
}

// registerConfidentialClient stores a password-grant client whose secret
// hashes to `secret` under the config's hasher, so it can authenticate via
// client_secret_post against the composed provider.
func registerConfidentialClient(t *testing.T, store *oidcstorage.MemoryStore, config *fosite.Config, clientID, secret string, scopes []string) {
	t.Helper()
	hashed, err := config.GetSecretsHasher(testContext()).Hash(testContext(), []byte(secret))
	if err != nil {
		t.Fatalf("failed to hash client secret: %v", err)
	}
	cli := &v1alpha1.OidcClient{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kubauth-system", Name: clientID},
		Spec: v1alpha1.OidcClientSpec{
			RedirectURIs:  []string{"https://app/callback"},
			GrantTypes:    []string{"password"},
			ResponseTypes: []string{"code"},
			Scopes:        scopes,
			Audiences:     []string{clientID},
			Public:        false,
		},
	}
	kc := oidcstorage.NewKubauthClient(cli, clientID, [][]byte{hashed})
	if err := store.SetClient(testContext(), kc); err != nil {
		t.Fatalf("failed to register client: %v", err)
	}
}

// tokenPOST builds a POST request to the token endpoint with a form body,
// exactly as a client would send it.
func tokenPOST(form url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://issuer.example.com/oauth2/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// TestComposeAllEnabled_ROPCFactoryIsWired drives a full password-grant
// token request through the composed provider. If
// OAuth2ResourceOwnerPasswordCredentialsFactory were not registered by
// ComposeAllEnabled, NewAccessRequest would fail to find a handler and
// return invalid_request. A successful access+id token proves the ROPC
// handler is composed in and reachable end-to-end.
func TestComposeAllEnabled_ROPCFactoryIsWired(t *testing.T) {
	config := newTestConfig()
	store := newTestStore(t, &fakeAuthenticator{}, true)
	registerConfidentialClient(t, store, config, "ropc-app", "s3cret", []string{"openid", "profile"})

	provider := ComposeAllEnabled(config, store, newTestKey(t), false)
	ctx := testContext()

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "ropc-app")
	form.Set("client_secret", "s3cret")
	form.Set("username", "alice")
	form.Set("password", "pw")
	form.Set("scope", "openid profile")

	ar, err := provider.NewAccessRequest(ctx, tokenPOST(form), &OIDCSession{})
	if err != nil {
		t.Fatalf("NewAccessRequest failed (ROPC handler likely not composed): %v", err)
	}
	if !ar.GetGrantTypes().ExactOne("password") {
		t.Fatalf("expected password grant, got %v", ar.GetGrantTypes())
	}
	// HandleScopes inside the ROPC handler must have granted requested scopes.
	for _, want := range []string{"openid", "profile"} {
		if !ar.GetGrantedScopes().Has(want) {
			t.Errorf("expected scope %q granted by ROPC handler, granted=%v", want, ar.GetGrantedScopes())
		}
	}

	resp, err := provider.NewAccessResponse(ctx, ar)
	if err != nil {
		t.Fatalf("NewAccessResponse failed: %v", err)
	}
	if resp.GetAccessToken() == "" {
		t.Error("composed provider should issue an access token for ROPC")
	}
	if resp.GetExtra("id_token") == nil {
		t.Error("composed provider should issue an id_token when openid is granted")
	}
}

// A wrong client secret must be rejected by the composed provider's client
// authentication, proving auth is actually enforced (not bypassed).
func TestComposeAllEnabled_ROPCRejectsBadClientSecret(t *testing.T) {
	config := newTestConfig()
	store := newTestStore(t, &fakeAuthenticator{}, true)
	registerConfidentialClient(t, store, config, "ropc-app", "right-secret", []string{"openid"})

	provider := ComposeAllEnabled(config, store, newTestKey(t), false)

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "ropc-app")
	form.Set("client_secret", "wrong-secret")
	form.Set("username", "alice")
	form.Set("password", "pw")
	form.Set("scope", "openid")

	_, err := provider.NewAccessRequest(testContext(), tokenPOST(form), &OIDCSession{})
	if err == nil {
		t.Fatal("expected client authentication to fail with wrong secret")
	}
	rfc := fosite.ErrorToRFC6749Error(err)
	if rfc.ErrorField != fosite.ErrInvalidClient.ErrorField {
		t.Fatalf("expected invalid_client, got %v (%v)", rfc.ErrorField, err)
	}
}

// When the server disables the password grant, the composed provider must
// reject ROPC requests even from an otherwise-valid client.
func TestComposeAllEnabled_ROPCRejectedWhenPasswordGrantDisabled(t *testing.T) {
	config := newTestConfig()
	store := newTestStore(t, &fakeAuthenticator{}, false) // password grant OFF
	registerConfidentialClient(t, store, config, "ropc-app", "s3cret", []string{"openid"})

	provider := ComposeAllEnabled(config, store, newTestKey(t), false)

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "ropc-app")
	form.Set("client_secret", "s3cret")
	form.Set("username", "alice")
	form.Set("password", "pw")
	form.Set("scope", "openid")

	_, err := provider.NewAccessRequest(testContext(), tokenPOST(form), &OIDCSession{})
	if err == nil {
		t.Fatal("expected ROPC to be rejected when password grant disabled")
	}
	rfc := fosite.ErrorToRFC6749Error(err)
	if rfc.ErrorField != fosite.ErrRequestForbidden.ErrorField {
		t.Fatalf("expected request_forbidden, got %v (%v)", rfc.ErrorField, err)
	}
}
