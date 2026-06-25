/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package fositepatch

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"log/slog"
	"testing"
	"time"

	"kubauth/cmd/oidc/authenticator"
	"kubauth/cmd/oidc/oidcstorage"
	"kubauth/internal/proto"

	"github.com/go-logr/logr"
	"github.com/ory/hydra/v2/fosite"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kubauth/api/kubauth/v1alpha1"
)

// discardLogger returns a slog.Logger that throws output away so the
// handlers under test can log freely without polluting test output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testContext returns a context carrying a (discard) slog logger, exactly
// as the production entrypoint does via logr.NewContextWithSlogLogger.
// The ROPC handler calls logr.FromContextAsSlogLogger(ctx) and then logs
// without a nil check, so callers must inject a logger or the handler
// panics on the error/success paths.
func testContext() context.Context {
	return logr.NewContextWithSlogLogger(context.Background(), discardLogger())
}

// boolPtr is a tiny helper for the *bool spec fields.
func boolPtr(b bool) *bool { return &b }

// testClientOpts configures the OidcClient backing a test KubauthClient.
type testClientOpts struct {
	clientID         string
	scopes           []string
	audiences        []string
	grantTypes       []string
	forceOpenIDScope *bool
}

// newTestClient builds a real oidcstorage.KubauthClient from an OidcClient
// CR. Using the production client type (rather than a hand-rolled fake)
// means the scope/audience handlers exercise the same GetAudience /
// IsForceOpenIdScope logic that runs in production.
func newTestClient(o testClientOpts) oidcstorage.KubauthClient {
	if o.clientID == "" {
		o.clientID = "test-client"
	}
	cli := &v1alpha1.OidcClient{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kubauth-system",
			Name:      o.clientID,
		},
		Spec: v1alpha1.OidcClientSpec{
			RedirectURIs:     []string{"https://app/callback"},
			GrantTypes:       o.grantTypes,
			ResponseTypes:    []string{"code"},
			Scopes:           o.scopes,
			Audiences:        o.audiences,
			ForceOpenIdScope: o.forceOpenIDScope,
		},
	}
	return oidcstorage.NewKubauthClient(cli, o.clientID, nil)
}

// fakeAuthenticator is a configurable authenticator.OidcAuthenticator used
// to drive the ROPC flow down its success / failure / nil-user branches
// without any real LDAP or HTTP backend.
type fakeAuthenticator struct {
	// authFn backs Authenticate (and, through MemoryStore, AuthenticateUserWithClaims).
	authFn func(ctx context.Context, login, password string) (*authenticator.OidcUser, error)
}

func (f *fakeAuthenticator) Identify(_ context.Context, login, _ string) (*authenticator.OidcUser, proto.Status, error) {
	return &authenticator.OidcUser{Login: login}, proto.Status("ok"), nil
}

func (f *fakeAuthenticator) Authenticate(ctx context.Context, login, password string) (*authenticator.OidcUser, error) {
	if f.authFn == nil {
		return &authenticator.OidcUser{Login: login}, nil
	}
	return f.authFn(ctx, login, password)
}

var _ authenticator.OidcAuthenticator = (*fakeAuthenticator)(nil)

// newTestStore builds a MemoryStore wired to the given authenticator with
// the password grant flag configured. issuer/keyID mirror what the real
// server sets so id-token claims look realistic.
func newTestStore(t *testing.T, auth authenticator.OidcAuthenticator, allowPasswordGrant bool) *oidcstorage.MemoryStore {
	t.Helper()
	store := oidcstorage.NewMemoryStore(auth)
	store.Issuer = "https://issuer.example.com"
	store.KeyID = "test-kid"
	store.AllowPasswordGrant = allowPasswordGrant
	return store
}

// newTestConfig builds a fosite.Config mirroring the production wiring in
// oidcserver.go (same global secret, exact lifespans, offline refresh
// scopes). The ExactScopeStrategy is set explicitly so scope filtering in
// the ROPC handler is deterministic.
func newTestConfig() *fosite.Config {
	return &fosite.Config{
		AccessTokenLifespan:  time.Hour,
		RefreshTokenLifespan: 24 * time.Hour,
		IDTokenLifespan:      time.Hour,
		TokenEntropy:         32,
		GlobalSecret:         []byte("some-secret-that-is-32-bytes-long"),
		RefreshTokenScopes:   []string{"offline", "offline_access"},
		AccessTokenIssuer:    "https://issuer.example.com",
		IDTokenIssuer:        "https://issuer.example.com",
		ScopeStrategy:        fosite.ExactScopeStrategy,
	}
}

// newTestKey generates an RSA key for signing, matching oidcserver.go.
func newTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return key
}
