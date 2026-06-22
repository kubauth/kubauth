/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package oidcserver

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"kubauth/cmd/oidc/oidcstorage"

	scsV2 "github.com/alexedwards/scs/v2"
	scsmem "github.com/alexedwards/scs/v2/memstore"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// bareServer builds an unconfigured OIDCServer wired with the given kube client.
// Used to drive Setup()/ensureJwtSigningKey directly.
func bareServer(t *testing.T, kube client.Client, secretName, secretNS string) *OIDCServer {
	t.Helper()
	loginTmpl, indexTmpl, welcomeTmpl := testTemplates()
	sso := scsV2.New()
	sso.Store = scsmem.New()
	login := scsV2.New()
	login.Store = scsmem.New()
	return &OIDCServer{
		Issuer:                  testIssuer,
		Storage:                 oidcstorage.NewMemoryStore(defaultAuth()),
		Authenticator:           defaultAuth(),
		Resources:               t.TempDir(),
		LoginTemplate:           loginTmpl,
		IndexTemplate:           indexTmpl,
		UpstreamWelcomeTemplate: welcomeTmpl,
		SsoSessionManager:       sso,
		LoginSessionManager:     login,
		KubeClient:              kube,
		EventRecorder:           record.NewFakeRecorder(16),
		JWTSigningKeySecretName: secretName,
		JWTSigningKeySecretNS:   secretNS,
		AccessTokenLifespan:     time.Hour,
		RefreshTokenLifespan:    time.Hour,
	}
}

// ============================================ Setup wires the storage

func TestSetup_PropagatesConfigToStorage(t *testing.T) {
	ts := buildServer(t, func(o *buildOpts) { o.allowPasswordGrant = true })
	if ts.store.Issuer != testIssuer {
		t.Errorf("Setup must set storage.Issuer: got %q", ts.store.Issuer)
	}
	if ts.store.KeyID != ts.kid {
		t.Errorf("Setup must set storage.KeyID: got %q, want %q", ts.store.KeyID, ts.kid)
	}
	if !ts.store.AllowPasswordGrant {
		t.Error("Setup must propagate AllowPasswordGrant to storage")
	}
	if ts.store.Authenticator == nil {
		t.Error("Setup must wire the authenticator into storage")
	}
}

// ============================================ ensureJwtSigningKey: generate

func TestEnsureJwtSigningKey_GeneratesAndPersistsWhenAbsent(t *testing.T) {
	const name, ns = "gen-key", "kubauth-system"
	kube := fake.NewClientBuilder().WithScheme(newScheme(t)).Build() // no secret seeded

	s := bareServer(t, kube, name, ns)
	mux := http.NewServeMux()
	if err := s.Setup(testCtx(), mux); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// A key + kid must now exist in-memory.
	if s.privateKey == nil || s.keyID == "" {
		t.Fatalf("expected a generated key and kid, got key=%v kid=%q", s.privateKey, s.keyID)
	}
	// And it must have been persisted to a Secret for restart stability.
	sec := &corev1.Secret{}
	if err := kube.Get(testCtx(), client.ObjectKey{Name: name, Namespace: ns}, sec); err != nil {
		t.Fatalf("generated key should be persisted as a Secret: %v", err)
	}
	if len(sec.Data["key.pem"]) == 0 || string(sec.Data["kid"]) != s.keyID {
		t.Errorf("persisted secret malformed: kidData=%q serverKid=%q", sec.Data["kid"], s.keyID)
	}
}

// ============================================ ensureJwtSigningKey: load existing

func TestEnsureJwtSigningKey_LoadsExistingKid(t *testing.T) {
	const name, ns = "load-key", "kubauth-system"
	sec, _, kid := preGeneratedKeySecret(t, name, ns)
	kube := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(sec).Build()

	s := bareServer(t, kube, name, ns)
	if err := s.Setup(testCtx(), http.NewServeMux()); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if s.keyID != kid {
		t.Errorf("must load existing kid: got %q, want %q", s.keyID, kid)
	}
}

// ============================================ ensureJwtSigningKey: malformed

func TestEnsureJwtSigningKey_MissingDataKeys_Errors(t *testing.T) {
	const name, ns = "bad-key", "kubauth-system"
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"kid": []byte("x")}, // missing key.pem
	}
	kube := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(sec).Build()

	s := bareServer(t, kube, name, ns)
	err := s.Setup(testCtx(), http.NewServeMux())
	if err == nil {
		t.Fatal("Setup must fail when the key secret is missing required data keys")
	}
}

func TestEnsureJwtSigningKey_UndecodablePEM_Errors(t *testing.T) {
	const name, ns = "bad-pem", "kubauth-system"
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"key.pem": []byte("not a pem block"), "kid": []byte("x")},
	}
	kube := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(sec).Build()

	s := bareServer(t, kube, name, ns)
	if err := s.Setup(testCtx(), http.NewServeMux()); err == nil {
		t.Fatal("Setup must fail on an undecodable PEM in the key secret")
	}
}

// ============================================ ensureJwtSigningKey: Get failure

// Inject a non-NotFound Get error via interceptor so ensureJwtSigningKey takes
// the "failed to load" branch (not the generate branch).
func TestEnsureJwtSigningKey_GetError_Propagates(t *testing.T) {
	const name, ns = "err-key", "kubauth-system"
	boom := errors.New("apiserver unavailable")
	kube := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, key client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				if key.Name == name {
					return boom
				}
				return nil
			},
		}).
		Build()

	s := bareServer(t, kube, name, ns)
	err := s.Setup(testCtx(), http.NewServeMux())
	if err == nil {
		t.Fatal("Setup must fail when the key Secret Get returns a non-NotFound error")
	}
}

// ============================================ ensureJwtSigningKey: Create failure

// When the secret is absent (NotFound) but Create fails, generation must error.
func TestEnsureJwtSigningKey_CreateError_Propagates(t *testing.T) {
	const name, ns = "create-fail", "kubauth-system"
	boom := errors.New("quota exceeded")
	kube := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
				if _, ok := obj.(*corev1.Secret); ok {
					return boom
				}
				return nil
			},
		}).
		Build()

	s := bareServer(t, kube, name, ns)
	if err := s.Setup(testCtx(), http.NewServeMux()); err == nil {
		t.Fatal("Setup must fail when persisting a newly generated key fails")
	}
}

// ============================================ runtime scheme sanity

// Guards against a future fixture change that forgets to register core/v1,
// which would make every Secret op silently fail with a scheme error.
func TestScheme_RegistersCoreAndCRD(t *testing.T) {
	s := newScheme(t)
	if !s.Recognizes(corev1.SchemeGroupVersion.WithKind("Secret")) {
		t.Error("scheme must recognise core/v1 Secret")
	}
}
