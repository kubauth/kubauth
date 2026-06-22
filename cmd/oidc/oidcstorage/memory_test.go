/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package oidcstorage

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"kubauth/api/kubauth/v1alpha1"
	"kubauth/cmd/oidc/authenticator"
	"kubauth/cmd/oidc/upstreams"
	"kubauth/internal/proto"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-logr/logr"
	"github.com/ory/hydra/v2/fosite"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// testCtx returns a context carrying a discard slog logger. Several MemoryStore
// methods call logr.FromContextAsSlogLogger(ctx) and panic on a bare context.
func testCtx() context.Context {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return logr.NewContextWithSlogLogger(context.Background(), logger)
}

// newJWK builds a minimal RSA public JWK tagged with keyID, used to seed the
// store's issuer public-key tables.
func newJWK(t *testing.T, keyID string) *jose.JSONWebKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return &jose.JSONWebKey{
		Key:       priv.Public(),
		KeyID:     keyID,
		Algorithm: "RS256",
		Use:       "sig",
	}
}

// ---------------------------------------------------------------- test doubles

// fakeAuthenticator is a configurable authenticator.OidcAuthenticator used to
// drive MemoryStore.Authenticate / AuthenticateUserWithClaims down both the
// success and error branches.
type fakeAuthenticator struct {
	user *authenticator.OidcUser
	err  error
}

func (f *fakeAuthenticator) Identify(_ context.Context, _ string, _ string) (*authenticator.OidcUser, proto.Status, error) {
	return f.user, proto.PasswordChecked, f.err
}

func (f *fakeAuthenticator) Authenticate(_ context.Context, _ string, _ string) (*authenticator.OidcUser, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.user, nil
}

var _ authenticator.OidcAuthenticator = &fakeAuthenticator{}

// newStore builds a MemoryStore with a fake authenticator that returns user.
func newStore(t *testing.T, user *authenticator.OidcUser, authErr error) *MemoryStore {
	t.Helper()
	return NewMemoryStore(&fakeAuthenticator{user: user, err: authErr})
}

// req builds a minimal fosite.Requester with a stable request ID, the value the
// token storage methods index by (GetID()).
func req(id string) fosite.Requester {
	r := fosite.NewRequest()
	r.SetID(id)
	return r
}

// internalUpstream returns a real, network-free upstreams.Upstream of the
// Internal type whose GetName() == name. NewUpstream short-circuits for the
// Internal type and never touches the network.
func internalUpstream(t *testing.T, name string) upstreams.Upstream {
	t.Helper()
	u, err := upstreams.NewUpstream(testCtx(), &v1alpha1.UpstreamProvider{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1alpha1.UpstreamProviderSpec{
			Type:        v1alpha1.UpstreamProviderTypeInternal,
			DisplayName: name + " display",
		},
	}, "", nil)
	if err != nil {
		t.Fatalf("internalUpstream(%q): unexpected error %v", name, err)
	}
	return u
}

// ---------------------------------------------------------------- constructor

func TestNewMemoryStore_InitializesMapsAndAuthenticator(t *testing.T) {
	a := &fakeAuthenticator{}
	s := NewMemoryStore(a)
	if s.Clients == nil || s.AuthorizeCodes == nil || s.IDSessions == nil ||
		s.AccessTokens == nil || s.RefreshTokens == nil || s.PKCES == nil ||
		s.AccessTokenRequestIDs == nil || s.RefreshTokenRequestIDs == nil ||
		s.BlacklistedJTIs == nil || s.IssuerPublicKeys == nil ||
		s.PARSessions == nil || s.Upstreams == nil {
		t.Fatal("NewMemoryStore left one or more maps nil")
	}
	if s.Authenticator != a {
		t.Error("authenticator not wired into the store")
	}
}

// ---------------------------------------------------------------- OIDC session

func TestOpenIDConnectSession_RoundTrip(t *testing.T) {
	ctx := testCtx()
	s := newStore(t, nil, nil)
	want := req("oidc-1")

	if err := s.CreateOpenIDConnectSession(ctx, "code-1", want); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetOpenIDConnectSession(ctx, "code-1", req("oidc-1"))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.GetID() != "oidc-1" {
		t.Errorf("get returned wrong requester id %q", got.GetID())
	}

	if err := s.DeleteOpenIDConnectSession(ctx, "code-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetOpenIDConnectSession(ctx, "code-1", req("oidc-1")); !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("after delete: want ErrNotFound, got %v", err)
	}
}

func TestGetOpenIDConnectSession_NotFound(t *testing.T) {
	s := newStore(t, nil, nil)
	got, err := s.GetOpenIDConnectSession(testCtx(), "missing", req("x"))
	if !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
	if got != nil {
		t.Errorf("want nil requester on miss, got %v", got)
	}
}

func TestDeleteOpenIDConnectSession_MissingIsNoop(t *testing.T) {
	s := newStore(t, nil, nil)
	if err := s.DeleteOpenIDConnectSession(testCtx(), "never-created"); err != nil {
		t.Errorf("deleting an absent session should be a no-op, got %v", err)
	}
}

// ---------------------------------------------------------------- authorize code

func TestAuthorizeCodeSession_RoundTrip(t *testing.T) {
	ctx := testCtx()
	s := newStore(t, nil, nil)

	if err := s.CreateAuthorizeCodeSession(ctx, "ac-1", req("ac-req-1")); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetAuthorizeCodeSession(ctx, "ac-1", nil)
	if err != nil {
		t.Fatalf("get active: %v", err)
	}
	if got.GetID() != "ac-req-1" {
		t.Errorf("wrong requester id %q", got.GetID())
	}
}

func TestGetAuthorizeCodeSession_NotFound(t *testing.T) {
	s := newStore(t, nil, nil)
	if _, err := s.GetAuthorizeCodeSession(testCtx(), "nope", nil); !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

func TestInvalidateAuthorizeCodeSession_MarksInactiveAndStillReturnsRequester(t *testing.T) {
	ctx := testCtx()
	s := newStore(t, nil, nil)
	if err := s.CreateAuthorizeCodeSession(ctx, "ac-2", req("ac-req-2")); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.InvalidateAuthorizeCodeSession(ctx, "ac-2"); err != nil {
		t.Fatalf("invalidate: %v", err)
	}
	// After invalidation Get must surface ErrInvalidatedAuthorizeCode but still
	// hand back the (now inactive) requester so the caller can revoke tokens.
	got, err := s.GetAuthorizeCodeSession(ctx, "ac-2", nil)
	if !errors.Is(err, fosite.ErrInvalidatedAuthorizeCode) {
		t.Errorf("want ErrInvalidatedAuthorizeCode, got %v", err)
	}
	if got == nil {
		t.Error("invalidated code should still return a (non-nil) requester")
	}
}

func TestInvalidateAuthorizeCodeSession_NotFound(t *testing.T) {
	s := newStore(t, nil, nil)
	if err := s.InvalidateAuthorizeCodeSession(testCtx(), "ghost"); !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

// ---------------------------------------------------------------- PKCE

func TestPKCERequestSession_RoundTrip(t *testing.T) {
	ctx := testCtx()
	s := newStore(t, nil, nil)

	if err := s.CreatePKCERequestSession(ctx, "pkce-1", req("pkce-req-1")); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetPKCERequestSession(ctx, "pkce-1", nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.GetID() != "pkce-req-1" {
		t.Errorf("wrong requester id %q", got.GetID())
	}

	if err := s.DeletePKCERequestSession(ctx, "pkce-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetPKCERequestSession(ctx, "pkce-1", nil); !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("after delete: want ErrNotFound, got %v", err)
	}
}

func TestGetPKCERequestSession_NotFound(t *testing.T) {
	s := newStore(t, nil, nil)
	if _, err := s.GetPKCERequestSession(testCtx(), "absent", nil); !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

func TestDeletePKCERequestSession_MissingIsNoop(t *testing.T) {
	s := newStore(t, nil, nil)
	if err := s.DeletePKCERequestSession(testCtx(), "absent"); err != nil {
		t.Errorf("deleting absent pkce should be no-op, got %v", err)
	}
}

// ---------------------------------------------------------------- access token

func TestAccessTokenSession_RoundTripAndRequestIDIndex(t *testing.T) {
	ctx := testCtx()
	s := newStore(t, nil, nil)

	if err := s.CreateAccessTokenSession(ctx, "sig-at-1", req("at-req-1")); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetAccessTokenSession(ctx, "sig-at-1", nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.GetID() != "at-req-1" {
		t.Errorf("wrong requester id %q", got.GetID())
	}
	// The request-ID -> signature side index must be populated for revocation.
	if sig := s.AccessTokenRequestIDs["at-req-1"]; sig != "sig-at-1" {
		t.Errorf("request-id index: got %q, want %q", sig, "sig-at-1")
	}

	if err := s.DeleteAccessTokenSession(ctx, "sig-at-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetAccessTokenSession(ctx, "sig-at-1", nil); !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("after delete: want ErrNotFound, got %v", err)
	}
}

func TestGetAccessTokenSession_NotFound(t *testing.T) {
	s := newStore(t, nil, nil)
	if _, err := s.GetAccessTokenSession(testCtx(), "missing", nil); !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

func TestRevokeAccessToken_DeletesByRequestID(t *testing.T) {
	ctx := testCtx()
	s := newStore(t, nil, nil)
	if err := s.CreateAccessTokenSession(ctx, "sig-at-2", req("at-req-2")); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.RevokeAccessToken(ctx, "at-req-2"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := s.GetAccessTokenSession(ctx, "sig-at-2", nil); !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("revoked token should be gone, got %v", err)
	}
}

func TestRevokeAccessToken_UnknownRequestIDIsNoop(t *testing.T) {
	// Unknown request id is not an error: there is simply nothing to revoke.
	s := newStore(t, nil, nil)
	if err := s.RevokeAccessToken(testCtx(), "never-issued"); err != nil {
		t.Errorf("revoking unknown request id should be a no-op, got %v", err)
	}
}

// ---------------------------------------------------------------- refresh token

func TestRefreshTokenSession_RoundTripAndRequestIDIndex(t *testing.T) {
	ctx := testCtx()
	s := newStore(t, nil, nil)

	if err := s.CreateRefreshTokenSession(ctx, "sig-rt-1", "sig-at-link", req("rt-req-1")); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetRefreshTokenSession(ctx, "sig-rt-1", nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.GetID() != "rt-req-1" {
		t.Errorf("wrong requester id %q", got.GetID())
	}
	if sig := s.RefreshTokenRequestIDs["rt-req-1"]; sig != "sig-rt-1" {
		t.Errorf("request-id index: got %q, want %q", sig, "sig-rt-1")
	}

	if err := s.DeleteRefreshTokenSession(ctx, "sig-rt-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetRefreshTokenSession(ctx, "sig-rt-1", nil); !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("after delete: want ErrNotFound, got %v", err)
	}
}

func TestGetRefreshTokenSession_NotFound(t *testing.T) {
	s := newStore(t, nil, nil)
	if _, err := s.GetRefreshTokenSession(testCtx(), "absent", nil); !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

func TestRevokeRefreshToken_MarksInactiveSoGetReturnsErrInactiveToken(t *testing.T) {
	ctx := testCtx()
	s := newStore(t, nil, nil)
	if err := s.CreateRefreshTokenSession(ctx, "sig-rt-2", "", req("rt-req-2")); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.RevokeRefreshToken(ctx, "rt-req-2"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	got, err := s.GetRefreshTokenSession(ctx, "sig-rt-2", nil)
	if !errors.Is(err, fosite.ErrInactiveToken) {
		t.Errorf("want ErrInactiveToken after revoke, got %v", err)
	}
	if got == nil {
		t.Error("revoked refresh token should still return the inactive requester")
	}
}

func TestRevokeRefreshToken_DanglingIndexReturnsNotFound(t *testing.T) {
	// The request-id index points at a signature that has no RefreshTokens
	// entry (e.g. the token was deleted out of band). Revoke must surface
	// ErrNotFound rather than silently succeeding.
	s := newStore(t, nil, nil)
	s.RefreshTokenRequestIDs["dangling-req"] = "missing-sig"
	if err := s.RevokeRefreshToken(testCtx(), "dangling-req"); !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("want ErrNotFound for dangling index, got %v", err)
	}
}

func TestRevokeRefreshToken_UnknownRequestIDIsNoop(t *testing.T) {
	s := newStore(t, nil, nil)
	if err := s.RevokeRefreshToken(testCtx(), "never-issued"); err != nil {
		t.Errorf("revoking unknown refresh request id should be a no-op, got %v", err)
	}
}

func TestRotateRefreshToken_RevokesBothRefreshAndAccess(t *testing.T) {
	ctx := testCtx()
	s := newStore(t, nil, nil)
	// Same request id ties an access token + refresh token together.
	if err := s.CreateAccessTokenSession(ctx, "sig-at-3", req("shared-req")); err != nil {
		t.Fatalf("create access: %v", err)
	}
	if err := s.CreateRefreshTokenSession(ctx, "sig-rt-3", "sig-at-3", req("shared-req")); err != nil {
		t.Fatalf("create refresh: %v", err)
	}
	if err := s.RotateRefreshToken(ctx, "shared-req", "sig-rt-3"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// Refresh marked inactive ...
	if _, err := s.GetRefreshTokenSession(ctx, "sig-rt-3", nil); !errors.Is(err, fosite.ErrInactiveToken) {
		t.Errorf("refresh should be inactive after rotate, got %v", err)
	}
	// ... and the linked access token deleted.
	if _, err := s.GetAccessTokenSession(ctx, "sig-at-3", nil); !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("access should be deleted after rotate, got %v", err)
	}
}

// ---------------------------------------------------------------- clients

func TestSetGetClient_RoundTrip(t *testing.T) {
	ctx := testCtx()
	s := newStore(t, nil, nil)
	c := NewKubauthClient(sampleOidcClient(), "client-a", nil)

	if err := s.SetClient(ctx, c); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := s.GetKubauthClient(ctx, "client-a")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.GetID() != "client-a" {
		t.Errorf("wrong client id %q", got.GetID())
	}
	// GetClient is the fosite.ClientManager adapter and must return the same client.
	fc, err := s.GetClient(ctx, "client-a")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if fc.GetID() != "client-a" {
		t.Errorf("GetClient wrong id %q", fc.GetID())
	}
}

func TestGetKubauthClient_NotFound(t *testing.T) {
	s := newStore(t, nil, nil)
	got, err := s.GetKubauthClient(testCtx(), "missing")
	if !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
	if got != nil {
		t.Errorf("want nil client, got %v", got)
	}
}

func TestGetClient_NotFound(t *testing.T) {
	s := newStore(t, nil, nil)
	if _, err := s.GetClient(testCtx(), "missing"); !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

func TestSetClient_SameK8sIdOverwrites(t *testing.T) {
	ctx := testCtx()
	s := newStore(t, nil, nil)
	// Re-applying the *same* CR (same namespace:name) under the same client_id
	// must overwrite, not error.
	if err := s.SetClient(ctx, NewKubauthClient(sampleOidcClient(), "dup", nil)); err != nil {
		t.Fatalf("first set: %v", err)
	}
	if err := s.SetClient(ctx, NewKubauthClient(sampleOidcClient(), "dup", nil)); err != nil {
		t.Errorf("re-set with identical k8sId should succeed, got %v", err)
	}
}

func TestSetClient_DifferentK8sIdSameClientIdIsDuplicationError(t *testing.T) {
	ctx := testCtx()
	s := newStore(t, nil, nil)
	if err := s.SetClient(ctx, NewKubauthClient(sampleOidcClient(), "shared-id", nil)); err != nil {
		t.Fatalf("first set: %v", err)
	}
	// Same client_id but a CR from a different namespace -> collision.
	other := sampleOidcClient()
	other.Namespace = "other-namespace"
	err := s.SetClient(ctx, NewKubauthClient(other, "shared-id", nil))
	if err == nil {
		t.Fatal("expected ClientDuplicationError, got nil")
	}
	var dup *ClientDuplicationError
	if !errors.As(err, &dup) {
		t.Fatalf("want *ClientDuplicationError, got %T (%v)", err, err)
	}
	if dup.GetExistingClient() != "kubauth-system:smoke-client" {
		t.Errorf("duplication error names wrong existing client: %q", dup.GetExistingClient())
	}
}

func TestDeleteClient_RemovesAndIsIdempotent(t *testing.T) {
	ctx := testCtx()
	s := newStore(t, nil, nil)
	if err := s.SetClient(ctx, NewKubauthClient(sampleOidcClient(), "del-me", nil)); err != nil {
		t.Fatalf("set: %v", err)
	}
	s.DeleteClient(ctx, "del-me")
	if _, err := s.GetKubauthClient(ctx, "del-me"); !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("after delete: want ErrNotFound, got %v", err)
	}
	// Deleting again must not panic.
	s.DeleteClient(ctx, "del-me")
}

// ---------------------------------------------------------------- token lifespans

func TestSetTokenLifespans_NotFound(t *testing.T) {
	s := newStore(t, nil, nil)
	if err := s.SetTokenLifespans("no-such-client", &fosite.ClientLifespanConfig{}); !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("want ErrNotFound for unknown client, got %v", err)
	}
}

func TestSetTokenLifespans_WrongClientTypeReturnsError(t *testing.T) {
	// kubauthClient implements fosite.Client but is not a
	// *fosite.DefaultClientWithCustomTokenLifespans, so the type assertion in
	// SetTokenLifespans fails and an error (not nil, not ErrNotFound) is returned.
	ctx := testCtx()
	s := newStore(t, nil, nil)
	if err := s.SetClient(ctx, NewKubauthClient(sampleOidcClient(), "wrong-type", nil)); err != nil {
		t.Fatalf("set: %v", err)
	}
	err := s.SetTokenLifespans("wrong-type", &fosite.ClientLifespanConfig{})
	if err == nil {
		t.Fatal("expected a type-assertion error, got nil")
	}
	if errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("expected type-assertion error, not ErrNotFound: %v", err)
	}
}

// ---------------------------------------------------------------- JTI blacklist

func TestClientAssertionJWT_SetThenKnownIsRejected(t *testing.T) {
	ctx := testCtx()
	s := newStore(t, nil, nil)

	// Unknown JTI is valid.
	if err := s.ClientAssertionJWTValid(ctx, "jti-1"); err != nil {
		t.Fatalf("fresh jti should be valid, got %v", err)
	}
	// Blacklist it with a future expiry.
	if err := s.SetClientAssertionJWT(ctx, "jti-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("set jwt: %v", err)
	}
	// Now it is known -> rejected.
	if err := s.ClientAssertionJWTValid(ctx, "jti-1"); !errors.Is(err, fosite.ErrJTIKnown) {
		t.Errorf("blacklisted jti: want ErrJTIKnown, got %v", err)
	}
	// Re-setting a still-live JTI is itself an ErrJTIKnown.
	if err := s.SetClientAssertionJWT(ctx, "jti-1", time.Now().Add(time.Hour)); !errors.Is(err, fosite.ErrJTIKnown) {
		t.Errorf("re-setting live jti: want ErrJTIKnown, got %v", err)
	}
}

func TestClientAssertionJWTValid_ExpiredEntryIsValidAgain(t *testing.T) {
	ctx := testCtx()
	s := newStore(t, nil, nil)
	// An already-expired blacklist entry must not reject the JTI.
	if err := s.SetClientAssertionJWT(ctx, "jti-exp", time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("set jwt: %v", err)
	}
	if err := s.ClientAssertionJWTValid(ctx, "jti-exp"); err != nil {
		t.Errorf("expired jti should validate, got %v", err)
	}
}

func TestSetClientAssertionJWT_PrunesExpiredEntries(t *testing.T) {
	ctx := testCtx()
	s := newStore(t, nil, nil)
	// Seed an expired entry directly, then add a fresh one: the set call prunes
	// expired entries as a side effect.
	s.BlacklistedJTIs["stale"] = time.Now().Add(-time.Hour)
	if err := s.SetClientAssertionJWT(ctx, "fresh", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("set: %v", err)
	}
	if _, ok := s.BlacklistedJTIs["stale"]; ok {
		t.Error("expired entry should have been pruned")
	}
	if _, ok := s.BlacklistedJTIs["fresh"]; !ok {
		t.Error("fresh entry should be present")
	}
}

func TestIsJWTUsed_TracksMarkJWTUsedForTime(t *testing.T) {
	ctx := testCtx()
	s := newStore(t, nil, nil)

	used, err := s.IsJWTUsed(ctx, "jti-used")
	if err != nil {
		t.Fatalf("IsJWTUsed: %v", err)
	}
	if used {
		t.Error("fresh jti should report not used")
	}
	if err := s.MarkJWTUsedForTime(ctx, "jti-used", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("mark: %v", err)
	}
	used, err = s.IsJWTUsed(ctx, "jti-used")
	if err != nil {
		t.Fatalf("IsJWTUsed (2): %v", err)
	}
	if !used {
		t.Error("after MarkJWTUsedForTime the jti must report used")
	}
}

// ---------------------------------------------------------------- PAR sessions

func TestPARSession_RoundTrip(t *testing.T) {
	ctx := testCtx()
	s := newStore(t, nil, nil)
	ar := fosite.NewAuthorizeRequest()
	ar.SetID("par-req-1")

	if err := s.CreatePARSession(ctx, "urn:req:1", ar); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetPARSession(ctx, "urn:req:1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.GetID() != "par-req-1" {
		t.Errorf("wrong PAR requester id %q", got.GetID())
	}

	if err := s.DeletePARSession(ctx, "urn:req:1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetPARSession(ctx, "urn:req:1"); !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("after delete: want ErrNotFound, got %v", err)
	}
}

func TestGetPARSession_NotFound(t *testing.T) {
	s := newStore(t, nil, nil)
	got, err := s.GetPARSession(testCtx(), "urn:absent")
	if !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
	if got != nil {
		t.Errorf("want nil on miss, got %v", got)
	}
}

func TestDeletePARSession_MissingIsNoop(t *testing.T) {
	s := newStore(t, nil, nil)
	if err := s.DeletePARSession(testCtx(), "urn:absent"); err != nil {
		t.Errorf("deleting absent PAR session should be no-op, got %v", err)
	}
}

// ---------------------------------------------------------------- upstreams

func TestUpstream_SetGetDeleteRoundTrip(t *testing.T) {
	ctx := testCtx()
	s := newStore(t, nil, nil)
	up := internalUpstream(t, "up-a")

	s.SetUpstream(ctx, up)
	got := s.GetUpstream(ctx, "up-a")
	if got == nil {
		t.Fatal("GetUpstream returned nil after SetUpstream")
	}
	if got.GetName() != "up-a" {
		t.Errorf("wrong upstream name %q", got.GetName())
	}

	s.DeleteUpstream(ctx, "up-a")
	if got := s.GetUpstream(ctx, "up-a"); got != nil {
		t.Errorf("after delete: want nil, got %v", got)
	}
}

func TestGetUpstream_MissingReturnsNil(t *testing.T) {
	s := newStore(t, nil, nil)
	if got := s.GetUpstream(testCtx(), "nope"); got != nil {
		t.Errorf("missing upstream: want nil, got %v", got)
	}
}

func TestGetUpstreams_ReturnsAllStored(t *testing.T) {
	ctx := testCtx()
	s := newStore(t, nil, nil)
	s.SetUpstream(ctx, internalUpstream(t, "u1"))
	s.SetUpstream(ctx, internalUpstream(t, "u2"))

	all := s.GetUpstreams(ctx)
	if len(all) != 2 {
		t.Fatalf("want 2 upstreams, got %d", len(all))
	}
	names := map[string]bool{}
	for _, u := range all {
		names[u.GetName()] = true
	}
	if !names["u1"] || !names["u2"] {
		t.Errorf("missing upstreams in result: %v", names)
	}
}

func TestGetUpstreams_EmptyStoreReturnsEmpty(t *testing.T) {
	s := newStore(t, nil, nil)
	if all := s.GetUpstreams(testCtx()); len(all) != 0 {
		t.Errorf("empty store: want 0 upstreams, got %d", len(all))
	}
}

func TestDeleteUpstream_MissingIsNoop(t *testing.T) {
	s := newStore(t, nil, nil)
	s.DeleteUpstream(testCtx(), "absent") // must not panic
}

// ---------------------------------------------------------------- authenticate

func TestAuthenticate_ReturnsLoginOnSuccess(t *testing.T) {
	s := newStore(t, &authenticator.OidcUser{Login: "alice"}, nil)
	sub, err := s.Authenticate(testCtx(), "alice", "pw")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if sub != "alice" {
		t.Errorf("subject: got %q, want alice", sub)
	}
}

func TestAuthenticate_PropagatesErrorAndEmptySubject(t *testing.T) {
	wantErr := errors.New("bad creds")
	s := newStore(t, nil, wantErr)
	sub, err := s.Authenticate(testCtx(), "alice", "wrong")
	if !errors.Is(err, wantErr) {
		t.Errorf("want propagated auth error, got %v", err)
	}
	if sub != "" {
		t.Errorf("subject should be empty on failure, got %q", sub)
	}
}

func TestAuthenticateUserWithClaims_ReturnsFullUser(t *testing.T) {
	user := &authenticator.OidcUser{
		Login:    "bob",
		FullName: "Bob Builder",
		Claims:   map[string]interface{}{"email": "bob@example.com"},
	}
	s := newStore(t, user, nil)
	got, err := s.AuthenticateUserWithClaims(testCtx(), "bob", "pw")
	if err != nil {
		t.Fatalf("authenticate with claims: %v", err)
	}
	if got == nil || got.Login != "bob" || got.FullName != "Bob Builder" {
		t.Fatalf("unexpected user %+v", got)
	}
	if got.Claims["email"] != "bob@example.com" {
		t.Errorf("claims not carried through: %v", got.Claims)
	}
}

func TestAuthenticateUserWithClaims_PropagatesError(t *testing.T) {
	wantErr := errors.New("nope")
	s := newStore(t, nil, wantErr)
	if _, err := s.AuthenticateUserWithClaims(testCtx(), "x", "y"); !errors.Is(err, wantErr) {
		t.Errorf("want propagated error, got %v", err)
	}
}

// ---------------------------------------------------------------- config getters

func TestConfigGetters(t *testing.T) {
	s := newStore(t, nil, nil)
	s.Issuer = "https://issuer.example"
	s.KeyID = "kid-7"
	s.AllowPasswordGrant = true

	if s.GetIssuer() != "https://issuer.example" {
		t.Errorf("GetIssuer: %q", s.GetIssuer())
	}
	if s.GetKeyID() != "kid-7" {
		t.Errorf("GetKeyID: %q", s.GetKeyID())
	}
	if !s.IsAllowPasswordGrant() {
		t.Error("IsAllowPasswordGrant: want true")
	}
}

func TestIsAllowPasswordGrant_DefaultFalse(t *testing.T) {
	s := newStore(t, nil, nil)
	if s.IsAllowPasswordGrant() {
		t.Error("default AllowPasswordGrant should be false")
	}
}

// ---------------------------------------------------------------- public keys

// jtiKey builds a tiny RSA JWK keyed by keyID with the given scopes and wires it
// into the store's IssuerPublicKeys nested maps under issuer/subject.
func seedPublicKey(t *testing.T, s *MemoryStore, issuer, subject, keyID string, scopes []string) {
	t.Helper()
	jwk := newJWK(t, keyID)
	s.IssuerPublicKeys[issuer] = IssuerPublicKeys{
		Issuer: issuer,
		KeysBySub: map[string]SubjectPublicKeys{
			subject: {
				Subject: subject,
				Keys: map[string]PublicKeyScopes{
					keyID: {Key: jwk, Scopes: scopes},
				},
			},
		},
	}
}

func TestGetPublicKey_FoundAndNotFound(t *testing.T) {
	s := newStore(t, nil, nil)
	seedPublicKey(t, s, "iss", "sub", "k1", []string{"read"})

	got, err := s.GetPublicKey(testCtx(), "iss", "sub", "k1")
	if err != nil {
		t.Fatalf("get public key: %v", err)
	}
	if got == nil || got.KeyID != "k1" {
		t.Fatalf("unexpected key %+v", got)
	}
	// Wrong key id / subject / issuer all yield ErrNotFound.
	for _, tc := range []struct{ iss, sub, kid string }{
		{"iss", "sub", "missing-kid"},
		{"iss", "missing-sub", "k1"},
		{"missing-iss", "sub", "k1"},
	} {
		if _, err := s.GetPublicKey(testCtx(), tc.iss, tc.sub, tc.kid); !errors.Is(err, fosite.ErrNotFound) {
			t.Errorf("GetPublicKey(%v): want ErrNotFound, got %v", tc, err)
		}
	}
}

func TestGetPublicKeys_ReturnsKeySetAndNotFound(t *testing.T) {
	s := newStore(t, nil, nil)
	seedPublicKey(t, s, "iss", "sub", "k1", nil)

	set, err := s.GetPublicKeys(testCtx(), "iss", "sub")
	if err != nil {
		t.Fatalf("get public keys: %v", err)
	}
	if set == nil || len(set.Keys) != 1 || set.Keys[0].KeyID != "k1" {
		t.Fatalf("unexpected key set %+v", set)
	}
	if _, err := s.GetPublicKeys(testCtx(), "iss", "missing"); !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("missing subject: want ErrNotFound, got %v", err)
	}
}

func TestGetPublicKeys_SubjectWithNoKeysIsNotFound(t *testing.T) {
	// A subject entry that exists but carries an empty key map must be treated
	// as not-found rather than returning an empty key set.
	s := newStore(t, nil, nil)
	s.IssuerPublicKeys["iss"] = IssuerPublicKeys{
		Issuer: "iss",
		KeysBySub: map[string]SubjectPublicKeys{
			"sub": {Subject: "sub", Keys: map[string]PublicKeyScopes{}},
		},
	}
	if _, err := s.GetPublicKeys(testCtx(), "iss", "sub"); !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("subject with no keys: want ErrNotFound, got %v", err)
	}
}

func TestGetPublicKeyScopes_FoundAndNotFound(t *testing.T) {
	s := newStore(t, nil, nil)
	seedPublicKey(t, s, "iss", "sub", "k1", []string{"read", "write"})

	scopes, err := s.GetPublicKeyScopes(testCtx(), "iss", "sub", "k1")
	if err != nil {
		t.Fatalf("get scopes: %v", err)
	}
	if len(scopes) != 2 || scopes[0] != "read" || scopes[1] != "write" {
		t.Errorf("unexpected scopes %v", scopes)
	}
	if _, err := s.GetPublicKeyScopes(testCtx(), "iss", "sub", "missing"); !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("missing key id: want ErrNotFound, got %v", err)
	}
}

// ---------------------------------------------------------------- self-providers

func TestStorageProviderAccessors_ReturnSelf(t *testing.T) {
	// The fosite.Storage facade methods must all hand back the store itself,
	// since MemoryStore implements every sub-storage interface.
	s := newStore(t, nil, nil)
	if s.ClientManager() != s {
		t.Error("ClientManager should return self")
	}
	if s.AccessTokenStorage() != s {
		t.Error("AccessTokenStorage should return self")
	}
	if s.RefreshTokenStorage() != s {
		t.Error("RefreshTokenStorage should return self")
	}
	if s.AuthorizeCodeStorage() != s {
		t.Error("AuthorizeCodeStorage should return self")
	}
	if s.OpenIDConnectRequestStorage() != s {
		t.Error("OpenIDConnectRequestStorage should return self")
	}
	if s.PKCERequestStorage() != s {
		t.Error("PKCERequestStorage should return self")
	}
	if s.PARStorage() != s {
		t.Error("PARStorage should return self")
	}
	if s.TokenRevocationStorage() != s {
		t.Error("TokenRevocationStorage should return self")
	}
	if s.RFC7523KeyStorage() != s {
		t.Error("RFC7523KeyStorage should return self")
	}
}
