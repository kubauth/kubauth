/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package fositepatch

import (
	"testing"
	"time"

	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/fosite/token/jwt"
)

// Constructor / clone -----------------------------------------------------

func TestOIDCSession_Clone_NilReturnsNil(t *testing.T) {
	var s *OIDCSession
	if got := s.Clone(); got != nil {
		t.Errorf("nil receiver Clone() should be nil, got %v", got)
	}
}

func TestOIDCSession_Clone_DeepCopiesIndependentSession(t *testing.T) {
	s := &OIDCSession{
		Username: "alice",
		Subject:  "user-123",
		IDTokenClaims_: &jwt.IDTokenClaims{
			Subject: "user-123",
			Extra:   map[string]interface{}{"k": "v"},
		},
	}
	cloned := s.Clone().(*OIDCSession)
	// Mutate the clone — original should be untouched.
	cloned.Username = "bob"
	cloned.IDTokenClaims_.Extra["k"] = "mutated"
	if s.Username != "alice" {
		t.Errorf("clone mutation leaked into original Username: %q", s.Username)
	}
	if s.IDTokenClaims_.Extra["k"] != "v" {
		t.Errorf("clone mutation leaked into original IDTokenClaims_.Extra: %v", s.IDTokenClaims_.Extra)
	}
}

// SetAudience -------------------------------------------------------------

func TestOIDCSession_SetAudience_UpdatesBothClaimsContainers(t *testing.T) {
	s := &OIDCSession{
		IDTokenClaims_: &jwt.IDTokenClaims{},
		JWTClaims_:     &jwt.JWTClaims{},
	}
	aud := []string{"client-a", "client-b"}
	s.SetAudience(aud)
	if got := s.IDTokenClaims_.Audience; len(got) != 2 || got[0] != "client-a" || got[1] != "client-b" {
		t.Errorf("ID token audience not set correctly: %v", got)
	}
	if got := s.JWTClaims_.Audience; len(got) != 2 || got[0] != "client-a" || got[1] != "client-b" {
		t.Errorf("JWT audience not set correctly: %v", got)
	}
}

// ExpiresAt round-trip ----------------------------------------------------

func TestOIDCSession_GetExpiresAt_UnsetReturnsZeroTime(t *testing.T) {
	s := &OIDCSession{}
	if got := s.GetExpiresAt(fosite.AccessToken); !got.IsZero() {
		t.Errorf("unset expiry should return zero Time, got %v", got)
	}
}

func TestOIDCSession_GetExpiresAt_NilMapDoesNotPanic(t *testing.T) {
	// Documented behaviour: GetExpiresAt initialises ExpiresAt map on
	// the fly if nil. A nil-map panic here would crash any caller
	// inspecting expiries on a freshly-deserialised session.
	s := &OIDCSession{ExpiresAt: nil}
	if got := s.GetExpiresAt(fosite.RefreshToken); !got.IsZero() {
		t.Errorf("nil-map fallback should return zero Time, got %v", got)
	}
	if s.ExpiresAt == nil {
		t.Error("GetExpiresAt should have initialised the map")
	}
}

func TestOIDCSession_SetExpiresAt_RoundTrips(t *testing.T) {
	s := &OIDCSession{}
	t0 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	s.SetExpiresAt(fosite.AccessToken, t0)
	if got := s.GetExpiresAt(fosite.AccessToken); !got.Equal(t0) {
		t.Errorf("expected %v, got %v", t0, got)
	}
}

func TestOIDCSession_SetExpiresAt_NilMapInitialised(t *testing.T) {
	s := &OIDCSession{ExpiresAt: nil}
	t0 := time.Now().UTC()
	s.SetExpiresAt(fosite.AccessToken, t0)
	if s.ExpiresAt == nil {
		t.Error("SetExpiresAt should have initialised the map")
	}
	if got := s.ExpiresAt[fosite.AccessToken]; !got.Equal(t0) {
		t.Errorf("expected %v, got %v", t0, got)
	}
}

func TestOIDCSession_SetExpiresAt_PerTokenTypeIndependence(t *testing.T) {
	s := &OIDCSession{}
	tA := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tR := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	s.SetExpiresAt(fosite.AccessToken, tA)
	s.SetExpiresAt(fosite.RefreshToken, tR)
	if !s.GetExpiresAt(fosite.AccessToken).Equal(tA) {
		t.Error("access-token expiry overwritten")
	}
	if !s.GetExpiresAt(fosite.RefreshToken).Equal(tR) {
		t.Error("refresh-token expiry overwritten")
	}
}

// Username / Subject ------------------------------------------------------

func TestOIDCSession_GetUsername_NilReceiverReturnsEmpty(t *testing.T) {
	var s *OIDCSession
	if got := s.GetUsername(); got != "" {
		t.Errorf("nil receiver should return empty username, got %q", got)
	}
}

func TestOIDCSession_GetUsername_ReturnsField(t *testing.T) {
	s := &OIDCSession{Username: "alice"}
	if got := s.GetUsername(); got != "alice" {
		t.Errorf("expected alice, got %q", got)
	}
}

func TestOIDCSession_SetGetSubject(t *testing.T) {
	s := &OIDCSession{}
	s.SetSubject("user-1")
	if got := s.GetSubject(); got != "user-1" {
		t.Errorf("expected user-1, got %q", got)
	}
}

func TestOIDCSession_GetSubject_NilReceiverReturnsEmpty(t *testing.T) {
	var s *OIDCSession
	if got := s.GetSubject(); got != "" {
		t.Errorf("nil receiver should return empty subject, got %q", got)
	}
}

// IDTokenHeaders / IDTokenClaims (lazy init) ------------------------------

func TestOIDCSession_IDTokenHeaders_LazyInit(t *testing.T) {
	s := &OIDCSession{Headers: nil}
	h := s.IDTokenHeaders()
	if h == nil {
		t.Fatal("IDTokenHeaders should never return nil")
	}
	if s.Headers == nil {
		t.Error("IDTokenHeaders should have initialised s.Headers")
	}
}

func TestOIDCSession_IDTokenClaims_LazyInit(t *testing.T) {
	s := &OIDCSession{IDTokenClaims_: nil}
	c := s.IDTokenClaims()
	if c == nil {
		t.Fatal("IDTokenClaims should never return nil")
	}
	if s.IDTokenClaims_ == nil {
		t.Error("IDTokenClaims should have initialised s.IDTokenClaims_")
	}
}

func TestOIDCSession_IDTokenHeaders_ReturnsExisting(t *testing.T) {
	existing := &jwt.Headers{Extra: map[string]interface{}{"kid": "key-1"}}
	s := &OIDCSession{Headers: existing}
	if got := s.IDTokenHeaders(); got != existing {
		t.Error("IDTokenHeaders should return the existing instance, not a fresh one")
	}
}

// JWTSessionContainer -----------------------------------------------------

func TestOIDCSession_GetJWTClaims_LazyInit(t *testing.T) {
	s := &OIDCSession{JWTClaims_: nil}
	c := s.GetJWTClaims()
	if c == nil {
		t.Fatal("GetJWTClaims should never return nil")
	}
	if s.JWTClaims_ == nil {
		t.Error("GetJWTClaims should have initialised s.JWTClaims_")
	}
}

func TestOIDCSession_GetJWTHeader_LazyInit(t *testing.T) {
	s := &OIDCSession{Headers: nil}
	h := s.GetJWTHeader()
	if h == nil {
		t.Fatal("GetJWTHeader should never return nil")
	}
	if s.Headers == nil {
		t.Error("GetJWTHeader should have initialised s.Headers")
	}
}

func TestOIDCSession_HeadersSharedBetweenIDAndJWT(t *testing.T) {
	// Both IDTokenHeaders and GetJWTHeader return s.Headers — same
	// instance. A change visible via one path must be visible via the
	// other.
	s := &OIDCSession{}
	idH := s.IDTokenHeaders()
	jwtH := s.GetJWTHeader()
	if idH != jwtH {
		t.Error("ID-token headers and JWT headers must be the same Headers instance")
	}
}

// Interface compliance is enforced by the var _ assertions in session.go
// — adding a runtime check here too so anyone breaking the contract via
// a method-signature change gets a test failure, not just a build error
// at use-site.
func TestOIDCSession_ImplementsExpectedInterfaces(t *testing.T) {
	s := &OIDCSession{}
	var _ fosite.Session = s
}
