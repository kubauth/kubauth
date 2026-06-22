/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package provider

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"kubauth/cmd/merger/config"
	"kubauth/internal/httpclient"
	"kubauth/internal/proto"

	"github.com/go-logr/logr"
)

func testCtx() context.Context {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return logr.NewContextWithSlogLogger(context.Background(), logger)
}

// newProvider wires a provider to an httptest server running handler h, after
// pointing cfg.HttpConfig at it. cfg is mutated by New (defaults applied).
func newProvider(t *testing.T, cfg *config.IdProviderConfig, h http.HandlerFunc) Provider {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	cfg.HttpConfig.BaseURL = srv.URL
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func respHandler(t *testing.T, resp proto.IdentityResponse) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}
}

func errHandler(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "boom", http.StatusInternalServerError)
}

func TestNew_AppliesDefaults(t *testing.T) {
	cfg := &config.IdProviderConfig{Name: "p1", HttpConfig: httpclient.Config{BaseURL: "http://example.com"}}
	if _, err := New(cfg); err != nil {
		t.Fatalf("New: %v", err)
	}
	if cfg.GroupPattern != "%s" {
		t.Errorf("GroupPattern default = %q, want %q", cfg.GroupPattern, "%s")
	}
	if cfg.ClaimPattern != "%s" {
		t.Errorf("ClaimPattern default = %q, want %q", cfg.ClaimPattern, "%s")
	}
	for name, b := range map[string]*bool{
		"Credential": cfg.CredentialAuthority,
		"Group":      cfg.GroupAuthority,
		"Claim":      cfg.ClaimAuthority,
		"Name":       cfg.NameAuthority,
		"Email":      cfg.EmailAuthority,
		"Critical":   cfg.Critical,
	} {
		if b == nil || !*b {
			t.Errorf("%sAuthority default = %v, want true", name, b)
		}
	}
}

func TestNew_InvalidURL(t *testing.T) {
	cfg := &config.IdProviderConfig{Name: "p", HttpConfig: httpclient.Config{BaseURL: "ftp://example.com"}}
	if _, err := New(cfg); err == nil {
		t.Fatal("expected error for non-http(s) URL scheme, got nil")
	}
}

func TestGetUserDetail_SuccessTranslatesGroupsClaimsUid(t *testing.T) {
	uid := 1000
	resp := proto.IdentityResponse{
		Status: proto.PasswordChecked,
		User: proto.User{
			Login:  "alice",
			Uid:    &uid,
			Groups: []string{"admin", "dev"},
			Claims: map[string]interface{}{"team": "blue"},
		},
	}
	cfg := &config.IdProviderConfig{Name: "ldap", GroupPattern: "ext:%s", ClaimPattern: "c_%s", UidOffset: 10000}
	ud, err := newProvider(t, cfg, respHandler(t, resp)).GetUserDetail(testCtx(), "alice", "pw")
	if err != nil {
		t.Fatalf("GetUserDetail: %v", err)
	}
	if ud.Status != proto.PasswordChecked {
		t.Errorf("status = %q, want %q", ud.Status, proto.PasswordChecked)
	}
	if got, want := ud.Translated.Groups, []string{"ext:admin", "ext:dev"}; !slices.Equal(got, want) {
		t.Errorf("translated groups = %v, want %v (GroupPattern applied)", got, want)
	}
	if ud.Translated.Claims["c_team"] != "blue" {
		t.Errorf("translated claims[c_team] = %v, want %q (ClaimPattern applied to key)", ud.Translated.Claims["c_team"], "blue")
	}
	if ud.Translated.Uid == nil || *ud.Translated.Uid != 11000 {
		t.Errorf("translated uid = %v, want 11000 (uid 1000 + offset 10000)", ud.Translated.Uid)
	}
	if ud.Provider.Name != "ldap" {
		t.Errorf("provider name = %q, want %q", ud.Provider.Name, "ldap")
	}
	if ud.User.Login != "alice" {
		t.Errorf("user passed through = %q, want alice", ud.User.Login)
	}
}

func TestGetUserDetail_CriticalFailureReturnsError(t *testing.T) {
	// Critical defaults to true.
	cfg := &config.IdProviderConfig{Name: "p"}
	ud, err := newProvider(t, cfg, errHandler).GetUserDetail(testCtx(), "x", "pw")
	if err == nil {
		t.Fatal("a critical provider must propagate the failure as an error")
	}
	if ud != nil {
		t.Errorf("want nil userDetail on critical failure, got %+v", ud)
	}
}

func TestGetUserDetail_NonCriticalFailureFailsSoft(t *testing.T) {
	no := false
	cfg := &config.IdProviderConfig{Name: "p", Critical: &no}
	ud, err := newProvider(t, cfg, errHandler).GetUserDetail(testCtx(), "ghost", "pw")
	if err != nil {
		t.Fatalf("a non-critical provider must not error on failure: %v", err)
	}
	if ud == nil {
		t.Fatal("non-critical failure must return a placeholder userDetail, got nil")
	}
	if ud.Status != proto.Undefined {
		t.Errorf("status = %q, want %q", ud.Status, proto.Undefined)
	}
	if ud.User.Login != "ghost" {
		t.Errorf("user = %q, want InitUser(ghost)", ud.User.Login)
	}
	if ud.Provider.Name != "p" {
		t.Errorf("provider name = %q, want p", ud.Provider.Name)
	}
}

func TestGetName(t *testing.T) {
	cfg := &config.IdProviderConfig{Name: "my-idp", HttpConfig: httpclient.Config{BaseURL: "http://example.com"}}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.GetName() != "my-idp" {
		t.Errorf("GetName() = %q, want my-idp", p.GetName())
	}
}
