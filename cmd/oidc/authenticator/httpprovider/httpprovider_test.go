/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package httpprovider

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"kubauth/cmd/oidc/authenticator"
	"kubauth/internal/httpclient"
	"kubauth/internal/proto"

	"github.com/go-logr/logr"
)

// testCtx returns a context carrying a discard slog logger. Identify calls
// logr.FromContextAsSlogLogger(ctx) and would panic on a bare context.
func testCtx() context.Context {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return logr.NewContextWithSlogLogger(context.Background(), logger)
}

// newProvider stands up an httptest server answering the v1/identity exchange
// with resp, and returns a provider wired to it through the real http client.
func newProvider(t *testing.T, resp proto.IdentityResponse) authenticator.OidcAuthenticator {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if r.URL.Path != "/v1/identity" {
			t.Errorf("path = %q, want /v1/identity", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	p, err := New(&httpclient.Config{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

// toStringSlice normalizes a claim value (either []string after enrichment or
// []interface{} straight from JSON) into a []string for comparison.
func toStringSlice(t *testing.T, v interface{}) []string {
	t.Helper()
	switch s := v.(type) {
	case nil:
		return nil
	case []string:
		return s
	case []interface{}:
		out := make([]string, 0, len(s))
		for _, e := range s {
			str, ok := e.(string)
			if !ok {
				t.Fatalf("claim element %v (%T) is not a string", e, e)
			}
			out = append(out, str)
		}
		return out
	default:
		t.Fatalf("claim value %v (%T) is not a string slice", v, v)
		return nil
	}
}

// TestIdentify_FederatesGroupsAndEmailsFromClaims is the regression test for the
// claims-federation bug: groups/emails carried *inside* the claims map must be
// merged with the dedicated User.Groups / User.Emails fields, not dropped.
func TestIdentify_FederatesGroupsAndEmailsFromClaims(t *testing.T) {
	resp := proto.IdentityResponse{
		Status: proto.PasswordChecked,
		User: proto.User{
			Login:  "alice",
			Groups: []string{"dedicated-grp"},
			Emails: []string{"alice@corp.io"},
			Claims: map[string]interface{}{
				"groups": []string{"claim-grp"},
				"emails": []string{"alice-alt@corp.io"},
			},
		},
	}
	user, status, err := newProvider(t, resp).Identify(testCtx(), "alice", "secret")
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if status != proto.PasswordChecked {
		t.Errorf("status = %q, want %q", status, proto.PasswordChecked)
	}
	// DedupAndSort => sorted ascending.
	if got, want := toStringSlice(t, user.Claims["groups"]), []string{"claim-grp", "dedicated-grp"}; !slices.Equal(got, want) {
		t.Errorf("claims[groups] = %v, want %v (group carried in claims must be federated)", got, want)
	}
	// AppendIfNotPresent => order preserved (dedicated first, then claim-carried).
	if got, want := toStringSlice(t, user.Claims["emails"]), []string{"alice@corp.io", "alice-alt@corp.io"}; !slices.Equal(got, want) {
		t.Errorf("claims[emails] = %v, want %v (email carried in claims must be federated)", got, want)
	}
}

func TestIdentify_EnrichesNameUidAuthorityEmail(t *testing.T) {
	uid := 4242
	resp := proto.IdentityResponse{
		Status:    proto.PasswordChecked,
		Authority: "corp-idp",
		User: proto.User{
			Login:  "bob",
			Name:   "Bob Smith",
			Uid:    &uid,
			Emails: []string{"bob@corp.io", "bob2@corp.io"},
			Claims: map[string]interface{}{},
		},
	}
	user, _, err := newProvider(t, resp).Identify(testCtx(), "bob", "pw")
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if user.FullName != "Bob Smith" {
		t.Errorf("FullName = %q, want %q", user.FullName, "Bob Smith")
	}
	if user.Claims["name"] != "Bob Smith" {
		t.Errorf("claims[name] = %v, want %q", user.Claims["name"], "Bob Smith")
	}
	if user.Claims["authority"] != "corp-idp" {
		t.Errorf("claims[authority] = %v, want %q", user.Claims["authority"], "corp-idp")
	}
	if uidv, ok := user.Claims["uid"].(int); !ok || uidv != 4242 {
		t.Errorf("claims[uid] = %v (%T), want int 4242", user.Claims["uid"], user.Claims["uid"])
	}
	if user.Claims["email"] != "bob@corp.io" {
		t.Errorf("claims[email] = %v, want first email %q", user.Claims["email"], "bob@corp.io")
	}
	if got, want := toStringSlice(t, user.Claims["emails"]), []string{"bob@corp.io", "bob2@corp.io"}; !slices.Equal(got, want) {
		t.Errorf("claims[emails] = %v, want %v", got, want)
	}
}

func TestIdentify_PropagatesStatus(t *testing.T) {
	resp := proto.IdentityResponse{
		Status: proto.PasswordFail,
		User:   proto.User{Login: "carol", Claims: map[string]interface{}{}},
	}
	user, status, err := newProvider(t, resp).Identify(testCtx(), "carol", "bad")
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if status != proto.PasswordFail {
		t.Errorf("status = %q, want %q", status, proto.PasswordFail)
	}
	if user == nil || user.Login != "carol" {
		t.Errorf("user = %+v, want login carol regardless of password status", user)
	}
}

func TestIdentify_ErrorOnNonArrayClaim(t *testing.T) {
	resp := proto.IdentityResponse{
		Status: proto.PasswordChecked,
		User:   proto.User{Login: "erin", Claims: map[string]interface{}{"groups": 123}},
	}
	if _, _, err := newProvider(t, resp).Identify(testCtx(), "erin", "pw"); err == nil {
		t.Fatal("expected error when claims[groups] is not a string array, got nil")
	}
}

func TestIdentify_SingleStringClaimGroup(t *testing.T) {
	resp := proto.IdentityResponse{
		Status: proto.PasswordChecked,
		User:   proto.User{Login: "frank", Claims: map[string]interface{}{"groups": "solo"}},
	}
	user, _, err := newProvider(t, resp).Identify(testCtx(), "frank", "pw")
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got, want := toStringSlice(t, user.Claims["groups"]), []string{"solo"}; !slices.Equal(got, want) {
		t.Errorf("claims[groups] = %v, want %v (a single string claim becomes a one-element group)", got, want)
	}
}

func TestAuthenticate_ReturnsUserWhenPasswordChecked(t *testing.T) {
	resp := proto.IdentityResponse{
		Status: proto.PasswordChecked,
		User:   proto.User{Login: "dave", Claims: map[string]interface{}{}},
	}
	user, err := newProvider(t, resp).Authenticate(testCtx(), "dave", "pw")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if user == nil || user.Login != "dave" {
		t.Errorf("user = %+v, want authenticated user dave", user)
	}
}

func TestAuthenticate_NilWhenNotPasswordChecked(t *testing.T) {
	for _, st := range []proto.Status{proto.PasswordFail, proto.PasswordUnchecked, proto.UserNotFound, proto.Disabled} {
		resp := proto.IdentityResponse{
			Status: st,
			User:   proto.User{Login: "x", Claims: map[string]interface{}{}},
		}
		user, err := newProvider(t, resp).Authenticate(testCtx(), "x", "pw")
		if err != nil {
			t.Fatalf("status %q: Authenticate: %v", st, err)
		}
		if user != nil {
			t.Errorf("status %q: user = %+v, want nil (not authenticated)", st, user)
		}
	}
}

func TestIdentifyAndAuthenticate_PropagateHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	p, err := New(&httpclient.Config{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, err := p.Identify(testCtx(), "x", "pw"); err == nil {
		t.Error("Identify: expected error on HTTP 500, got nil")
	}
	if _, err := p.Authenticate(testCtx(), "x", "pw"); err == nil {
		t.Error("Authenticate: expected error on HTTP 500, got nil")
	}
}

func TestNew_InvalidURL(t *testing.T) {
	if _, err := New(&httpclient.Config{BaseURL: "ftp://example.com"}); err == nil {
		t.Fatal("expected error for non-http(s) URL scheme, got nil")
	}
}
