/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package fositepatch

import (
	"testing"

	"github.com/ory/hydra/v2/fosite"
)

// scopeReqWith builds a real *fosite.AccessRequest carrying the given
// requested scopes and client. HandleScopes only depends on the
// ScopeRequester surface, which *fosite.AccessRequest satisfies.
func scopeReqWith(client fosite.Client, requested ...string) *fosite.AccessRequest {
	ar := fosite.NewAccessRequest(&OIDCSession{})
	ar.Client = client
	ar.RequestedScope = fosite.Arguments(requested)
	return ar
}

func contains(args fosite.Arguments, s string) bool {
	for _, a := range args {
		if a == s {
			return true
		}
	}
	return false
}

func count(args fosite.Arguments, s string) int {
	n := 0
	for _, a := range args {
		if a == s {
			n++
		}
	}
	return n
}

// --- HandleScopes --------------------------------------------------------

func TestHandleScopes_GrantsAllRequestedScopes(t *testing.T) {
	client := newTestClient(testClientOpts{scopes: []string{"openid", "profile", "email"}})
	ar := scopeReqWith(client, "openid", "profile", "email")

	HandleScopes(ar, discardLogger())

	granted := ar.GetGrantedScopes()
	for _, want := range []string{"openid", "profile", "email"} {
		if !contains(granted, want) {
			t.Errorf("expected scope %q to be granted, granted=%v", want, granted)
		}
	}
}

func TestHandleScopes_GrantsNothingWhenNoneRequested(t *testing.T) {
	client := newTestClient(testClientOpts{scopes: []string{"openid"}})
	ar := scopeReqWith(client) // no requested scopes

	HandleScopes(ar, discardLogger())

	if got := len(ar.GetGrantedScopes()); got != 0 {
		t.Errorf("expected no granted scopes, got %v", ar.GetGrantedScopes())
	}
}

// HandleScopes grants exactly what was requested. It deliberately does NOT
// re-filter against the client scope list (the comment in scopehandler.go
// notes that out-of-list scopes are rejected upstream). This test pins that
// contract so a future "defensive filter" change is a conscious decision.
func TestHandleScopes_DoesNotFilterAgainstClientScopeList(t *testing.T) {
	client := newTestClient(testClientOpts{scopes: []string{"openid"}})
	ar := scopeReqWith(client, "openid", "not-in-client-list")

	HandleScopes(ar, discardLogger())

	if !contains(ar.GetGrantedScopes(), "not-in-client-list") {
		t.Errorf("HandleScopes should grant requested scopes verbatim, granted=%v", ar.GetGrantedScopes())
	}
}

func TestHandleScopes_ForceOpenIdAddsOpenidWhenNotRequested(t *testing.T) {
	client := newTestClient(testClientOpts{
		scopes:           []string{"openid", "profile"},
		forceOpenIDScope: boolPtr(true),
	})
	ar := scopeReqWith(client, "profile") // openid NOT requested

	HandleScopes(ar, discardLogger())

	if !contains(ar.GetGrantedScopes(), "openid") {
		t.Errorf("force-openid client should have openid granted, granted=%v", ar.GetGrantedScopes())
	}
}

func TestHandleScopes_ForceOpenIdDoesNotDuplicateOpenid(t *testing.T) {
	client := newTestClient(testClientOpts{
		scopes:           []string{"openid"},
		forceOpenIDScope: boolPtr(true),
	})
	ar := scopeReqWith(client, "openid") // already requested

	HandleScopes(ar, discardLogger())

	// fosite.GrantScope dedupes, so openid must appear exactly once.
	if c := count(ar.GetGrantedScopes(), "openid"); c != 1 {
		t.Errorf("openid should be granted exactly once, got %d (granted=%v)", c, ar.GetGrantedScopes())
	}
}

func TestHandleScopes_ForceOpenIdFalseDoesNotAddOpenid(t *testing.T) {
	client := newTestClient(testClientOpts{
		scopes:           []string{"openid", "profile"},
		forceOpenIDScope: boolPtr(false),
	})
	ar := scopeReqWith(client, "profile")

	HandleScopes(ar, discardLogger())

	if contains(ar.GetGrantedScopes(), "openid") {
		t.Errorf("force-openid=false must not inject openid, granted=%v", ar.GetGrantedScopes())
	}
}

// A non-KubauthClient (plain fosite client) must not trip the force-openid
// type assertion. This guards the `if client2, ok := ...` branch.
func TestHandleScopes_NonKubauthClientSkipsForceOpenid(t *testing.T) {
	plain := &fosite.DefaultClient{ID: "plain", Scopes: []string{"profile"}}
	ar := scopeReqWith(plain, "profile")

	HandleScopes(ar, discardLogger())

	if !contains(ar.GetGrantedScopes(), "profile") {
		t.Errorf("requested scope should still be granted for plain client, granted=%v", ar.GetGrantedScopes())
	}
	if contains(ar.GetGrantedScopes(), "openid") {
		t.Errorf("plain client must not get force-openid injection, granted=%v", ar.GetGrantedScopes())
	}
}

// --- HandleAudience ------------------------------------------------------

func audienceReqWith(client fosite.Client, requested ...string) *fosite.AccessRequest {
	ar := fosite.NewAccessRequest(&OIDCSession{})
	ar.Client = client
	ar.RequestedAudience = fosite.Arguments(requested)
	return ar
}

func TestHandleAudience_GrantsRequestedAudience(t *testing.T) {
	client := newTestClient(testClientOpts{clientID: "cid", audiences: []string{"api-a", "api-b"}})
	ar := audienceReqWith(client, "api-a", "api-b")

	HandleAudience(ar, discardLogger())

	granted := ar.GetGrantedAudience()
	for _, want := range []string{"api-a", "api-b"} {
		if !contains(granted, want) {
			t.Errorf("expected audience %q granted, granted=%v", want, granted)
		}
	}
	// client_id must NOT be force-added when explicit audiences are present.
	if contains(granted, "cid") {
		t.Errorf("client_id should not be granted when audience explicitly requested, granted=%v", granted)
	}
}

func TestHandleAudience_DefaultsToClientIdWhenNoneRequested(t *testing.T) {
	client := newTestClient(testClientOpts{clientID: "my-client-id"})
	ar := audienceReqWith(client) // no requested audience

	HandleAudience(ar, discardLogger())

	granted := ar.GetGrantedAudience()
	if len(granted) != 1 || granted[0] != "my-client-id" {
		t.Errorf("expected client_id as sole default audience, got %v", granted)
	}
}

func TestHandleAudience_SingleRequestedAudience(t *testing.T) {
	client := newTestClient(testClientOpts{clientID: "cid", audiences: []string{"only-api"}})
	ar := audienceReqWith(client, "only-api")

	HandleAudience(ar, discardLogger())

	granted := ar.GetGrantedAudience()
	if len(granted) != 1 || granted[0] != "only-api" {
		t.Errorf("expected only-api as sole granted audience, got %v", granted)
	}
}
