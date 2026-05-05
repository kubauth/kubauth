/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package fositepatch

import (
	"reflect"
	"sort"
	"testing"
)

// Helpers ------------------------------------------------------------------

func keysSorted(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// alwaysAllowedClaims is a package-level var; its keys must always appear
// in the allowed set regardless of the granted scopes. This helper builds
// the expected union for a test case.
func expectedAllowedKeys(extraScopes ...string) []string {
	all := map[string]struct{}{}
	for k := range alwaysAllowedClaims {
		all[k] = struct{}{}
	}
	for _, sc := range extraScopes {
		for _, c := range claimsByScope[sc] {
			all[c] = struct{}{}
		}
	}
	return keysSorted(all)
}

// Tests --------------------------------------------------------------------

func TestAllowedIDTokenClaimsFor_NoScopesYieldsOnlyProtocolClaims(t *testing.T) {
	got := AllowedIDTokenClaimsFor(nil)
	if !reflect.DeepEqual(keysSorted(got), expectedAllowedKeys()) {
		t.Errorf("got %v, want only alwaysAllowedClaims", keysSorted(got))
	}
	// `sub` is a top-level IDTokenClaims field, not an Extra entry —
	// must NOT appear in the Extra-claim allow-set.
	if _, ok := got["sub"]; ok {
		t.Errorf("`sub` leaked into Extra allow-set")
	}
}

func TestAllowedIDTokenClaimsFor_OpenIDScopeAddsNothing(t *testing.T) {
	// Per OIDC Core, `openid` itself doesn't grant Extra claims —
	// `sub` is top-level, not an Extra.
	withOpenID := AllowedIDTokenClaimsFor([]string{"openid"})
	without := AllowedIDTokenClaimsFor(nil)
	if !reflect.DeepEqual(keysSorted(withOpenID), keysSorted(without)) {
		t.Errorf("openid scope should add no Extra claims; got diff:\n  with=%v\n  without=%v",
			keysSorted(withOpenID), keysSorted(without))
	}
}

func TestAllowedIDTokenClaimsFor_ProfileScopeAddsProfileClaims(t *testing.T) {
	got := AllowedIDTokenClaimsFor([]string{"profile"})
	for _, want := range []string{"name", "family_name", "given_name", "preferred_username", "picture", "locale"} {
		if _, ok := got[want]; !ok {
			t.Errorf("profile scope missing claim %q", want)
		}
	}
	if _, ok := got["email"]; ok {
		t.Errorf("profile scope must NOT grant `email`")
	}
}

func TestAllowedIDTokenClaimsFor_GroupsScopeAddsGroupsClaim(t *testing.T) {
	got := AllowedIDTokenClaimsFor([]string{"groups"})
	if _, ok := got["groups"]; !ok {
		t.Errorf("groups scope must grant `groups` claim")
	}
}

func TestAllowedIDTokenClaimsFor_AlwaysAllowedSurviveScopelessCall(t *testing.T) {
	got := AllowedIDTokenClaimsFor(nil)
	for k := range alwaysAllowedClaims {
		if _, ok := got[k]; !ok {
			t.Errorf("alwaysAllowed claim %q missing from result", k)
		}
	}
}

func TestAllowedIDTokenClaimsFor_KubauthExtensionsArePresent(t *testing.T) {
	// `authority` and `uid` are kubauth-specific extensions guaranteed
	// to ride every id_token regardless of scope (downstream tooling
	// relies on them).
	got := AllowedIDTokenClaimsFor(nil)
	for _, want := range []string{"authority", "uid"} {
		if _, ok := got[want]; !ok {
			t.Errorf("kubauth extension claim %q must be in alwaysAllowed", want)
		}
	}
}

func TestAllowedIDTokenClaimsFor_RatIsExplicitlyExcluded(t *testing.T) {
	// `rat` (fosite/hydra "requested at") is intentionally excluded —
	// strict OIDC RPs flag it as non-spec. See scope_filter.go comment.
	got := AllowedIDTokenClaimsFor([]string{"openid", "profile", "email", "groups", "address", "phone"})
	if _, ok := got["rat"]; ok {
		t.Errorf("`rat` must NOT be in the allowed set under any scope combination")
	}
}

func TestAllowedIDTokenClaimsFor_UnknownScopesIgnored(t *testing.T) {
	got := AllowedIDTokenClaimsFor([]string{"this-is-not-a-real-scope", "neither-is-this"})
	if !reflect.DeepEqual(keysSorted(got), expectedAllowedKeys()) {
		t.Errorf("unknown scopes should yield same set as no scopes; got %v", keysSorted(got))
	}
}

func TestFilterExtraClaimsByScope_DropsUnauthorisedClaims(t *testing.T) {
	extra := map[string]interface{}{
		"name":          "alice",
		"email":         "alice@example.org",
		"groups":        []string{"admin"},
		"phone_number":  "+33-123",
		"address":       "1 rue Test",
		"rat":           1730000000, // fosite leak — must be dropped
		"authority":     "ucrd",     // kubauth extension — must stay
		"unknown_claim": "leak-me",  // not in allow-list — must be dropped
	}
	got := FilterExtraClaimsByScope(extra, []string{"openid", "profile", "email"})
	if _, ok := got["name"]; !ok {
		t.Errorf("`name` should survive (granted by `profile`)")
	}
	if _, ok := got["email"]; !ok {
		t.Errorf("`email` should survive (granted by `email` scope)")
	}
	if _, ok := got["authority"]; !ok {
		t.Errorf("`authority` should survive (alwaysAllowed)")
	}
	for _, k := range []string{"groups", "phone_number", "address", "rat", "unknown_claim"} {
		if _, ok := got[k]; ok {
			t.Errorf("%q should be dropped under scopes [openid profile email]", k)
		}
	}
}

func TestFilterExtraClaimsByScope_NilExtraReturnsNil(t *testing.T) {
	if got := FilterExtraClaimsByScope(nil, []string{"openid", "profile"}); got != nil {
		t.Errorf("nil input must yield nil, got %v", got)
	}
}

func TestFilterExtraClaimsByScope_EmptyExtraStaysEmpty(t *testing.T) {
	in := map[string]interface{}{}
	got := FilterExtraClaimsByScope(in, []string{"openid", "profile"})
	if len(got) != 0 {
		t.Errorf("empty input must yield empty map, got %v", got)
	}
}

func TestFilterExtraClaimsByScope_MutatesAndReturnsSameMap(t *testing.T) {
	// Documented behaviour: mutates the passed-in map. A future
	// refactor that breaks this contract is a behavioural change
	// callers must opt into.
	extra := map[string]interface{}{"name": "alice", "leak": "x"}
	got := FilterExtraClaimsByScope(extra, []string{"profile"})
	// Same map identity: pointer-comparable via reflect on map header
	// (Go maps are reference types — checking via len and identity
	// of the original is the idiomatic way).
	if &got == nil || len(extra) != len(got) {
		t.Errorf("expected same map, got different — extra=%v got=%v", extra, got)
	}
	if _, ok := extra["leak"]; ok {
		t.Errorf("expected mutation: `leak` should have been deleted from the original map")
	}
}

func TestFilterExtraClaimsByScope_AllScopesGranted(t *testing.T) {
	extra := map[string]interface{}{
		"name":          "alice",
		"email":         "alice@example.org",
		"groups":        []string{"admin"},
		"phone_number":  "+33-123",
		"address":       "1 rue Test",
	}
	got := FilterExtraClaimsByScope(extra, []string{"openid", "profile", "email", "groups", "address", "phone"})
	for _, want := range []string{"name", "email", "groups", "phone_number", "address"} {
		if _, ok := got[want]; !ok {
			t.Errorf("with all scopes, %q should remain", want)
		}
	}
}
