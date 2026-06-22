/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package oidcserver

import (
	"reflect"
	"testing"
)

func TestMapUpstreamClaimsToUser_NilClaims_Errors(t *testing.T) {
	u, err := mapUpstreamClaimsToUser(nil)
	if err == nil {
		t.Fatal("nil claims must return an error")
	}
	if u != nil {
		t.Errorf("user must be nil on error, got %+v", u)
	}
}

func TestMapUpstreamClaimsToUser_MissingSub_Errors(t *testing.T) {
	u, err := mapUpstreamClaimsToUser(map[string]interface{}{"name": "Bob"})
	if err == nil {
		t.Fatal("claims without sub must return an error")
	}
	if u != nil {
		t.Errorf("user must be nil when sub is missing, got %+v", u)
	}
}

func TestMapUpstreamClaimsToUser_EmptySub_Errors(t *testing.T) {
	// sub present but empty is treated as missing.
	_, err := mapUpstreamClaimsToUser(map[string]interface{}{"sub": ""})
	if err == nil {
		t.Fatal("empty sub must return an error")
	}
}

func TestMapUpstreamClaimsToUser_NonStringSub_Errors(t *testing.T) {
	// A non-string sub fails the `claims["sub"].(string)` assertion -> "".
	_, err := mapUpstreamClaimsToUser(map[string]interface{}{"sub": 12345})
	if err == nil {
		t.Fatal("non-string sub must return an error")
	}
}

func TestMapUpstreamClaimsToUser_LoginIsSubAndClaimsPreserved(t *testing.T) {
	claims := map[string]interface{}{
		"sub":    "user-42",
		"name":   "Carol Coder",
		"email":  "carol@test",
		"groups": []string{"a", "b"},
	}
	u, err := mapUpstreamClaimsToUser(claims)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Login != "user-42" {
		t.Errorf("login must equal sub: got %q", u.Login)
	}
	if u.FullName != "Carol Coder" {
		t.Errorf("fullName must come from the name claim: got %q", u.FullName)
	}
	// The original claim map is carried through verbatim (same contents).
	if !reflect.DeepEqual(u.Claims, claims) {
		t.Errorf("claims not preserved: got %v, want %v", u.Claims, claims)
	}
}

func TestMapUpstreamClaimsToUser_MissingName_EmptyFullName(t *testing.T) {
	u, err := mapUpstreamClaimsToUser(map[string]interface{}{"sub": "user-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.FullName != "" {
		t.Errorf("missing name claim must yield empty FullName, got %q", u.FullName)
	}
}

func TestMapUpstreamClaimsToUser_NonStringName_EmptyFullName(t *testing.T) {
	u, err := mapUpstreamClaimsToUser(map[string]interface{}{"sub": "user-1", "name": 99})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.FullName != "" {
		t.Errorf("non-string name must yield empty FullName, got %q", u.FullName)
	}
}
