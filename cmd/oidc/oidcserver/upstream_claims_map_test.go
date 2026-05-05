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

func TestMapUpstreamClaimsToUserClaims_NilClaimsErrors(t *testing.T) {
	user, err := mapUpstreamClaimsToUserClaims(nil)
	if err == nil {
		t.Fatalf("expected error for nil claims, got user=%+v", user)
	}
	if user != nil {
		t.Errorf("expected nil user on error, got %+v", user)
	}
}

func TestMapUpstreamClaimsToUserClaims_MissingSubErrors(t *testing.T) {
	user, err := mapUpstreamClaimsToUserClaims(map[string]interface{}{
		"name": "alice",
	})
	if err == nil {
		t.Fatalf("expected error for missing sub, got user=%+v", user)
	}
}

func TestMapUpstreamClaimsToUserClaims_EmptySubErrors(t *testing.T) {
	user, err := mapUpstreamClaimsToUserClaims(map[string]interface{}{
		"sub":  "",
		"name": "alice",
	})
	if err == nil {
		t.Fatalf("expected error for empty sub, got user=%+v", user)
	}
}

func TestMapUpstreamClaimsToUserClaims_NonStringSubErrors(t *testing.T) {
	user, err := mapUpstreamClaimsToUserClaims(map[string]interface{}{
		"sub": 12345, // int — type assertion fails, sub becomes "" → error
	})
	if err == nil {
		t.Fatalf("expected error for non-string sub, got user=%+v", user)
	}
}

func TestMapUpstreamClaimsToUserClaims_LoginPrefersPreferredUsername(t *testing.T) {
	user, err := mapUpstreamClaimsToUserClaims(map[string]interface{}{
		"sub":                "user-uuid-1234",
		"preferred_username": "alice",
		"email":              "alice@example.org",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Login != "alice" {
		t.Errorf("expected Login=alice (from preferred_username), got %q", user.Login)
	}
}

func TestMapUpstreamClaimsToUserClaims_LoginFallsBackToEmail(t *testing.T) {
	user, err := mapUpstreamClaimsToUserClaims(map[string]interface{}{
		"sub":   "user-uuid-1234",
		"email": "alice@example.org",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Login != "alice@example.org" {
		t.Errorf("expected Login=alice@example.org (from email), got %q", user.Login)
	}
}

func TestMapUpstreamClaimsToUserClaims_LoginFallsBackToSub(t *testing.T) {
	user, err := mapUpstreamClaimsToUserClaims(map[string]interface{}{
		"sub": "user-uuid-1234",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Login != "user-uuid-1234" {
		t.Errorf("expected Login=user-uuid-1234 (from sub), got %q", user.Login)
	}
}

func TestMapUpstreamClaimsToUserClaims_EmptyPreferredUsernameSkipsToEmail(t *testing.T) {
	user, err := mapUpstreamClaimsToUserClaims(map[string]interface{}{
		"sub":                "user-uuid-1234",
		"preferred_username": "",
		"email":              "alice@example.org",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Login != "alice@example.org" {
		t.Errorf("empty preferred_username should fall through to email, got Login=%q", user.Login)
	}
}

func TestMapUpstreamClaimsToUserClaims_FullNameFromName(t *testing.T) {
	user, err := mapUpstreamClaimsToUserClaims(map[string]interface{}{
		"sub":  "x",
		"name": "Alice Wonderland",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.FullName != "Alice Wonderland" {
		t.Errorf("expected FullName='Alice Wonderland', got %q", user.FullName)
	}
}

func TestMapUpstreamClaimsToUserClaims_FullNameEmptyWhenAbsent(t *testing.T) {
	user, err := mapUpstreamClaimsToUserClaims(map[string]interface{}{
		"sub": "x",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.FullName != "" {
		t.Errorf("expected FullName='' when name absent, got %q", user.FullName)
	}
}

func TestMapUpstreamClaimsToUserClaims_ClaimsAreFullyCopied(t *testing.T) {
	in := map[string]interface{}{
		"sub":   "user-1",
		"name":  "Alice",
		"email": "alice@example.org",
		"custom_field": map[string]interface{}{
			"nested": "value",
		},
	}
	user, err := mapUpstreamClaimsToUserClaims(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(user.Claims, in) {
		t.Errorf("Claims should be a copy of input. got=%v want=%v", user.Claims, in)
	}
}

func TestMapUpstreamClaimsToUserClaims_ClaimsCopyIsIndependent(t *testing.T) {
	// The function copies the input map — mutating the result must
	// NOT affect the caller's map (defensive isolation).
	in := map[string]interface{}{
		"sub":  "user-1",
		"name": "Alice",
	}
	user, err := mapUpstreamClaimsToUserClaims(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	user.Claims["injected"] = "leak"
	if _, ok := in["injected"]; ok {
		t.Errorf("mutation of user.Claims leaked back into input map")
	}
}
