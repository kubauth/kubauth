/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package oidcstorage

import (
	"reflect"
	"testing"
	"time"

	"kubauth/api/kubauth/v1alpha1"

	"github.com/ory/hydra/v2/fosite"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// helpers ----------------------------------------------------------------

func boolPtr(b bool) *bool { return &b }

func sampleOidcClient() *v1alpha1.OidcClient {
	return &v1alpha1.OidcClient{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kubauth-system",
			Name:      "smoke-client",
		},
		Spec: v1alpha1.OidcClientSpec{
			RedirectURIs:  []string{"https://app/callback", "https://app/cb"},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email"},
			Audiences:     []string{"smoke-client", "another-aud"},
			Public:        false,
			Description:   "test client",
			EntryURL:      "https://app/",
			PostLogoutURL: "https://app/logged-out",
			DisplayName:   "Smoke Client",
			Style:         "default",
			UpstreamProviders:   []string{"up-public"},
			AccessTokenLifespan: metav1.Duration{Duration: 30 * time.Minute},
			IDTokenLifespan:     metav1.Duration{Duration: 5 * time.Minute},
			// RefreshTokenLifespan left zero — fallback applies.
		},
	}
}

// Constructor + identity -------------------------------------------------

func TestNewKubauthClient_PopulatesIDsAndK8sId(t *testing.T) {
	cli := sampleOidcClient()
	hashes := [][]byte{[]byte("hash-a"), []byte("hash-b")}
	c := NewKubauthClient(cli, "smoke-client", hashes)
	if c.GetID() != "smoke-client" {
		t.Errorf("GetID: got %q", c.GetID())
	}
	// k8sId is `<namespace>:<name>` — used to detect cross-namespace
	// duplicate registrations.
	if c.GetK8sId() != "kubauth-system:smoke-client" {
		t.Errorf("GetK8sId: got %q", c.GetK8sId())
	}
}

func TestGetK8sObject_ReturnsSameInstance(t *testing.T) {
	cli := sampleOidcClient()
	c := NewKubauthClient(cli, "id", nil)
	if c.GetK8sObject() != cli {
		t.Error("GetK8sObject must return the original CR pointer (no copy)")
	}
}

// Hashed secrets ---------------------------------------------------------

func TestSecrets_NilSlicesGiveNilAndZero(t *testing.T) {
	c := NewKubauthClient(sampleOidcClient(), "id", nil)
	if got := c.GetHashedSecret(); got != nil {
		t.Errorf("nil secrets: GetHashedSecret should be nil, got %v", got)
	}
	if got := c.GetRotatedHashes(); got != nil {
		t.Errorf("nil secrets: GetRotatedHashes should be nil, got %v", got)
	}
	if c.GetSecretCount() != 0 {
		t.Errorf("nil secrets: count should be 0, got %d", c.GetSecretCount())
	}
}

func TestSecrets_FirstIsActiveRestAreRotated(t *testing.T) {
	c := NewKubauthClient(sampleOidcClient(), "id", [][]byte{
		[]byte("active"), []byte("rot1"), []byte("rot2"),
	})
	if string(c.GetHashedSecret()) != "active" {
		t.Errorf("active secret should be the first, got %q", c.GetHashedSecret())
	}
	rot := c.GetRotatedHashes()
	if len(rot) != 2 || string(rot[0]) != "rot1" || string(rot[1]) != "rot2" {
		t.Errorf("rotated secrets wrong: %v", rot)
	}
	if c.GetSecretCount() != 3 {
		t.Errorf("count: got %d", c.GetSecretCount())
	}
}

func TestSecrets_OnlyOneSecret_NoRotated(t *testing.T) {
	c := NewKubauthClient(sampleOidcClient(), "id", [][]byte{[]byte("only")})
	if rot := c.GetRotatedHashes(); rot != nil && len(rot) != 0 {
		t.Errorf("single-secret client: rotated should be empty, got %v", rot)
	}
}

// Spec accessors (mirrored fields) ---------------------------------------

func TestSpecAccessors_ReturnSpecFields(t *testing.T) {
	cli := sampleOidcClient()
	c := NewKubauthClient(cli, "smoke-client", nil)
	cases := []struct {
		name string
		got  any
		want any
	}{
		{"RedirectURIs", c.GetRedirectURIs(), []string{"https://app/callback", "https://app/cb"}},
		{"GrantTypes", []string(c.GetGrantTypes()), []string{"authorization_code", "refresh_token"}},
		{"ResponseTypes", []string(c.GetResponseTypes()), []string{"code"}},
		{"Scopes", []string(c.GetScopes()), []string{"openid", "profile", "email"}},
		{"IsPublic", c.IsPublic(), false},
		{"Description", c.GetDescription(), "test client"},
		{"EntryURL", c.GetEntryURL(), "https://app/"},
		{"PostLogoutURL", c.GetPostLogoutURL(), "https://app/logged-out"},
		{"DisplayName", c.GetDisplayName(), "Smoke Client"},
		{"Style", c.GetStyle(), "default"},
		{"UpstreamProviders", c.GetUpstreamProviders(), []string{"up-public"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !reflect.DeepEqual(tc.got, tc.want) {
				t.Errorf("got %v, want %v", tc.got, tc.want)
			}
		})
	}
}

// IsForceOpenIdScope (nil ptr handling) ----------------------------------

func TestIsForceOpenIdScope_NilDefaultsFalse(t *testing.T) {
	cli := sampleOidcClient() // ForceOpenIdScope unset
	c := NewKubauthClient(cli, "id", nil)
	if c.IsForceOpenIdScope() {
		t.Error("nil pointer should default to false")
	}
}

func TestIsForceOpenIdScope_TrueWhenSet(t *testing.T) {
	cli := sampleOidcClient()
	cli.Spec.ForceOpenIdScope = boolPtr(true)
	c := NewKubauthClient(cli, "id", nil)
	if !c.IsForceOpenIdScope() {
		t.Error("expected true")
	}
}

func TestIsForceOpenIdScope_FalseWhenSet(t *testing.T) {
	cli := sampleOidcClient()
	cli.Spec.ForceOpenIdScope = boolPtr(false)
	c := NewKubauthClient(cli, "id", nil)
	if c.IsForceOpenIdScope() {
		t.Error("expected false")
	}
}

// GetAudience (auto-include client_id) -----------------------------------

func TestGetAudience_IncludesClientIdWhenNotPresent(t *testing.T) {
	// HandleAudience() in fosite defaults to granting client_id when no
	// audience is explicitly requested. Kubauth allows it implicitly.
	cli := sampleOidcClient()
	cli.Spec.Audiences = []string{"only-aud"} // no smoke-client
	c := NewKubauthClient(cli, "smoke-client", nil)
	got := c.GetAudience()
	found := false
	for _, a := range got {
		if a == "smoke-client" {
			found = true
		}
	}
	if !found {
		t.Errorf("client id should be appended to audiences, got %v", got)
	}
}

func TestGetAudience_ReturnsAsIsWhenClientIdAlreadyPresent(t *testing.T) {
	cli := sampleOidcClient() // contains "smoke-client" in audiences
	c := NewKubauthClient(cli, "smoke-client", nil)
	got := c.GetAudience()
	count := 0
	for _, a := range got {
		if a == "smoke-client" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("client id should appear exactly once when already in spec, got %d", count)
	}
}

// GetEffectiveLifespan ---------------------------------------------------

func TestGetEffectiveLifespan_AccessTokenUsesSpecValue(t *testing.T) {
	cli := sampleOidcClient() // AccessTokenLifespan = 30m
	c := NewKubauthClient(cli, "id", nil).(fosite.ClientWithCustomTokenLifespans)
	got := c.GetEffectiveLifespan(fosite.GrantTypeAuthorizationCode, fosite.AccessToken, time.Hour)
	if got != 30*time.Minute {
		t.Errorf("expected 30m, got %v", got)
	}
}

func TestGetEffectiveLifespan_IDTokenUsesSpecValue(t *testing.T) {
	cli := sampleOidcClient() // IDTokenLifespan = 5m
	c := NewKubauthClient(cli, "id", nil).(fosite.ClientWithCustomTokenLifespans)
	got := c.GetEffectiveLifespan(fosite.GrantTypeAuthorizationCode, fosite.IDToken, time.Hour)
	if got != 5*time.Minute {
		t.Errorf("expected 5m, got %v", got)
	}
}

func TestGetEffectiveLifespan_RefreshTokenUnsetUsesFallback(t *testing.T) {
	cli := sampleOidcClient() // RefreshTokenLifespan unset (zero)
	c := NewKubauthClient(cli, "id", nil).(fosite.ClientWithCustomTokenLifespans)
	fallback := 7 * 24 * time.Hour
	got := c.GetEffectiveLifespan(fosite.GrantTypeAuthorizationCode, fosite.RefreshToken, fallback)
	if got != fallback {
		t.Errorf("expected fallback %v, got %v", fallback, got)
	}
}

func TestGetEffectiveLifespan_AccessTokenUnsetUsesFallback(t *testing.T) {
	cli := sampleOidcClient()
	cli.Spec.AccessTokenLifespan = metav1.Duration{} // zero
	c := NewKubauthClient(cli, "id", nil).(fosite.ClientWithCustomTokenLifespans)
	fallback := 90 * time.Minute
	got := c.GetEffectiveLifespan(fosite.GrantTypeAuthorizationCode, fosite.AccessToken, fallback)
	if got != fallback {
		t.Errorf("expected fallback %v, got %v", fallback, got)
	}
}

func TestGetEffectiveLifespan_UnknownTokenTypeUsesFallback(t *testing.T) {
	c := NewKubauthClient(sampleOidcClient(), "id", nil).(fosite.ClientWithCustomTokenLifespans)
	fallback := 13 * time.Second
	got := c.GetEffectiveLifespan(fosite.GrantTypeAuthorizationCode, fosite.TokenType("unknown"), fallback)
	if got != fallback {
		t.Errorf("expected fallback for unknown token type, got %v", fallback)
	}
}
