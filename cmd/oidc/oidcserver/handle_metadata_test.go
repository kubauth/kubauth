/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package oidcserver

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/http"
	"testing"
)

// ============================================================ JWKS endpoint

func TestJWKS_ReturnsSingleKeyMatchingSigningKey(t *testing.T) {
	ts := buildServer(t)

	rr := ts.do(newGet(t, "/.well-known/jwks.json"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type: got %q", ct)
	}

	body := decodeJSON(t, rr)
	keysAny, ok := body["keys"].([]interface{})
	if !ok || len(keysAny) != 1 {
		t.Fatalf("expected exactly one key, got %v", body["keys"])
	}
	jwk, ok := keysAny[0].(map[string]interface{})
	if !ok {
		t.Fatalf("key is not an object: %T", keysAny[0])
	}

	// Static metadata.
	for k, want := range map[string]string{"kty": "RSA", "use": "sig", "alg": "RS256"} {
		if got, _ := jwk[k].(string); got != want {
			t.Errorf("jwk[%q]: got %q, want %q", k, got, want)
		}
	}
	// kid must equal the kid loaded from the secret (deterministic in the fixture).
	if got, _ := jwk["kid"].(string); got != ts.kid {
		t.Errorf("kid: got %q, want %q", got, ts.kid)
	}

	// The n/e components must reconstruct the fixture's public key exactly.
	pub := ts.key.Public().(*rsa.PublicKey)
	wantN := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	wantE := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	if got, _ := jwk["n"].(string); got != wantN {
		t.Errorf("modulus n mismatch\n got %s\nwant %s", got, wantN)
	}
	if got, _ := jwk["e"].(string); got != wantE {
		t.Errorf("exponent e mismatch: got %q, want %q", got, wantE)
	}

	// And the decoded n must equal the real modulus (defends against a future
	// encoding change that round-trips through base64 but corrupts the number).
	nDecoded, err := base64.RawURLEncoding.DecodeString(jwk["n"].(string))
	if err != nil {
		t.Fatalf("decode n: %v", err)
	}
	if new(big.Int).SetBytes(nDecoded).Cmp(pub.N) != 0 {
		t.Error("decoded modulus does not equal the signing key modulus")
	}
}

// ====================================================== OIDC configuration

func TestOpenIDConfiguration_CoreEndpointsDerivedFromIssuer(t *testing.T) {
	ts := buildServer(t)

	rr := ts.do(newGet(t, "/.well-known/openid-configuration"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type: got %q", ct)
	}

	cfg := decodeJSON(t, rr)
	wantEndpoints := map[string]string{
		"issuer":                 testIssuer,
		"authorization_endpoint": testIssuer + "/oauth2/auth",
		"token_endpoint":         testIssuer + "/oauth2/token",
		"userinfo_endpoint":      testIssuer + "/userinfo",
		"end_session_endpoint":   testIssuer + "/oauth2/logout",
		"jwks_uri":               testIssuer + "/.well-known/jwks.json",
		"introspection_endpoint": testIssuer + "/oauth2/introspect",
	}
	for k, want := range wantEndpoints {
		if got, _ := cfg[k].(string); got != want {
			t.Errorf("%s: got %q, want %q", k, got, want)
		}
	}
	if got, _ := cfg["id_token_signing_alg_values_supported"].([]interface{}); len(got) != 1 || got[0] != "RS256" {
		t.Errorf("signing algs: got %v, want [RS256]", cfg["id_token_signing_alg_values_supported"])
	}
}

func TestOpenIDConfiguration_GrantTypesOmitPasswordByDefault(t *testing.T) {
	ts := buildServer(t) // AllowPasswordGrant defaults to false

	cfg := decodeJSON(t, ts.do(newGet(t, "/.well-known/openid-configuration")))
	if containsString(toStrings(cfg["grant_types_supported"]), "password") {
		t.Errorf("password grant must not be advertised when disabled: %v", cfg["grant_types_supported"])
	}
}

func TestOpenIDConfiguration_GrantTypesIncludePasswordWhenEnabled(t *testing.T) {
	ts := buildServer(t, func(o *buildOpts) { o.allowPasswordGrant = true })

	cfg := decodeJSON(t, ts.do(newGet(t, "/.well-known/openid-configuration")))
	if !containsString(toStrings(cfg["grant_types_supported"]), "password") {
		t.Errorf("password grant must be advertised when enabled: %v", cfg["grant_types_supported"])
	}
}

func TestOpenIDConfiguration_PKCEMethods_S256Only_ByDefault(t *testing.T) {
	ts := buildServer(t) // AllowPKCEPlain defaults to false

	cfg := decodeJSON(t, ts.do(newGet(t, "/.well-known/openid-configuration")))
	methods := toStrings(cfg["code_challenge_methods_supported"])
	if !containsString(methods, "S256") {
		t.Errorf("S256 must always be supported, got %v", methods)
	}
	if containsString(methods, "plain") {
		t.Errorf("plain must not be advertised when not allowed, got %v", methods)
	}
}

func TestOpenIDConfiguration_PKCEMethods_IncludePlainWhenAllowed(t *testing.T) {
	ts := buildServer(t)
	ts.srv.AllowPKCEPlain = true // getSupportedPKCEMethods reads this field directly

	cfg := decodeJSON(t, ts.do(newGet(t, "/.well-known/openid-configuration")))
	methods := toStrings(cfg["code_challenge_methods_supported"])
	if !containsString(methods, "plain") || !containsString(methods, "S256") {
		t.Errorf("expected both S256 and plain, got %v", methods)
	}
}

// getSupportedPKCEMethods is exercised indirectly above, but the unit-level
// branch is asserted here for clarity and to pin the "always S256" invariant.
func TestGetSupportedPKCEMethods_Unit(t *testing.T) {
	s := &OIDCServer{AllowPKCEPlain: false}
	if got := s.getSupportedPKCEMethods(); len(got) != 1 || got[0] != "S256" {
		t.Errorf("disabled: got %v, want [S256]", got)
	}
	s.AllowPKCEPlain = true
	got := s.getSupportedPKCEMethods()
	if len(got) != 2 || got[0] != "S256" || got[1] != "plain" {
		t.Errorf("enabled: got %v, want [S256 plain]", got)
	}
}

// ----------------------------------------------------------------- helpers

func toStrings(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
