/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package oidcserver

import (
	"net/http"
	"testing"
)

// accessTokenForUser runs the full code flow and returns an opaque/JWT access
// token plus the token-response map, for use by userinfo / introspection tests.
func (ts *testServer) accessTokenForUser(t *testing.T, scope string) string {
	t.Helper()
	q := authzQuery(testClientID, scope, nil)
	code := ts.loginForCode(t, q, testUserLogin, testUserPassword)
	tokens, rr := ts.exchangeCode(t, code, testClientID, testClientSecret, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("token exchange failed: %d %q", rr.Code, rr.Body.String())
	}
	return mustString(t, tokens, "access_token")
}

// ============================================ /userinfo

func TestUserInfo_ValidBearer_ReturnsSubAndMappedClaims(t *testing.T) {
	ts := buildServer(t)
	accessToken := ts.accessTokenForUser(t, "openid profile email groups")

	req := newGet(t, "/userinfo")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := ts.do(req)

	if rr.Code != http.StatusOK {
		t.Fatalf("userinfo: got %d body=%q", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type: got %q", ct)
	}
	claims := decodeJSON(t, rr)
	if sub, _ := claims["sub"].(string); sub != testUserLogin {
		t.Errorf("sub: got %q, want %q", sub, testUserLogin)
	}
	if email, _ := claims["email"].(string); email != "alice@test" {
		t.Errorf("email claim: got %q, want alice@test", email)
	}
	if name, _ := claims["name"].(string); name != "Alice Example" {
		t.Errorf("name claim: got %q", name)
	}
	// azp is explicitly stripped from the userinfo response by the handler.
	if _, present := claims["azp"]; present {
		t.Error("azp must not be exposed via /userinfo")
	}
}

func TestUserInfo_MissingAuthorizationHeader_Returns401(t *testing.T) {
	ts := buildServer(t)

	rr := ts.do(newGet(t, "/userinfo"))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no auth header: got %d, want 401", rr.Code)
	}
	if wa := rr.Header().Get("WWW-Authenticate"); wa == "" {
		t.Error("a 401 from userinfo must carry a WWW-Authenticate challenge")
	}
}

func TestUserInfo_NonBearerScheme_Returns401(t *testing.T) {
	ts := buildServer(t)

	req := newGet(t, "/userinfo")
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rr := ts.do(req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("non-bearer scheme: got %d, want 401 body=%q", rr.Code, rr.Body.String())
	}
}

func TestUserInfo_GarbageToken_Returns401(t *testing.T) {
	ts := buildServer(t)

	req := newGet(t, "/userinfo")
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	rr := ts.do(req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("garbage token: got %d, want 401 body=%q", rr.Code, rr.Body.String())
	}
	if wa := rr.Header().Get("WWW-Authenticate"); wa == "" {
		t.Error("invalid token must yield a WWW-Authenticate challenge")
	}
}

func TestUserInfo_JwtAccessTokenMode_StillResolvesClaims(t *testing.T) {
	ts := buildServer(t, func(o *buildOpts) { o.jwtAccessToken = true })
	accessToken := ts.accessTokenForUser(t, "openid email")

	req := newGet(t, "/userinfo")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := ts.do(req)

	if rr.Code != http.StatusOK {
		t.Fatalf("userinfo (jwt mode): got %d body=%q", rr.Code, rr.Body.String())
	}
	claims := decodeJSON(t, rr)
	if sub, _ := claims["sub"].(string); sub != testUserLogin {
		t.Errorf("sub: got %q, want %q", sub, testUserLogin)
	}
}
