/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package oidcserver

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v3/jwt"
)

// ============================================ authorization_code happy path

func TestToken_AuthorizationCode_IssuesTokensAndIDToken(t *testing.T) {
	ts := buildServer(t)

	q := authzQuery(testClientID, "openid profile email groups", nil)
	code := ts.loginForCode(t, q, testUserLogin, testUserPassword)

	tokens, rr := ts.exchangeCode(t, code, testClientID, testClientSecret, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("token endpoint: got %d body=%q", rr.Code, rr.Body.String())
	}

	accessToken := mustString(t, tokens, "access_token")
	if tt, _ := tokens["token_type"].(string); !strings.EqualFold(tt, "bearer") {
		t.Errorf("token_type: got %q, want bearer", tt)
	}
	if _, ok := tokens["expires_in"]; !ok {
		t.Error("expires_in missing from token response")
	}

	// openid scope requested => an ID token must be present and well-formed.
	rawID := mustString(t, tokens, "id_token")
	claims := parseSignedClaims(t, ts, rawID)
	if sub, _ := claims["sub"].(string); sub != testUserLogin {
		t.Errorf("id_token sub: got %q, want %q", sub, testUserLogin)
	}
	if iss, _ := claims["iss"].(string); iss != testIssuer {
		t.Errorf("id_token iss: got %q, want %q", iss, testIssuer)
	}
	if aud := claims["aud"]; !audienceContains(aud, testClientID) {
		t.Errorf("id_token aud must contain client id, got %v", aud)
	}
	// azp is added by newSession for non-empty client id.
	if azp, _ := claims["azp"].(string); azp != testClientID {
		t.Errorf("id_token azp: got %q, want %q", azp, testClientID)
	}
	// Mapped user claims must propagate into the ID token.
	if email, _ := claims["email"].(string); email != "alice@test" {
		t.Errorf("id_token email: got %q", email)
	}

	if accessToken == "" {
		t.Error("empty access token")
	}
}

func TestToken_AuthorizationCode_IDTokenSignatureVerifiesAgainstJWKS(t *testing.T) {
	ts := buildServer(t)

	q := authzQuery(testClientID, "openid", nil)
	code := ts.loginForCode(t, q, testUserLogin, testUserPassword)
	tokens, rr := ts.exchangeCode(t, code, testClientID, testClientSecret, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("token endpoint failed: %d %q", rr.Code, rr.Body.String())
	}
	rawID := mustString(t, tokens, "id_token")

	// Parsing with the public key is the real signature check.
	tok, err := jwt.ParseSigned(rawID)
	if err != nil {
		t.Fatalf("parse id_token: %v", err)
	}
	out := map[string]interface{}{}
	if err := tok.Claims(ts.key.Public(), &out); err != nil {
		t.Fatalf("id_token signature verification failed: %v", err)
	}
	// Header kid must point at the advertised JWKS kid.
	if len(tok.Headers) == 0 || tok.Headers[0].KeyID != ts.kid {
		t.Errorf("id_token kid header: got %+v, want %q", tok.Headers, ts.kid)
	}
}

// ============================================ refresh_token grant

func TestToken_RefreshToken_RotatesAndReturnsNewAccessToken(t *testing.T) {
	ts := buildServer(t)

	// offline_access (or offline scope) is required for a refresh token.
	q := authzQuery(testClientID, "openid offline", nil)
	code := ts.loginForCode(t, q, testUserLogin, testUserPassword)
	tokens, rr := ts.exchangeCode(t, code, testClientID, testClientSecret, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("initial exchange failed: %d %q", rr.Code, rr.Body.String())
	}
	refreshToken := mustString(t, tokens, "refresh_token")
	firstAccess := mustString(t, tokens, "access_token")

	// Now redeem the refresh token.
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("scope", "openid offline")
	req := newPostForm(t, "/oauth2/token", form)
	req.SetBasicAuth(testClientID, testClientSecret)
	rr2 := ts.do(req)
	if rr2.Code != http.StatusOK {
		t.Fatalf("refresh exchange: got %d body=%q", rr2.Code, rr2.Body.String())
	}
	refreshed := decodeJSON(t, rr2)
	newAccess := mustString(t, refreshed, "access_token")
	if newAccess == firstAccess {
		t.Error("refresh should mint a different access token")
	}
	if _, ok := refreshed["id_token"]; !ok {
		t.Error("refresh with openid scope should return a fresh id_token")
	}
}

func TestToken_RefreshToken_OldTokenInvalidAfterRotation(t *testing.T) {
	ts := buildServer(t)

	q := authzQuery(testClientID, "openid offline", nil)
	code := ts.loginForCode(t, q, testUserLogin, testUserPassword)
	tokens, _ := ts.exchangeCode(t, code, testClientID, testClientSecret, nil)
	refreshToken := mustString(t, tokens, "refresh_token")

	redeem := func() *http.Response {
		form := url.Values{}
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", refreshToken)
		req := newPostForm(t, "/oauth2/token", form)
		req.SetBasicAuth(testClientID, testClientSecret)
		return ts.do(req).Result()
	}

	res1 := redeem()
	defer func() { _ = res1.Body.Close() }()
	if res1.StatusCode != http.StatusOK {
		t.Fatalf("first refresh redemption should succeed, got %d", res1.StatusCode)
	}
	// Reusing the same (now-rotated) refresh token must fail.
	res2 := redeem()
	defer func() { _ = res2.Body.Close() }()
	if res2.StatusCode == http.StatusOK {
		t.Error("reusing a rotated refresh token must not succeed")
	}
}

// ============================================ client_credentials grant

func TestToken_ClientCredentials_GrantsConfiguredScopes(t *testing.T) {
	ts := buildServer(t)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "openid profile")
	req := newPostForm(t, "/oauth2/token", form)
	req.SetBasicAuth(testClientID, testClientSecret)

	rr := ts.do(req)
	if rr.Code != http.StatusOK {
		t.Fatalf("client_credentials: got %d body=%q", rr.Code, rr.Body.String())
	}
	tokens := decodeJSON(t, rr)
	if _, ok := tokens["access_token"].(string); !ok {
		t.Errorf("client_credentials must return an access_token, got %v", tokens)
	}
	// client_credentials is not a user flow: no id_token.
	if _, ok := tokens["id_token"]; ok {
		t.Error("client_credentials must not return an id_token")
	}
}

// ============================================ error paths

func TestToken_UnknownClient_ReturnsInvalidClient(t *testing.T) {
	ts := buildServer(t)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	req := newPostForm(t, "/oauth2/token", form)
	req.SetBasicAuth("ghost-client", "whatever")

	rr := ts.do(req)
	if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown client: got %d body=%q", rr.Code, rr.Body.String())
	}
	body := decodeJSON(t, rr)
	if errCode, _ := body["error"].(string); errCode != "invalid_client" {
		t.Errorf("expected invalid_client, got %q (%v)", errCode, body)
	}
}

func TestToken_WrongClientSecret_ReturnsInvalidClient(t *testing.T) {
	ts := buildServer(t)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	req := newPostForm(t, "/oauth2/token", form)
	req.SetBasicAuth(testClientID, "wrong-secret")

	rr := ts.do(req)
	body := decodeJSON(t, rr)
	if errCode, _ := body["error"].(string); errCode != "invalid_client" {
		t.Errorf("expected invalid_client for bad secret, got %q (%v)", errCode, body)
	}
}

func TestToken_UnsupportedGrantType_IsRejected(t *testing.T) {
	ts := buildServer(t)

	form := url.Values{}
	form.Set("grant_type", "totally_made_up")
	req := newPostForm(t, "/oauth2/token", form)
	req.SetBasicAuth(testClientID, testClientSecret)

	rr := ts.do(req)
	if rr.Code == http.StatusOK {
		t.Fatalf("unsupported grant type must not succeed, body=%q", rr.Body.String())
	}
	body := decodeJSON(t, rr)
	if errCode, _ := body["error"].(string); errCode == "" {
		t.Errorf("expected an OAuth2 error code, got %v", body)
	}
}

func TestToken_AuthorizationCode_CannotBeRedeemedTwice(t *testing.T) {
	ts := buildServer(t)

	q := authzQuery(testClientID, "openid", nil)
	code := ts.loginForCode(t, q, testUserLogin, testUserPassword)

	_, rr1 := ts.exchangeCode(t, code, testClientID, testClientSecret, nil)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first redemption should succeed, got %d body=%q", rr1.Code, rr1.Body.String())
	}
	// Replaying the same code must be rejected (and per RFC, fosite revokes
	// previously issued tokens — we only assert the rejection here).
	_, rr2 := ts.exchangeCode(t, code, testClientID, testClientSecret, nil)
	if rr2.Code == http.StatusOK {
		t.Fatalf("replayed authorization code must be rejected, body=%q", rr2.Body.String())
	}
	body := decodeJSON(t, rr2)
	if errCode, _ := body["error"].(string); errCode == "" {
		t.Errorf("expected an error code on code replay, got %v", body)
	}
}

func TestToken_AuthorizationCode_WrongRedirectURIRejected(t *testing.T) {
	ts := buildServer(t)

	q := authzQuery(testClientID, "openid", nil)
	code := ts.loginForCode(t, q, testUserLogin, testUserPassword)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://evil.test/steal") // not the one used to obtain the code
	req := newPostForm(t, "/oauth2/token", form)
	req.SetBasicAuth(testClientID, testClientSecret)

	rr := ts.do(req)
	if rr.Code == http.StatusOK {
		t.Fatalf("redirect_uri mismatch must be rejected, body=%q", rr.Body.String())
	}
	body := decodeJSON(t, rr)
	if errCode, _ := body["error"].(string); errCode == "" {
		t.Errorf("expected error code on redirect_uri mismatch, got %v", body)
	}
}

// ============================================ JWT access token mode

func TestToken_JwtAccessTokenMode_AccessTokenIsVerifiableJWT(t *testing.T) {
	ts := buildServer(t, func(o *buildOpts) { o.jwtAccessToken = true })

	q := authzQuery(testClientID, "openid profile", nil)
	code := ts.loginForCode(t, q, testUserLogin, testUserPassword)
	tokens, rr := ts.exchangeCode(t, code, testClientID, testClientSecret, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("token exchange failed: %d %q", rr.Code, rr.Body.String())
	}
	accessToken := mustString(t, tokens, "access_token")

	// In JWT-access-token mode the access token itself is a signed JWT.
	tok, err := jwt.ParseSigned(accessToken)
	if err != nil {
		t.Fatalf("access token is not a parseable JWT: %v", err)
	}
	out := map[string]interface{}{}
	if err := tok.Claims(ts.key.Public(), &out); err != nil {
		t.Fatalf("JWT access token signature did not verify: %v", err)
	}
	if sub, _ := out["sub"].(string); sub != testUserLogin {
		t.Errorf("JWT access token sub: got %q, want %q", sub, testUserLogin)
	}
	if iss, _ := out["iss"].(string); iss != testIssuer {
		t.Errorf("JWT access token iss: got %q, want %q", iss, testIssuer)
	}
}

// ----------------------------------------------------------------- helpers

// parseSignedClaims verifies the JWS signature with the fixture public key and
// returns the claims. Fails the test on any signature/parse error.
func parseSignedClaims(t *testing.T, ts *testServer, raw string) map[string]interface{} {
	t.Helper()
	tok, err := jwt.ParseSigned(raw)
	if err != nil {
		t.Fatalf("parse signed token: %v", err)
	}
	claims := map[string]interface{}{}
	if err := tok.Claims(ts.key.Public(), &claims); err != nil {
		t.Fatalf("verify signature: %v", err)
	}
	return claims
}

// audienceContains handles aud being a string or a []interface{} (both legal in JWT).
func audienceContains(aud interface{}, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []interface{}:
		for _, e := range v {
			if s, ok := e.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}
