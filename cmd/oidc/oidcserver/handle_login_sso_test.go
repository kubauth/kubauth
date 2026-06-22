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
	"time"

	"kubauth/cmd/oidc/authenticator"
)

// ============================================ SSO session reuse

// When SSO is active (the user previously logged in with "remember"), a second
// authorize/login GET must complete the flow directly (302 with a code) without
// re-prompting for credentials. This exercises handleLogin's SSO-reuse branch,
// which round-trips the stored user through the JSON codec into a
// map[string]interface{}.
func TestLogin_SsoReuse_CompletesWithoutPasswordPrompt(t *testing.T) {
	ts := buildServer(t, func(o *buildOpts) { o.ssoMode = SsoOnDemand })

	q := authzQuery(testClientID, "openid profile", nil)

	// First login: GET to prime session, POST with remember=on to persist SSO.
	getRR := ts.do(newGet(t, "/oauth2/login?"+q.Encode()))
	cookies := readCookies(getRR)

	form := url.Values{}
	form.Set("login", testUserLogin)
	form.Set("password", testUserPassword)
	form.Set("remember", "on")
	postReq := newPostForm(t, "/oauth2/login", form)
	for _, c := range cookies {
		postReq.AddCookie(c)
	}
	postRR := ts.do(postReq)
	if !isRedirect(postRR.Code) {
		t.Fatalf("first login should redirect with a code, got %d body=%q", postRR.Code, postRR.Body.String())
	}
	if codeFromLocation(t, postRR.Header().Get("Location")) == "" {
		t.Fatalf("first login carried no code: %q", postRR.Header().Get("Location"))
	}

	// Carry forward all cookies set across the two responses (login + sso).
	sessionCookies := mergeCookies(cookies, readCookies(postRR))

	// Second authorize: a plain GET /oauth2/login with the SSO cookie must
	// complete immediately (no form), returning a fresh code.
	secondReq := newGet(t, "/oauth2/login?"+q.Encode())
	for _, c := range sessionCookies {
		secondReq.AddCookie(c)
	}
	secondRR := ts.do(secondReq)

	if !isRedirect(secondRR.Code) {
		t.Fatalf("SSO reuse must redirect (no password prompt), got %d body=%q", secondRR.Code, secondRR.Body.String())
	}
	loc := secondRR.Header().Get("Location")
	if code := codeFromLocation(t, loc); code == "" {
		t.Fatalf("SSO reuse must yield an authorization code, location=%q", loc)
	}
	if u, _ := url.Parse(loc); u != nil && u.Path == "/oauth2/login" {
		t.Errorf("SSO reuse must not bounce back to the login page: %q", loc)
	}
}

// Without remember (onDemand) the SSO user is not persisted, so a second GET
// must fall back to rendering the login form rather than completing silently.
func TestLogin_OnDemandNoRemember_DoesNotPersistSso(t *testing.T) {
	ts := buildServer(t, func(o *buildOpts) { o.ssoMode = SsoOnDemand })

	q := authzQuery(testClientID, "openid", nil)
	getRR := ts.do(newGet(t, "/oauth2/login?"+q.Encode()))
	cookies := readCookies(getRR)

	form := url.Values{}
	form.Set("login", testUserLogin)
	form.Set("password", testUserPassword)
	// remember intentionally omitted
	postReq := newPostForm(t, "/oauth2/login", form)
	for _, c := range cookies {
		postReq.AddCookie(c)
	}
	postRR := ts.do(postReq)
	if !isRedirect(postRR.Code) {
		t.Fatalf("login should still succeed for this request, got %d", postRR.Code)
	}

	sessionCookies := mergeCookies(cookies, readCookies(postRR))
	secondReq := newGet(t, "/oauth2/login?"+q.Encode())
	for _, c := range sessionCookies {
		secondReq.AddCookie(c)
	}
	secondRR := ts.do(secondReq)

	// No persisted SSO => login form is rendered (200), not a silent redirect.
	if secondRR.Code != http.StatusOK {
		t.Fatalf("without remember, second GET should render the form (200), got %d", secondRR.Code)
	}
	if !strings.Contains(secondRR.Body.String(), "form=true") {
		t.Errorf("expected the login form to be re-rendered, body=%q", secondRR.Body.String())
	}
}

// ============================================ newSession unit

func TestNewSession_PopulatesClaimsAndAzp(t *testing.T) {
	ts := buildServer(t)
	user := &authenticator.OidcUser{
		Login:    testUserLogin,
		FullName: "Alice Example",
		Claims: map[string]interface{}{
			"sub":   testUserLogin,
			"email": "alice@test",
		},
	}
	sess := ts.srv.newSession(user, testClientID)

	if sess.Subject != testUserLogin {
		t.Errorf("session subject: got %q, want %q", sess.Subject, testUserLogin)
	}
	if sess.IDTokenClaims_ == nil || sess.JWTClaims_ == nil {
		t.Fatal("newSession must initialise both ID and JWT claim containers")
	}
	if sess.IDTokenClaims_.Subject != testUserLogin {
		t.Errorf("id token subject: got %q", sess.IDTokenClaims_.Subject)
	}
	if got := sess.IDTokenClaims_.Issuer; got != testIssuer {
		t.Errorf("id token issuer: got %q, want %q", got, testIssuer)
	}
	// azp is added for a non-empty client id.
	if azp, _ := sess.IDTokenClaims_.Extra["azp"].(string); azp != testClientID {
		t.Errorf("azp: got %q, want %q", azp, testClientID)
	}
	// kid header must be set from the server key id.
	if kid, _ := sess.Headers.Extra["kid"].(string); kid != ts.kid {
		t.Errorf("session header kid: got %q, want %q", kid, ts.kid)
	}
}

func TestNewSession_NilUser_EmptySubject_NoAzpForEmptyClient(t *testing.T) {
	ts := buildServer(t)
	sess := ts.srv.newSession(nil, "")

	if sess.Subject != "" {
		t.Errorf("nil user should give empty subject, got %q", sess.Subject)
	}
	if _, ok := sess.IDTokenClaims_.Extra["azp"]; ok {
		t.Error("azp must not be added for an empty client id")
	}
	// Expiry on the JWT claims must reflect AccessTokenLifespan.
	if sess.JWTClaims_.ExpiresAt.Before(time.Now()) {
		t.Error("JWT claims ExpiresAt should be in the future")
	}
}

// ----------------------------------------------------------------- helpers

func mergeCookies(sets ...[]*http.Cookie) []*http.Cookie {
	byName := map[string]*http.Cookie{}
	var order []string
	for _, set := range sets {
		for _, c := range set {
			if _, seen := byName[c.Name]; !seen {
				order = append(order, c.Name)
			}
			byName[c.Name] = c // later sets override earlier (fresher value)
		}
	}
	out := make([]*http.Cookie, 0, len(order))
	for _, n := range order {
		out = append(out, byName[n])
	}
	return out
}
