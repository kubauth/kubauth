/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package oidcserver

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"kubauth/cmd/oidc/authenticator"
)

var errBoom = errors.New("backend exploded")

// ============================================ GET /oauth2/auth

func TestAuthorize_ValidGet_RedirectsToLoginPreservingQuery(t *testing.T) {
	ts := buildServer(t)

	q := authzQuery(testClientID, "openid profile", nil)
	rr := ts.do(newGet(t, "/oauth2/auth?"+q.Encode()))

	if rr.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302 body=%q", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location %q: %v", loc, err)
	}
	if u.Path != "/oauth2/login" {
		t.Errorf("redirect path: got %q, want /oauth2/login", u.Path)
	}
	// The original authorize parameters must be carried over verbatim so the
	// login step can rebuild the request.
	for _, key := range []string{"client_id", "redirect_uri", "response_type", "scope", "state"} {
		if u.Query().Get(key) != q.Get(key) {
			t.Errorf("query %q not preserved: got %q, want %q", key, u.Query().Get(key), q.Get(key))
		}
	}
}

func TestAuthorize_UnknownClient_WritesAuthorizeError(t *testing.T) {
	ts := buildServer(t)

	q := authzQuery("no-such-client", "openid", nil)
	rr := ts.do(newGet(t, "/oauth2/auth?"+q.Encode()))

	// fosite rejects before the login redirect; an unknown client cannot be
	// redirected to (untrusted redirect_uri), so the error is rendered locally.
	if rr.Code == http.StatusFound {
		// If it did redirect, it must NOT be to our login page with a valid flow.
		if strings.Contains(rr.Header().Get("Location"), "/oauth2/login") {
			t.Fatalf("unknown client should not reach the login page")
		}
	}
	if rr.Code == http.StatusOK {
		t.Fatalf("unknown client must not yield 200, body=%q", rr.Body.String())
	}
}

func TestAuthorize_InvalidRedirectURI_DoesNotRedirectToLogin(t *testing.T) {
	ts := buildServer(t)

	q := authzQuery(testClientID, "openid", nil)
	q.Set("redirect_uri", "https://attacker.test/cb") // not whitelisted
	rr := ts.do(newGet(t, "/oauth2/auth?"+q.Encode()))

	if rr.Code == http.StatusFound && strings.Contains(rr.Header().Get("Location"), "/oauth2/login") {
		t.Fatalf("a non-whitelisted redirect_uri must be rejected, not forwarded to login")
	}
}

func TestAuthorize_UnsupportedResponseType_IsRejected(t *testing.T) {
	ts := buildServer(t)

	q := authzQuery(testClientID, "openid", nil)
	q.Set("response_type", "token") // client only allows "code"
	rr := ts.do(newGet(t, "/oauth2/auth?"+q.Encode()))

	if rr.Code == http.StatusFound && strings.Contains(rr.Header().Get("Location"), "/oauth2/login") {
		t.Fatalf("unsupported response_type should not reach the login page")
	}
}

// ============================================ method handling

func TestAuthorize_PostMethod_NotAllowed(t *testing.T) {
	ts := buildServer(t)

	q := authzQuery(testClientID, "openid", nil)
	// A POST that nonetheless parses as a valid authorize request hits the
	// explicit method guard returning 405.
	req := newPostForm(t, "/oauth2/auth", q)
	rr := ts.do(req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /oauth2/auth: got %d, want 405 body=%q", rr.Code, rr.Body.String())
	}
}

// ============================================ login GET that fronts authorize

func TestLogin_Get_RendersLoginForm(t *testing.T) {
	// With no upstream providers configured, the default internal provider is
	// used and the login form is shown.
	ts := buildServer(t)

	q := authzQuery(testClientID, "openid", nil)
	rr := ts.do(newGet(t, "/oauth2/login?"+q.Encode()))

	if rr.Code != http.StatusOK {
		t.Fatalf("login GET: got %d, want 200 body=%q", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type: got %q, want text/html", ct)
	}
	if !strings.Contains(rr.Body.String(), "form=true") {
		t.Errorf("expected login form to be shown, body=%q", rr.Body.String())
	}
}

func TestLogin_Post_InvalidCredentials_RendersInvalidLogin(t *testing.T) {
	ts := buildServer(t)

	q := authzQuery(testClientID, "openid", nil)

	// Prime the session via GET.
	getRR := ts.do(newGet(t, "/oauth2/login?"+q.Encode()))
	cookies := readCookies(getRR)

	form := url.Values{}
	form.Set("login", testUserLogin)
	form.Set("password", "wrong-password")
	postReq := newPostForm(t, "/oauth2/login", form)
	for _, c := range cookies {
		postReq.AddCookie(c)
	}
	rr := ts.do(postReq)

	// Bad credentials => authenticator returns (nil, nil) => login page re-rendered.
	if rr.Code != http.StatusOK {
		t.Fatalf("invalid login: got %d, want 200 (re-render) body=%q", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "invalid=true") {
		t.Errorf("expected invalid-login flag in rendered page, body=%q", rr.Body.String())
	}
}

func TestLogin_Post_AuthenticatorError_Returns500(t *testing.T) {
	ts := buildServer(t, func(o *buildOpts) {
		o.auth = &fakeAuthenticator{
			authFunc: func(_ context.Context, _, _ string) (*authenticator.OidcUser, error) {
				return nil, errBoom
			},
		}
	})

	q := authzQuery(testClientID, "openid", nil)
	getRR := ts.do(newGet(t, "/oauth2/login?"+q.Encode()))
	cookies := readCookies(getRR)

	form := url.Values{}
	form.Set("login", testUserLogin)
	form.Set("password", testUserPassword)
	postReq := newPostForm(t, "/oauth2/login", form)
	for _, c := range cookies {
		postReq.AddCookie(c)
	}
	rr := ts.do(postReq)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("authenticator error: got %d, want 500 body=%q", rr.Code, rr.Body.String())
	}
}

func TestLogin_Post_NoSessionQuery_BadRequest(t *testing.T) {
	ts := buildServer(t)

	// POST without first doing the GET that stores authQuery in the session.
	form := url.Values{}
	form.Set("login", testUserLogin)
	form.Set("password", testUserPassword)
	rr := ts.do(newPostForm(t, "/oauth2/login", form))

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("missing session authQuery: got %d, want 400 body=%q", rr.Code, rr.Body.String())
	}
}
