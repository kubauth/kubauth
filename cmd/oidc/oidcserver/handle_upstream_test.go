/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package oidcserver

import (
	"net/http"
	"net/url"
	"testing"

	"kubauth/cmd/oidc/upstreams"
)

// The upstream handlers run behind the login/SSO session middleware. To reach
// branches that read the session (authQuery, state, provider), we first do a
// GET /oauth2/login to obtain a primed session cookie, then replay it.

// primedLoginCookies performs the login GET that stores authQuery in the
// session, returning the cookies to carry into the upstream request.
func (ts *testServer) primedLoginCookies(t *testing.T, q url.Values) []*http.Cookie {
	t.Helper()
	rr := ts.do(newGet(t, "/oauth2/login?"+q.Encode()))
	cookies := readCookies(rr)
	if len(cookies) == 0 {
		t.Fatalf("login GET set no cookie (status %d)", rr.Code)
	}
	return cookies
}

func (ts *testServer) getWithCookies(t *testing.T, path string, cookies []*http.Cookie) *http.Request {
	t.Helper()
	req := newGet(t, path)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

// ============================================ handleUpstreamGo

func TestUpstreamGo_NonGet_405(t *testing.T) {
	ts := buildServer(t)
	rr := ts.do(newPostForm(t, "/upstream/go", url.Values{}))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /upstream/go: got %d, want 405", rr.Code)
	}
}

func TestUpstreamGo_MissingProviderParam_400(t *testing.T) {
	ts := buildServer(t)
	q := authzQuery(testClientID, "openid", nil)
	cookies := ts.primedLoginCookies(t, q)

	// No upstreamProvider query param.
	rr := ts.do(ts.getWithCookies(t, "/upstream/go", cookies))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("missing upstreamProvider: got %d body=%q", rr.Code, rr.Body.String())
	}
}

func TestUpstreamGo_NoAuthQueryInSession_400(t *testing.T) {
	ts := buildServer(t)
	// No prior login GET => no authQuery in session, but provide the param so
	// we exercise the session guard specifically.
	rr := ts.do(newGet(t, "/upstream/go?upstreamProvider=some"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("missing authQuery: got %d body=%q", rr.Code, rr.Body.String())
	}
}

func TestUpstreamGo_UnknownUpstream_404(t *testing.T) {
	ts := buildServer(t)
	q := authzQuery(testClientID, "openid", nil)
	cookies := ts.primedLoginCookies(t, q)

	rr := ts.do(ts.getWithCookies(t, "/upstream/go?upstreamProvider=ghost", cookies))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown upstream: got %d body=%q", rr.Code, rr.Body.String())
	}
}

func TestUpstreamGo_InternalUpstream_NoCodeFlow_400(t *testing.T) {
	ts := buildServer(t)
	// Internal upstream returns ok=false from OAuth2AuthCodeSettings.
	ts.store.SetUpstream(testCtx(), upstreams.NewInternalUpstream("Sign in"))

	q := authzQuery(testClientID, "openid", nil)
	cookies := ts.primedLoginCookies(t, q)

	rr := ts.do(ts.getWithCookies(t, "/upstream/go?upstreamProvider=internal", cookies))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("internal upstream (no code flow): got %d body=%q", rr.Code, rr.Body.String())
	}
}

// ============================================ handleUpstreamCallback

func TestUpstreamCallback_NonGet_405(t *testing.T) {
	ts := buildServer(t)
	rr := ts.do(newPostForm(t, "/upstream/callback", url.Values{}))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /upstream/callback: got %d, want 405", rr.Code)
	}
}

func TestUpstreamCallback_ProviderError_400(t *testing.T) {
	ts := buildServer(t)
	rr := ts.do(newGet(t, "/upstream/callback?error=access_denied&error_description=nope"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("upstream error param: got %d body=%q", rr.Code, rr.Body.String())
	}
}

func TestUpstreamCallback_MissingCodeOrState_400(t *testing.T) {
	ts := buildServer(t)
	// code present, state missing.
	rr := ts.do(newGet(t, "/upstream/callback?code=abc"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("missing state: got %d body=%q", rr.Code, rr.Body.String())
	}
}

func TestUpstreamCallback_StateMismatch_400(t *testing.T) {
	ts := buildServer(t)
	// Session has no stored state, so any provided state mismatches.
	q := authzQuery(testClientID, "openid", nil)
	cookies := ts.primedLoginCookies(t, q)

	rr := ts.do(ts.getWithCookies(t, "/upstream/callback?code=abc&state=does-not-match", cookies))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("state mismatch: got %d body=%q", rr.Code, rr.Body.String())
	}
}

// ============================================ handleUpstreamWelcome

func TestUpstreamWelcome_NotOnDemand_404(t *testing.T) {
	ts := buildServer(t) // default SsoMode is SsoNever
	rr := ts.do(newGet(t, "/upstream/welcome"))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("welcome when not onDemand: got %d, want 404 body=%q", rr.Code, rr.Body.String())
	}
}

func TestUpstreamWelcome_OnDemand_NoPendingUser_400(t *testing.T) {
	ts := buildServer(t, func(o *buildOpts) { o.ssoMode = SsoOnDemand })
	// onDemand but no pending upstream user in session.
	rr := ts.do(newGet(t, "/upstream/welcome"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("welcome with no pending user: got %d, want 400 body=%q", rr.Code, rr.Body.String())
	}
}
