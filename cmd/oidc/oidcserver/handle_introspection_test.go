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

	"kubauth/cmd/oidc/oidcstorage"
)

// ============================================ confidential client introspection

func TestIntrospect_ActiveToken_ConfidentialClient(t *testing.T) {
	ts := buildServer(t)
	accessToken := ts.accessTokenForUser(t, "openid email")

	form := url.Values{}
	form.Set("token", accessToken)
	req := newPostForm(t, "/oauth2/introspect", form)
	req.SetBasicAuth(testClientID, testClientSecret) // confidential client auth
	rr := ts.do(req)

	if rr.Code != http.StatusOK {
		t.Fatalf("introspect: got %d body=%q", rr.Code, rr.Body.String())
	}
	body := decodeJSON(t, rr)
	if active, _ := body["active"].(bool); !active {
		t.Fatalf("expected active=true for a freshly issued token, got %v", body)
	}
	if sub, _ := body["sub"].(string); sub != testUserLogin {
		t.Errorf("introspection sub: got %q, want %q", sub, testUserLogin)
	}
}

func TestIntrospect_InvalidToken_ConfidentialClient_ReturnsInactive(t *testing.T) {
	ts := buildServer(t)

	form := url.Values{}
	form.Set("token", "definitely-not-valid")
	req := newPostForm(t, "/oauth2/introspect", form)
	req.SetBasicAuth(testClientID, testClientSecret)
	rr := ts.do(req)

	// RFC 7662: an unknown but well-formed request returns active=false, 200.
	if rr.Code != http.StatusOK {
		t.Fatalf("introspect invalid token: got %d body=%q", rr.Code, rr.Body.String())
	}
	body := decodeJSON(t, rr)
	if active, _ := body["active"].(bool); active {
		t.Errorf("invalid token must be reported inactive, got %v", body)
	}
}

func TestIntrospect_NoClientAuth_NonPublicPath_Errors(t *testing.T) {
	ts := buildServer(t)
	accessToken := ts.accessTokenForUser(t, "openid")

	// No Authorization header and the body client_id is a confidential client,
	// so the public-client fast path is not taken and fosite rejects it.
	form := url.Values{}
	form.Set("token", accessToken)
	form.Set("client_id", testClientID) // confidential, not public
	rr := ts.do(newPostForm(t, "/oauth2/introspect", form))

	if rr.Code == http.StatusOK {
		body := decodeJSON(t, rr)
		if active, _ := body["active"].(bool); active {
			t.Fatalf("confidential client without auth must not get an active introspection")
		}
	}
}

// ============================================ public client introspection path

func TestIntrospect_PublicClient_ActiveToken(t *testing.T) {
	// Register a public client and mint a token for it via PKCE-less code flow.
	// The public client allows code flow; we drive it through the login helper.
	ts := buildServer(t, func(o *buildOpts) {
		o.clients = []oidcstorage.KubauthClient{confidentialClient(t), publicClient(t)}
	})

	// Mint an access token for the PUBLIC client (no client secret at token endpoint).
	q := authzQuery(testPublicClient, "openid", nil)
	code := ts.loginForCode(t, q, testUserLogin, testUserPassword)
	tokens, rr := ts.exchangeCode(t, code, testPublicClient, "", nil) // public: client_id in body, no secret
	if rr.Code != http.StatusOK {
		t.Fatalf("public client token exchange: got %d body=%q", rr.Code, rr.Body.String())
	}
	accessToken := mustString(t, tokens, "access_token")

	// Introspect via the public-client branch: no Authorization header,
	// client_id + token in the form body.
	form := url.Values{}
	form.Set("client_id", testPublicClient)
	form.Set("token", accessToken)
	form.Set("token_type_hint", "access_token")
	rr2 := ts.do(newPostForm(t, "/oauth2/introspect", form))

	if rr2.Code != http.StatusOK {
		t.Fatalf("public introspect: got %d body=%q", rr2.Code, rr2.Body.String())
	}
	body := decodeJSON(t, rr2)
	if active, _ := body["active"].(bool); !active {
		t.Fatalf("public client active token must introspect as active, got %v", body)
	}
}

func TestIntrospect_PublicClient_InvalidToken_ReturnsInactiveJSON(t *testing.T) {
	ts := buildServer(t, func(o *buildOpts) {
		o.clients = []oidcstorage.KubauthClient{publicClient(t)}
	})

	form := url.Values{}
	form.Set("client_id", testPublicClient)
	form.Set("token", "garbage-token")
	rr := ts.do(newPostForm(t, "/oauth2/introspect", form))

	if rr.Code != http.StatusOK {
		t.Fatalf("public introspect invalid: got %d body=%q", rr.Code, rr.Body.String())
	}
	body := decodeJSON(t, rr)
	if active, _ := body["active"].(bool); active {
		t.Errorf("invalid token for public client must be inactive, got %v", body)
	}
}
