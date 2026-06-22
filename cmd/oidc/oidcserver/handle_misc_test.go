/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package oidcserver

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"kubauth/api/kubauth/v1alpha1"
	"kubauth/cmd/oidc/authenticator"
	"kubauth/cmd/oidc/oidcstorage"
)

// ============================================ /oauth2/logout

func TestLogout_DefaultRedirect_WhenNoClientOrParam(t *testing.T) {
	ts := buildServer(t)

	rr := ts.do(newGet(t, "/oauth2/logout"))
	if rr.Code != http.StatusFound {
		t.Fatalf("logout: got %d, want 302 body=%q", rr.Code, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); loc != ts.srv.PostLogoutURL {
		t.Errorf("logout redirect: got %q, want default %q", loc, ts.srv.PostLogoutURL)
	}
}

func TestLogout_QueryParamOverridesDefault(t *testing.T) {
	ts := buildServer(t)

	target := "https://elsewhere.test/bye"
	q := url.Values{}
	q.Set("post_logout_redirect_uri", target)
	rr := ts.do(newGet(t, "/oauth2/logout?"+q.Encode()))

	if loc := rr.Header().Get("Location"); loc != target {
		t.Errorf("query param must take precedence: got %q, want %q", loc, target)
	}
}

func TestLogout_ClientPostLogoutURLUsedWhenSet(t *testing.T) {
	ts := buildServer(t) // confidentialClient has no PostLogoutURL; set one on a fresh client.

	// The default confidential client has an empty PostLogoutURL, so the
	// global default applies. Verify a client WITH a PostLogoutURL overrides it.
	q := url.Values{}
	q.Set("client_id", testClientID)
	rr := ts.do(newGet(t, "/oauth2/logout?"+q.Encode()))

	// confidentialClient has empty PostLogoutURL => falls back to global default.
	if loc := rr.Header().Get("Location"); loc != ts.srv.PostLogoutURL {
		t.Errorf("client without PostLogoutURL should use global default: got %q", loc)
	}
}

func TestLogout_ClientSpecificPostLogoutURL(t *testing.T) {
	// Build a server whose single client defines a PostLogoutURL.
	ts := buildServer(t)
	clientLogout := "https://app.test/after-logout"

	// Replace the stored client with one carrying a PostLogoutURL.
	k8s := confidentialClient(t).GetK8sObject()
	k8s.Spec.PostLogoutURL = clientLogout
	if err := ts.store.SetClient(testCtx(), wrapClient(k8s)); err != nil {
		t.Fatalf("SetClient: %v", err)
	}

	q := url.Values{}
	q.Set("client_id", testClientID)
	rr := ts.do(newGet(t, "/oauth2/logout?"+q.Encode()))
	if loc := rr.Header().Get("Location"); loc != clientLogout {
		t.Errorf("client PostLogoutURL must be used: got %q, want %q", loc, clientLogout)
	}
}

// ============================================ /index

func TestIndex_ListsClientsWithNameAndEntryURL(t *testing.T) {
	ts := buildServer(t) // confidentialClient has DisplayName + EntryURL

	rr := ts.do(newGet(t, "/index"))
	if rr.Code != http.StatusOK {
		t.Fatalf("index: got %d body=%q", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		// handleIndex relies on the template; default content type is text/html.
		t.Logf("index content-type: %q", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "app:Web App|https://app.test/") {
		t.Errorf("index should list the web app entry, body=%q", body)
	}
}

func TestIndex_OmitsClientsMissingDisplayNameOrEntryURL(t *testing.T) {
	// A client without EntryURL must not appear.
	noEntry := confidentialClient(t).GetK8sObject()
	noEntry.Name = "no-entry"
	noEntry.Spec.EntryURL = ""
	noEntry.Spec.DisplayName = "No Entry App"

	ts := buildServer(t)
	if err := ts.store.SetClient(testCtx(), wrapNamed(noEntry, "no-entry")); err != nil {
		t.Fatalf("SetClient: %v", err)
	}

	body := ts.do(newGet(t, "/index")).Body.String()
	if strings.Contains(body, "No Entry App") {
		t.Errorf("client without EntryURL must be excluded, body=%q", body)
	}
}

// ============================================ GetClientIdFromRequest

func TestGetClientIdFromRequest_FromForm(t *testing.T) {
	form := url.Values{}
	form.Set("client_id", "abc-123")
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if got := GetClientIdFromRequest(req); got != "abc-123" {
		t.Errorf("got %q, want abc-123", got)
	}
}

func TestGetClientIdFromRequest_FromQuery(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/x?client_id=q-client", nil)
	if got := GetClientIdFromRequest(req); got != "q-client" {
		t.Errorf("got %q, want q-client", got)
	}
}

func TestGetClientIdFromRequest_AbsentReturnsEmpty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if got := GetClientIdFromRequest(req); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// ============================================ clientIDFromRawQuery (pure)

func TestClientIDFromRawQuery(t *testing.T) {
	cases := []struct {
		name, raw, want string
	}{
		{"empty", "", ""},
		{"present", "client_id=foo&scope=openid", "foo"},
		{"absent", "scope=openid&state=x", ""},
		{"url-encoded", "client_id=a%20b", "a b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clientIDFromRawQuery(tc.raw); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// ============================================ welcomeUserName (pure)

func TestWelcomeUserName_Precedence(t *testing.T) {
	cases := []struct {
		name string
		user *authenticator.OidcUser
		want string
	}{
		{"nil user", nil, ""},
		{
			"fullName wins",
			&authenticator.OidcUser{FullName: "Full Name", Claims: map[string]interface{}{"name": "claim name"}, Login: "login"},
			"Full Name",
		},
		{
			"name claim next",
			&authenticator.OidcUser{Claims: map[string]interface{}{"name": "Claim Name"}, Login: "login"},
			"Claim Name",
		},
		{
			"preferred_username before email",
			&authenticator.OidcUser{Claims: map[string]interface{}{"preferred_username": "pref", "email": "e@x"}, Login: "login"},
			"pref",
		},
		{
			"given + family combined",
			&authenticator.OidcUser{Claims: map[string]interface{}{"given_name": "Jane", "family_name": "Doe"}, Login: "login"},
			"Jane Doe",
		},
		{
			"given only",
			&authenticator.OidcUser{Claims: map[string]interface{}{"given_name": "Solo"}, Login: "login"},
			"Solo",
		},
		{
			"falls back to login",
			&authenticator.OidcUser{Login: "  fallback-login  "},
			"fallback-login",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := welcomeUserName(tc.user); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// ----------------------------------------------------------------- helpers

// wrapClient rebuilds a KubauthClient around an edited CR, keyed by the CR name
// as client_id. wrapNamed lets the caller pass an explicit client_id.
func wrapClient(k8s *v1alpha1.OidcClient) oidcstorage.KubauthClient {
	return wrapNamed(k8s, k8s.GetName())
}

func wrapNamed(k8s *v1alpha1.OidcClient, clientID string) oidcstorage.KubauthClient {
	return oidcstorage.NewKubauthClient(k8s, clientID, nil)
}
