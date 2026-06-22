/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package upstreams

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ---------------------------------------------------------------------------
// Fake upstream IdP: serves discovery, JWKS, and userinfo over httptest so the
// real go-oidc provider/verifier exercises the federation flow end to end.
// ---------------------------------------------------------------------------

const testKeyID = "test-key-1"

// fakeIdP is an in-memory upstream OIDC provider backed by httptest.
type fakeIdP struct {
	t      *testing.T
	server *httptest.Server
	signer jose.Signer
	pubJWK jose.JSONWebKey

	// Tunable behaviour for negative tests. Guarded by nothing: the test sets
	// these before issuing the request that reaches the relevant handler.
	signingAlgs       []string // advertised id_token_signing_alg_values_supported
	omitUserInfoURL   bool     // discovery doc has no userinfo_endpoint
	userInfoStatus    int      // status returned by the userinfo endpoint (0 => 200)
	userInfoBody      string   // raw body returned by the userinfo endpoint
	userInfoCalls     int      // number of times userinfo was hit
	lastUserInfoAuth  string   // Authorization header seen by userinfo
	jwksStatus        int      // status returned by the jwks endpoint (0 => 200)
	discoveryStatus   int      // status returned by discovery (0 => 200)
	discoveryRawBody  string   // if set, returned verbatim by discovery
	overrideIssuer    string   // if set, used as the discovery "issuer" value
	codeChallengeMeth []string // advertised code_challenge_methods_supported
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", testKeyID),
	)
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}
	f := &fakeIdP{
		t:           t,
		signer:      signer,
		signingAlgs: []string{"RS256"},
		pubJWK: jose.JSONWebKey{
			Key:       priv.Public(),
			KeyID:     testKeyID,
			Algorithm: "RS256",
			Use:       "sig",
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.handleDiscovery)
	mux.HandleFunc("/jwks", f.handleJWKS)
	mux.HandleFunc("/userinfo", f.handleUserInfo)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeIdP) issuer() string {
	if f.overrideIssuer != "" {
		return f.overrideIssuer
	}
	return f.server.URL
}

func (f *fakeIdP) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	if f.discoveryStatus != 0 {
		w.WriteHeader(f.discoveryStatus)
		return
	}
	if f.discoveryRawBody != "" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(f.discoveryRawBody))
		return
	}
	doc := map[string]interface{}{
		"issuer":                                f.issuer(),
		"authorization_endpoint":                f.server.URL + "/auth",
		"token_endpoint":                        f.server.URL + "/token",
		"jwks_uri":                              f.server.URL + "/jwks",
		"id_token_signing_alg_values_supported": f.signingAlgs,
	}
	if !f.omitUserInfoURL {
		doc["userinfo_endpoint"] = f.server.URL + "/userinfo"
	}
	if len(f.codeChallengeMeth) > 0 {
		doc["code_challenge_methods_supported"] = f.codeChallengeMeth
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		f.t.Errorf("encode discovery: %v", err)
	}
}

func (f *fakeIdP) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	if f.jwksStatus != 0 {
		w.WriteHeader(f.jwksStatus)
		return
	}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{f.pubJWK}}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(set); err != nil {
		f.t.Errorf("encode jwks: %v", err)
	}
}

func (f *fakeIdP) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	f.userInfoCalls++
	f.lastUserInfoAuth = r.Header.Get("Authorization")
	if f.userInfoStatus != 0 {
		w.WriteHeader(f.userInfoStatus)
		if f.userInfoBody != "" {
			_, _ = w.Write([]byte(f.userInfoBody))
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if f.userInfoBody != "" {
		_, _ = w.Write([]byte(f.userInfoBody))
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"sub":   "user-1",
		"email": "user@example.com",
		"name":  "User One",
	})
}

// signIDToken signs the given claim set as a compact JWS (a JWT) with the IdP key.
func (f *fakeIdP) signIDToken(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	jws, err := f.signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign id token: %v", err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize id token: %v", err)
	}
	return compact
}

// standardClaims returns a valid-by-default ID token claim set for the given IdP/client.
func (f *fakeIdP) standardClaims(clientID string) map[string]interface{} {
	return map[string]interface{}{
		"iss":   f.issuer(),
		"sub":   "user-1",
		"aud":   clientID,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"email": "user@example.com",
		"name":  "User One",
	}
}

// newOIDCUpstream builds a real *upstream via NewUpstream pointed at the fake IdP
// (discovery path). mutate may tweak the spec before construction.
func (f *fakeIdP) newOIDCUpstream(t *testing.T, clientID, clientSecret string, mutate func(*kubauthv1alpha1.UpstreamProviderSpec)) Upstream {
	t.Helper()
	spec := kubauthv1alpha1.UpstreamProviderSpec{
		Type:      kubauthv1alpha1.UpstreamProviderTypeOidc,
		IssuerURL: f.server.URL,
		ClientId:  clientID,
		Scopes:    []string{"openid", "email"},
	}
	if mutate != nil {
		mutate(&spec)
	}
	up := &kubauthv1alpha1.UpstreamProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "test-upstream"},
		Spec:       spec,
	}
	u, err := NewUpstream(context.Background(), up, clientSecret, nil)
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	return u
}

// ---------------------------------------------------------------------------
// NewUpstream / NewInternalUpstream construction
// ---------------------------------------------------------------------------

func TestNewInternalUpstream_basics(t *testing.T) {
	u := NewInternalUpstream("Local login")
	if u.GetName() != "internal" {
		t.Errorf("GetName = %q, want internal", u.GetName())
	}
	if u.GetDisplayName() != "Local login" {
		t.Errorf("GetDisplayName = %q, want Local login", u.GetDisplayName())
	}
	if u.GetProviderType() != kubauthv1alpha1.UpstreamProviderTypeInternal {
		t.Errorf("GetProviderType = %q, want internal", u.GetProviderType())
	}
	// Internal upstream has no OIDC provider: auth-code settings unavailable.
	if settings, ok := u.OAuth2AuthCodeSettings(); ok || settings != nil {
		t.Errorf("OAuth2AuthCodeSettings = (%v, %v), want (nil, false)", settings, ok)
	}
	if cfg := u.GetEffectiveConfig(); cfg != nil {
		t.Errorf("GetEffectiveConfig = %v, want nil for internal", cfg)
	}
	// ClientContext on an upstream with no http client returns ctx unchanged.
	ctx := context.Background()
	if got := u.ClientContext(ctx); got != ctx {
		t.Errorf("ClientContext returned a different context for internal upstream")
	}
	// ParseAndVerifyIDToken must fail clearly when there is no provider.
	if _, err := u.ParseAndVerifyIDToken(ctx, "whatever"); err == nil {
		t.Errorf("ParseAndVerifyIDToken on internal upstream: want error, got nil")
	}
	// FetchUserInfoClaims returns (nil, nil) when there is no provider.
	claims, err := u.FetchUserInfoClaims(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "x"}))
	if err != nil {
		t.Errorf("FetchUserInfoClaims on internal upstream: unexpected error %v", err)
	}
	if claims != nil {
		t.Errorf("FetchUserInfoClaims on internal upstream: want nil, got %v", claims)
	}
}

func TestNewUpstream_internalTypeSkipsDiscovery(t *testing.T) {
	// An internal-typed UpstreamProvider must not attempt any HTTP discovery,
	// even with a bogus issuer URL: NewUpstream short-circuits on the type.
	up := &kubauthv1alpha1.UpstreamProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "int"},
		Spec: kubauthv1alpha1.UpstreamProviderSpec{
			Type:        kubauthv1alpha1.UpstreamProviderTypeInternal,
			DisplayName: "Internal",
			IssuerURL:   "http://127.0.0.1:1/does-not-exist",
		},
	}
	u, err := NewUpstream(context.Background(), up, "", nil)
	if err != nil {
		t.Fatalf("NewUpstream(internal): unexpected error %v", err)
	}
	if u.GetProviderType() != kubauthv1alpha1.UpstreamProviderTypeInternal {
		t.Errorf("type = %q, want internal", u.GetProviderType())
	}
	if _, ok := u.OAuth2AuthCodeSettings(); ok {
		t.Errorf("internal upstream should not expose OAuth2AuthCodeSettings")
	}
}

func TestNewUpstream_discoverySuccess(t *testing.T) {
	f := newFakeIdP(t)
	f.codeChallengeMeth = []string{"S256", "plain"}
	u := f.newOIDCUpstream(t, "client-abc", "secret-xyz", nil)

	if u.GetProviderType() != kubauthv1alpha1.UpstreamProviderTypeOidc {
		t.Errorf("type = %q, want oidc", u.GetProviderType())
	}
	settings, ok := u.OAuth2AuthCodeSettings()
	if !ok {
		t.Fatalf("OAuth2AuthCodeSettings ok = false, want true after discovery")
	}
	if settings.ClientID != "client-abc" {
		t.Errorf("ClientID = %q, want client-abc", settings.ClientID)
	}
	if settings.ClientSecret != "secret-xyz" {
		t.Errorf("ClientSecret = %q, want secret-xyz", settings.ClientSecret)
	}
	if settings.Endpoint.AuthURL != f.server.URL+"/auth" {
		t.Errorf("AuthURL = %q, want %q", settings.Endpoint.AuthURL, f.server.URL+"/auth")
	}
	if settings.Endpoint.TokenURL != f.server.URL+"/token" {
		t.Errorf("TokenURL = %q, want %q", settings.Endpoint.TokenURL, f.server.URL+"/token")
	}
	if !settings.SupportsPKCES256 {
		t.Errorf("SupportsPKCES256 = false, want true (S256 advertised)")
	}
	if strings.Join(settings.Scopes, ",") != "openid,email" {
		t.Errorf("Scopes = %v, want [openid email]", settings.Scopes)
	}

	// EffectiveConfig is populated from discovery for the controller status.
	cfg := u.GetEffectiveConfig()
	if cfg == nil {
		t.Fatalf("GetEffectiveConfig = nil after discovery, want populated")
	}
	if cfg.UserInfoURL != f.server.URL+"/userinfo" {
		t.Errorf("EffectiveConfig.UserInfoURL = %q, want %q", cfg.UserInfoURL, f.server.URL+"/userinfo")
	}
	if cfg.JWKSURL != f.server.URL+"/jwks" {
		t.Errorf("EffectiveConfig.JWKSURL = %q, want %q", cfg.JWKSURL, f.server.URL+"/jwks")
	}
	if strings.Join(cfg.Algorithms, ",") != "RS256" {
		t.Errorf("EffectiveConfig.Algorithms = %v, want [RS256]", cfg.Algorithms)
	}
}

func TestNewUpstream_discoveryIssuerMismatch(t *testing.T) {
	f := newFakeIdP(t)
	// Discovery doc advertises an issuer that does not match the requested one:
	// go-oidc must reject this (mis-configuration / token-substitution guard).
	f.overrideIssuer = "https://evil.example.com"
	up := &kubauthv1alpha1.UpstreamProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "mismatch"},
		Spec: kubauthv1alpha1.UpstreamProviderSpec{
			Type:      kubauthv1alpha1.UpstreamProviderTypeOidc,
			IssuerURL: f.server.URL,
			ClientId:  "c",
		},
	}
	_, err := NewUpstream(context.Background(), up, "", nil)
	if err == nil {
		t.Fatalf("NewUpstream: want issuer-mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "oidc provider") {
		t.Errorf("error = %v, want it wrapped as 'oidc provider' failure", err)
	}
}

func TestNewUpstream_discoveryHTTPError(t *testing.T) {
	f := newFakeIdP(t)
	f.discoveryStatus = http.StatusInternalServerError
	up := &kubauthv1alpha1.UpstreamProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "boom"},
		Spec: kubauthv1alpha1.UpstreamProviderSpec{
			Type:      kubauthv1alpha1.UpstreamProviderTypeOidc,
			IssuerURL: f.server.URL,
			ClientId:  "c",
		},
	}
	_, err := NewUpstream(context.Background(), up, "", nil)
	if err == nil {
		t.Fatalf("NewUpstream: want error on discovery 500, got nil")
	}
}

func TestNewUpstream_invalidIssuerURLScheme(t *testing.T) {
	// httpclient.New rejects non-http(s) schemes before any network call.
	up := &kubauthv1alpha1.UpstreamProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "bad-scheme"},
		Spec: kubauthv1alpha1.UpstreamProviderSpec{
			Type:      kubauthv1alpha1.UpstreamProviderTypeOidc,
			IssuerURL: "ftp://example.com",
			ClientId:  "c",
		},
	}
	_, err := NewUpstream(context.Background(), up, "", nil)
	if err == nil {
		t.Fatalf("NewUpstream: want error for ftp:// issuer, got nil")
	}
	if !strings.Contains(err.Error(), "http client") {
		t.Errorf("error = %v, want it wrapped as 'http client' failure", err)
	}
}

func TestNewUpstream_explicitConfigSkipsDiscovery(t *testing.T) {
	f := newFakeIdP(t)
	// With ExplicitConfig set, NewUpstream must NOT call discovery. Point the
	// well-known handler at a 500 so any discovery attempt would fail the test.
	f.discoveryStatus = http.StatusInternalServerError
	explicit := &kubauthv1alpha1.UpstreamProviderConfig{
		AuthURL:          f.server.URL + "/auth",
		TokenURL:         f.server.URL + "/token",
		UserInfoURL:      f.server.URL + "/userinfo",
		JWKSURL:          f.server.URL + "/jwks",
		Algorithms:       []string{"RS256"},
		IntrospectionURL: f.server.URL + "/introspect",
		EndSessionURL:    f.server.URL + "/logout",
	}
	u := f.newOIDCUpstream(t, "client-1", "sec", func(s *kubauthv1alpha1.UpstreamProviderSpec) {
		s.ExplicitConfig = explicit
	})

	settings, ok := u.OAuth2AuthCodeSettings()
	if !ok {
		t.Fatalf("OAuth2AuthCodeSettings ok = false, want true with explicit config")
	}
	if settings.Endpoint.TokenURL != f.server.URL+"/token" {
		t.Errorf("TokenURL = %q, want %q", settings.Endpoint.TokenURL, f.server.URL+"/token")
	}
	cfg := u.GetEffectiveConfig()
	if cfg == nil {
		t.Fatalf("GetEffectiveConfig = nil, want populated from explicit config")
	}
	if cfg.IntrospectionURL != f.server.URL+"/introspect" {
		t.Errorf("IntrospectionURL = %q, want %q", cfg.IntrospectionURL, f.server.URL+"/introspect")
	}
	if cfg.EndSessionURL != f.server.URL+"/logout" {
		t.Errorf("EndSessionURL = %q, want %q", cfg.EndSessionURL, f.server.URL+"/logout")
	}
	// Explicit config did not advertise S256 PKCE.
	if settings.SupportsPKCES256 {
		t.Errorf("SupportsPKCES256 = true, want false (no code_challenge_methods in explicit config)")
	}
}

// ---------------------------------------------------------------------------
// ParseAndVerifyIDToken: the core federation token-verification path
// ---------------------------------------------------------------------------

func TestParseAndVerifyIDToken_success(t *testing.T) {
	f := newFakeIdP(t)
	u := f.newOIDCUpstream(t, "client-abc", "", nil)

	claims := f.standardClaims("client-abc")
	claims["groups"] = []interface{}{"admins", "dev"}
	raw := f.signIDToken(t, claims)

	got, err := u.ParseAndVerifyIDToken(context.Background(), raw)
	if err != nil {
		t.Fatalf("ParseAndVerifyIDToken: unexpected error %v", err)
	}
	if got["sub"] != "user-1" {
		t.Errorf("sub = %v, want user-1", got["sub"])
	}
	if got["email"] != "user@example.com" {
		t.Errorf("email = %v, want user@example.com", got["email"])
	}
	groups, ok := got["groups"].([]interface{})
	if !ok || len(groups) != 2 || groups[0] != "admins" {
		t.Errorf("groups = %v, want [admins dev]", got["groups"])
	}
	// Registered claims survive verification (cleanup is a separate step).
	if got["iss"] != f.server.URL {
		t.Errorf("iss = %v, want %v", got["iss"], f.server.URL)
	}
}

func TestParseAndVerifyIDToken_audienceMismatch(t *testing.T) {
	f := newFakeIdP(t)
	u := f.newOIDCUpstream(t, "client-abc", "", nil)

	// Token issued for a different audience than the configured clientId.
	claims := f.standardClaims("some-other-client")
	raw := f.signIDToken(t, claims)

	_, err := u.ParseAndVerifyIDToken(context.Background(), raw)
	if err == nil {
		t.Fatalf("ParseAndVerifyIDToken: want audience-mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "audience") {
		t.Errorf("error = %v, want audience mismatch", err)
	}
}

func TestParseAndVerifyIDToken_expired(t *testing.T) {
	f := newFakeIdP(t)
	u := f.newOIDCUpstream(t, "client-abc", "", nil)

	claims := f.standardClaims("client-abc")
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	raw := f.signIDToken(t, claims)

	_, err := u.ParseAndVerifyIDToken(context.Background(), raw)
	if err == nil {
		t.Fatalf("ParseAndVerifyIDToken: want expiry error, got nil")
	}
	var expErr *oidc.TokenExpiredError
	if !errors.As(err, &expErr) {
		t.Errorf("error = %v, want *oidc.TokenExpiredError", err)
	}
}

func TestParseAndVerifyIDToken_issuerMismatch(t *testing.T) {
	f := newFakeIdP(t)
	u := f.newOIDCUpstream(t, "client-abc", "", nil)

	claims := f.standardClaims("client-abc")
	claims["iss"] = "https://attacker.example.com"
	raw := f.signIDToken(t, claims)

	_, err := u.ParseAndVerifyIDToken(context.Background(), raw)
	if err == nil {
		t.Fatalf("ParseAndVerifyIDToken: want issuer-mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "different provider") {
		t.Errorf("error = %v, want issuer mismatch ('different provider')", err)
	}
}

func TestParseAndVerifyIDToken_badSignature(t *testing.T) {
	f := newFakeIdP(t)
	u := f.newOIDCUpstream(t, "client-abc", "", nil)

	// Sign with a DIFFERENT key than the one published at the JWKS endpoint.
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	otherSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: otherKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", testKeyID),
	)
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}
	payload, err := json.Marshal(f.standardClaims("client-abc"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	jws, err := otherSigner.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	_, err = u.ParseAndVerifyIDToken(context.Background(), raw)
	if err == nil {
		t.Fatalf("ParseAndVerifyIDToken: want signature-verification error, got nil")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("error = %v, want signature failure", err)
	}
}

func TestParseAndVerifyIDToken_malformedToken(t *testing.T) {
	f := newFakeIdP(t)
	u := f.newOIDCUpstream(t, "client-abc", "", nil)

	_, err := u.ParseAndVerifyIDToken(context.Background(), "not-a-jwt")
	if err == nil {
		t.Fatalf("ParseAndVerifyIDToken: want malformed-jwt error, got nil")
	}
	if !strings.Contains(err.Error(), "malformed") {
		t.Errorf("error = %v, want malformed jwt", err)
	}
}

// ---------------------------------------------------------------------------
// FetchUserInfoClaims: the userinfo leg of federation
// ---------------------------------------------------------------------------

func TestFetchUserInfoClaims_success(t *testing.T) {
	f := newFakeIdP(t)
	f.userInfoBody = `{"sub":"user-1","email":"user@example.com","name":"User One","department":"eng"}`
	u := f.newOIDCUpstream(t, "client-abc", "", nil)

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "access-token-123", TokenType: "Bearer"})
	claims, err := u.FetchUserInfoClaims(context.Background(), ts)
	if err != nil {
		t.Fatalf("FetchUserInfoClaims: unexpected error %v", err)
	}
	if claims["sub"] != "user-1" {
		t.Errorf("sub = %v, want user-1", claims["sub"])
	}
	if claims["department"] != "eng" {
		t.Errorf("department = %v, want eng", claims["department"])
	}
	if f.userInfoCalls != 1 {
		t.Errorf("userInfoCalls = %d, want 1", f.userInfoCalls)
	}
	// The access token must be forwarded as a Bearer credential to the IdP.
	if f.lastUserInfoAuth != "Bearer access-token-123" {
		t.Errorf("userinfo Authorization = %q, want %q", f.lastUserInfoAuth, "Bearer access-token-123")
	}
}

func TestFetchUserInfoClaims_noUserInfoEndpoint(t *testing.T) {
	f := newFakeIdP(t)
	f.omitUserInfoURL = true // discovery doc has no userinfo_endpoint
	u := f.newOIDCUpstream(t, "client-abc", "", nil)

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "tok"})
	claims, err := u.FetchUserInfoClaims(context.Background(), ts)
	if err != nil {
		t.Fatalf("FetchUserInfoClaims: unexpected error %v", err)
	}
	if claims != nil {
		t.Errorf("claims = %v, want nil when no userinfo endpoint", claims)
	}
	if f.userInfoCalls != 0 {
		t.Errorf("userInfoCalls = %d, want 0 (endpoint absent)", f.userInfoCalls)
	}
}

func TestFetchUserInfoClaims_httpError(t *testing.T) {
	f := newFakeIdP(t)
	f.userInfoStatus = http.StatusUnauthorized
	f.userInfoBody = "nope"
	u := f.newOIDCUpstream(t, "client-abc", "", nil)

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "tok"})
	_, err := u.FetchUserInfoClaims(context.Background(), ts)
	if err == nil {
		t.Fatalf("FetchUserInfoClaims: want error on 401, got nil")
	}
}

func TestFetchUserInfoClaims_malformedJSON(t *testing.T) {
	f := newFakeIdP(t)
	f.userInfoBody = "{not json"
	u := f.newOIDCUpstream(t, "client-abc", "", nil)

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "tok"})
	_, err := u.FetchUserInfoClaims(context.Background(), ts)
	if err == nil {
		t.Fatalf("FetchUserInfoClaims: want decode error on bad JSON, got nil")
	}
}

func TestFetchUserInfoClaims_tokenSourceError(t *testing.T) {
	f := newFakeIdP(t)
	u := f.newOIDCUpstream(t, "client-abc", "", nil)

	_, err := u.FetchUserInfoClaims(context.Background(), errTokenSource{})
	if err == nil {
		t.Fatalf("FetchUserInfoClaims: want error when token source fails, got nil")
	}
	if f.userInfoCalls != 0 {
		t.Errorf("userInfoCalls = %d, want 0 (token never obtained)", f.userInfoCalls)
	}
}

// errTokenSource always fails to mint a token, exercising the token-source error path.
type errTokenSource struct{}

func (errTokenSource) Token() (*oauth2.Token, error) {
	return nil, errors.New("token source boom")
}

// ---------------------------------------------------------------------------
// End-to-end federation: verify ID token, fetch userinfo, then apply the
// claim transformations (cleanup + renaming) as the federation pipeline does.
// ---------------------------------------------------------------------------

func TestFederationFlow_verifyFetchTransformMerge(t *testing.T) {
	f := newFakeIdP(t)
	f.userInfoBody = `{"sub":"user-1","department":"eng","email":"ui@example.com"}`
	u := f.newOIDCUpstream(t, "client-abc", "", func(s *kubauthv1alpha1.UpstreamProviderSpec) {
		s.UseUserInfo = true
		// Rename upstream "name" claim to canonical "display_name", drop "email".
		s.ClaimRenamings = []kubauthv1alpha1.ClaimRenamingSpec{
			{OldName: "name", NewName: "display_name", Operation: kubauthv1alpha1.RenamingOperationRename},
		}
		s.ClaimRemovals = []string{"email"}
	})

	if !u.UseUserInfo() {
		t.Fatalf("UseUserInfo = false, want true")
	}

	// 1) Verify the ID token.
	idClaims := f.standardClaims("client-abc")
	idClaims["name"] = "User One"
	raw := f.signIDToken(t, idClaims)
	verified, err := u.ParseAndVerifyIDToken(context.Background(), raw)
	if err != nil {
		t.Fatalf("ParseAndVerifyIDToken: %v", err)
	}

	// 2) Fetch userinfo and merge into the claim set (userinfo wins on conflict,
	//    matching the federation merge order: id token first, userinfo overlaid).
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "tok", TokenType: "Bearer"})
	uiClaims, err := u.FetchUserInfoClaims(context.Background(), ts)
	if err != nil {
		t.Fatalf("FetchUserInfoClaims: %v", err)
	}
	merged := cloneClaimSet(verified)
	for k, v := range uiClaims {
		merged[k] = v
	}
	if merged["department"] != "eng" {
		t.Errorf("merged department = %v, want eng (from userinfo)", merged["department"])
	}

	// 3) Cleanup registered/removed claims, then rename.
	cleaned := u.CleanupClaims(merged)
	if _, ok := cleaned["iss"]; ok {
		t.Errorf("cleaned still has iss; CleanupClaims must drop registered claims")
	}
	if _, ok := cleaned["email"]; ok {
		t.Errorf("cleaned still has email; ClaimRemovals must drop it")
	}
	if cleaned["sub"] != "user-1" {
		t.Errorf("cleaned sub = %v, want user-1 (sub must survive cleanup)", cleaned["sub"])
	}

	final := u.PerformRenaming(cleaned)
	if final["display_name"] != "User One" {
		t.Errorf("final display_name = %v, want User One (renamed from name)", final["display_name"])
	}
	if _, ok := final["name"]; ok {
		t.Errorf("final still has name; rename must move it to display_name")
	}
	if final["department"] != "eng" {
		t.Errorf("final department = %v, want eng (preserved through transforms)", final["department"])
	}
}

// ---------------------------------------------------------------------------
// ClientContext wires the upstream's TLS-aware http client into the ctx so the
// oidc library uses it. We assert the value actually changes for an OIDC upstream.
// ---------------------------------------------------------------------------

func TestClientContext_wrapsHTTPClientForOIDC(t *testing.T) {
	f := newFakeIdP(t)
	u := f.newOIDCUpstream(t, "client-abc", "", nil)

	ctx := context.Background()
	wrapped := u.ClientContext(ctx)
	if wrapped == ctx {
		t.Errorf("ClientContext returned the same context; expected the upstream http client to be injected")
	}
	// And the wrapped context must carry a usable client: a fresh provider built
	// from it can complete discovery against the fake IdP over plain http.
	if _, err := oidc.NewProvider(wrapped, f.server.URL); err != nil {
		t.Errorf("oidc.NewProvider via ClientContext failed: %v", err)
	}
}
