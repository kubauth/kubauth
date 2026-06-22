/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Shared test fixture for the OIDC HTTP handlers.
//
// buildServer wires a real fosite provider (via fositepatch.ComposeAllEnabled),
// the real in-memory storage (oidcstorage.MemoryStore), real scs session
// managers (in-memory store) and a fake controller-runtime k8s client. The
// returned *http.ServeMux is what Setup() registers, so handlers are exercised
// through the exact same routing/middleware stack as production.
//
// The fake authenticator lets a test decide what user (and claims) a
// login/password produces, which is the seam used to mint real authorization
// codes and then exchange them for tokens.
package oidcserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"kubauth/api/kubauth/v1alpha1"
	"kubauth/cmd/oidc/authenticator"
	"kubauth/cmd/oidc/oidcstorage"
	"kubauth/cmd/oidc/sessioncodec"
	"kubauth/internal/proto"

	scsV2 "github.com/alexedwards/scs/v2"
	scsmem "github.com/alexedwards/scs/v2/memstore"
	"github.com/go-logr/logr"
	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// ----------------------------------------------------------------- constants

const (
	testIssuer       = "https://idp.test"
	testClientID     = "web-app"
	testClientSecret = "s3cr3t-value"
	testPublicClient = "spa-app"
	testRedirectURI  = "https://app.test/callback"
	testUserLogin    = "alice"
	testUserPassword = "correct-horse"
)

// ----------------------------------------------------------------- logger ctx

// testCtx returns a context carrying a discard slog logger. Many handlers and
// storage methods call logr.FromContextAsSlogLogger(ctx) and would panic on a
// bare context.Background().
func testCtx() context.Context {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return logr.NewContextWithSlogLogger(context.Background(), logger)
}

// ----------------------------------------------------------- fake authenticator

// fakeAuthenticator is a controllable OidcAuthenticator. authFunc backs
// Authenticate (password-checked login), identFunc backs Identify.
type fakeAuthenticator struct {
	authFunc  func(ctx context.Context, login, password string) (*authenticator.OidcUser, error)
	identFunc func(ctx context.Context, login, password string) (*authenticator.OidcUser, proto.Status, error)
}

func (f *fakeAuthenticator) Authenticate(ctx context.Context, login, password string) (*authenticator.OidcUser, error) {
	if f.authFunc != nil {
		return f.authFunc(ctx, login, password)
	}
	return nil, nil
}

func (f *fakeAuthenticator) Identify(ctx context.Context, login, password string) (*authenticator.OidcUser, proto.Status, error) {
	if f.identFunc != nil {
		return f.identFunc(ctx, login, password)
	}
	return nil, proto.UserNotFound, nil
}

var _ authenticator.OidcAuthenticator = (*fakeAuthenticator)(nil)

// defaultAuth returns an authenticator that accepts exactly testUserLogin /
// testUserPassword and returns a user carrying a representative claim set.
func defaultAuth() *fakeAuthenticator {
	return &fakeAuthenticator{
		authFunc: func(_ context.Context, login, password string) (*authenticator.OidcUser, error) {
			if login == testUserLogin && password == testUserPassword {
				return &authenticator.OidcUser{
					Login:    testUserLogin,
					FullName: "Alice Example",
					Claims: map[string]interface{}{
						"sub":            testUserLogin,
						"name":           "Alice Example",
						"email":          "alice@test",
						"email_verified": true,
						"groups":         []string{"dev", "admin"},
					},
				}, nil
			}
			// nil user => invalid credentials (not an error)
			return nil, nil
		},
	}
}

// ----------------------------------------------------------------- templates

// Minimal templates so login/index/welcome handlers can render without the
// real resource files. Field names match the model structs.
func testTemplates() (login, index, welcome *template.Template) {
	login = template.Must(template.New("login").Parse(
		`<html><body>LOGIN invalid={{.InvalidLogin}} form={{.ShowLoginForm}} noprov={{.ShowNoProviderMessage}}{{range .UpstreamButtons}} btn:{{.Name}}{{end}}</body></html>`))
	index = template.Must(template.New("index").Parse(
		`<html><body>INDEX{{range .Entries}} app:{{.DisplayName}}|{{.EntryURL}}{{end}}</body></html>`))
	welcome = template.Must(template.New("welcome").Parse(
		`<html><body>WELCOME {{.UserName}}</body></html>`))
	return
}

// ----------------------------------------------------------------- k8s client

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := scheme.AddToScheme(s); err != nil { // core/v1 (Secret)
		t.Fatalf("clientgo AddToScheme: %v", err)
	}
	if err := v1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("v1alpha1 AddToScheme: %v", err)
	}
	return s
}

// preGeneratedKeySecret returns a Secret already holding an RSA key + kid, so
// ensureJwtSigningKey takes the "load existing" branch deterministically.
func preGeneratedKeySecret(t *testing.T, name, ns string) (*corev1.Secret, *rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	const kid = "test-kid-1"
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Type:       corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"key.pem": pemBytes,
			"kid":     []byte(kid),
		},
	}
	return sec, key, kid
}

// ----------------------------------------------------------------- clients

// confidentialClient builds a registered confidential client supporting the
// authorization-code + refresh-token + client-credentials grants.
func confidentialClient(t *testing.T) oidcstorage.KubauthClient {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(testClientSecret), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	cli := &v1alpha1.OidcClient{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kubauth-system", Name: testClientID},
		Spec: v1alpha1.OidcClientSpec{
			RedirectURIs:  []string{testRedirectURI},
			GrantTypes:    []string{"authorization_code", "refresh_token", "client_credentials"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email", "groups", "offline"},
			Audiences:     []string{testClientID},
			Public:        false,
			DisplayName:   "Web App",
			EntryURL:      "https://app.test/",
			Description:   "the web app",
		},
	}
	return oidcstorage.NewKubauthClient(cli, testClientID, [][]byte{h})
}

// publicClient builds a registered public client (no secret) using PKCE.
func publicClient(t *testing.T) oidcstorage.KubauthClient {
	t.Helper()
	cli := &v1alpha1.OidcClient{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kubauth-system", Name: testPublicClient},
		Spec: v1alpha1.OidcClientSpec{
			RedirectURIs:  []string{testRedirectURI},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email", "offline"},
			Public:        true,
			DisplayName:   "SPA App",
			EntryURL:      "https://spa.test/",
		},
	}
	return oidcstorage.NewKubauthClient(cli, testPublicClient, nil)
}

// ----------------------------------------------------------------- fixture

// testServer bundles the wired server, its mux and the knobs a test may swap.
type testServer struct {
	srv    *OIDCServer
	mux    *http.ServeMux
	auth   *fakeAuthenticator
	store  *oidcstorage.MemoryStore
	kube   client.Client
	key    *rsa.PrivateKey
	kid    string
	issuer string
}

type buildOpts struct {
	auth               *fakeAuthenticator
	clients            []oidcstorage.KubauthClient
	ssoMode            SsoMode
	allowPasswordGrant bool
	enforcePKCE        bool
	jwtAccessToken     bool
	kubeObjects        []client.Object
}

// buildServer wires a ready-to-serve OIDCServer with sane defaults. Tests pass
// option mutators to customise. It calls the real Setup(), so JWKS/issuer/keyID
// are all derived exactly as in production.
func buildServer(t *testing.T, mutators ...func(*buildOpts)) *testServer {
	t.Helper()
	opts := &buildOpts{
		auth:    defaultAuth(),
		clients: []oidcstorage.KubauthClient{confidentialClient(t)},
		ssoMode: SsoNever,
	}
	for _, m := range mutators {
		m(opts)
	}

	const secretName, secretNS = "kubauth-jwt-key", "kubauth-system"
	sec, key, kid := preGeneratedKeySecret(t, secretName, secretNS)

	objs := append([]client.Object{sec}, opts.kubeObjects...)
	kube := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(objs...).Build()

	return buildServerWithClient(t, opts, kube, key, kid, secretName, secretNS)
}

// buildServerWithClient is the shared tail used by buildServer and by tests
// that need to inject a fake client with interceptors.
func buildServerWithClient(t *testing.T, opts *buildOpts, kube client.Client, key *rsa.PrivateKey, kid, secretName, secretNS string) *testServer {
	t.Helper()

	store := oidcstorage.NewMemoryStore(opts.auth)
	for _, c := range opts.clients {
		if err := store.SetClient(testCtx(), c); err != nil {
			t.Fatalf("SetClient: %v", err)
		}
	}

	loginTmpl, indexTmpl, welcomeTmpl := testTemplates()

	sso := scsV2.New()
	sso.Store = scsmem.New()
	// Match production: the SSO session is serialised with the JSON codec, so a
	// stored *OidcUser round-trips back as map[string]interface{} — which is
	// exactly what handleLogin's SSO-reuse path type-asserts.
	sso.Codec = sessioncodec.JSONCodec{}
	login := scsV2.New()
	login.Store = scsmem.New()

	srv := &OIDCServer{
		Issuer:                  testIssuer,
		Storage:                 store,
		Authenticator:           opts.auth,
		Resources:               t.TempDir(),
		LoginTemplate:           loginTmpl,
		IndexTemplate:           indexTmpl,
		UpstreamWelcomeTemplate: welcomeTmpl,
		SsoSessionManager:       sso,
		LoginSessionManager:     login,
		PostLogoutURL:           "https://idp.test/loggedout",
		KubeClient:              kube,
		EventRecorder:           record.NewFakeRecorder(64),
		JWTSigningKeySecretName: secretName,
		JWTSigningKeySecretNS:   secretNS,
		AccessTokenLifespan:     time.Hour,
		RefreshTokenLifespan:    time.Hour,
		AllowPasswordGrant:      opts.allowPasswordGrant,
		EnforcePKCE:             opts.enforcePKCE,
		JwtAccessToken:          opts.jwtAccessToken,
		DefaultStyle:            "default",
		SsoMode:                 opts.ssoMode,
		DefaultLoginLabel:       "Sign in",
	}

	mux := http.NewServeMux()
	if err := srv.Setup(testCtx(), mux); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	return &testServer{
		srv:    srv,
		mux:    mux,
		auth:   opts.auth,
		store:  store,
		kube:   kube,
		key:    key,
		kid:    kid,
		issuer: testIssuer,
	}
}

// ----------------------------------------------------------------- request helpers

// do sends a request through the mux and returns the recorder. The request
// already carries the discard-logger context.
func (ts *testServer) do(req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	ts.mux.ServeHTTP(rr, req.WithContext(testCtx()))
	return rr
}

func newGet(t *testing.T, path string) *http.Request {
	t.Helper()
	return httptest.NewRequest(http.MethodGet, path, nil)
}

func newPostForm(t *testing.T, path string, form url.Values) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// ----------------------------------------------------------------- flow helper

// authzQuery builds the query string for an authorization-code request.
func authzQuery(clientID, scope string, extra url.Values) url.Values {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", testRedirectURI)
	q.Set("scope", scope)
	q.Set("state", "xyz-state")
	for k, vs := range extra {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	return q
}

// loginForCode drives a full /oauth2/login POST (with the authQuery primed by a
// prior GET) and returns the authorization code extracted from the redirect
// Location, plus the cookies in play. It fails the test if no code is issued.
//
// The two-step GET-then-POST is required because the raw authorize query is
// stashed in the login session by the GET handler and read back by the POST.
func (ts *testServer) loginForCode(t *testing.T, q url.Values, login, password string) string {
	t.Helper()

	// Step 1: GET /oauth2/login?<authz query> — primes the session cookie.
	getReq := newGet(t, "/oauth2/login?"+q.Encode())
	getRR := ts.do(getReq)
	cookies := readCookies(getRR)
	if len(cookies) == 0 {
		t.Fatalf("login GET set no session cookie (status %d)", getRR.Code)
	}

	// Step 2: POST credentials, carrying the session cookie back.
	form := url.Values{}
	form.Set("login", login)
	form.Set("password", password)
	postReq := newPostForm(t, "/oauth2/login", form)
	for _, c := range cookies {
		postReq.AddCookie(c)
	}
	postRR := ts.do(postReq)

	if postRR.Code != http.StatusFound && postRR.Code != http.StatusSeeOther {
		t.Fatalf("login POST: expected redirect, got %d body=%q", postRR.Code, postRR.Body.String())
	}
	loc := postRR.Header().Get("Location")
	code := codeFromLocation(t, loc)
	if code == "" {
		t.Fatalf("login POST redirect carried no code: %q", loc)
	}
	return code
}

// exchangeCode posts an authorization_code grant to /oauth2/token and returns
// the decoded JSON token response and the raw recorder.
func (ts *testServer) exchangeCode(t *testing.T, code, clientID, clientSecret string, extra url.Values) (map[string]interface{}, *httptest.ResponseRecorder) {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", testRedirectURI)
	for k, vs := range extra {
		for _, v := range vs {
			form.Add(k, v)
		}
	}
	req := newPostForm(t, "/oauth2/token", form)
	if clientSecret != "" {
		req.SetBasicAuth(clientID, clientSecret)
	} else {
		form.Set("client_id", clientID)
		req = newPostForm(t, "/oauth2/token", form)
	}
	rr := ts.do(req)
	out := map[string]interface{}{}
	if rr.Body.Len() > 0 {
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
	}
	return out, rr
}

// ----------------------------------------------------------------- small utils

func readCookies(rr *httptest.ResponseRecorder) []*http.Cookie {
	res := &http.Response{Header: rr.Header()}
	return res.Cookies()
}

// isRedirect reports whether the status is one of the 3xx codes fosite/the
// handlers use for authorize redirects (302 Found or 303 See Other).
func isRedirect(code int) bool {
	return code == http.StatusFound || code == http.StatusSeeOther
}

func codeFromLocation(t *testing.T, loc string) string {
	t.Helper()
	if loc == "" {
		return ""
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse redirect location %q: %v", loc, err)
	}
	return u.Query().Get("code")
}

func decodeJSON(t *testing.T, rr *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	out := map[string]interface{}{}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode JSON (body=%q): %v", rr.Body.String(), err)
	}
	return out
}

// mustString fetches a string field or fails.
func mustString(t *testing.T, m map[string]interface{}, key string) string {
	t.Helper()
	v, ok := m[key].(string)
	if !ok || v == "" {
		t.Fatalf("expected non-empty string field %q in %v", key, m)
	}
	return v
}
