/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package fositepatch

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"kubauth/cmd/oidc/authenticator"
	"kubauth/cmd/oidc/oidcstorage"

	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/fosite/compose"
	"github.com/ory/hydra/v2/fosite/token/jwt"
)

// newROPCHandler builds a ResourceOwnerPasswordCredentialsGrantHandler the
// same way ComposeAllEnabled does: via the production factory wired to a
// real compose.CommonStrategy (HMAC core + OIDC JWT). This means
// PopulateTokenEndpointResponse exercises real token generation, not a mock.
func newROPCHandler(t *testing.T, store *oidcstorage.MemoryStore, config *fosite.Config) *ResourceOwnerPasswordCredentialsGrantHandler {
	t.Helper()
	key := newTestKey(t)
	keyGetter := func(context.Context) (interface{}, error) { return key, nil }
	strategy := &compose.CommonStrategy{
		CoreStrategy:      compose.NewOAuth2HMACStrategy(config),
		OIDCTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, config),
		Signer:            &jwt.DefaultSigner{GetPrivateKey: keyGetter},
	}
	h, ok := OAuth2ResourceOwnerPasswordCredentialsFactory(config, store, strategy).(*ResourceOwnerPasswordCredentialsGrantHandler)
	if !ok {
		t.Fatal("factory did not return *ResourceOwnerPasswordCredentialsGrantHandler")
	}
	return h
}

// ropcRequestOpts configures a ROPC access request.
type ropcRequestOpts struct {
	grantType      string // defaults to "password"
	client         fosite.Client
	requestedScope []string
	requestedAud   []string
	form           url.Values
}

// newROPCRequest builds a real *fosite.AccessRequest for the token endpoint.
func newROPCRequest(o ropcRequestOpts) *fosite.AccessRequest {
	ar := fosite.NewAccessRequest(&OIDCSession{})
	gt := o.grantType
	if gt == "" {
		gt = "password"
	}
	ar.GrantTypes = fosite.Arguments{gt}
	ar.Client = o.client
	ar.RequestedScope = fosite.Arguments(o.requestedScope)
	ar.RequestedAudience = fosite.Arguments(o.requestedAud)
	if o.form != nil {
		ar.Form = o.form
	}
	return ar
}

// credForm builds a username/password (+ client_id) POST body.
func credForm(username, password, clientID string) url.Values {
	f := url.Values{}
	f.Set("username", username)
	f.Set("password", password)
	if clientID != "" {
		f.Set("client_id", clientID)
	}
	return f
}

// passwordClient is a client allowed to use the password grant.
func passwordClient(scopes, audiences []string) oidcstorage.KubauthClient {
	return newTestClient(testClientOpts{
		clientID:   "ropc-client",
		scopes:     scopes,
		audiences:  audiences,
		grantTypes: []string{"password"},
	})
}

// --- CanHandleTokenEndpointRequest / GetName -----------------------------

func TestROPC_CanHandle_OnlyExactPasswordGrant(t *testing.T) {
	h := &ResourceOwnerPasswordCredentialsGrantHandler{}
	ctx := testContext()

	if !h.CanHandleTokenEndpointRequest(ctx, newROPCRequest(ropcRequestOpts{grantType: "password"})) {
		t.Error("should handle exact 'password' grant")
	}
	if h.CanHandleTokenEndpointRequest(ctx, newROPCRequest(ropcRequestOpts{grantType: "authorization_code"})) {
		t.Error("must not handle 'authorization_code' grant")
	}
	// More than one grant type is not an exact match.
	multi := fosite.NewAccessRequest(&OIDCSession{})
	multi.GrantTypes = fosite.Arguments{"password", "refresh_token"}
	if h.CanHandleTokenEndpointRequest(ctx, multi) {
		t.Error("must not handle when password is combined with another grant")
	}
}

func TestROPC_GetName(t *testing.T) {
	h := &ResourceOwnerPasswordCredentialsGrantHandler{}
	if got := h.GetName(); got != "ResourceOwnerPasswordCredentialsGrantHandler" {
		t.Errorf("unexpected handler name %q", got)
	}
}

func TestROPC_CanSkipClientAuth_IsFalse(t *testing.T) {
	h := &ResourceOwnerPasswordCredentialsGrantHandler{}
	if h.CanSkipClientAuth(testContext(), nil) {
		t.Error("ROPC must always require client authentication")
	}
}

// --- HandleTokenEndpointRequest: rejection paths -------------------------

func TestROPC_Handle_UnknownGrantRejected(t *testing.T) {
	store := newTestStore(t, &fakeAuthenticator{}, true)
	h := newROPCHandler(t, store, newTestConfig())

	req := newROPCRequest(ropcRequestOpts{
		grantType: "authorization_code",
		client:    passwordClient([]string{"openid"}, nil),
		form:      credForm("alice", "pw", "ropc-client"),
	})
	err := h.HandleTokenEndpointRequest(testContext(), req)
	if !errors.Is(err, fosite.ErrUnknownRequest) {
		t.Fatalf("expected ErrUnknownRequest, got %v", err)
	}
}

func TestROPC_Handle_PasswordGrantDisabledByServer(t *testing.T) {
	// AllowPasswordGrant=false even though the client lists the grant.
	store := newTestStore(t, &fakeAuthenticator{}, false)
	h := newROPCHandler(t, store, newTestConfig())

	req := newROPCRequest(ropcRequestOpts{
		client: passwordClient([]string{"openid"}, nil),
		form:   credForm("alice", "pw", "ropc-client"),
	})
	err := h.HandleTokenEndpointRequest(testContext(), req)
	rfc := fosite.ErrorToRFC6749Error(err)
	if rfc.ErrorField != fosite.ErrRequestForbidden.ErrorField {
		t.Fatalf("expected request_forbidden, got %v (%v)", rfc.ErrorField, err)
	}
}

func TestROPC_Handle_ClientNotAllowedPasswordGrant(t *testing.T) {
	store := newTestStore(t, &fakeAuthenticator{}, true)
	h := newROPCHandler(t, store, newTestConfig())

	// Client without "password" in its grant types.
	client := newTestClient(testClientOpts{
		clientID:   "ropc-client",
		scopes:     []string{"openid"},
		grantTypes: []string{"authorization_code"},
	})
	req := newROPCRequest(ropcRequestOpts{
		client: client,
		form:   credForm("alice", "pw", "ropc-client"),
	})
	err := h.HandleTokenEndpointRequest(testContext(), req)
	rfc := fosite.ErrorToRFC6749Error(err)
	if rfc.ErrorField != fosite.ErrUnauthorizedClient.ErrorField {
		t.Fatalf("expected unauthorized_client, got %v (%v)", rfc.ErrorField, err)
	}
}

func TestROPC_Handle_RequestedScopeOutsideClientRejected(t *testing.T) {
	store := newTestStore(t, &fakeAuthenticator{}, true)
	h := newROPCHandler(t, store, newTestConfig())

	req := newROPCRequest(ropcRequestOpts{
		client:         passwordClient([]string{"openid"}, nil),
		requestedScope: []string{"openid", "admin"}, // admin not allowed
		form:           credForm("alice", "pw", "ropc-client"),
	})
	err := h.HandleTokenEndpointRequest(testContext(), req)
	rfc := fosite.ErrorToRFC6749Error(err)
	if rfc.ErrorField != fosite.ErrInvalidScope.ErrorField {
		t.Fatalf("expected invalid_scope, got %v (%v)", rfc.ErrorField, err)
	}
}

func TestROPC_Handle_RequestedAudienceOutsideClientRejected(t *testing.T) {
	store := newTestStore(t, &fakeAuthenticator{}, true)
	h := newROPCHandler(t, store, newTestConfig())

	// Client audience is only its own id (+ auto client_id). Request a
	// foreign audience -> AudienceStrategy rejects it.
	req := newROPCRequest(ropcRequestOpts{
		client:       passwordClient([]string{"openid"}, []string{"ropc-client"}),
		requestedAud: []string{"https://foreign-api"},
		form:         credForm("alice", "pw", "ropc-client"),
	})
	err := h.HandleTokenEndpointRequest(testContext(), req)
	if err == nil {
		t.Fatal("expected audience rejection, got nil")
	}
	rfc := fosite.ErrorToRFC6749Error(err)
	if rfc.ErrorField != fosite.ErrInvalidRequest.ErrorField {
		t.Fatalf("expected invalid_request for bad audience, got %v (%v)", rfc.ErrorField, err)
	}
}

func TestROPC_Handle_MissingUsernameRejected(t *testing.T) {
	store := newTestStore(t, &fakeAuthenticator{}, true)
	h := newROPCHandler(t, store, newTestConfig())

	req := newROPCRequest(ropcRequestOpts{
		client: passwordClient([]string{"openid"}, nil),
		form:   credForm("", "pw", "ropc-client"), // empty username
	})
	err := h.HandleTokenEndpointRequest(testContext(), req)
	rfc := fosite.ErrorToRFC6749Error(err)
	if rfc.ErrorField != fosite.ErrInvalidRequest.ErrorField {
		t.Fatalf("expected invalid_request, got %v (%v)", rfc.ErrorField, err)
	}
}

func TestROPC_Handle_MissingPasswordRejected(t *testing.T) {
	store := newTestStore(t, &fakeAuthenticator{}, true)
	h := newROPCHandler(t, store, newTestConfig())

	req := newROPCRequest(ropcRequestOpts{
		client: passwordClient([]string{"openid"}, nil),
		form:   credForm("alice", "", "ropc-client"), // empty password
	})
	err := h.HandleTokenEndpointRequest(testContext(), req)
	rfc := fosite.ErrorToRFC6749Error(err)
	if rfc.ErrorField != fosite.ErrInvalidRequest.ErrorField {
		t.Fatalf("expected invalid_request, got %v (%v)", rfc.ErrorField, err)
	}
}

func TestROPC_Handle_AuthenticatorErrorBecomesServerError(t *testing.T) {
	authErr := errors.New("ldap unreachable")
	store := newTestStore(t, &fakeAuthenticator{
		authFn: func(context.Context, string, string) (*authenticator.OidcUser, error) {
			return nil, authErr
		},
	}, true)
	h := newROPCHandler(t, store, newTestConfig())

	req := newROPCRequest(ropcRequestOpts{
		client: passwordClient([]string{"openid"}, nil),
		form:   credForm("alice", "pw", "ropc-client"),
	})
	err := h.HandleTokenEndpointRequest(testContext(), req)
	rfc := fosite.ErrorToRFC6749Error(err)
	if rfc.ErrorField != fosite.ErrServerError.ErrorField {
		t.Fatalf("expected server_error, got %v (%v)", rfc.ErrorField, err)
	}
}

func TestROPC_Handle_NilUserBecomesInvalidGrant(t *testing.T) {
	// Authenticator returns (nil, nil): bad credentials, no error.
	store := newTestStore(t, &fakeAuthenticator{
		authFn: func(context.Context, string, string) (*authenticator.OidcUser, error) {
			return nil, nil
		},
	}, true)
	h := newROPCHandler(t, store, newTestConfig())

	req := newROPCRequest(ropcRequestOpts{
		client: passwordClient([]string{"openid"}, nil),
		form:   credForm("alice", "wrong-pw", "ropc-client"),
	})
	err := h.HandleTokenEndpointRequest(testContext(), req)
	rfc := fosite.ErrorToRFC6749Error(err)
	if rfc.ErrorField != fosite.ErrInvalidGrant.ErrorField {
		t.Fatalf("expected invalid_grant, got %v (%v)", rfc.ErrorField, err)
	}
}

// --- HandleTokenEndpointRequest: success path ----------------------------

func TestROPC_Handle_SuccessGrantsScopesAndSetsSessionSubject(t *testing.T) {
	store := newTestStore(t, &fakeAuthenticator{
		authFn: func(_ context.Context, login, _ string) (*authenticator.OidcUser, error) {
			return &authenticator.OidcUser{
				Login:  login,
				Claims: map[string]interface{}{"email": "alice@example.com"},
			}, nil
		},
	}, true)
	h := newROPCHandler(t, store, newTestConfig())

	req := newROPCRequest(ropcRequestOpts{
		client:         passwordClient([]string{"openid", "profile"}, nil),
		requestedScope: []string{"openid", "profile"},
		form:           credForm("alice", "pw", "ropc-client"),
	})
	if err := h.HandleTokenEndpointRequest(testContext(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Scopes granted via HandleScopes.
	for _, want := range []string{"openid", "profile"} {
		if !req.GetGrantedScopes().Has(want) {
			t.Errorf("expected granted scope %q, granted=%v", want, req.GetGrantedScopes())
		}
	}
	// Session must carry the authenticated subject.
	session, ok := req.GetSession().(*OIDCSession)
	if !ok {
		t.Fatalf("session is not *OIDCSession: %T", req.GetSession())
	}
	if session.GetSubject() != "alice" {
		t.Errorf("expected subject alice, got %q", session.GetSubject())
	}
	if session.IDTokenClaims_.Extra["email"] != "alice@example.com" {
		t.Errorf("expected email claim propagated, got %v", session.IDTokenClaims_.Extra)
	}
	// azp added because client_id present in form.
	if session.IDTokenClaims_.Get("azp") != "ropc-client" {
		t.Errorf("expected azp=ropc-client, got %v", session.IDTokenClaims_.Get("azp"))
	}
}

// The password must be scrubbed from the request form after auth so it can
// never leak into stored sessions / logs.
func TestROPC_Handle_PasswordDeletedFromForm(t *testing.T) {
	store := newTestStore(t, &fakeAuthenticator{}, true)
	h := newROPCHandler(t, store, newTestConfig())

	form := credForm("alice", "super-secret", "ropc-client")
	req := newROPCRequest(ropcRequestOpts{
		client: passwordClient([]string{"openid"}, nil),
		form:   form,
	})
	if err := h.HandleTokenEndpointRequest(testContext(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := req.GetRequestForm().Get("password"); got != "" {
		t.Errorf("password must be deleted from form, still present: %q", got)
	}
	if got := req.GetRequestForm().Get("username"); got != "alice" {
		t.Errorf("username should remain, got %q", got)
	}
}

func TestROPC_Handle_AccessAndRefreshExpirySet(t *testing.T) {
	store := newTestStore(t, &fakeAuthenticator{}, true)
	h := newROPCHandler(t, store, newTestConfig()) // refresh lifespan 24h > -1

	req := newROPCRequest(ropcRequestOpts{
		client: passwordClient([]string{"openid"}, nil),
		form:   credForm("alice", "pw", "ropc-client"),
	})
	if err := h.HandleTokenEndpointRequest(testContext(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.GetSession().GetExpiresAt(fosite.AccessToken).IsZero() {
		t.Error("access-token expiry should be set")
	}
	if req.GetSession().GetExpiresAt(fosite.RefreshToken).IsZero() {
		t.Error("refresh-token expiry should be set for positive refresh lifespan")
	}
}

// id-token expiry must only be set when openid scope is granted.
func TestROPC_Handle_IDTokenExpirySetOnlyWithOpenidScope(t *testing.T) {
	store := newTestStore(t, &fakeAuthenticator{}, true)
	h := newROPCHandler(t, store, newTestConfig())

	// With openid.
	reqWith := newROPCRequest(ropcRequestOpts{
		client:         passwordClient([]string{"openid", "profile"}, nil),
		requestedScope: []string{"openid"},
		form:           credForm("alice", "pw", "ropc-client"),
	})
	if err := h.HandleTokenEndpointRequest(testContext(), reqWith); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqWith.GetSession().GetExpiresAt(fosite.IDToken).IsZero() {
		t.Error("id-token expiry should be set when openid is granted")
	}

	// Without openid.
	reqWithout := newROPCRequest(ropcRequestOpts{
		client:         passwordClient([]string{"openid", "profile"}, nil),
		requestedScope: []string{"profile"},
		form:           credForm("alice", "pw", "ropc-client"),
	})
	if err := h.HandleTokenEndpointRequest(testContext(), reqWithout); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reqWithout.GetSession().GetExpiresAt(fosite.IDToken).IsZero() {
		t.Error("id-token expiry must remain unset without openid scope")
	}
}

// --- PopulateTokenEndpointResponse: full token issuance ------------------

func TestROPC_Populate_RejectsNonPasswordGrant(t *testing.T) {
	store := newTestStore(t, &fakeAuthenticator{}, true)
	h := newROPCHandler(t, store, newTestConfig())

	req := newROPCRequest(ropcRequestOpts{
		grantType: "authorization_code",
		client:    passwordClient([]string{"openid"}, nil),
	})
	err := h.PopulateTokenEndpointResponse(testContext(), req, fosite.NewAccessResponse())
	if !errors.Is(err, fosite.ErrUnknownRequest) {
		t.Fatalf("expected ErrUnknownRequest, got %v", err)
	}
}

func TestROPC_Populate_IssuesAccessTokenAndRefreshToken(t *testing.T) {
	store := newTestStore(t, &fakeAuthenticator{}, true)
	config := newTestConfig()
	h := newROPCHandler(t, store, config)
	ctx := testContext()

	req := newROPCRequest(ropcRequestOpts{
		client:         passwordClient([]string{"openid"}, nil),
		requestedScope: []string{"openid"},
		form:           credForm("alice", "pw", "ropc-client"),
	})
	req.SetID("req-1")
	if err := h.HandleTokenEndpointRequest(ctx, req); err != nil {
		t.Fatalf("handle failed: %v", err)
	}

	resp := fosite.NewAccessResponse()
	if err := h.PopulateTokenEndpointResponse(ctx, req, resp); err != nil {
		t.Fatalf("populate failed: %v", err)
	}

	if resp.GetAccessToken() == "" {
		t.Error("access token should be populated")
	}
	if resp.GetTokenType() != "bearer" {
		t.Errorf("expected bearer token type, got %q", resp.GetTokenType())
	}
	// refresh_token granted because client did not request offline scopes
	// AND RefreshTokenScopes is non-empty (HasOneOf is false -> issue? see
	// logic). The handler issues a refresh token when granted scopes include
	// one of the refresh scopes OR refresh scopes config is empty. With
	// neither, no refresh token is issued.
	if resp.GetExtra("refresh_token") != nil {
		t.Errorf("no refresh token expected without offline scope, got %v", resp.GetExtra("refresh_token"))
	}
	// id_token must be present because openid was granted.
	if resp.GetExtra("id_token") == nil {
		t.Error("id_token should be present when openid granted")
	}
	// Access token must have been persisted in storage.
	if len(store.AccessTokens) == 0 {
		t.Error("access token session should be stored")
	}
}

func TestROPC_Populate_RefreshTokenIssuedWithOfflineScope(t *testing.T) {
	store := newTestStore(t, &fakeAuthenticator{}, true)
	config := newTestConfig()
	h := newROPCHandler(t, store, config)
	ctx := testContext()

	req := newROPCRequest(ropcRequestOpts{
		client:         passwordClient([]string{"openid", "offline"}, nil),
		requestedScope: []string{"openid", "offline"},
		form:           credForm("alice", "pw", "ropc-client"),
	})
	req.SetID("req-2")
	if err := h.HandleTokenEndpointRequest(ctx, req); err != nil {
		t.Fatalf("handle failed: %v", err)
	}
	resp := fosite.NewAccessResponse()
	if err := h.PopulateTokenEndpointResponse(ctx, req, resp); err != nil {
		t.Fatalf("populate failed: %v", err)
	}
	if resp.GetExtra("refresh_token") == nil {
		t.Error("refresh token expected when offline scope granted")
	}
	if len(store.RefreshTokens) == 0 {
		t.Error("refresh token session should be stored")
	}
}

// id_token must be omitted when openid was not granted.
func TestROPC_Populate_NoIDTokenWithoutOpenid(t *testing.T) {
	store := newTestStore(t, &fakeAuthenticator{}, true)
	h := newROPCHandler(t, store, newTestConfig())
	ctx := testContext()

	req := newROPCRequest(ropcRequestOpts{
		client:         passwordClient([]string{"openid", "profile"}, nil),
		requestedScope: []string{"profile"},
		form:           credForm("alice", "pw", "ropc-client"),
	})
	req.SetID("req-3")
	if err := h.HandleTokenEndpointRequest(ctx, req); err != nil {
		t.Fatalf("handle failed: %v", err)
	}
	resp := fosite.NewAccessResponse()
	if err := h.PopulateTokenEndpointResponse(ctx, req, resp); err != nil {
		t.Fatalf("populate failed: %v", err)
	}
	if resp.GetExtra("id_token") != nil {
		t.Errorf("id_token must be absent without openid, got %v", resp.GetExtra("id_token"))
	}
}
