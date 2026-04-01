// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fositepatch

import (
	"context"
	"kubauth/cmd/oidc/authenticator"
	"kubauth/cmd/oidc/oidcstorage"
	"time"

	"github.com/go-logr/logr"

	"github.com/ory/hydra/v2/fosite/handler/oauth2"
	"github.com/ory/hydra/v2/fosite/handler/openid"
	"github.com/ory/hydra/v2/fosite/token/jwt"

	"github.com/ory/x/errorsx"

	"github.com/ory/hydra/v2/fosite"
)

// ExtendedResourceOwnerStorage extends the standard storage with OidcAuthenticator functionality
type ExtendedResourceOwnerStorage interface {
	oauth2.ResourceOwnerPasswordCredentialsGrantStorage
	AuthenticateUserWithClaims(ctx context.Context, name string, secret string) (*authenticator.OidcUser, error)
	GetIssuer() string
	GetKeyID() string
	IsAllowPasswordGrant() bool
	openid.OpenIDConnectRequestStorageProvider
}

var _ ExtendedResourceOwnerStorage = &oidcstorage.MemoryStore{}

var _ fosite.TokenEndpointHandler = (*ResourceOwnerPasswordCredentialsGrantHandler)(nil)

// OAuth2ResourceOwnerPasswordCredentialsFactory creates an OAuth2 resource owner password credentials grant handler.
//
// Deprecated: The ROPC grant type is widely discouraged and will be omitted in OAuth 2.1.
func OAuth2ResourceOwnerPasswordCredentialsFactory(config fosite.Configurator, storage fosite.Storage, strategy interface{}) interface{} {
	return &ResourceOwnerPasswordCredentialsGrantHandler{
		ExtendedStorage: storage.(ExtendedResourceOwnerStorage),
		Strategy: strategy.(interface {
			oauth2.AccessTokenStrategyProvider
			oauth2.RefreshTokenStrategyProvider
		}),
		OpenIDConnectStrategy: strategy.(interface {
			OpenIDConnectTokenStrategy() openid.OpenIDConnectTokenStrategy
		}).OpenIDConnectTokenStrategy(),
		Config: config,
	}
}

// Deprecated: The ROPC grant type is widely discouraged and will be omitted in OAuth 2.1.
type ResourceOwnerPasswordCredentialsGrantHandler struct {
	ExtendedStorage ExtendedResourceOwnerStorage
	Strategy        interface {
		oauth2.AccessTokenStrategyProvider
		oauth2.RefreshTokenStrategyProvider
	}
	OpenIDConnectStrategy openid.OpenIDConnectTokenStrategy
	Config                interface {
		fosite.ScopeStrategyProvider
		fosite.AudienceStrategyProvider
		fosite.RefreshTokenScopesProvider
		fosite.RefreshTokenLifespanProvider
		fosite.AccessTokenLifespanProvider
		fosite.IDTokenLifespanProvider
		fosite.IDTokenIssuerProvider
	}
}

type Session interface {
	SetSubject(subject string)
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.2
func (c *ResourceOwnerPasswordCredentialsGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	logger := logr.FromContextAsSlogLogger(ctx)
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}
	if !c.ExtendedStorage.IsAllowPasswordGrant() {
		return errorsx.WithStack(fosite.ErrRequestForbidden.WithHint("This server does not  allow to use authorization grant 'password'. Check server configuration"))
	}

	if !request.GetClient().GetGrantTypes().Has("password") {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint("The client is not allowed to use authorization grant 'password'."))
	}

	client := request.GetClient()
	for _, scope := range request.GetRequestedScopes() {
		if !c.Config.GetScopeStrategy(ctx)(client.GetScopes(), scope) {
			return errorsx.WithStack(fosite.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	if err := c.Config.GetAudienceStrategy(ctx)(client.GetAudience(), request.GetRequestedAudience()); err != nil {
		return err
	}

	username := request.GetRequestForm().Get("username")
	password := request.GetRequestForm().Get("password")
	clientId := request.GetRequestForm().Get("client_id")

	if username == "" || password == "" {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("Username or password are missing from the POST body."))
	}

	user, err := c.ExtendedStorage.AuthenticateUserWithClaims(ctx, username, password)
	if err != nil {
		logger.Error("Failed to authenticate user:", "error", err)
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	if user == nil {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("Unable to authenticate the provided username and password credentials."))
	}

	newSession := c.createSessionWithUserClaims(user, clientId)
	request.SetSession(newSession)

	delete(request.GetRequestForm(), "password")

	HandleScopes(request, logger)
	HandleAudience(request, logger)

	atLifespan := fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantTypePassword, fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	request.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(atLifespan).Round(time.Second))

	rtLifespan := fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantTypePassword, fosite.RefreshToken, c.Config.GetRefreshTokenLifespan(ctx))
	if rtLifespan > -1 {
		request.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(rtLifespan).Round(time.Second))
	}

	if request.GetGrantedScopes().Has("openid") {
		idTokenLifespan := fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantTypePassword, fosite.IDToken, c.Config.GetIDTokenLifespan(ctx))
		request.GetSession().SetExpiresAt(fosite.IDToken, time.Now().UTC().Add(idTokenLifespan).Round(time.Second))
	}

	return nil
}

func (c *ResourceOwnerPasswordCredentialsGrantHandler) GetName() string {
	return "ResourceOwnerPasswordCredentialsGrantHandler"
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.3.3
func (c *ResourceOwnerPasswordCredentialsGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	atLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypePassword, fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	accessTokenSignature, err := c.IssueAccessToken(ctx, atLifespan, requester, responder)
	if err != nil {
		return err
	}

	var refresh, refreshSignature string
	if len(c.Config.GetRefreshTokenScopes(ctx)) == 0 || requester.GetGrantedScopes().HasOneOf(c.Config.GetRefreshTokenScopes(ctx)...) {
		var err error
		refresh, refreshSignature, err = c.Strategy.RefreshTokenStrategy().GenerateRefreshToken(ctx, requester)
		if err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		} else if err := c.ExtendedStorage.RefreshTokenStorage().CreateRefreshTokenSession(ctx, refreshSignature, accessTokenSignature, requester.Sanitize([]string{})); err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	if refresh != "" {
		responder.SetExtra("refresh_token", refresh)
	}

	if requester.GetGrantedScopes().Has("openid") {
		idTokenLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypePassword, fosite.IDToken, c.Config.GetIDTokenLifespan(ctx))

		idToken, err := c.OpenIDConnectStrategy.GenerateIDToken(ctx, idTokenLifespan, requester)
		if err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}

		if err := c.ExtendedStorage.OpenIDConnectRequestStorage().CreateOpenIDConnectSession(ctx, accessTokenSignature, requester.Sanitize([]string{})); err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}

		responder.SetExtra("id_token", idToken)
	}

	return nil
}

func (c *ResourceOwnerPasswordCredentialsGrantHandler) IssueAccessToken(ctx context.Context, atLifespan time.Duration, requester fosite.AccessRequester, responder fosite.AccessResponder) (signature string, err error) {
	token, signature, err := c.Strategy.AccessTokenStrategy().GenerateAccessToken(ctx, requester)
	if err != nil {
		return "", err
	} else if err := c.ExtendedStorage.AccessTokenStorage().CreateAccessTokenSession(ctx, signature, requester.Sanitize([]string{})); err != nil {
		return "", err
	}

	if !requester.GetSession().GetExpiresAt(fosite.AccessToken).IsZero() {
		atLifespan = time.Duration(requester.GetSession().GetExpiresAt(fosite.AccessToken).UnixNano() - time.Now().UTC().UnixNano())
	}

	responder.SetAccessToken(token)
	responder.SetTokenType("bearer")
	responder.SetExpiresIn(atLifespan)
	responder.SetScopes(requester.GetGrantedScopes())

	return signature, nil
}

func (c *ResourceOwnerPasswordCredentialsGrantHandler) CanSkipClientAuth(ctx context.Context, _ fosite.AccessRequester) bool {
	return false
}

func (c *ResourceOwnerPasswordCredentialsGrantHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne("password")
}

func (c *ResourceOwnerPasswordCredentialsGrantHandler) createSessionWithUserClaims(user *authenticator.OidcUser, clientId string) *OIDCSession {
	now := time.Now()
	var subject string
	var extra map[string]interface{}
	if user != nil {
		subject = user.Login
		extra = user.Claims
	}

	idTokenClaims := &jwt.IDTokenClaims{
		Issuer:      c.ExtendedStorage.GetIssuer(),
		Subject:     subject,
		Audience:    []string{clientId},
		IssuedAt:    now,
		RequestedAt: now,
		AuthTime:    now,
		Extra:       extra,
	}

	if clientId != "" {
		idTokenClaims.Add("azp", clientId)
	}

	jwtClaims := &jwt.JWTClaims{
		Issuer:   c.ExtendedStorage.GetIssuer(),
		Subject:  subject,
		Audience: []string{clientId},
		IssuedAt: now,
		Extra:    extra,
	}

	return &OIDCSession{
		IDTokenClaims_: idTokenClaims,
		JWTClaims_:     jwtClaims,
		Headers: &jwt.Headers{
			Extra: map[string]interface{}{
				"kid": c.ExtendedStorage.GetKeyID(),
			},
		},
		Subject:  subject,
		Username: subject,
	}
}
