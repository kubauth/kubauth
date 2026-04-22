// Copyright © 2024 Ory Corp
// Copyright © 2025 Kubotal
// SPDX-License-Identifier: Apache-2.0

package oidcstorage

import (
	"context"
	"errors"
	"fmt"
	"kubauth/cmd/oidc/authenticator"
	"kubauth/cmd/oidc/upstreams"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/ory/hydra/v2/fosite/handler/rfc7523"

	"github.com/go-jose/go-jose/v3"
	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/fosite/handler/oauth2"
	"github.com/ory/hydra/v2/fosite/handler/openid"
	"github.com/ory/hydra/v2/fosite/handler/pkce"
)

type MemoryUserRelation struct {
	Username string
	Password string
}

type IssuerPublicKeys struct {
	Issuer    string
	KeysBySub map[string]SubjectPublicKeys
}

type SubjectPublicKeys struct {
	Subject string
	Keys    map[string]PublicKeyScopes
}

type PublicKeyScopes struct {
	Key    *jose.JSONWebKey
	Scopes []string
}

type MemoryStore struct {
	Clients        map[string]KubauthClient
	AuthorizeCodes map[string]StoreAuthorizeCode
	IDSessions     map[string]fosite.Requester
	AccessTokens   map[string]fosite.Requester
	RefreshTokens  map[string]StoreRefreshToken
	PKCES          map[string]fosite.Requester
	//Users           map[string]MemoryUserRelation
	BlacklistedJTIs map[string]time.Time
	// In-memory request ID to token signatures
	AccessTokenRequestIDs  map[string]string
	RefreshTokenRequestIDs map[string]string
	// Public keys to check signature in auth grant jwt assertion.
	IssuerPublicKeys   map[string]IssuerPublicKeys
	PARSessions        map[string]fosite.AuthorizeRequester
	Upstreams          map[string]upstreams.Upstream
	Authenticator      authenticator.OidcAuthenticator
	Issuer             string
	KeyID              string
	AllowPasswordGrant bool

	clientsMutex                sync.RWMutex
	authorizeCodesMutex         sync.RWMutex
	idSessionsMutex             sync.RWMutex
	accessTokensMutex           sync.RWMutex
	refreshTokensMutex          sync.RWMutex
	pkcesMutex                  sync.RWMutex
	usersMutex                  sync.RWMutex
	blacklistedJTIsMutex        sync.RWMutex
	accessTokenRequestIDsMutex  sync.RWMutex
	refreshTokenRequestIDsMutex sync.RWMutex
	issuerPublicKeysMutex       sync.RWMutex
	parSessionsMutex            sync.RWMutex
	upstreamMutex               sync.RWMutex
}

func NewMemoryStore(idp authenticator.OidcAuthenticator) *MemoryStore {
	return &MemoryStore{
		Clients:        make(map[string]KubauthClient),
		AuthorizeCodes: make(map[string]StoreAuthorizeCode),
		IDSessions:     make(map[string]fosite.Requester),
		AccessTokens:   make(map[string]fosite.Requester),
		RefreshTokens:  make(map[string]StoreRefreshToken),
		PKCES:          make(map[string]fosite.Requester),
		//Users:                  make(map[string]MemoryUserRelation),
		AccessTokenRequestIDs:  make(map[string]string),
		RefreshTokenRequestIDs: make(map[string]string),
		BlacklistedJTIs:        make(map[string]time.Time),
		IssuerPublicKeys:       make(map[string]IssuerPublicKeys),
		PARSessions:            make(map[string]fosite.AuthorizeRequester),
		Upstreams:              make(map[string]upstreams.Upstream),
		Authenticator:          idp,
	}
}

type StoreAuthorizeCode struct {
	active bool
	fosite.Requester
}

type StoreRefreshToken struct {
	active               bool
	accessTokenSignature string
	fosite.Requester
}

// ------------------------------------------------------ OpenIDConnectSession

func (s *MemoryStore) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) error {
	s.idSessionsMutex.Lock()
	defer s.idSessionsMutex.Unlock()

	logger := logr.FromContextAsSlogLogger(ctx)
	logger.Debug("CreateOpenIDConnectSession", "code", authorizeCode, "requesterId", requester.GetID())
	s.IDSessions[authorizeCode] = requester
	return nil
}

func (s *MemoryStore) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	s.idSessionsMutex.RLock()
	defer s.idSessionsMutex.RUnlock()

	logger := logr.FromContextAsSlogLogger(ctx)
	cl, ok := s.IDSessions[authorizeCode]
	if !ok {
		logger.Debug("GetOpenIDConnectSession() NOT FOUND!", "code", authorizeCode, "requesterId", requester.GetID())
		return nil, fosite.ErrNotFound
	}
	logger.Debug("GetOpenIDConnectSession() found!", "code", authorizeCode, "requesterId", requester.GetID())
	return cl, nil
}

func (s *MemoryStore) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	s.idSessionsMutex.Lock()
	defer s.idSessionsMutex.Unlock()

	logger := logr.FromContextAsSlogLogger(ctx)
	logger.Debug("DeleteOpenIDConnectSession", "code", authorizeCode)

	delete(s.IDSessions, authorizeCode)
	return nil
}

// ------------------------------------------------------ Upstreams

func (s *MemoryStore) GetUpstream(_ context.Context, name string) upstreams.Upstream {
	s.upstreamMutex.RLock()
	defer s.upstreamMutex.RUnlock()
	upstream, ok := s.Upstreams[name]
	if !ok {
		return nil
	}
	return upstream
}

func (s *MemoryStore) GetUpstreams(_ context.Context) []upstreams.Upstream {
	s.upstreamMutex.RLock()
	defer s.upstreamMutex.RUnlock()
	return slices.Collect(maps.Values(s.Upstreams))
}

//
//func (s *MemoryStore) GetUpstreams(_ context.Context) []upstreams.UpstreamLabel {
//	s.upstreamMutex.RLock()
//	defer s.upstreamMutex.RUnlock()
//	upstreamLabels := make([]upstreams.UpstreamLabel, len(s.Upstreams))
//	idx := 0
//	for _, upstream := range s.Upstreams {
//		upstreamLabels[idx] = upstream.GetLabel()
//		idx++
//	}
//	return upstreamLabels
//}
//
//// ListUpstreamsInNamespace returns in-memory upstreams whose storage key is under the given
//// namespace (keys are "namespace:name" per upstreams.BuildUpstreamId).
//func (s *MemoryStore) ListUpstreamsInNamespace(_ context.Context, namespace string) []upstreams.Upstream {
//	s.upstreamMutex.RLock()
//	defer s.upstreamMutex.RUnlock()
//	prefix := namespace + ":"
//	var keys []string
//	for k := range s.Upstreams {
//		if strings.HasPrefix(k, prefix) {
//			keys = append(keys, k)
//		}
//	}
//	sort.Strings(keys)
//	out := make([]upstreams.Upstream, 0, len(keys))
//	for _, k := range keys {
//		out = append(out, s.Upstreams[k])
//	}
//	return out
//}
//
//// GetUpstreamByReference resolves ref as a full storage key (GetUpstream), as a resource name
//// in the configured upstream namespace, or as the first name match within that namespace.
//func (s *MemoryStore) GetUpstreamByReference(ctx context.Context, ref, namespace string) (upstreams.Upstream, error) {
//	u, err := s.GetUpstream(ctx, ref)
//	if err == nil {
//		return u, nil
//	}
//	u, err = s.GetUpstream(ctx, upstreams.BuildUpstreamId(ref, namespace))
//	if err == nil {
//		return u, nil
//	}
//	for _, cand := range s.ListUpstreamsInNamespace(ctx, namespace) {
//		if cand.GetResourceName() == ref {
//			return cand, nil
//		}
//	}
//	return nil, fosite.ErrNotFound
//}

func (s *MemoryStore) SetUpstream(ctx context.Context, upstream upstreams.Upstream) {
	s.upstreamMutex.Lock()
	defer s.upstreamMutex.Unlock()
	logger := logr.FromContextAsSlogLogger(ctx)
	logger.Debug("SetUpstream", "name", upstream.GetName(), "upstream", upstream)
	s.Upstreams[upstream.GetName()] = upstream
}

func (s *MemoryStore) DeleteUpstream(ctx context.Context, name string) {
	s.upstreamMutex.Lock()
	defer s.upstreamMutex.Unlock()
	logger := logr.FromContextAsSlogLogger(ctx)
	logger.Debug("DeleteUpstream", "name", name)
	delete(s.Upstreams, name)
}

// ------------------------------------------------------ Oidc Clients

func (s *MemoryStore) GetKubauthClient(_ context.Context, id string) (KubauthClient, error) {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	cl, ok := s.Clients[id]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return cl, nil
}

// This to comply to fosite.ClientManager interface

func (s *MemoryStore) GetClient(_ context.Context, id string) (fosite.Client, error) {
	return s.GetKubauthClient(context.Background(), id)
}

//func (s *MemoryStore) SetClients(_ context.Context, clients map[string]FositeClient) {
//	s.clientsMutex.Lock()
//	defer s.clientsMutex.Unlock()
//	s.Clients = clients
//}

type ClientDuplicationError struct {
	existingClient string
}

func (e *ClientDuplicationError) Error() string {
	return fmt.Sprintf("duplicate client_id with %s", e.existingClient)
}

func (e *ClientDuplicationError) GetExistingClient() string {
	return e.existingClient
}

func (s *MemoryStore) SetClient(ctx context.Context, client KubauthClient) error {
	logger := logr.FromContextAsSlogLogger(ctx)
	s.clientsMutex.Lock()
	defer s.clientsMutex.Unlock()
	oldClient, ok := s.Clients[client.GetID()]
	if ok && oldClient.GetK8sId() != client.GetK8sId() {
		return &ClientDuplicationError{
			existingClient: oldClient.GetK8sId(),
		}
	}
	s.Clients[client.GetID()] = client
	logger.Debug("SettingClient", "clientId", client.GetID(), "clientCount", len(s.Clients), "secretCount", client.GetSecretCount())
	return nil
}

func (s *MemoryStore) DeleteClient(ctx context.Context, clientId string) {
	logger := logr.FromContextAsSlogLogger(ctx)
	s.clientsMutex.Lock()
	defer s.clientsMutex.Unlock()
	delete(s.Clients, clientId)
	logger.Debug("DeleteClient", "clientId", clientId, "clientCount", len(s.Clients))
}

// ----------------------------------------------------------------

func (s *MemoryStore) SetTokenLifespans(clientID string, lifespans *fosite.ClientLifespanConfig) error {
	if client, ok := s.Clients[clientID]; ok {
		c2 := client.(fosite.Client)
		if clc, ok := c2.(*fosite.DefaultClientWithCustomTokenLifespans); ok {
			clc.SetTokenLifespans(lifespans)
			return nil
		}
		return fosite.ErrorToRFC6749Error(errors.New("failed to set token lifespans due to failed client type assertion"))
	}
	return fosite.ErrNotFound
}

func (s *MemoryStore) ClientAssertionJWTValid(_ context.Context, jti string) error {
	s.blacklistedJTIsMutex.RLock()
	defer s.blacklistedJTIsMutex.RUnlock()

	if exp, exists := s.BlacklistedJTIs[jti]; exists && exp.After(time.Now()) {
		return fosite.ErrJTIKnown
	}

	return nil
}

func (s *MemoryStore) SetClientAssertionJWT(_ context.Context, jti string, exp time.Time) error {
	s.blacklistedJTIsMutex.Lock()
	defer s.blacklistedJTIsMutex.Unlock()

	// delete expired jtis
	for j, e := range s.BlacklistedJTIs {
		if e.Before(time.Now()) {
			delete(s.BlacklistedJTIs, j)
		}
	}

	if _, exists := s.BlacklistedJTIs[jti]; exists {
		return fosite.ErrJTIKnown
	}

	s.BlacklistedJTIs[jti] = exp
	return nil
}

func (s *MemoryStore) CreateAuthorizeCodeSession(_ context.Context, code string, req fosite.Requester) error {
	s.authorizeCodesMutex.Lock()
	defer s.authorizeCodesMutex.Unlock()

	s.AuthorizeCodes[code] = StoreAuthorizeCode{active: true, Requester: req}
	return nil
}

func (s *MemoryStore) GetAuthorizeCodeSession(_ context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	s.authorizeCodesMutex.RLock()
	defer s.authorizeCodesMutex.RUnlock()

	rel, ok := s.AuthorizeCodes[code]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	if !rel.active {
		return rel, fosite.ErrInvalidatedAuthorizeCode
	}

	return rel.Requester, nil
}

func (s *MemoryStore) InvalidateAuthorizeCodeSession(_ context.Context, code string) error {
	s.authorizeCodesMutex.Lock()
	defer s.authorizeCodesMutex.Unlock()

	rel, ok := s.AuthorizeCodes[code]
	if !ok {
		return fosite.ErrNotFound
	}
	rel.active = false
	s.AuthorizeCodes[code] = rel
	return nil
}

func (s *MemoryStore) CreatePKCERequestSession(_ context.Context, code string, req fosite.Requester) error {
	s.pkcesMutex.Lock()
	defer s.pkcesMutex.Unlock()

	s.PKCES[code] = req
	return nil
}

func (s *MemoryStore) GetPKCERequestSession(_ context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	s.pkcesMutex.RLock()
	defer s.pkcesMutex.RUnlock()

	rel, ok := s.PKCES[code]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return rel, nil
}

func (s *MemoryStore) DeletePKCERequestSession(_ context.Context, code string) error {
	s.pkcesMutex.Lock()
	defer s.pkcesMutex.Unlock()

	delete(s.PKCES, code)
	return nil
}

func (s *MemoryStore) CreateAccessTokenSession(_ context.Context, signature string, req fosite.Requester) error {
	// We first lock accessTokenRequestIDsMutex and then accessTokensMutex because this is the same order
	// locking happens in RevokeAccessToken and using the same order prevents deadlocks.
	s.accessTokenRequestIDsMutex.Lock()
	defer s.accessTokenRequestIDsMutex.Unlock()
	s.accessTokensMutex.Lock()
	defer s.accessTokensMutex.Unlock()

	s.AccessTokens[signature] = req
	s.AccessTokenRequestIDs[req.GetID()] = signature
	return nil
}

func (s *MemoryStore) GetAccessTokenSession(_ context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	s.accessTokensMutex.RLock()
	defer s.accessTokensMutex.RUnlock()

	rel, ok := s.AccessTokens[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return rel, nil
}

func (s *MemoryStore) DeleteAccessTokenSession(_ context.Context, signature string) error {
	s.accessTokensMutex.Lock()
	defer s.accessTokensMutex.Unlock()

	delete(s.AccessTokens, signature)
	return nil
}

func (s *MemoryStore) CreateRefreshTokenSession(_ context.Context, signature, accessTokenSignature string, req fosite.Requester) error {
	// We first lock refreshTokenRequestIDsMutex and then refreshTokensMutex because this is the same order
	// locking happens in RevokeRefreshToken and using the same order prevents deadlocks.
	s.refreshTokenRequestIDsMutex.Lock()
	defer s.refreshTokenRequestIDsMutex.Unlock()
	s.refreshTokensMutex.Lock()
	defer s.refreshTokensMutex.Unlock()

	s.RefreshTokens[signature] = StoreRefreshToken{active: true, Requester: req, accessTokenSignature: accessTokenSignature}
	s.RefreshTokenRequestIDs[req.GetID()] = signature
	return nil
}

func (s *MemoryStore) GetRefreshTokenSession(_ context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	s.refreshTokensMutex.RLock()
	defer s.refreshTokensMutex.RUnlock()

	rel, ok := s.RefreshTokens[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	if !rel.active {
		return rel, fosite.ErrInactiveToken
	}
	return rel, nil
}

func (s *MemoryStore) DeleteRefreshTokenSession(_ context.Context, signature string) error {
	s.refreshTokensMutex.Lock()
	defer s.refreshTokensMutex.Unlock()

	delete(s.RefreshTokens, signature)
	return nil
}

func (s *MemoryStore) Authenticate(ctx context.Context, name string, secret string) (subject string, err error) {
	s.usersMutex.RLock()
	defer s.usersMutex.RUnlock()

	//rel, ok := s.Users[name]
	//if !ok {
	//	return "", fosite.ErrNotFound
	//}
	//if rel.Password != secret {
	//	return "", fosite.ErrNotFound.WithDebug("Invalid credentials")
	//}
	//return uuid.New().String(), nil
	usr, err := s.Authenticator.Authenticate(ctx, name, secret)
	if err != nil {
		return "", err
	}
	return usr.Login, nil
}

// AuthenticateUserWithClaims returns the full user object with claims
func (s *MemoryStore) AuthenticateUserWithClaims(ctx context.Context, name string, secret string) (*authenticator.OidcUser, error) {
	s.usersMutex.RLock()
	defer s.usersMutex.RUnlock()

	return s.Authenticator.Authenticate(ctx, name, secret)
}

// GetIssuer returns the configured issuer
func (s *MemoryStore) GetIssuer() string {
	return s.Issuer
}

// GetKeyID returns the configured key ID
func (s *MemoryStore) GetKeyID() string {
	return s.KeyID
}

func (s *MemoryStore) IsAllowPasswordGrant() bool {
	return s.AllowPasswordGrant
}

func (s *MemoryStore) RevokeRefreshToken(_ context.Context, requestID string) error {
	s.refreshTokenRequestIDsMutex.Lock()
	defer s.refreshTokenRequestIDsMutex.Unlock()

	if signature, exists := s.RefreshTokenRequestIDs[requestID]; exists {
		rel, ok := s.RefreshTokens[signature]
		if !ok {
			return fosite.ErrNotFound
		}
		rel.active = false
		s.RefreshTokens[signature] = rel
	}
	return nil
}

func (s *MemoryStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	s.accessTokenRequestIDsMutex.RLock()
	defer s.accessTokenRequestIDsMutex.RUnlock()

	if signature, exists := s.AccessTokenRequestIDs[requestID]; exists {
		if err := s.DeleteAccessTokenSession(ctx, signature); err != nil {
			return err
		}
	}
	return nil
}

func (s *MemoryStore) GetPublicKey(_ context.Context, issuer string, subject string, keyId string) (*jose.JSONWebKey, error) {
	s.issuerPublicKeysMutex.RLock()
	defer s.issuerPublicKeysMutex.RUnlock()

	if issuerKeys, ok := s.IssuerPublicKeys[issuer]; ok {
		if subKeys, ok := issuerKeys.KeysBySub[subject]; ok {
			if keyScopes, ok := subKeys.Keys[keyId]; ok {
				return keyScopes.Key, nil
			}
		}
	}

	return nil, fosite.ErrNotFound
}
func (s *MemoryStore) GetPublicKeys(_ context.Context, issuer string, subject string) (*jose.JSONWebKeySet, error) {
	s.issuerPublicKeysMutex.RLock()
	defer s.issuerPublicKeysMutex.RUnlock()

	if issuerKeys, ok := s.IssuerPublicKeys[issuer]; ok {
		if subKeys, ok := issuerKeys.KeysBySub[subject]; ok {
			if len(subKeys.Keys) == 0 {
				return nil, fosite.ErrNotFound
			}

			keys := make([]jose.JSONWebKey, 0, len(subKeys.Keys))
			for _, keyScopes := range subKeys.Keys {
				keys = append(keys, *keyScopes.Key)
			}

			return &jose.JSONWebKeySet{Keys: keys}, nil
		}
	}

	return nil, fosite.ErrNotFound
}

func (s *MemoryStore) GetPublicKeyScopes(_ context.Context, issuer string, subject string, keyId string) ([]string, error) {
	s.issuerPublicKeysMutex.RLock()
	defer s.issuerPublicKeysMutex.RUnlock()

	if issuerKeys, ok := s.IssuerPublicKeys[issuer]; ok {
		if subKeys, ok := issuerKeys.KeysBySub[subject]; ok {
			if keyScopes, ok := subKeys.Keys[keyId]; ok {
				return keyScopes.Scopes, nil
			}
		}
	}

	return nil, fosite.ErrNotFound
}

func (s *MemoryStore) IsJWTUsed(ctx context.Context, jti string) (bool, error) {
	err := s.ClientAssertionJWTValid(ctx, jti)
	if err != nil {
		return true, nil
	}

	return false, nil
}

func (s *MemoryStore) MarkJWTUsedForTime(ctx context.Context, jti string, exp time.Time) error {
	return s.SetClientAssertionJWT(ctx, jti, exp)
}

// CreatePARSession stores the pushed authorization request context. The requestURI is used to derive the key.
func (s *MemoryStore) CreatePARSession(_ context.Context, requestURI string, request fosite.AuthorizeRequester) error {
	s.parSessionsMutex.Lock()
	defer s.parSessionsMutex.Unlock()

	s.PARSessions[requestURI] = request
	return nil
}

// GetPARSession gets the push authorization request context. If the request is nil, a new request object
// is created. Otherwise, the same object is updated.
func (s *MemoryStore) GetPARSession(_ context.Context, requestURI string) (fosite.AuthorizeRequester, error) {
	s.parSessionsMutex.RLock()
	defer s.parSessionsMutex.RUnlock()

	r, ok := s.PARSessions[requestURI]
	if !ok {
		return nil, fosite.ErrNotFound
	}

	return r, nil
}

// DeletePARSession deletes the context.
func (s *MemoryStore) DeletePARSession(_ context.Context, requestURI string) (err error) {
	s.parSessionsMutex.Lock()
	defer s.parSessionsMutex.Unlock()

	delete(s.PARSessions, requestURI)
	return nil
}

func (s *MemoryStore) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) (err error) {
	// Graceful token rotation can be implemented here, but it's beyond the scope of this example. Check
	// the Ory Hydra implementation for reference.
	if err := s.RevokeRefreshToken(ctx, requestID); err != nil {
		return err
	}
	return s.RevokeAccessToken(ctx, requestID)
}

// Storage provider methods required by the hydra-embedded fosite.
// Each returns self since MemoryStore directly implements all sub-storage interfaces.

var _ fosite.Storage = &MemoryStore{}

func (s *MemoryStore) ClientManager() fosite.ClientManager                             { return s }
func (s *MemoryStore) AccessTokenStorage() oauth2.AccessTokenStorage                   { return s }
func (s *MemoryStore) RefreshTokenStorage() oauth2.RefreshTokenStorage                 { return s }
func (s *MemoryStore) AuthorizeCodeStorage() oauth2.AuthorizeCodeStorage               { return s }
func (s *MemoryStore) OpenIDConnectRequestStorage() openid.OpenIDConnectRequestStorage { return s }
func (s *MemoryStore) PKCERequestStorage() pkce.PKCERequestStorage                     { return s }
func (s *MemoryStore) PARStorage() fosite.PARStorage                                   { return s }

func (s *MemoryStore) TokenRevocationStorage() oauth2.TokenRevocationStorage { return s }
func (s *MemoryStore) RFC7523KeyStorage() rfc7523.RFC7523KeyStorage          { return s }
