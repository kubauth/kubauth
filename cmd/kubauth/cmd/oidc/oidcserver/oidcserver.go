package oidcserver

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/google/uuid"
	"html/template"
	"kubauth/cmd/kubauth/cmd/oidc/userdb"
	"net/http"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"kubauth/cmd/kubauth/cmd/oidc/storage"
)

type OIDCServer struct {
	Issuer        string
	Storage       *storage.MemoryStore
	Resources     string
	UserDb        userdb.UserDb
	LoginTemplate *template.Template

	oauth2     fosite.OAuth2Provider
	config     *fosite.Config
	privateKey *rsa.PrivateKey
	keyID      string
}

func (s *OIDCServer) Setup(router *http.ServeMux) {
	var err error
	// Generate RSA key for JWT signing
	s.privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate RSA key: %v", err))
	}
	s.keyID = uuid.NewString()

	// Configure fosite
	s.config = &fosite.Config{
		AccessTokenLifespan:   time.Hour,
		TokenEntropy:          32,
		GlobalSecret:          []byte("some-secret-that-is-32-bytes-long"),
		RefreshTokenScopes:    []string{"offline"},
		AuthorizeCodeLifespan: time.Minute * 10,
		AccessTokenIssuer:     s.Issuer,
		IDTokenIssuer:         s.Issuer,
	}

	s.oauth2 = compose.ComposeAllEnabled(s.config, s.Storage, s.privateKey)

	//
	//oidcServer := &OIDCServer{
	//	oauth2:        oauth2,
	//	Storage:       storage,
	//	config:        fositeConfig,
	//	privateKey:    privateKey,
	//	keyID:         keyID,
	//	issuer:        issuer,
	//	Resources:     resources,
	//	UserDb:        userDb,
	//	LoginTemplate: loginTemplate,
	//}

	// Set up routes
	router.HandleFunc("/oauth2/auth", s.handleAuthorize)
	router.HandleFunc("/oauth2/token", s.handleToken)
	router.HandleFunc("/.well-known/openid-configuration", s.handleOpenIDConfiguration)
	router.HandleFunc("/userinfo", s.handleUserInfo)
	router.HandleFunc("/.well-known/jwks.json", s.handleJWKS)
	//router.HandleFunc("/oauth2/revoke", oidcServer.revokeEndpoint)
	router.HandleFunc("/oauth2/introspect", s.HandleTokenIntrospection)

	fmt.Printf("OIDC Server starting on %s\n", s.Issuer)
	fmt.Printf("OpenID Configuration: %s/.well-known/openid-configuration\n", s.Issuer)
	fmt.Printf("Authorization endpoint: %s/oauth2/auth\n", s.Issuer)
	fmt.Printf("Token endpoint: %s/oauth2/token\n", s.Issuer)

}

// A session is passed from the `/auth` to the `/token` endpoint. You probably want to store data like: "Who made the request",
// "What organization does that person belong to" and so on.
// For our use case, the session will meet the requirements imposed by JWT access tokens, HMAC access tokens and OpenID Connect
// ID Tokens plus a custom field

// newSession is a helper function for creating a new session. This may look like a lot of code but since we are
// setting up multiple strategies it is a bit longer.
// Usually, you could do:
//
//	session = new(fosite.DefaultSession)
func (s *OIDCServer) newSession(user *userdb.User) *openid.DefaultSession {
	if user == nil {
		return &openid.DefaultSession{}
	}
	return &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:      s.Issuer,
			Subject:     user.Login,
			Audience:    []string{"https://my-client.my-application.com"},
			ExpiresAt:   time.Now().Add(time.Hour * 6),
			IssuedAt:    time.Now(),
			RequestedAt: time.Now(),
			AuthTime:    time.Now(),
			Extra:       user.Claims,
		},
		Headers: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
	}
}
