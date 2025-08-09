package oidcserver

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/google/uuid"
	"html/template"
	"kubauth/cmd/kubauth/cmd/oidc/config"
	"kubauth/cmd/kubauth/cmd/oidc/userdb"
	"net/http"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"kubauth/cmd/kubauth/cmd/oidc/storage"
)

// OIDC server configuration
type OIDCServer struct {
	oauth2        fosite.OAuth2Provider
	storage       *storage.MemoryStore
	config        *fosite.Config
	privateKey    *rsa.PrivateKey
	keyID         string
	issuer        string
	resources     string
	userDb        userdb.UserDb
	loginTemplate *template.Template
}

func NewOIDCServer(router *http.ServeMux, userDb userdb.UserDb, loginTemplate *template.Template, storage *storage.MemoryStore) *OIDCServer {
	issuer := config.Conf.Issuer

	// Generate RSA key for JWT signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate RSA key: %v", err))
	}
	keyID := uuid.NewString()

	// Configure fosite
	fositeConfig := &fosite.Config{
		AccessTokenLifespan:   time.Hour,
		TokenEntropy:          32,
		GlobalSecret:          []byte("some-secret-that-is-32-bytes-long"),
		RefreshTokenScopes:    []string{"offline"},
		AuthorizeCodeLifespan: time.Minute * 10,
		AccessTokenIssuer:     issuer,
		IDTokenIssuer:         issuer,
	}

	oauth2 := compose.ComposeAllEnabled(fositeConfig, storage, privateKey)
	//
	//client1 := &fosite.DefaultClient{
	//	ID:             "my-client",
	//	Secret:         []byte("$2a$12$9vdc.xb3Zf4ts/C2pSvIOuGmFiv0EStBJWslaaycavblaIjYZ9Mia"),            // hashed "my-secret"
	//	RotatedSecrets: [][]byte{[]byte(`$2y$10$X51gLxUQJ.hGw1epgHTE5u0bt64xM0COU7K9iAp.OFg8p2pUd.1zC `)}, // = "foobaz",
	//	//RotatedSecrets: nil,
	//	RedirectURIs:  []string{"http://localhost:9001/wo_callback", "http://localhost:8080/callback"},
	//	ResponseTypes: []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
	//	GrantTypes:    []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
	//	Scopes:        []string{"fosite", "openid", "photos", "offline", "profile", "email"},
	//}
	//
	//myStorage.Clients["my-client"] = client1
	//fmt.Printf("Stored client: %+v\n", client1)
	//
	//client2 := &fosite.DefaultClient{
	//	ID:             "example-app",
	//	Secret:         []byte("$2a$12$pxfZs1UOw3y.4IJAOVqG8OIr4n6304Y2QRBefiQpB3AnDGthYF4ba"), // hashd of ZXhhbXBsZS1hcHAtc2VjcmV0
	//	RotatedSecrets: nil,
	//	RedirectURIs:   []string{"http://localhost:5555/callback"},
	//	ResponseTypes:  []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
	//	GrantTypes:     []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
	//	//Scopes:         []string{"openid", "profile", "email"},
	//	Scopes: []string{"fosite", "openid", "photos", "offline", "profile", "email", "groups"},
	//}
	//
	//myStorage.Clients["example-app"] = client2
	//fmt.Printf("Stored client2: %+v\n", client2)

	oidcServer := &OIDCServer{
		oauth2:        oauth2,
		storage:       storage,
		config:        fositeConfig,
		privateKey:    privateKey,
		keyID:         keyID,
		issuer:        issuer,
		resources:     config.Conf.Resources,
		userDb:        userDb,
		loginTemplate: loginTemplate,
	}

	// Set up routes
	router.HandleFunc("/oauth2/auth", oidcServer.handleAuthorize)
	router.HandleFunc("/oauth2/token", oidcServer.handleToken)
	router.HandleFunc("/.well-known/openid-configuration", oidcServer.handleOpenIDConfiguration)
	router.HandleFunc("/userinfo", oidcServer.handleUserInfo)
	router.HandleFunc("/.well-known/jwks.json", oidcServer.handleJWKS)
	//router.HandleFunc("/oauth2/revoke", oidcServer.revokeEndpoint)
	router.HandleFunc("/oauth2/introspect", oidcServer.HandleTokenIntrospection)

	fmt.Printf("OIDC Server starting on %s\n", issuer)
	fmt.Printf("OpenID Configuration: %s/.well-known/openid-configuration\n", issuer)
	fmt.Printf("Authorization endpoint: %s/oauth2/auth\n", issuer)
	fmt.Printf("Token endpoint: %s/oauth2/token\n", issuer)

	return oidcServer
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
func newSession(user *userdb.User) *openid.DefaultSession {
	if user == nil {
		return &openid.DefaultSession{}
	}
	return &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:      config.Conf.Issuer,
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
