package oidcserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"html/template"
	"kubauth/cmd/kubauth/cmd/oidc/fositepatch"
	"kubauth/cmd/kubauth/cmd/oidc/userdb"
	"net/http"
	"path"
	"time"

	"github.com/go-logr/logr"

	scsV2 "github.com/alexedwards/scs/v2"
	"github.com/google/uuid"

	"kubauth/cmd/kubauth/cmd/oidc/oidcstorage"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type OIDCServer struct {
	Issuer         string
	Storage        *oidcstorage.MemoryStore
	Resources      string
	UserDb         userdb.UserDb
	LoginTemplate  *template.Template
	IndexTemplate  *template.Template
	SessionManager *scsV2.SessionManager
	PostLogoutURL  string

	KubeClient              client.Client
	JWTSigningKeySecretName string
	JWTSigningKeySecretNS   string

	oauth2               fosite.OAuth2Provider
	config               *fosite.Config
	privateKey           *rsa.PrivateKey
	keyID                string
	AccessTokenLifespan  time.Duration
	RefreshTokenLifespan time.Duration
	AllowPasswordGrant   bool
	EnforcePKCE          bool
	AllowPKCEPlain       bool
}

func (s *OIDCServer) Setup(ctx context.Context, router *http.ServeMux) error {
	logger := logr.FromContextAsSlogLogger(ctx)
	// Load or generate RSA key from Kubernetes Secret if configured
	if err := s.ensureJwtSigningKey(ctx); err != nil {
		return fmt.Errorf("failed to load/generate JWT signing key: %w", err)
	}

	logger.Debug("Setting up OIDC server", "kid", s.keyID)

	// Configure storage with UserDb and other dependencies
	s.Storage.UserDb = s.UserDb
	s.Storage.Issuer = s.Issuer
	s.Storage.KeyID = s.keyID
	s.Storage.AllowPasswordGrant = s.AllowPasswordGrant

	// Configure fosite
	s.config = &fosite.Config{
		AccessTokenLifespan:   s.AccessTokenLifespan,
		RefreshTokenLifespan:  s.RefreshTokenLifespan,
		TokenEntropy:          32,
		GlobalSecret:          []byte("some-secret-that-is-32-bytes-long"),
		RefreshTokenScopes:    []string{"offline", "offline_access"},
		AuthorizeCodeLifespan: time.Minute * 10,
		AccessTokenIssuer:     s.Issuer,
		IDTokenIssuer:         s.Issuer,

		// PKCE Configuration
		EnforcePKCE:                    s.EnforcePKCE,    // Enforce PKCE for all authorization code flows
		EnablePKCEPlainChallengeMethod: s.AllowPKCEPlain, // Control whether to allow insecure 'plain' method
		EnforcePKCEForPublicClients:    s.EnforcePKCE,    // Use same setting as general enforcement
	}

	s.oauth2 = fositepatch.ComposeAllEnabled(s.config, s.Storage, s.privateKey)

	// Set up routes
	router.HandleFunc("/oauth2/auth", s.handleAuthorize)
	router.Handle("/oauth2/login", s.SessionManager.LoadAndSave(http.HandlerFunc(s.handleLogin)))
	router.Handle("/oauth2/logout", s.SessionManager.LoadAndSave(http.HandlerFunc(s.handleLogout)))
	router.HandleFunc("/oauth2/token", s.handleToken)
	router.HandleFunc("/.well-known/openid-configuration", s.handleOpenIDConfiguration)
	router.HandleFunc("/userinfo", s.handleUserInfo)
	router.HandleFunc("/.well-known/jwks.json", s.handleJWKS)
	//router.HandleFunc("/oauth2/revoke", oidcServer.revokeEndpoint)
	router.HandleFunc("/oauth2/introspect", s.HandleTokenIntrospection)
	router.HandleFunc("/index", s.handleIndex)

	// Static file server for CSS and other assets
	staticDir := path.Join(s.Resources, "static")
	router.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))

	logger.Info("OIDC Server starting", "issuer", s.Issuer, "configuration", fmt.Sprintf("%s/.well-known/openid-configuration", s.Issuer))
	return nil
}

// ensureJwtSigningKey loads an RSA private key and key ID from a Secret, or creates them if absent.
func (s *OIDCServer) ensureJwtSigningKey(ctx context.Context) error {
	logger := logr.FromContextAsSlogLogger(ctx)
	secret := &corev1.Secret{}
	key := types.NamespacedName{Name: s.JWTSigningKeySecretName, Namespace: s.JWTSigningKeySecretNS}
	var err error
	if err = s.KubeClient.Get(ctx, key, secret); err == nil {
		// Secret exists: decode key and kid
		pemBytes, ok := secret.Data["key.pem"]
		kidBytes, ok2 := secret.Data["kid"]
		if !ok || !ok2 {
			return fmt.Errorf("secret %s missing required data keys", key)
		}

		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return fmt.Errorf("failed to decode PEM from secret %s", key)
		}

		var priv *rsa.PrivateKey
		switch block.Type {
		case "RSA PRIVATE KEY":
			p, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return fmt.Errorf("failed parsing PKCS1 private key from secret: %w", err)
			}
			priv = p
		case "PRIVATE KEY":
			anyKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return fmt.Errorf("failed parsing PKCS8 private key from secret: %w", err)
			}
			k, ok := anyKey.(*rsa.PrivateKey)
			if !ok {
				return fmt.Errorf("unsupported private key type in secret: %T", anyKey)
			}
			priv = k
		default:
			return fmt.Errorf("unsupported PEM block type in secret: %s", block.Type)
		}
		logger.Info("Using existing secret for JWT signing key")
		s.privateKey = priv
		s.keyID = string(kidBytes)
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to load JWT signing key: %w", err)
	}

	// Secret not found or get error: create new key and store
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}
	// Marshal to PKCS1 PEM
	pkcs1 := x509.MarshalPKCS1PrivateKey(priv)
	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkcs1}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, pemBlock); err != nil {
		return fmt.Errorf("failed to encode PEM: %w", err)
	}
	newKID := uuid.NewString()
	sec := &corev1.Secret{}
	sec.Name = s.JWTSigningKeySecretName
	sec.Namespace = s.JWTSigningKeySecretNS
	sec.Type = corev1.SecretTypeOpaque
	sec.Data = map[string][]byte{
		"key.pem": buf.Bytes(),
		"kid":     []byte(newKID),
	}
	if err := s.KubeClient.Create(ctx, sec); err != nil {
		return fmt.Errorf("failed creating secret: %w", err)
	}
	logger.Info("Generating a new secret for JWT signing key")
	// Assign
	s.privateKey = priv
	s.keyID = newKID
	return nil
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
func (s *OIDCServer) newSession(user *userdb.User, clientId string) *openid.DefaultSession {
	if user == nil {
		return &openid.DefaultSession{}
	}
	claims := &jwt.IDTokenClaims{
		Issuer:      s.Issuer,
		Subject:     user.Login,
		Audience:    []string{clientId},
		IssuedAt:    time.Now(),
		RequestedAt: time.Now(),
		AuthTime:    time.Now(),
		Extra:       user.Claims,
	}
	// fosite does not explicitly handle azp claims
	claims.Add("azp", clientId)
	return &openid.DefaultSession{
		Claims: claims,
		Headers: &jwt.Headers{
			Extra: map[string]interface{}{
				"kid": s.keyID,
			},
		},
	}
}
