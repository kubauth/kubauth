package oidcserver

import (
	"encoding/json"
	"kubauth/cmd/kubauth/cmd/oidc/config"
	"net/http"
)

// Handle OpenID Connect configuration endpoint
func (s *OIDCServer) handleOpenIDConfiguration(w http.ResponseWriter, _ *http.Request) {
	baseURL := config.Conf.Issuer

	oidcConfig := map[string]interface{}{
		"issuer":                                baseURL,
		"authorization_endpoint":                baseURL + "/oauth2/auth",
		"token_endpoint":                        baseURL + "/oauth2/token",
		"userinfo_endpoint":                     baseURL + "/userinfo",
		"jwks_uri":                              baseURL + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code", "token", "id_token", "code token", "code id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline", "address", "phone", "groups"}, // This is non-exhaustive
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported":                      []string{"sub", "iss", "name", "email", "profile", "email_verified", "groups"}, // This is non-exhaustive
		"code_challenge_methods_supported":      []string{"S256"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(oidcConfig)
}
