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

package oidcserver

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-logr/logr"
	"golang.org/x/oauth2"
)

const (
	sessUpstreamState    = "upstreamOAuthState"
	sessUpstreamNonce    = "upstreamOAuthNonce"
	sessUpstreamVerifier = "upstreamPkceVerifier"
	sessUpstreamPKCE     = "upstreamPkceUsed"
	sessUpstreamProvider = "upstreamOAuthProvider"
)

func randomURLSafeString(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// handleUpstreamGo starts the upstream OIDC authorization code flow for the selected provider.
func (s *OIDCServer) handleUpstreamGo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := logr.FromContextAsSlogLogger(ctx)
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := r.URL.Query().Get("upstreamProvider")
	if name == "" {
		logger.Info("handleUpstreamGo: missing upstreamProvider query parameter")
		http.Error(w, "missing upstreamProvider parameter", http.StatusBadRequest)
		return
	}
	rawQuery := s.LoginSessionManager.GetString(ctx, "authQuery")
	if rawQuery == "" {
		logger.Info("handleUpstreamGo: no auth query in session")
		http.Error(w, "session expired: restart login from the client application", http.StatusBadRequest)
		return
	}

	u := s.Storage.GetUpstream(ctx, name)
	if u == nil {
		logger.Info("handleUpstreamGo: unknown upstream", "upstream", name)
		http.Error(w, "unknown upstream provider", http.StatusNotFound)
		return
	}
	settings, ok := u.OAuth2AuthCodeSettings()
	if !ok || settings == nil {
		logger.Info("handleUpstreamGo: upstream does not support OIDC code flow", "upstream", name)
		http.Error(w, "upstream does not support external OIDC login", http.StatusBadRequest)
		return
	}

	state, err := randomURLSafeString(32)
	if err != nil {
		logger.Error("handleUpstreamGo: state", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := randomURLSafeString(16)
	if err != nil {
		logger.Error("handleUpstreamGo: nonce", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.LoginSessionManager.Put(ctx, sessUpstreamState, state)
	s.LoginSessionManager.Put(ctx, sessUpstreamNonce, nonce)
	s.LoginSessionManager.Put(ctx, sessUpstreamProvider, name)
	s.LoginSessionManager.Put(ctx, sessUpstreamPKCE, "")

	cfg := oauth2.Config{
		ClientID:     settings.ClientID,
		ClientSecret: settings.ClientSecret,
		RedirectURL:  settings.RedirectURL,
		Endpoint:     settings.Endpoint,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.AccessTypeOffline,
	}
	if settings.SupportsPKCES256 {
		verifier := oauth2.GenerateVerifier()
		s.LoginSessionManager.Put(ctx, sessUpstreamVerifier, verifier)
		s.LoginSessionManager.Put(ctx, sessUpstreamPKCE, "1")
		opts = append(opts, oauth2.S256ChallengeOption(verifier))
	}

	authURL := cfg.AuthCodeURL(state, opts...)
	logger.Info("redirecting to upstream authorize", "upstream", name, "pkce", settings.SupportsPKCES256)
	http.Redirect(w, r, authURL, http.StatusFound)
}
