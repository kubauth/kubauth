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
	"kubauth/cmd/oidc/authenticator"
	"kubauth/cmd/oidc/fositepatch"
	"net/http"
	"strings"

	"github.com/go-logr/logr"
	"github.com/ory/hydra/v2/fosite"
)

// Handle dedicated login endpoint for GET (render) and POST (authenticate)
func (s *OIDCServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := logr.FromContextAsSlogLogger(ctx)

	switch r.Method {
	case http.MethodGet:
		rawQuery := r.URL.RawQuery
		clientId := r.URL.Query().Get("client_id")
		// OIDC Core 1.0 §3.1.2.1: `prompt` is a space-delimited
		// list. Two values matter to us today:
		//   - `none`: never display UI; return `login_required` if
		//     the user isn't already authenticated.
		//   - `login`: force re-authentication; don't auto-complete
		//     the flow from an existing SSO session.
		// `consent` and `select_account` are not implemented (kubauth
		// has no consent UI and a session is one-user-per-session);
		// silently ignored — clients that pass them still get a
		// best-effort flow rather than an error.
		promptValues := strings.Fields(r.URL.Query().Get("prompt"))
		promptNone, promptLogin := false, false
		for _, p := range promptValues {
			switch p {
			case "none":
				promptNone = true
			case "login":
				promptLogin = true
			}
		}
		logger.Debug("handleLogin(GET)", "clientID", clientId, "prompt", promptValues)

		// Persist the authorization query in the session so the POST can retrieve it
		s.LoginSessionManager.Put(ctx, "authQuery", rawQuery)
		// For the index page.
		s.LoginSessionManager.Put(ctx, "clientId", clientId)

		// If user already authenticated (SSO) AND the client didn't
		// ask for re-authentication via `prompt=login`, complete the
		// OIDC flow directly.
		if !promptLogin {
			if v := s.SsoSessionManager.Get(ctx, "ssoUser"); v != nil {
				u, ok := v.(map[string]interface{})
				if ok {
					if login, ok := u["Login"].(string); ok && login != "" {
						claims := u["Claims"].(map[string]interface{})
						if rawQuery != "" {
							req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/oauth2/auth?"+rawQuery, nil)
							if err == nil {
								ar, err := s.oauth2.NewAuthorizeRequest(ctx, req)
								if err == nil {
									fositepatch.HandleScopes(ar, logger)
									fositepatch.HandleAudience(ar, logger)

									session := s.newSession(&authenticator.OidcUser{Login: login, Claims: claims}, clientId)
									response, err := s.oauth2.NewAuthorizeResponse(ctx, ar, session)
									if err == nil {
										logger.Info("Successfully logged in using existing SSO session", "login", login)
										s.oauth2.WriteAuthorizeResponse(ctx, w, ar, response)
										return
									}
								}
							}
						}
					}
				}
			}
		}

		// We're about to render the login page (no SSO bypass
		// available, or `prompt=login` forced re-auth). If the
		// client also said `prompt=none`, that's a contradiction —
		// the spec says we MUST return `login_required` instead.
		if promptNone {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/oauth2/auth?"+rawQuery, nil)
			if err == nil {
				ar, arErr := s.oauth2.NewAuthorizeRequest(ctx, req)
				if arErr == nil {
					logger.Info("prompt=none with no active session — returning login_required",
						"clientID", clientId)
					s.oauth2.WriteAuthorizeError(ctx, w, ar, fosite.ErrLoginRequired)
					return
				}
				// fosite refused the rebuilt request — surface its
				// error rather than the prompt=none one; the client
				// should fix its request first.
				s.oauth2.WriteAuthorizeError(ctx, w, ar, arErr)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Otherwise, render login page
		s.displayLoginResponse(ctx, w, r, clientId, false)
		return
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			logger.Error("Failed to parse form", "error", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		login := r.PostForm.Get("login")
		password := r.PostForm.Get("password")
		remember := r.PostForm.Get("remember") == "on"

		rawQuery := s.LoginSessionManager.GetString(ctx, "authQuery")
		if rawQuery == "" {
			logger.Error("No authorization query found in session")
			http.Error(w, "Session expired. Please restart the login flow.", http.StatusBadRequest)
			return
		}

		r.URL.RawQuery = rawQuery
		clientId := r.URL.Query().Get("client_id")

		user, err := s.Authenticator.Authenticate(ctx, login, password)
		if err != nil {
			logger.Error("failed to authenticate", "login", login, "error", err)
			http.Error(w, "Internal error on ID provider subsystem. Contact your system administrator", http.StatusInternalServerError)
			return
		}
		if user == nil {
			s.displayLoginResponse(ctx, w, r, clientId, true)
			return
		}

		// Successful authentication: renew session and conditionally persist SSO principal
		_ = s.SsoSessionManager.RenewToken(ctx)
		if s.SsoMode == SsoAlways || (s.SsoMode == SsoOnDemand && remember) {
			s.SsoSessionManager.Put(ctx, "ssoUser", user)
		}

		// Reconstruct original authorize request using preserved raw query
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/oauth2/auth?"+rawQuery, nil)
		if err != nil {
			logger.Error("Failed to recreate authorize request", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Parse and validate authorize request
		ar, err := s.oauth2.NewAuthorizeRequest(ctx, req)
		if err != nil {
			logger.Error("Failed to parse authorize request after login", "error", err)
			s.oauth2.WriteAuthorizeError(ctx, w, ar, err)
			return
		}

		fositepatch.HandleScopes(ar, logger)
		fositepatch.HandleAudience(ar, logger)

		session := s.newSession(user, clientId)

		logger.Info("Successfully logged in a new SSO session", "login", login)

		// Generate authorize response (typically a redirect)
		response, err := s.oauth2.NewAuthorizeResponse(ctx, ar, session)
		if err != nil {
			logger.Error("Failed to create authorize response", "error", err)
			s.oauth2.WriteAuthorizeError(ctx, w, ar, err)
			return
		}
		s.oauth2.WriteAuthorizeResponse(ctx, w, ar, response)
		return
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
}
