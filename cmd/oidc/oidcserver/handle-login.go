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
	"net/url"

	"github.com/go-logr/logr"
)

// Handle dedicated login endpoint for GET (render) and POST (authenticate)
func (s *OIDCServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := logr.FromContextAsSlogLogger(ctx)

	switch r.Method {
	case http.MethodGet:
		clientId := r.URL.Query().Get("client_id")
		logger.Debug("handleLogin(GET)", "clientID", clientId)
		// If user already authenticated (SSO), complete the OIDC flow directly
		if v := s.SessionManager.Get(ctx, "ssoUser"); v != nil {
			//fmt.Printf("============ v.type: %T  v:%v\n", v, v)
			u, ok := v.(map[string]interface{})
			if ok {
				if login, ok := u["Login"].(string); ok && login != "" {
					claims := u["Claims"].(map[string]interface{})
					//if login, ok := v.(string); ok && login != "" {
					rawQuery := r.URL.RawQuery
					if rawQuery != "" {
						// Recreate authorize request and finish flow without prompting login
						req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/oauth2/auth?"+rawQuery, nil)
						if err == nil {
							ar, err := s.oauth2.NewAuthorizeRequest(ctx, req)
							if err == nil {

								fositepatch.HandleScopes(ar, logger)
								//for _, sc := range ar.GetRequestedScopes() {
								//	logger.Debug("Adding scope", "scope", sc, "method", "GET")
								//	ar.GrantScope(sc)
								//}

								//ar.GrantScope("offline")
								//ar.GrantScope("openid")

								session := s.newSession(&authenticator.User{Login: login, Claims: claims}, clientId)
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
		// Otherwise, render login page
		s.displayLoginResponse(w, r.URL.RawQuery, false)
		return
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			logger.Error("Failed to parse form", "error", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		login := r.PostForm.Get("login")
		password := r.PostForm.Get("password")
		rawQuery := r.PostForm.Get("rq")
		remember := r.PostForm.Get("remember") == "on"

		query, err := url.ParseQuery(rawQuery)
		if err != nil {
			logger.Error("failed to parse initial query", "query", rawQuery, "error", err)
			http.Error(w, "Internal error on ID provider subsystem. Contact your system administrator", http.StatusInternalServerError)
			return
		}
		clientId := query.Get("client_id")
		user, err := s.UserDb.Authenticate(login, password)
		if err != nil {
			logger.Error("failed to authenticate", "login", login, "error", err)
			http.Error(w, "Internal error on ID provider subsystem. Contact your system administrator", http.StatusInternalServerError)
			return
		}
		if user == nil {
			s.displayLoginResponse(w, rawQuery, true)
			return
		}

		// Successful authentication: renew session and conditionally persist SSO principal
		_ = s.SessionManager.RenewToken(ctx)
		if remember {
			s.SessionManager.Put(ctx, "ssoUser", user)
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
		//client := ar.GetClient()
		//for _, sc := range ar.GetRequestedScopes() {
		//	if client.GetScopes().Has(sc) || client.GetScopes().Has("*") {
		//		logger.Debug("Adding scope", "scope", sc)
		//		ar.GrantScope(sc)
		//	} else {
		//		logger.Debug("Skipping scope", "scope", sc)
		//	}
		//}
		//if client2, ok := client.(oidcstorage.FositeClient); ok {
		//	if client2.IsForceOpenIdScope() {
		//		logger.Debug("Forcing openid scope")
		//		ar.GrantScope("openid") // Will take care of duplicate
		//	}
		//}
		// Grant required scopes and create session
		//ar.GrantScope("offline") // To have a refresh token
		//ar.GrantScope("openid")

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
