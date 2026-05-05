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
	"encoding/json"
	"kubauth/cmd/oidc/fositepatch"
	"net/http"
	"strings"

	"github.com/go-logr/logr"
	"github.com/ory/hydra/v2/fosite"
)

// Handle userinfo endpoint
func (s *OIDCServer) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := logr.FromContextAsSlogLogger(ctx)

	authz := r.Header.Get("Authorization")
	// RFC 7235 §2.1: the auth scheme name is case-insensitive. The
	// OpenID Conformance Suite (and some HTTP clients) sends a
	// lowercase `bearer` prefix; reject only when the prefix is missing
	// entirely, not when its case differs.
	const bearerPrefix = "Bearer "
	if len(authz) <= len(bearerPrefix) || !strings.EqualFold(authz[:len(bearerPrefix)], bearerPrefix) {
		logger.Error("missing bearer token on userinfo handler")
		w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\", error_description=\"missing bearer token\"")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	accessToken := authz[len(bearerPrefix):]

	_, ar, err := s.oauth2.IntrospectToken(ctx, accessToken, fosite.AccessToken, s.newSession(nil, GetClientIdFromRequest(r)), "openid")
	if err != nil {
		logger.Error("invalid token or expired on userinfo handler")
		w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\", error_description=\"token invalid or expired\"")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	sess, ok := ar.GetSession().(*fositepatch.OIDCSession)
	if !ok || sess == nil || sess.IDTokenClaims_ == nil {
		logger.Error("Unable to get session claims on userinfo handler", "session", sess)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	idClaims := sess.IDTokenClaims_

	// OIDC §5.4: a userinfo response may include claims only when
	// the corresponding scope was granted. Filter the session's
	// Extra map by the access token's granted scopes — see
	// fositepatch.AllowedIDTokenClaimsFor for the scope→claim
	// mapping kubauth uses (mirrors the id_token filter installed
	// in fositepatch.NewScopeFilteringIDTokenStrategy).
	allowed := fositepatch.AllowedIDTokenClaimsFor(ar.GetGrantedScopes())
	claims := make(map[string]interface{}, len(idClaims.Extra)+1)
	for k, v := range idClaims.Extra {
		if _, ok := allowed[k]; ok {
			claims[k] = v
		}
	}
	delete(claims, "azp") // userinfo doesn't carry the authorized-party claim
	// `sub` is mandatory in every userinfo response (OIDC §5.3.2);
	// it lives on the top-level IDTokenClaims, not in Extra.
	claims["sub"] = idClaims.Subject

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(claims)
}
