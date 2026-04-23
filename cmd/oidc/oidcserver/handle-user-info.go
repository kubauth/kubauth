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
	if authz == "" || !strings.HasPrefix(authz, "Bearer ") {
		logger.Error("missing bearer token on userinfo handler")
		w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\", error_description=\"missing bearer token\"")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	accessToken := strings.TrimPrefix(authz, "Bearer ")

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
	claims := idClaims.Extra
	if claims == nil {
		claims = map[string]interface{}{}
	}
	delete(claims, "azp") // Remove, as not in user definition
	claims["sub"] = idClaims.Subject

	//claims := map[string]interface{}{
	//	"sub": sess.Claims.Subject,
	//}
	//
	//granted := map[string]struct{}{}
	//for _, sc := range ar.GetGrantedScopes() {
	//	granted[sc] = struct{}{}
	//}
	//
	//if _, ok := granted["email"]; ok {
	//	if v, ok2 := sess.Claims.Extra["email"]; ok2 {
	//		claims["email"] = v
	//	}
	//}
	//if _, ok := granted["profile"]; ok {
	//	if v, ok2 := sess.Claims.Extra["name"]; ok2 {
	//		claims["name"] = v
	//	}
	//}
	//if _, ok := granted["groups"]; ok {
	//	if v, ok2 := sess.Claims.Extra["groups"]; ok2 {
	//		claims["groups"] = v
	//	}
	//}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(claims)
}
