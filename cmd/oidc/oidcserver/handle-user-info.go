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
	"net/http"
	"strings"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
)

// Handle userinfo endpoint
func (s *OIDCServer) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	authz := r.Header.Get("Authorization")
	if authz == "" || !strings.HasPrefix(authz, "Bearer ") {
		w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\", error_description=\"missing bearer token\"")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	accessToken := strings.TrimPrefix(authz, "Bearer ")

	_, ar, err := s.oauth2.IntrospectToken(ctx, accessToken, fosite.AccessToken, s.newSession(nil, GetClientIdFromRequest(r)), "openid")
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\", error_description=\"token invalid or expired\"")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	sess, _ := ar.GetSession().(*openid.DefaultSession)
	if sess == nil || sess.Claims == nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	//fmt.Printf("============= claims: %+v\n", sess.Claims)

	claims := sess.Claims.Extra
	delete(claims, "azp") // Remove, as not in user definition
	claims["sub"] = sess.Claims.Subject

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
