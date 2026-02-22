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
	"log"
	"net/http"
	"net/url"

	"github.com/go-logr/logr"
	"github.com/ory/fosite"
)

func (s *OIDCServer) HandleTokenIntrospection(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	logger := logr.FromContextAsSlogLogger(ctx)
	mySessionData := s.newSession(nil, "")

	// Try standard introspection first (handles confidential clients with Basic Auth or Bearer token)
	ir, err := s.oauth2.NewIntrospectionRequest(ctx, req, mySessionData)
	if err == nil {
		s.oauth2.WriteIntrospectionResponse(ctx, rw, ir)
		return
	}

	// Check if this might be a public client request (no Authorization header, but client_id in body)
	if req.Header.Get("Authorization") == "" {
		if parseErr := req.ParseForm(); parseErr == nil {
			clientID := req.PostForm.Get("client_id")
			token := req.PostForm.Get("token")

			if clientID != "" && token != "" {
				// Verify this is a valid public client
				client, clientErr := s.Storage.GetClient(ctx, clientID)
				if clientErr == nil && client.IsPublic() {
					// Public client - perform introspection without client authentication
					logger.Debug("Processing introspection for public client", "client_id", clientID)

					// Introspect the token directly
					tokenTypeHint := req.PostForm.Get("token_type_hint")
					var tt fosite.TokenType
					switch tokenTypeHint {
					case "access_token":
						tt = fosite.AccessToken
					case "refresh_token":
						tt = fosite.RefreshToken
					default:
						tt = fosite.AccessToken
					}

					tokenType, accessRequest, introErr := s.oauth2.IntrospectToken(ctx, token, tt, mySessionData)
					if introErr != nil {
						// Token is not active - return inactive response per RFC 7662
						logger.Debug("Token introspection failed for public client", "error", introErr)
						rw.Header().Set("Content-Type", "application/json;charset=UTF-8")
						rw.WriteHeader(http.StatusOK)
						rw.Write([]byte(`{"active":false}`))
						return
					}

					// Build introspection response
					response := &fosite.IntrospectionResponse{
						Active:          true,
						AccessRequester: accessRequest,
						TokenUse:        tokenType,
					}
					s.oauth2.WriteIntrospectionResponse(ctx, rw, response)
					return
				}
			}
		}
	}

	// Fall back to error response
	log.Printf("Error occurred in NewIntrospectionRequest: %+v", err)
	s.oauth2.WriteIntrospectionError(ctx, rw, err)
}

// Helper to unescape URL-encoded strings
func urlUnescape(s string) string {
	unescaped, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}
	return unescaped
}
