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
	"context"
	"kubauth/cmd/oidc/authenticator"
	"kubauth/cmd/oidc/fositepatch"
	"net/http"

	"github.com/go-logr/logr"
)

// completeUpstreamAuthorize finalizes the Kubauth authorize response for a user authenticated via an upstream provider.
// It rebuilds the original /oauth2/auth request from the preserved raw query and writes the fosite response.
func (s *OIDCServer) completeUpstreamAuthorize(ctx context.Context, w http.ResponseWriter, rawQuery string, user *authenticator.OidcUser) {
	logger := logr.FromContextAsSlogLogger(ctx)
	clientID := clientIDFromRawQuery(rawQuery)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/oauth2/auth?"+rawQuery, nil)
	if err != nil {
		logger.Error("recreate authorize request", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ar, err := s.oauth2.NewAuthorizeRequest(ctx, req)
	if err != nil {
		logger.Error("NewAuthorizeRequest after upstream", "error", err)
		s.oauth2.WriteAuthorizeError(ctx, w, ar, err)
		return
	}
	fositepatch.HandleScopes(ar, logger)
	fositepatch.HandleAudience(ar, logger)

	session := s.newSession(user, clientID)
	response, err := s.oauth2.NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		logger.Error("NewAuthorizeResponse after upstream", "error", err)
		s.oauth2.WriteAuthorizeError(ctx, w, ar, err)
		return
	}
	logger.Info("upstream OIDC login completed", "login", user.Login)
	s.oauth2.WriteAuthorizeResponse(ctx, w, ar, response)
}
