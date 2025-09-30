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
	"fmt"
	"kubauth/cmd/oidc/oidcstorage"
	"net/http"

	"github.com/go-logr/logr"
)

//func (s *OIDCServer) getPostLogoutURL(ctx context.Context, clientId string) string {
//	logger := logr.FromContextAsSlogLogger(ctx)
//	if clientId == "" {
//		return ""
//	}
//	logger.Debug("getting post logout URL", "client_id", clientId)
//	client, err := s.Storage.GetClient(ctx, clientId)
//	if err != nil {
//		cli, ok := client.(oidcstorage.FositeClient)
//		if ok {
//			if cli.GetPostLogoutURL() != "" {
//				return cli.GetPostLogoutURL()
//			}
//		}
//	}
//	return ""
//}

// Handle SsoSession logout
func (s *OIDCServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := logr.FromContextAsSlogLogger(ctx)

	// Compute post logout url
	// Set default value
	postLogoutURL := s.PostLogoutURL

	// Override with client defined value, if any
	clientId := r.URL.Query().Get("client_id")
	if clientId != "" {
		client, err := s.Storage.GetClient(ctx, clientId)
		if err == nil {
			cli, ok := client.(oidcstorage.FositeClient)
			if ok {
				if cli.GetPostLogoutURL() != "" {
					postLogoutURL = cli.GetPostLogoutURL()
				}
			}
		}
	}

	// Override with value from URL, if any
	plo := r.URL.Query().Get("post_logout_redirect_uri")
	if plo != "" {
		postLogoutURL = plo

	}

	// Logout locally
	if err := s.SessionManager.Destroy(ctx); err != nil {
		logger.Error("failed to destroy local session", "error", err, "errType", fmt.Sprintf("%T", err))
	}
	http.Redirect(w, r, postLogoutURL, http.StatusFound)
}
