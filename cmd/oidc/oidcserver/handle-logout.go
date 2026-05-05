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
	"net/http"
	"net/url"

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
		client, err := s.Storage.GetKubauthClient(ctx, clientId)
		if err == nil {
			if client.GetPostLogoutURL() != "" {
				postLogoutURL = client.GetPostLogoutURL()
			}
		}
	}

	// Override with value from URL, if any
	plo := r.URL.Query().Get("post_logout_redirect_uri")
	if plo != "" {
		postLogoutURL = plo

	}

	// Logout locally
	if err := s.SsoSessionManager.Destroy(ctx); err != nil {
		logger.Error("failed to destroy local SSO session", "error", err, "errType", fmt.Sprintf("%T", err))
	}
	// Clean the loginSession, but preserve clientId for the index page to be with the correct style
	clientId2 := s.LoginSessionManager.GetString(ctx, "clientId")
	if err := s.LoginSessionManager.Destroy(ctx); err != nil {
		logger.Error("failed to destroy local login session", "error", err, "errType", fmt.Sprintf("%T", err))
	}
	s.LoginSessionManager.Put(ctx, "clientId", clientId2)

	// OIDC RP-Initiated Logout 1.0 §3: if `state` is included in the
	// request, the OP MUST echo it on the redirect to
	// post_logout_redirect_uri. Some RPs also expect `iss` (the
	// auth-server-issuer-identification draft) — emit when the
	// request asked for it.
	postLogoutURL = appendLogoutQuery(postLogoutURL, r.URL.Query())
	http.Redirect(w, r, postLogoutURL, http.StatusFound)
}

// appendLogoutQuery copies the OIDC RP-Initiated-Logout response
// parameters (`state`, `iss`) from the incoming request's query
// onto the post-logout redirect URL. Existing query params on the
// postLogoutURL are preserved; the response params are appended.
func appendLogoutQuery(postLogoutURL string, requestQuery url.Values) string {
	state := requestQuery.Get("state")
	if state == "" {
		return postLogoutURL
	}
	u, err := url.Parse(postLogoutURL)
	if err != nil {
		// Bad URL configured — fall back to raw concatenation rather
		// than dropping `state` silently. The browser will surface
		// the malformed URL clearly enough.
		sep := "?"
		if u != nil && u.RawQuery != "" {
			sep = "&"
		}
		return postLogoutURL + sep + "state=" + url.QueryEscape(state)
	}
	q := u.Query()
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String()
}
