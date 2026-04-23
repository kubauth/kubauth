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
	"encoding/json"
	"kubauth/cmd/oidc/authenticator"
	"kubauth/internal/global"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-logr/logr"
)

type UpstreamWelcomeModel struct {
	UserName string
	Style    string
	Version  string
	BuildTs  string
}

// handleUpstreamWelcome renders the SSO confirmation page (GET) and resumes the authorize flow (POST)
// when SsoMode is onDemand. It is the only place where SSO is persisted in that mode for upstream flows.
func (s *OIDCServer) handleUpstreamWelcome(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := logr.FromContextAsSlogLogger(ctx)

	if s.SsoMode != SsoOnDemand {
		http.NotFound(w, r)
		return
	}

	user, ok := s.loadPendingUpstreamUser(ctx)
	if !ok {
		logger.Error("handleUpstreamWelcome: no pending upstream user in session")
		http.Error(w, "session expired: restart login from the client application", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		rawQuery := s.LoginSessionManager.GetString(ctx, "authQuery")
		clientID := clientIDFromRawQuery(rawQuery)
		model := UpstreamWelcomeModel{
			UserName: welcomeUserName(user),
			Style:    s.getStyle(ctx, clientID),
			Version:  global.Version,
			BuildTs:  global.BuildTs,
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := s.UpstreamWelcomeTemplate.Execute(w, model); err != nil {
			logger.Error("welcome template error", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
		return
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			logger.Error("handleUpstreamWelcome: failed to parse form", "error", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		remember := r.PostForm.Get("remember") == "on"
		rawQuery := s.LoginSessionManager.GetString(ctx, "authQuery")
		if rawQuery == "" {
			logger.Error("handleUpstreamWelcome: no auth query in session")
			http.Error(w, "session expired: restart login from the client application", http.StatusBadRequest)
			return
		}
		s.LoginSessionManager.Remove(ctx, sessPendingUpstreamUser)
		if remember {
			s.SsoSessionManager.Put(ctx, "ssoUser", user)
		}
		s.completeUpstreamAuthorize(ctx, w, rawQuery, user)
		return
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func (s *OIDCServer) loadPendingUpstreamUser(ctx context.Context) (*authenticator.OidcUser, bool) {
	raw := s.LoginSessionManager.GetString(ctx, sessPendingUpstreamUser)
	if raw == "" {
		return nil, false
	}
	u := &authenticator.OidcUser{}
	if err := json.Unmarshal([]byte(raw), u); err != nil {
		return nil, false
	}
	if u.Login == "" {
		return nil, false
	}
	return u, true
}

// welcomeUserName derives a display name from mapped user claims, preferring human-readable
// claims and falling back to the login. Returns an empty string when nothing suitable is found.
func welcomeUserName(user *authenticator.OidcUser) string {
	if user == nil {
		return ""
	}
	if s := strings.TrimSpace(user.FullName); s != "" {
		return s
	}
	if user.Claims != nil {
		for _, k := range []string{"name", "preferred_username", "nickname", "email"} {
			if v, ok := user.Claims[k].(string); ok {
				if t := strings.TrimSpace(v); t != "" {
					return t
				}
			}
		}
		given, _ := user.Claims["given_name"].(string)
		family, _ := user.Claims["family_name"].(string)
		given, family = strings.TrimSpace(given), strings.TrimSpace(family)
		switch {
		case given != "" && family != "":
			return given + " " + family
		case given != "":
			return given
		case family != "":
			return family
		}
	}
	return strings.TrimSpace(user.Login)
}

func clientIDFromRawQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	v, err := url.ParseQuery(rawQuery)
	if err != nil {
		return ""
	}
	return v.Get("client_id")
}
