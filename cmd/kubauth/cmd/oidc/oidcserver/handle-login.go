package oidcserver

import (
	"net/http"

	"github.com/go-logr/logr"
)

// Handle dedicated login endpoint for GET (render) and POST (authenticate)
func (s *OIDCServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := logr.FromContextAsSlogLogger(ctx)

	switch r.Method {
	case http.MethodGet:
		// Render login page. Expect original authorize request query preserved in URL
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

		user, err := s.UserDb.Authenticate(login, password)
		if err != nil {
			logger.Error("failed to authenticate", "login", login, "error", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if user == nil {
			s.displayLoginResponse(w, rawQuery, true)
			return
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

		// Grant required scopes and create session
		ar.GrantScope("offline") // To have a refresh token
		ar.GrantScope("openid")

		session := s.newSession(user)

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
