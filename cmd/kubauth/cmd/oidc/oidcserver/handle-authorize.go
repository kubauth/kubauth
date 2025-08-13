package oidcserver

import (
	"html/template"
	"net/http"

	"github.com/go-logr/logr"

	"github.com/ory/fosite"
)

func (s *OIDCServer) displayLoginResponse(w http.ResponseWriter, rawQuery string, invalidLogin bool) {
	//fmt.Printf("RawQuery: %s\n", rawQuery)
	data := map[string]interface{}{
		"RawQuery":     template.HTML(rawQuery),
		"InvalidLogin": invalidLogin,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.LoginTemplate.Execute(w, data); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// Handle authorization endpoint
func (s *OIDCServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := logr.FromContextAsSlogLogger(ctx)

	// Let's create an AuthorizeRequest object!
	// It will analyze the request and extract important information like scopes, response type and others.
	ar, err := s.oauth2.NewAuthorizeRequest(ctx, r) // authorize_request_handler/326
	if err != nil {
		err2 := fosite.ErrorToRFC6749Error(err)
		// fmt.Printf("Authorization request error: %v  hint=%s  desc=%s\n", err2.ErrorField, err2.HintField, err2.DescriptionField)
		logger.Error("Failed to create authorize request", "error", err2)
		s.oauth2.WriteAuthorizeError(ctx, w, ar, err) //   authorize_error/13
		return
	}

	logger.Debug("handleAuthorize", "requestedScopes", ar.GetRequestedScopes())

	if r.Method == "GET" {
		// Redirect to dedicated login endpoint, preserving the original authorization query
		http.Redirect(w, r, "/oauth2/login?"+r.URL.RawQuery, http.StatusFound)
		return
	}

	// Only GET is supported for /oauth2/auth in this flow
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}
