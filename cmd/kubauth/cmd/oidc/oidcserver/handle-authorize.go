package oidcserver

import (
	"fmt"
	"github.com/go-logr/logr"
	"html/template"
	"net/http"

	"github.com/ory/fosite"
)

func (s *OIDCServer) displayLoginResponse(w http.ResponseWriter, r *http.Request, invalidLogin bool) {
	rq := r.URL.RawQuery
	//fmt.Printf("RawQuery: %s\n", rq)
	data := map[string]interface{}{
		"RawQuery":     template.HTML(rq),
		"InvalidLogin": invalidLogin,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.loginTemplate.Execute(w, data); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
	return
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
		fmt.Printf("Authorization request error: %v  hint=%s  desc=%s\n", err2.ErrorField, err2.HintField, err2.DescriptionField)
		s.oauth2.WriteAuthorizeError(ctx, w, ar, err) //   authorize_error/13
		return
	}

	logger.Debug("handleAuthorize", "requestedScopes", ar.GetRequestedScopes())

	if r.Method == "GET" {
		// As we currently do not implement SSO, display the login page on each authorize request from client
		s.displayLoginResponse(w, r, false)
		return
	}
	err = r.ParseForm()
	if err != nil {
		s.oauth2.WriteAuthorizeError(ctx, w, ar, err)
		return
	}
	login := r.PostForm.Get("login")
	password := r.PostForm.Get("password")
	user, err := s.userDb.Authenticate(login, password)
	if err != nil {
		s.displayLoginResponse(w, r, true)
		return
	}
	ar.GrantScope("offline") // To have a refresh token
	ar.GrantScope("openid")
	//ar.GrantScope("email")
	//ar.GrantScope("profile")

	// For simplicity, we'll auto-approve the request
	// In a real implementation, you'd show a login/consent page
	// See comment in fosite-example/oauth2_auth.go/56
	session := newSession(user)

	// Now we need to get a response. This is the place where the AuthorizeEndpointHandlers kick in and start processing the request.
	// NewAuthorizeResponse is capable of running multiple response type handlers which in turn enables this library
	// to support open id connect.
	response, err := s.oauth2.NewAuthorizeResponse(ctx, ar, session) // authorize_response_writer/17
	if err != nil {
		err2 := fosite.ErrorToRFC6749Error(err)
		fmt.Printf("Authorization response error: %v  hint=%s  desc=%s\n", err2.ErrorField, err2.HintField, err2.DescriptionField)
		s.oauth2.WriteAuthorizeError(ctx, w, ar, err) //   authorize_error/13
		return
	}

	// Last but not least, send the response!
	// Typically a redirect
	s.oauth2.WriteAuthorizeResponse(ctx, w, ar, response) // authorize_write/11
}
