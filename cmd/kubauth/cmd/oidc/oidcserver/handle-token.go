package oidcserver

import (
	"fmt"
	"github.com/ory/fosite"
	"net/http"
)

// Handle token endpoint
func (s *OIDCServer) handleToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// This will create an access request object and iterate through the registered TokenEndpointHandlers to validate the request.
	session := newSession(nil)
	accessRequest, err := s.oauth2.NewAccessRequest(ctx, r, session) // access_request_handler/46
	if err != nil {
		err2 := fosite.ErrorToRFC6749Error(err)
		fmt.Printf("Token handleToken.NewAccessRequest error: '%v'  hint:'%s' desc='%s'\n", err2, err2.HintField, err2.DescriptionField)
		s.oauth2.WriteAccessError(ctx, w, accessRequest, err) // access_error/13
		return
	}

	// If this is a client_credentials grant, grant all requested scopes
	// NewAccessRequest validated that all requested scopes the client is allowed to perform
	// based on configured scope matching strategy.
	if accessRequest.GetGrantTypes().ExactOne("client_credentials") { // access_request.go/23
		for _, scope := range accessRequest.GetRequestedScopes() { // request.go/63
			accessRequest.GrantScope(scope) // request.go/120
		}
	}

	// Next we create a response for the access request. Again, we iterate through the TokenEndpointHandlers
	// and aggregate the result in response.
	response, err := s.oauth2.NewAccessResponse(ctx, accessRequest) // access_response_writer/16
	if err != nil {
		err2 := fosite.ErrorToRFC6749Error(err)
		fmt.Printf("Token handleToken.NewAccessResponse error: '%v'  hint:'%s' desc='%s'\n", err2, err2.HintField, err2.DescriptionField)
		s.oauth2.WriteAccessError(ctx, w, accessRequest, err) // access_error/13
		return
	}

	// Return the response
	s.oauth2.WriteAccessResponse(ctx, w, accessRequest, response) // access_write.go

	// The client now has a valid access token
}
