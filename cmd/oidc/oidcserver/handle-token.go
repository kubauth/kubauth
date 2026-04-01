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
	"kubauth/cmd/oidc/fositepatch"
	"net/http"

	"github.com/go-logr/logr"
	"github.com/ory/hydra/v2/fosite"
)

// Handle token endpoint
func (s *OIDCServer) handleToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// This will create an access request object and iterate through the registered TokenEndpointHandlers to validate the request.
	session := s.newSession(nil, GetClientIdFromRequest(r))
	accessRequest, err := s.oauth2.NewAccessRequest(ctx, r, session) // access_request_handler/46
	if err != nil {
		err2 := fosite.ErrorToRFC6749Error(err)
		fmt.Printf("Token handleToken.NewAccessRequest error: '%v'  hint:'%s' desc='%s'\n", err2, err2.HintField, err2.DescriptionField)
		s.oauth2.WriteAccessError(ctx, w, accessRequest, err) // access_error/13
		return
	}

	// If this is a client_credentials grant, grant all requested scopes and audience
	// NewAccessRequest validated that all requested scopes the client is allowed to perform
	// based on configured scope matching strategy.
	if accessRequest.GetGrantTypes().ExactOne("client_credentials") { // access_request.go/23
		logger := logr.FromContextAsSlogLogger(ctx)
		fositepatch.HandleScopes(accessRequest, logger)
		fositepatch.HandleAudience(accessRequest, logger)
	}

	// Next we create a response for the access request. Again, we iterate through the TokenEndpointHandlers
	// and aggregate the result in response.
	response, err := s.oauth2.NewAccessResponse(ctx, accessRequest) // access_response_writer/16
	if err != nil {
		err2 := fosite.ErrorToRFC6749Error(err)
		fmt.Printf("Token handleToken.NewAccessResponse error: '%v'  hint:'%s' desc='%s' debug='%s' cause='%+v'\n", err2, err2.HintField, err2.DescriptionField, err2.DebugField, err2.Unwrap())
		s.oauth2.WriteAccessError(ctx, w, accessRequest, err) // access_error/13
		return
	}

	// Return the response
	s.oauth2.WriteAccessResponse(ctx, w, accessRequest, response) // access_write.go

	// The client now has a valid access token
}
