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
)

func (s *OIDCServer) HandleTokenIntrospection(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	mySessionData := s.newSession(nil, "")
	ir, err := s.oauth2.NewIntrospectionRequest(ctx, req, mySessionData) // introspection_request_handler.go/98
	if err != nil {
		log.Printf("Error occurred in NewIntrospectionRequest: %+v", err)
		s.oauth2.WriteIntrospectionError(ctx, rw, err) // introspection_response_writer.go/36
		return
	}

	s.oauth2.WriteIntrospectionResponse(ctx, rw, ir) // WriteIntrospectionResponse
}
