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
