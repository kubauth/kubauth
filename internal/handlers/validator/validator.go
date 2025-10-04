package validator

import (
	"fmt"
	"github.com/go-logr/logr"
	"kubauth/internal/proto"
	"net/http"
)

type Validator interface {
	// Validate If false, it is up to the validator to log error and perform http.Error(writer, ....)
	Validate(writer http.ResponseWriter, request *http.Request, identityRequest *proto.IdentityRequest) bool
}

// ----------------------------------------------------

type OnlyGetValidator struct{}

var _ Validator = &OnlyGetValidator{}

func (o OnlyGetValidator) Validate(writer http.ResponseWriter, request *http.Request, identityRequest *proto.IdentityRequest) bool {
	if request.Method != http.MethodGet {
		logger := logr.FromContextAsSlogLogger(request.Context())
		logger.Error("Method not allowed", "method", request.Method)
		http.Error(writer, "Method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

// ----------------------------------------------------

type NoDetailValidator struct{}

var _ Validator = &NoDetailValidator{}

func (o NoDetailValidator) Validate(writer http.ResponseWriter, request *http.Request, identityRequest *proto.IdentityRequest) bool {
	if identityRequest.Detailed {
		logger := logr.FromContextAsSlogLogger(request.Context())
		logger.Error("Can't handle detailed identity request")
		http.Error(writer, fmt.Sprintf("Can't handle detailed identity request"), http.StatusBadRequest)
		return false
	}
	return true
}
