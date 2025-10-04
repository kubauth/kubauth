package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-logr/logr"
	"kubauth/internal/handlers/protector"
	"kubauth/internal/handlers/validator"
	"kubauth/internal/proto"
	"net/http"
)

type Authenticator interface {
	// Authenticate - We pass request by value, as we may modify it.
	Authenticate(ctx context.Context, request *proto.IdentityRequest) (*proto.IdentityResponse, error)
}

type IdentityHandler struct {
	Validators    []validator.Validator
	Authenticator Authenticator
	Protector     protector.Protector
}

var _ http.Handler = &IdentityHandler{}

func (i *IdentityHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	logger := logr.FromContextAsSlogLogger(ctx)

	var identityRequest proto.IdentityRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&identityRequest)
	if err != nil {
		logger.Error("error decoding identity request", "error", err)
		http.Error(writer, fmt.Sprintf("Payload decoding: %v", err), http.StatusBadRequest)
		return
	}

	locked := i.Protector.EntryForLogin(ctx, identityRequest.Login)
	if locked {
		logger.Error("locked")
		http.Error(writer, fmt.Sprintf("locked"), http.StatusServiceUnavailable)
		return
	}
	if i.Validators != nil {
		for _, aValidator := range i.Validators {
			if !aValidator.Validate(writer, request, &identityRequest) {
				return
			}
		}
	}
	identityResponse, err := i.Authenticator.Authenticate(ctx, &identityRequest)
	if err != nil {
		logger.Error(err.Error())
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	i.Protector.ProtectLoginResult(ctx, identityRequest.Login, identityResponse.Status)
	logger.Info("User status", "login", identityRequest.Login, "status", identityResponse.Status)
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	err = json.NewEncoder(writer).Encode(identityResponse)
	if err != nil {
		panic(err)
	}
}
