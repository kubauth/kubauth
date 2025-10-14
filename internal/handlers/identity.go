/*
Copyright (c) Kubotal 2025.

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

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"kubauth/internal/handlers/protector"
	"kubauth/internal/handlers/validator"
	"kubauth/internal/proto"
	"net/http"

	"github.com/go-logr/logr"
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
	//logger.Info("User status", "login", identityRequest.Login, "status", identityResponse.Status)
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	err = json.NewEncoder(writer).Encode(identityResponse)
	if err != nil {
		panic(err)
	}
}
