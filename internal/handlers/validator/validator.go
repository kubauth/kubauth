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

package validator

import (
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
