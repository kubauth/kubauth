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

package fositepatch

import (
	"github.com/ory/fosite"
	"kubauth/cmd/oidc/oidcstorage"
	"log/slog"
)

type ScopeRequester interface {
	GetRequestedScopes() (scopes fosite.Arguments)
	GetClient() (client fosite.Client)
	GrantScope(scope string)
}

func HandleScopes(ar ScopeRequester, logger *slog.Logger) {
	client := ar.GetClient()
	for _, sc := range ar.GetRequestedScopes() { // Request with scope not in client scope list are rejected before this
		logger.Debug("Adding scope", "scope", sc)
		ar.GrantScope(sc)
	}
	if client2, ok := client.(oidcstorage.FositeClient); ok {
		if client2.IsForceOpenIdScope() {
			logger.Debug("Forcing openid scope")
			ar.GrantScope("openid") // Will take care of duplicate
		}
	}

}
