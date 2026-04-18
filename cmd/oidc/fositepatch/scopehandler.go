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
	"kubauth/cmd/oidc/oidcstorage"
	"log/slog"

	"github.com/ory/hydra/v2/fosite"
)

type ScopeRequester interface {
	GetRequestedScopes() (scopes fosite.Arguments)
	GetClient() (client fosite.Client)
	GrantScope(scope string)
}

type AudienceRequester interface {
	GetRequestedAudience() (audience fosite.Arguments)
	GetClient() (client fosite.Client)
	GrantAudience(audience string)
}

// HandleScopes grants all requested scopes on the authorize request
func HandleScopes(ar ScopeRequester, logger *slog.Logger) {
	client := ar.GetClient()
	for _, sc := range ar.GetRequestedScopes() { // Request with scope not in client scope list are rejected before this
		logger.Debug("Adding scope", "scope", sc)
		ar.GrantScope(sc)
	}
	if client2, ok := client.(oidcstorage.KubauthClient); ok {
		if client2.IsForceOpenIdScope() {
			logger.Debug("Forcing openid scope")
			ar.GrantScope("openid") // Will take care of duplicate
		}
	}
}

// HandleAudience grants the requested audience on the authorize request.
// If no audience is requested, it grants the client_id as the default audience.
func HandleAudience(ar AudienceRequester, logger *slog.Logger) {
	requestedAudience := ar.GetRequestedAudience()
	if len(requestedAudience) > 0 {
		for _, aud := range requestedAudience {
			logger.Debug("Adding audience", "audience", aud)
			ar.GrantAudience(aud)
		}
	} else {
		// Default: grant client_id as audience if none requested
		clientID := ar.GetClient().GetID()
		logger.Debug("No audience requested, using client_id as default audience", "audience", clientID)
		ar.GrantAudience(clientID)
	}
}
