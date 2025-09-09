package fositepatch

import (
	"github.com/ory/fosite"
	"kubauth/cmd/kubauth/cmd/oidc/oidcstorage"
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
