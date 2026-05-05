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
	"context"

	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/fosite/compose"
	"github.com/ory/hydra/v2/fosite/token/jwt"
)

// ComposeAllEnabled returns a fosite instance with all OAuth2 and OpenID Connect handlers enabled.
func ComposeAllEnabled(config *fosite.Config, storage fosite.Storage, key interface{}, jwtAccessToken bool) fosite.OAuth2Provider {
	keyGetter := func(context.Context) (interface{}, error) {
		return key, nil
	}

	// Wrap the OIDC token strategy with kubauth's scope-aware filter
	// so id_tokens only carry Extra claims authorised by the granted
	// scopes (OIDC §5.4). See scope_filter.go.
	oidcTokenStrategy := NewScopeFilteringIDTokenStrategy(
		compose.NewOpenIDConnectStrategy(keyGetter, config),
	)

	var strategy *compose.CommonStrategy
	if jwtAccessToken {
		strategy = &compose.CommonStrategy{
			CoreStrategy:      compose.NewOAuth2JWTStrategy(keyGetter, compose.NewOAuth2HMACStrategy(config), config),
			OIDCTokenStrategy: oidcTokenStrategy,
			Signer:            &jwt.DefaultSigner{GetPrivateKey: keyGetter},
		}
	} else {
		strategy = &compose.CommonStrategy{
			CoreStrategy:      compose.NewOAuth2HMACStrategy(config),
			OIDCTokenStrategy: oidcTokenStrategy,
			Signer:            &jwt.DefaultSigner{GetPrivateKey: keyGetter},
		}
	}

	return compose.Compose(
		config,
		storage,
		strategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2AuthorizeImplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		OAuth2ResourceOwnerPasswordCredentialsFactory,
		compose.RFC7523AssertionGrantFactory,

		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectImplicitFactory,
		compose.OpenIDConnectHybridFactory,
		compose.OpenIDConnectRefreshFactory,

		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,

		compose.OAuth2PKCEFactory,
		compose.PushedAuthorizeHandlerFactory,
	)
}
