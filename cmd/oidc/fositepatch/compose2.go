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

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/token/jwt"
)

// ComposeAllEnabled returns a fosite instance with all OAuth2 and OpenID Connect handlers enabled.
func ComposeAllEnabled(config *fosite.Config, storage interface{}, key interface{}) fosite.OAuth2Provider {
	keyGetter := func(context.Context) (interface{}, error) {
		return key, nil
	}
	return compose.Compose(
		config,
		storage,
		&compose.CommonStrategy{
			CoreStrategy:               compose.NewOAuth2HMACStrategy(config),
			OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, config),
			Signer:                     &jwt.DefaultSigner{GetPrivateKey: keyGetter},
		},
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
