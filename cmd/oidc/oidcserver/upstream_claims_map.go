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

package oidcserver

import (
	"fmt"
	"kubauth/cmd/oidc/authenticator"
)

// mapUpstreamClaimsToUserClaims maps verified upstream OIDC claims (ID token and/or UserInfo)
// into the Kubauth user model used for fosite sessions and tokens.
func mapUpstreamClaimsToUser(claims map[string]interface{}) (*authenticator.OidcUser, error) {
	if claims == nil {
		return nil, fmt.Errorf("no claims")
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("missing sub claim")
	}
	login := sub
	fullName := ""
	if s, ok := claims["name"].(string); ok {
		fullName = s
	}
	return &authenticator.OidcUser{
		Login:    login,
		Claims:   claims,
		FullName: fullName,
	}, nil
}
