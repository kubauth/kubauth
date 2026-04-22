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

package upstreams

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OAuth2AuthCodeSettings holds values needed to run an OAuth2 / OIDC authorization code flow
// against this upstream.
type OAuth2AuthCodeSettings struct {
	ClientID         string
	ClientSecret     string
	RedirectURL      string
	Endpoint         oauth2.Endpoint
	SupportsPKCES256 bool
}

func (u *upstream) supportsPKCES256() bool {
	for _, m := range u.codeChallengeMethods {
		if m == "S256" {
			return true
		}
	}
	return false
}

func (u *upstream) OAuth2AuthCodeSettings() (*OAuth2AuthCodeSettings, bool) {
	if u.provider == nil {
		return nil, false
	}
	return &OAuth2AuthCodeSettings{
		ClientID:         u.clientId,
		ClientSecret:     u.clientSecret,
		RedirectURL:      u.redirectURL,
		Endpoint:         u.provider.Endpoint(),
		SupportsPKCES256: u.supportsPKCES256(),
	}, true
}

func (u *upstream) ClientContext(ctx context.Context) context.Context {
	if u.httpClient == nil {
		return ctx
	}
	return oidc.ClientContext(ctx, u.httpClient)
}

func (u *upstream) ParseAndVerifyIDToken(ctx context.Context, rawIDToken string) (map[string]interface{}, error) {
	if u.provider == nil {
		return nil, fmt.Errorf("upstream has no OIDC provider")
	}
	verifier := u.provider.Verifier(&oidc.Config{ClientID: u.clientId})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func (u *upstream) FetchUserInfoClaims(ctx context.Context, tokenSource oauth2.TokenSource) (map[string]interface{}, error) {
	if u.provider == nil || u.provider.UserInfoEndpoint() == "" {
		return nil, nil
	}
	ui, err := u.provider.UserInfo(ctx, tokenSource)
	if err != nil {
		return nil, err
	}
	var claims map[string]interface{}
	if err := ui.Claims(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}
