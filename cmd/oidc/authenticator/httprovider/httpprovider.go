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

package httprovider

import (
	"kubauth/cmd/oidc/authenticator"
	"kubauth/internal/httpclient"
	proto2 "kubauth/internal/proto"
)

type httpProvider struct {
	httpClient httpclient.HttpClient
}

var _ authenticator.OidcAuthenticator = &httpProvider{}

func New(config *httpclient.Config) (authenticator.OidcAuthenticator, error) {
	httpClient, err := httpclient.New(config)
	if err != nil {
		return nil, err
	}
	idp := &httpProvider{
		httpClient: httpClient,
	}
	return idp, nil
}

func (u *httpProvider) Authenticate(login string, password string) (*authenticator.OidcUser, error) {
	request := &proto2.IdentityRequest{
		Login:    login,
		Password: password,
		Detailed: false,
	}
	response := &proto2.IdentityResponse{}
	err := proto2.Exchange(u.httpClient, "GET", "v1/identity", request, response)
	if err != nil {
		return nil, err
	}
	if response.Status != proto2.PasswordChecked {
		return nil, nil
	}
	fullName := ""
	if len(response.CommonNames) > 0 {
		fullName = response.CommonNames[0]
	}
	return &authenticator.OidcUser{
		Login:    login,
		Claims:   response.Claims,
		FullName: fullName,
	}, nil
}
