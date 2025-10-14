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

package httpprovider

import (
	"context"
	"fmt"
	"kubauth/cmd/oidc/authenticator"
	"kubauth/internal/httpclient"
	"kubauth/internal/misc"
	"kubauth/internal/proto"

	"github.com/go-logr/logr"
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

func (u *httpProvider) Authenticate(ctx context.Context, login string, password string) (*authenticator.OidcUser, error) {
	logger := logr.FromContextAsSlogLogger(ctx)
	request := &proto.IdentityRequest{
		Login:    login,
		Password: password,
	}
	response := &proto.IdentityResponse{}
	err := proto.Exchange(u.httpClient, "GET", "v1/identity", request, response)
	if err != nil {
		return nil, err
	}
	if response.Status != proto.PasswordChecked {
		return nil, nil
	}
	// ------------------------------------------- Enrich user's claim with value
	// Ensure response coherency
	if response.User.Claims == nil {
		response.User.Claims = make(map[string]interface{})
	}
	if response.User.Groups == nil {
		response.User.Groups = make([]string, 0)
	}
	if response.User.Emails == nil {
		response.User.Emails = make([]string, 0)
	}
	claims := response.User.Claims

	// ---- Handle name
	if response.User.Name != "" {
		claims["name"] = response.User.Name
	}

	// ---- Handle groups
	groupFromClaims, err := getStringArrayInMap(claims, "groups")
	if err != nil {
		return nil, err
	}
	groups := append(response.User.Groups, groupFromClaims...)
	groups = misc.DedupAndSort(groups)
	if len(groups) != 0 {
		claims["groups"] = groups
	}

	// ---- Handle emails
	emailsFromClaims, err := getStringArrayInMap(claims, "emails")
	if err != nil {
		return nil, err
	}
	emails := misc.AppendIfNotPresent(response.User.Emails, emailsFromClaims)
	if len(emails) != 0 {
		claims["emails"] = emails
		claims["email"] = emails[0]
	}

	// ------- Handle authority
	if response.Authority != "" {
		claims["authority"] = response.Authority
	}

	// ------ Handle uid
	if response.User.Uid != nil {
		claims["uid"] = *response.User.Uid
	}

	logger.Info("User authenticated", "login", login, "name", response.User.Name, "claims", claims)

	return &authenticator.OidcUser{
		Login:    login,
		Claims:   claims,
		FullName: response.User.Name,
	}, nil
}

func getStringArrayInMap(m map[string]interface{}, key string) ([]string, error) {
	if entry, exists := m["key"]; exists && entry != nil {
		// Try to convert claims["groups"] to []string
		switch v := entry.(type) {
		case []string:
			// Direct []string - append to merged groups
			return v, nil
		case []interface{}:
			// []interface{} - convert each element to string if possible
			result := make([]string, 0, len(v))
			for _, item := range v {
				if str, ok := item.(string); ok {
					result = append(result, str)
				}
			}
			return result, nil
		case string:
			// Single string - treat as single group
			return []string{v}, nil
		default:
			return nil, fmt.Errorf("entry Claims[%s] is not a []string", key)
		}
	}
	return []string{}, nil
}
