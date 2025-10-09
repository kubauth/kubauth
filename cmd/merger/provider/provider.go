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

package provider

import (
	"context"
	"fmt"
	"github.com/go-logr/logr"
	"kubauth/cmd/merger/config"
	"kubauth/internal/httpclient"
	"kubauth/internal/proto"
)

type Provider interface {
	GetUserDetail(ctx context.Context, login, password string) (*proto.UserDetail, error)
	GetName() string
}

type provider struct {
	config     *config.ProviderConfig
	httpClient httpclient.HttpClient
}

var yes = true

var _ Provider = &provider{}

func New(config *config.ProviderConfig) (Provider, error) {
	// Set config default
	if config.CredentialAuthority == nil {
		config.CredentialAuthority = &yes
	}
	if config.GroupAuthority == nil {
		config.GroupAuthority = &yes
	}
	if config.GroupPattern == "" {
		config.GroupPattern = "%s"
	}
	if config.ClaimAuthority == nil {
		config.ClaimAuthority = &yes
	}
	if config.ClaimPattern == "" {
		config.ClaimPattern = "%s"
	}
	if config.NameAuthority == nil {
		config.NameAuthority = &yes
	}
	if config.EmailAuthority == nil {
		config.EmailAuthority = &yes
	}
	if config.Critical == nil {
		config.Critical = &yes
	}

	httpClient, err := httpclient.New(&config.HttpConfig)
	if err != nil {
		return nil, err
	}

	return &provider{
		config:     config,
		httpClient: httpClient,
	}, nil
}

func (p *provider) GetUserDetail(ctx context.Context, login, password string) (*proto.UserDetail, error) {
	request := &proto.IdentityRequest{
		Login:    login,
		Password: password,
	}
	logger := logr.FromContextAsSlogLogger(ctx)
	response := &proto.IdentityResponse{}
	err := proto.Exchange(p.httpClient, "GET", "v1/identity", request, response)
	if err != nil {
		if *p.config.Critical {
			logger.Error("Provider failure. Aborting", "error", err, "login", login, "provider", p.config.Name)
			return nil, err
		}
		logger.Error("Provider failure. Skipping", "error", err, "login", login, "provider", p.config.Name)
		return &proto.UserDetail{
			User:     proto.InitUser(login),
			Status:   proto.Undefined,
			Provider: p.getSpec(),
			Translated: proto.Translated{
				Uid:    nil,
				Groups: []string{},
				Claims: map[string]interface{}{},
			},
		}, nil
	}
	userDetail := &proto.UserDetail{
		User:     response.User,
		Status:   response.Status,
		Provider: p.getSpec(),
		Translated: proto.Translated{
			Uid:    nil,
			Groups: make([]string, len(response.User.Groups)),
			Claims: map[string]interface{}{},
		},
	}
	for idx := range response.User.Groups {
		userDetail.Translated.Groups[idx] = fmt.Sprintf(p.config.GroupPattern, response.User.Groups[idx])
	}
	for claim, value := range response.User.Claims {
		userDetail.Translated.Claims[fmt.Sprintf(p.config.ClaimPattern, claim)] = value
	}
	if response.User.Uid != nil {
		uid := *response.User.Uid + p.config.UidOffset
		userDetail.Translated.Uid = &uid
	}
	return userDetail, nil
}

func (p *provider) getSpec() proto.ProviderSpec {
	return proto.ProviderSpec{
		Name:                p.config.Name,
		CredentialAuthority: *p.config.CredentialAuthority,
		GroupAuthority:      *p.config.GroupAuthority,
		ClaimAuthority:      *p.config.ClaimAuthority,
		EmailAuthority:      *p.config.EmailAuthority,
		NameAuthority:       *p.config.NameAuthority,
	}
}
func (p *provider) GetName() string {
	return p.config.Name
}
