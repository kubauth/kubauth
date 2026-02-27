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

package oidcstorage

import (
	"kubauth/api/kubauth/v1alpha1"
	"time"

	"github.com/ory/fosite"
)

type FositeClient interface {
	fosite.ClientWithSecretRotation
	GetName() string
	GetDescription() string
	GetEntryURL() string
	GetPostLogoutURL() string
	GetDisplayName() string
	IsForceOpenIdScope() bool
	GetSecretCount() int
}

type fositeClient struct {
	clientId      string // From metadata.name
	spec          *v1alpha1.OidcClientSpec
	hashedSecrets [][]byte
}

func NewFositeClient(cli *v1alpha1.OidcClient, hashedSecrets [][]byte) FositeClient {
	return &fositeClient{
		clientId:      cli.GetName(),
		spec:          &cli.Spec,
		hashedSecrets: hashedSecrets,
	}
}

var _ FositeClient = &fositeClient{}

var _ fosite.ClientWithCustomTokenLifespans = &fositeClient{}

func (k *fositeClient) GetID() string {
	return k.clientId
}

func (k *fositeClient) GetHashedSecret() []byte {
	if k.hashedSecrets == nil || len(k.hashedSecrets) == 0 {
		return nil
	}
	return []byte(k.hashedSecrets[0])
}

func (k *fositeClient) GetRotatedHashes() [][]byte {
	if k.hashedSecrets == nil || len(k.hashedSecrets) < 1 {
		return nil
	}
	return k.hashedSecrets[1:]
}

func (k *fositeClient) GetSecretCount() int {
	if k.hashedSecrets == nil {
		return 0
	}
	return len(k.hashedSecrets)
}

func (k *fositeClient) GetRedirectURIs() []string {
	return k.spec.RedirectURIs
}

func (k *fositeClient) GetGrantTypes() fosite.Arguments {
	return k.spec.GrantTypes
}

func (k *fositeClient) GetResponseTypes() fosite.Arguments {
	return k.spec.ResponseTypes
}

func (k *fositeClient) GetScopes() fosite.Arguments {
	return k.spec.Scopes
}

func (k *fositeClient) IsPublic() bool {
	return k.spec.Public
}

func (k *fositeClient) GetAudience() fosite.Arguments {
	return k.spec.Audiences
}

func (k *fositeClient) GetName() string {
	return k.GetName()
}

func (k *fositeClient) GetDescription() string {
	return k.spec.Description
}

func (k *fositeClient) GetEntryURL() string {
	return k.spec.EntryURL
}

func (k *fositeClient) GetPostLogoutURL() string {
	return k.spec.PostLogoutURL
}

func (k *fositeClient) GetDisplayName() string {
	return k.spec.DisplayName
}

func (k *fositeClient) IsForceOpenIdScope() bool {
	if k.spec.ForceOpenIdScope == nil {
		return false
	}
	return *k.spec.ForceOpenIdScope
}

func (k *fositeClient) GetEffectiveLifespan(gt fosite.GrantType, tt fosite.TokenType, fallback time.Duration) time.Duration {
	//fmt.Printf("############### GetEffectiveLifespan client:%s grant type:%s   tokenType:%s   fallBack:%s\n", k.clientId, gt, tt, fallback)
	if tt == fosite.AccessToken {
		if k.spec.AccessTokenLifespan.Duration != 0 {
			return k.spec.AccessTokenLifespan.Duration
		}
		return fallback
	}
	if tt == fosite.RefreshToken {
		if k.spec.RefreshTokenLifespan.Duration != 0 {
			return k.spec.RefreshTokenLifespan.Duration
		}
		return fallback
	}
	if tt == fosite.IDToken {
		if k.spec.IDTokenLifespan.Duration != 0 {
			// fmt.Printf("GetEffectiveLifespan(id_token) => %s\n", k.spec.IDTokenLifespan.Duration)
			return k.spec.IDTokenLifespan.Duration
		}
		return fallback
	}
	return fallback
}
