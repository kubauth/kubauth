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
	"fmt"
	"kubauth/api/kubauth/v1alpha1"
	"strings"
	"time"

	"github.com/ory/hydra/v2/fosite"
)

type KubauthClient interface {
	fosite.ClientWithSecretRotation
	GetDescription() string
	GetEntryURL() string
	GetPostLogoutURL() string
	GetDisplayName() string
	IsForceOpenIdScope() bool
	GetSecretCount() int
	GetK8sId() string // Used to check against duplicated OIDC client_id
	GetStyle() string
	GetUpstreamProviders() []string
	GetK8sObject() *v1alpha1.OidcClient
}

type kubauthClient struct {
	clientId      string // From metadata.name or metadata.namespace + "_" + metadata.name
	k8sObject     *v1alpha1.OidcClient
	hashedSecrets [][]byte
	k8sId         string
}

func NewKubauthClient(cli *v1alpha1.OidcClient, clientId string, hashedSecrets [][]byte) KubauthClient {
	return &kubauthClient{
		clientId:      clientId,
		k8sObject:     cli,
		hashedSecrets: hashedSecrets,
		k8sId:         fmt.Sprintf("%s:%s", cli.Namespace, cli.GetName()),
	}
}

var _ KubauthClient = &kubauthClient{}

var _ fosite.ClientWithCustomTokenLifespans = &kubauthClient{}

func (k *kubauthClient) GetID() string {
	return k.clientId
}

func (k *kubauthClient) GetK8sId() string {
	return k.k8sId
}

func (k *kubauthClient) GetHashedSecret() []byte {
	if k.hashedSecrets == nil || len(k.hashedSecrets) == 0 {
		return nil
	}
	return []byte(k.hashedSecrets[0])
}

func (k *kubauthClient) GetRotatedHashes() [][]byte {
	if k.hashedSecrets == nil || len(k.hashedSecrets) < 1 {
		return nil
	}
	return k.hashedSecrets[1:]
}

func (k *kubauthClient) GetSecretCount() int {
	if k.hashedSecrets == nil {
		return 0
	}
	return len(k.hashedSecrets)
}

func (k *kubauthClient) GetRedirectURIs() []string {
	return k.k8sObject.Spec.RedirectURIs
}

func (k *kubauthClient) GetGrantTypes() fosite.Arguments {
	return k.k8sObject.Spec.GrantTypes
}

func (k *kubauthClient) GetResponseTypes() fosite.Arguments {
	return k.k8sObject.Spec.ResponseTypes
}

func (k *kubauthClient) GetScopes() fosite.Arguments {
	return k.k8sObject.Spec.Scopes
}

func (k *kubauthClient) IsPublic() bool {
	return k.k8sObject.Spec.Public
}

func (k *kubauthClient) GetAudience() fosite.Arguments {
	for _, aud := range k.k8sObject.Spec.Audiences {
		if aud == k.clientId {
			return k.k8sObject.Spec.Audiences
		}
	}
	// Always allow the client's own ID as audience, since HandleAudience()
	// defaults to granting client_id when no audience is explicitly requested.
	return append(k.k8sObject.Spec.Audiences, k.clientId)
}

func (k *kubauthClient) GetDescription() string {
	return k.k8sObject.Spec.Description
}

func (k *kubauthClient) GetEntryURL() string {
	return k.k8sObject.Spec.EntryURL
}

func (k *kubauthClient) GetPostLogoutURL() string {
	return k.k8sObject.Spec.PostLogoutURL
}

func (k *kubauthClient) GetDisplayName() string {
	return k.k8sObject.Spec.DisplayName
}

func (k *kubauthClient) IsForceOpenIdScope() bool {
	if k.k8sObject.Spec.ForceOpenIdScope == nil {
		return false
	}
	return *k.k8sObject.Spec.ForceOpenIdScope
}

func (k *kubauthClient) GetEffectiveLifespan(gt fosite.GrantType, tt fosite.TokenType, fallback time.Duration) time.Duration {
	//fmt.Printf("############### GetEffectiveLifespan client:%s grant type:%s   tokenType:%s   fallBack:%s\n", k.clientId, gt, tt, fallback)
	if tt == fosite.AccessToken {
		if k.k8sObject.Spec.AccessTokenLifespan.Duration != 0 {
			return k.k8sObject.Spec.AccessTokenLifespan.Duration
		}
		return fallback
	}
	if tt == fosite.RefreshToken {
		if k.k8sObject.Spec.RefreshTokenLifespan.Duration != 0 {
			return k.k8sObject.Spec.RefreshTokenLifespan.Duration
		}
		return fallback
	}
	if tt == fosite.IDToken {
		if k.k8sObject.Spec.IDTokenLifespan.Duration != 0 {
			// fmt.Printf("GetEffectiveLifespan(id_token) => %s\n", k.spec.IDTokenLifespan.Duration)
			return k.k8sObject.Spec.IDTokenLifespan.Duration
		}
		return fallback
	}
	return fallback
}

func (k *kubauthClient) GetStyle() string {
	return k.k8sObject.Spec.Style
}

func (k *kubauthClient) GetUpstreamProviders() []string {
	return k.k8sObject.Spec.UpstreamProviders
}

func (k *kubauthClient) parseK8sID() (namespace, name string, ok bool) {
	parts := strings.SplitN(k.k8sId, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func (k *kubauthClient) GetK8sObject() *v1alpha1.OidcClient {
	return k.k8sObject
}
