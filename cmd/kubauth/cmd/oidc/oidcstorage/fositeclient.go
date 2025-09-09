package oidcstorage

import (
	"github.com/ory/fosite"
	"kubauth/api/kubauth/v1alpha1"
	"time"
)

type FositeClient interface {
	fosite.Client
	GetName() string
	GetDescription() string
	GetEntryURL() string
	GetPostLogoutURL() string
	GetDisplayName() string
	IsForceOpenIdScope() bool
}

type fositeClient struct {
	clientId string // From metadata.name
	spec     *v1alpha1.OidcClientSpec
}

func NewFositeClient(cli *v1alpha1.OidcClient) FositeClient {
	return &fositeClient{
		clientId: cli.GetName(),
		spec:     &cli.Spec,
	}
}

var _ FositeClient = &fositeClient{}

var _ fosite.ClientWithCustomTokenLifespans = &fositeClient{}

func (k *fositeClient) GetID() string {
	return k.clientId
}

func (k *fositeClient) GetHashedSecret() []byte {
	return []byte(k.spec.HashedSecret)
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
