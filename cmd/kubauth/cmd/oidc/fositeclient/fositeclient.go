package fositeclient

import (
	"github.com/ory/fosite"
	"kubauth/api/kubauth/v1alpha1"
)

type fositeClient struct {
	spec *v1alpha1.OidcClientSpec
}

func NewFositeClient(spec *v1alpha1.OidcClientSpec) fosite.Client {
	return &fositeClient{
		spec: spec,
	}
}

var _ fosite.Client = &fositeClient{}

func (k *fositeClient) GetID() string {
	return k.spec.Id
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
