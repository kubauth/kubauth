package khclient

import (
	"github.com/ory/fosite"
	"kubauth/api/kubauth/v1alpha1"
)

type KhClient struct {
	spec *v1alpha1.OidcClientSpec
}

var _ fosite.Client = &KhClient{}

func (k *KhClient) GetID() string {
	return k.spec.Id
}

func (k *KhClient) GetHashedSecret() []byte {
	return []byte(k.spec.HashedSecret)
}

func (k *KhClient) GetRedirectURIs() []string {
	return k.spec.RedirectUris
}

func (k *KhClient) GetGrantTypes() fosite.Arguments {
	return k.spec.GrantTypes
}

func (k *KhClient) GetResponseTypes() fosite.Arguments {
	return k.spec.ResponseTypes
}

func (k *KhClient) GetScopes() fosite.Arguments {
	return k.spec.Scopes
}

func (k *KhClient) IsPublic() bool {
	return k.spec.Public
}

func (k *KhClient) GetAudience() fosite.Arguments {
	return k.spec.Audiences
}
