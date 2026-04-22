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
	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"
	"kubauth/internal/httpclient"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Upstream is the representation if an upstream server in memory, after loading from an UpstreamProvider CRD
type Upstream interface {
	GetName() string
	GetDisplayName() string
	GetEffectiveConfig() *kubauthv1alpha1.UpstreamProviderConfig
	GetProviderType() kubauthv1alpha1.UpstreamProviderType
	IsClientSpecific() bool
}

type upstream struct {
	name           string
	clientSpecific bool
	myType         kubauthv1alpha1.UpstreamProviderType
	displayName    string
	issuerURL      string
	redirectURL    string
	clientId       string
	clientSecret   string
	// Computed
	provider         *oidc.Provider
	introspectionURL string
	endSessionURL    string
	JwksURL          string
	Algorithms       []string
}

var _ Upstream = &upstream{}

// NewUpstream Create a new internal Upstream Object
// WARNING: This function can return an error AND a (partial) upstream object
func NewUpstream(ctx context.Context, upstreamProvider *kubauthv1alpha1.UpstreamProvider, clientSecret string, caData string) (Upstream, error) {
	if upstreamProvider.Spec.Type == kubauthv1alpha1.UpstreamProviderTypeInternal {
		upstream := &upstream{
			name:           upstreamProvider.Name,
			clientSpecific: upstreamProvider.Spec.ClientSpecific,
			myType:         upstreamProvider.Spec.Type,
			displayName:    upstreamProvider.Spec.DisplayName,
		}
		// Nothing more to do
		return upstream, nil
	}
	upstream := &upstream{
		name:           upstreamProvider.Name,
		clientSpecific: upstreamProvider.Spec.ClientSpecific,
		myType:         upstreamProvider.Spec.Type,
		displayName:    upstreamProvider.Spec.DisplayName,
		issuerURL:      upstreamProvider.Spec.IssuerURL,
		redirectURL:    upstreamProvider.Spec.RedirectURL,
		clientId:       upstreamProvider.Spec.ClientId,
		clientSecret:   clientSecret,
	}
	// We need to set an http.Client and store it in context for the oidc library
	httpClientConfig := &httpclient.Config{
		BaseURL:            upstreamProvider.Spec.IssuerURL,
		InsecureSkipVerify: upstreamProvider.Spec.InsecureSkipVerify,
		RootCaDatas:        []string{caData},
		DumpExchanges:      upstreamProvider.Spec.DumpExchanges,
	}

	httpClient, err := httpclient.New(httpClientConfig)
	if err != nil {
		return nil, fmt.Errorf("error creating http client: %w", err)
	}
	ctx = oidc.ClientContext(ctx, httpClient.GetBaseHttpDotClient())

	if upstreamProvider.Spec.ExplicitConfig == nil {
		// We will use discovery
		upstream.provider, err = oidc.NewProvider(ctx, upstreamProvider.Spec.IssuerURL)
		if err != nil {
			return nil, fmt.Errorf("error on upstream oidc provider: %w", err)
		}
		// We need to claim some configuration values from the response.body as, either they are not managed by the oidc.Provider at all or they are private without getter
		var extraConfig struct {
			IntrospectionURL string   `json:"introspection_endpoint"`
			EndSessionURL    string   `json:"end_session_endpoint"`
			JwksURL          string   `json:"jwks_uri"`
			Algorithms       []string `json:"id_token_signing_alg_values_supported"`
		}
		err = upstream.provider.Claims(&extraConfig)
		if err != nil {
			return nil, fmt.Errorf("error fetching complementary endpoints: %w", err)
		}
		upstream.introspectionURL = extraConfig.IntrospectionURL
		upstream.endSessionURL = extraConfig.EndSessionURL
		upstream.JwksURL = extraConfig.JwksURL
		upstream.Algorithms = extraConfig.Algorithms

	} else {
		// No discovery. Use explicit config
		providerConfig := ToOIDCProviderConfig(upstreamProvider.Spec.IssuerURL, upstreamProvider.Spec.ExplicitConfig)
		upstream.provider = providerConfig.NewProvider(ctx)
		// Just copy for
		upstream.introspectionURL = upstreamProvider.Spec.ExplicitConfig.IntrospectionURL
		upstream.endSessionURL = upstreamProvider.Spec.ExplicitConfig.EndSessionURL
		upstream.JwksURL = upstreamProvider.Spec.ExplicitConfig.JWKSURL
		upstream.Algorithms = upstreamProvider.Spec.ExplicitConfig.Algorithms
	}
	return upstream, nil
}

func (u *upstream) GetName() string {
	return u.name
}

func (u *upstream) GetDisplayName() string {
	if u.displayName != "" {
		return u.displayName
	}
	return u.name
}

func (u *upstream) GetProviderType() kubauthv1alpha1.UpstreamProviderType {
	return u.myType
}

func (u *upstream) IsClientSpecific() bool {
	return u.clientSpecific
}

func (u *upstream) GetEffectiveConfig() *kubauthv1alpha1.UpstreamProviderConfig {
	if u.provider == nil {
		return nil
	}
	return &kubauthv1alpha1.UpstreamProviderConfig{
		AuthURL:          u.provider.Endpoint().AuthURL,
		TokenURL:         u.provider.Endpoint().TokenURL,
		DeviceAuthURL:    u.provider.Endpoint().DeviceAuthURL,
		UserInfoURL:      u.provider.UserInfoEndpoint(),
		JWKSURL:          u.JwksURL,
		Algorithms:       u.Algorithms,
		IntrospectionURL: u.introspectionURL,
		EndSessionURL:    u.endSessionURL,
	}
}

// ToOIDCProviderConfig maps API discovery-shaped config to go-oidc's ProviderConfig.
func ToOIDCProviderConfig(issuerURL string, d *kubauthv1alpha1.UpstreamProviderConfig) *oidc.ProviderConfig {
	if d == nil {
		return nil
	}
	return &oidc.ProviderConfig{
		IssuerURL:     issuerURL,
		AuthURL:       d.AuthURL,
		TokenURL:      d.TokenURL,
		DeviceAuthURL: d.DeviceAuthURL,
		UserInfoURL:   d.UserInfoURL,
		JWKSURL:       d.JWKSURL,
		Algorithms:    d.Algorithms,
	}
}
