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
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// type ClaimSet map[string]interface{}

// Upstream is the representation if an upstream server in memory, after loading from an UpstreamProvider CRD
type Upstream interface {
	GetName() string
	GetDisplayName() string
	GetEffectiveConfig() *kubauthv1alpha1.UpstreamProviderConfig
	GetProviderType() kubauthv1alpha1.UpstreamProviderType
	IsClientSpecific() bool

	// OAuth2AuthCodeSettings returns client and endpoint configuration for upstream OIDC
	// authorization code flow. ok is false for providers that do not support it (e.g. Internal).
	OAuth2AuthCodeSettings() (*OAuth2AuthCodeSettings, bool)
	// ClientContext returns ctx wrapped with the upstream HTTP client for token/userinfo calls.
	ClientContext(ctx context.Context) context.Context
	// ParseAndVerifyIDToken verifies the ID token against this upstream and returns its claims as a map.
	ParseAndVerifyIDToken(ctx context.Context, rawIDToken string) (map[string]interface{}, error)
	// FetchUserInfoClaims returns UserInfo claims when supported; nil map if there is no userinfo endpoint.
	FetchUserInfoClaims(ctx context.Context, tokenSource oauth2.TokenSource) (map[string]interface{}, error)
	// IsUseUserInfo we want to user userInfo endpoint
	IsUseUserInfo() bool
	// PerformRenaming rename claims
	PerformRenaming(claims map[string]interface{}) map[string]interface{}
	// CleanupClaims remove 'technical' claims (https://openid.net/specs/openid-connect-core-1_0.html#IDToken)
	// and the one from the ClaimRemovals list
	CleanupClaims(claims map[string]interface{}) map[string]interface{}
}

type upstream struct {
	name         string
	spec         kubauthv1alpha1.UpstreamProviderSpec
	clientSecret string // resolved from Secret; not part of Spec
	// Computed
	provider    *oidc.Provider
	httpClient  *http.Client
	extraConfig extraConfig
}

type extraConfig struct {
	IntrospectionURL     string   `json:"introspection_endpoint"`
	EndSessionURL        string   `json:"end_session_endpoint"`
	JwksURL              string   `json:"jwks_uri"`
	Algorithms           []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethods []string `json:"code_challenge_methods_supported"`
}

var _ Upstream = &upstream{}

func NewInternalUpstream(welcomeMessage string) Upstream {
	return &upstream{
		name: "internal",
		spec: kubauthv1alpha1.UpstreamProviderSpec{
			Type:        kubauthv1alpha1.UpstreamProviderTypeInternal,
			DisplayName: welcomeMessage,
		},
	}
}

// NewUpstream Create a new Upstream Object
// WARNING: This function can return an error AND a (partial) upstream object
// caPEM is the raw PEM-encoded CA bundle for the upstream issuer (may be nil).
func NewUpstream(ctx context.Context, upstreamProvider *kubauthv1alpha1.UpstreamProvider, clientSecret string, caPEM []byte) (Upstream, error) {
	spec := *upstreamProvider.Spec.DeepCopy()
	if spec.Type == kubauthv1alpha1.UpstreamProviderTypeInternal {
		return &upstream{
			name: upstreamProvider.Name,
			spec: spec,
		}, nil
	}
	u := &upstream{
		name:         upstreamProvider.Name,
		spec:         spec,
		clientSecret: clientSecret,
	}
	// We need to set an http.Client and store it in context for the oidc library
	httpClientConfig := &httpclient.Config{
		BaseURL:            spec.IssuerURL,
		InsecureSkipVerify: spec.InsecureSkipVerify,
		DumpExchanges:      spec.DumpExchanges,
		Label:              "upstreamProvider/" + upstreamProvider.Name,
	}
	if len(caPEM) > 0 {
		httpClientConfig.RootCaBytes = [][]byte{caPEM}
	}

	httpClient, err := httpclient.New(httpClientConfig)
	if err != nil {
		return nil, fmt.Errorf("error creating http client: %w", err)
	}
	u.httpClient = httpClient.GetBaseHttpDotClient()
	ctx = oidc.ClientContext(ctx, u.httpClient)

	if spec.ExplicitConfig == nil {
		// We will use discovery
		u.provider, err = oidc.NewProvider(ctx, spec.IssuerURL)
		if err != nil {
			return nil, fmt.Errorf("error on upstream oidc provider: %w", err)
		}
		// We need to claim some configuration values from the response.body as, either they are not managed by the oidc.Provider at all or they are private without getter
		err = u.provider.Claims(&u.extraConfig)
		if err != nil {
			return nil, fmt.Errorf("error fetching complementary endpoints: %w", err)
		}
	} else {
		// No discovery. Use explicit config
		providerConfig := ToOIDCProviderConfig(spec.IssuerURL, spec.ExplicitConfig)
		u.provider = providerConfig.NewProvider(ctx)
		u.extraConfig.IntrospectionURL = spec.ExplicitConfig.IntrospectionURL
		u.extraConfig.EndSessionURL = spec.ExplicitConfig.EndSessionURL
		u.extraConfig.JwksURL = spec.ExplicitConfig.JWKSURL
		u.extraConfig.Algorithms = spec.ExplicitConfig.Algorithms
	}
	return u, nil
}

func (u *upstream) GetName() string {
	return u.name
}

func (u *upstream) GetDisplayName() string {
	if u.spec.DisplayName != "" {
		return u.spec.DisplayName
	}
	return u.name
}

func (u *upstream) GetProviderType() kubauthv1alpha1.UpstreamProviderType {
	return u.spec.Type
}

func (u *upstream) IsClientSpecific() bool {
	return u.spec.ClientSpecific
}

func (u *upstream) IsUseUserInfo() bool {
	return u.spec.UseUserInfo
}

func (u *upstream) CleanupClaims(claims map[string]interface{}) map[string]interface{} {
	//TODO implement me
	return claims
}

func (u *upstream) PerformRenaming(claims map[string]interface{}) map[string]interface{} {
	//TODO implement me
	return claims
}

// GetEffectiveConfig is not used in the interaction, but by the controller to update the status
func (u *upstream) GetEffectiveConfig() *kubauthv1alpha1.UpstreamProviderConfig {
	if u.provider == nil {
		return nil
	}
	return &kubauthv1alpha1.UpstreamProviderConfig{
		AuthURL:          u.provider.Endpoint().AuthURL,
		TokenURL:         u.provider.Endpoint().TokenURL,
		DeviceAuthURL:    u.provider.Endpoint().DeviceAuthURL,
		UserInfoURL:      u.provider.UserInfoEndpoint(),
		JWKSURL:          u.extraConfig.JwksURL,
		Algorithms:       u.extraConfig.Algorithms,
		IntrospectionURL: u.extraConfig.IntrospectionURL,
		EndSessionURL:    u.extraConfig.EndSessionURL,
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
