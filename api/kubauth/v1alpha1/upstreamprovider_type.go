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

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CertificateAuthoritySource references a PEM-encoded CA bundle in a ConfigMap or Secret
// in the same namespace as the UpstreamProvider resource. Exactly one of ConfigMap or Secret must be set.
type CertificateAuthoritySource struct {
	// ConfigMap containing the CA bundle. Mutually exclusive with Secret.
	// +optional
	ConfigMap *corev1.LocalObjectReference `json:"configMap,omitempty"`

	// Secret containing the CA bundle. Mutually exclusive with ConfigMap.
	// +optional
	Secret *corev1.LocalObjectReference `json:"secret,omitempty"`

	// Key within the referenced ConfigMap or Secret. Defaults to "ca.crt" if empty.
	// +optional
	Key string `json:"key,omitempty"`
}

type SecretSource struct {
	// K8s Secret containing the secret value.
	// +required
	Secret *corev1.LocalObjectReference `json:"secret"`

	// Key within the referenced ConfigMap or Secret.
	// +required
	Key string `json:"key"`
}

// UpstreamProviderConfig mirrors the subset of the OIDC discovery document represented by
// github.com/coreos/go-oidc/v3/oidc.ProviderConfig. It is defined here (not embedded) so CRD types
// stay self-contained and controller-gen can generate DeepCopy.
// See https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
type UpstreamProviderConfig struct {
	// +optional
	//IssuerURL string `json:"issuer"`
	// +optional
	AuthURL string `json:"authorization_endpoint"`
	// +optional
	TokenURL string `json:"token_endpoint"`
	// +optional
	DeviceAuthURL string `json:"device_authorization_endpoint"`
	// +optional
	UserInfoURL string `json:"userinfo_endpoint"`
	// +optional
	JWKSURL string `json:"jwks_uri"`
	// +optional
	Algorithms []string `json:"id_token_signing_alg_values_supported"`

	// The following are not provided by the github.com/coreos/go-oidc/v3/oidc library, directly
	// +optional
	IntrospectionURL string `json:"introspection_endpoint"`
	// +optional
	EndSessionURL string `json:"end_session_endpoint"`
}

type UpstreamProviderType string

const UpstreamProviderTypeOidc UpstreamProviderType = "oidc"
const UpstreamProviderTypeInternal UpstreamProviderType = "internal"

type UpstreamProviderSpec struct {

	// The upstream type.
	// +kubebuilder:validation:Enum=oidc;internal
	// +required
	Type UpstreamProviderType `json:"type"`

	// Name prompted to the user
	// Required for all but internal. When internal, "" means display the dialog. A value means display a button
	// +optional
	DisplayName string `json:"displayName"`

	// If set, will appear only if in the client upstream list
	// +optional
	// +default:value=false
	ClientSpecific bool `json:"clientSpecific"`

	// The issuer URL
	// +optional
	IssuerURL string `json:"issuerURL"`

	// CertificateAuthority references a PEM-encoded CA bundle used to verify TLS to the upstream issuer (e.g. private PKI).
	// +optional
	CertificateAuthority *CertificateAuthoritySource `json:"certificateAuthority,omitempty"`

	// Allow to skip server certificate validation
	// +optional
	// +default:value=false
	InsecureSkipVerify bool `json:"insecureSkipVerify"`

	// +optional
	RedirectURL string `json:"redirectURL"`

	// +optional
	ClientId string `json:"clientId"`

	// +optional
	ClientSecret *SecretSource `json:"clientSecret"`

	// +optional
	Scopes []string `json:"scopes"`

	// Allow to replace missing configuration discovery. Or to fix uncorrected value
	// It all or nothing -> if != nil take this config and don't perform discovery. If == nil, use discovery.
	// +optional
	ExplicitConfig *UpstreamProviderConfig `json:"explicitConfig,omitempty"`

	// For debugging
	// +optional
	// +default:value=false
	DumpExchanges bool `json:"dumpExchanges"`
}

type UpstreamProviderPhase string

const UpstreamProviderPhaseReady = UpstreamProviderPhase("READY")
const UpstreamProviderPhaseError = UpstreamProviderPhase("ERROR")

// UpstreamProviderStatus defines the observed state of User
type UpstreamProviderStatus struct {
	// +required
	Phase UpstreamProviderPhase `json:"phase"`

	// +optional
	Message string `json:"message"`

	// The resulting configuration in case of discovery
	EffectiveConfig *UpstreamProviderConfig `json:"effectiveConfig"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=upstreams
// +kubebuilder:printcolumn:name="IssuerURL",type=string,JSONPath=`.spec.issuerURL`
// +kubebuilder:printcolumn:name="ClientId",type=string,JSONPath=`.spec.clientId`
// +kubebuilder:printcolumn:name="RedirectURL",type=string,JSONPath=`.spec.redirectURL`

type UpstreamProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   UpstreamProviderSpec   `json:"spec,omitempty"`
	Status UpstreamProviderStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// UpstreamProviderList contains a list of User
type UpstreamProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []UpstreamProvider `json:"items"`
}

func init() {
	SchemeBuilder.Register(&UpstreamProvider{}, &UpstreamProviderList{})
}
