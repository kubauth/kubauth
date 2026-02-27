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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

/* NOTES:
Not (yet?) implemented
- ClientWithSecretRotation
- OpenIDConnectClient (Seems we are able to handle id_token without this ?)
- ResponseModeClient
*/

type OidcClientSecretSpec struct {
	// +required
	Name string `json:"name"`

	// +required
	Key string `json:"key"`

	// true, if the value is hashed (More secured)
	// +default:value=false
	Hashed bool `json:"hashed"`
}

// OidcClientSpec defines the desired state of OidcClient
// client_id is metadata.name
type OidcClientSpec struct {
	// The following markers will use OpenAPI v3 schema to validate the value
	// More info: https://book.kubebuilder.io/reference/markers/crd-validation.html

	// A list of k8s secret hosting the client_secret.
	// Required for non public oidcClient
	// +optional
	Secrets []OidcClientSecretSpec `json:"secrets"`

	// The client's allowed redirect URIs.
	// +required
	RedirectURIs []string `json:"redirectURIs"`

	// The client's allowed grant types.
	// +required
	GrantTypes []string `json:"grantTypes"`

	// The client's allowed response types.
	// All allowed combinations of response types have to be listed, each combination having
	// response types of the combination separated by a space.
	// +required
	ResponseTypes []string `json:"responseTypes"`

	// The scopes this client is allowed to request.
	// +required
	Scopes []string `json:"scopes"`

	// true, if this client is marked as public.
	// +default:value=false
	Public bool `json:"public"`

	// +optional
	Audiences []string `json:"audiences,omitempty"`

	// Force openid scope, even if not requested.
	// +optional
	ForceOpenIdScope *bool `json:"forceOpenIdScope,omitempty"`

	// Where to redirected user on logout.
	// Will take precedence on the same global configuration value.
	// May be overridden by a query parameter on the logout url
	// +optional
	PostLogoutURL string `json:"postLogoutURL,omitempty"`

	// Application name. May be used to be displayed in an application list
	// +optional
	DisplayName string `json:"displayName,omitempty"`

	// A human oriented description
	// +optional
	Description string `json:"description,omitempty"`

	// The application entry URL. May be used to build a user-friendly list
	// +optional
	EntryURL string `json:"entryURL,omitempty"`

	// +optional
	AccessTokenLifespan metav1.Duration `json:"accessTokenLifespan,omitempty"`
	// +optional
	RefreshTokenLifespan metav1.Duration `json:"refreshTokenLifespan,omitempty"`
	// +optional
	IDTokenLifespan metav1.Duration `json:"idTokenLifespan,omitempty"`
}

type OidcClientPhase string

const OidcClientPhaseReady = OidcClientPhase("READY")
const OidcClientPhaseError = OidcClientPhase("ERROR")

// OidcClientStatus defines the observed state of OidcClient.
type OidcClientStatus struct {
	Phase OidcClientPhase `json:"phase"`

	// +optional
	Message string `json:"message"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:printcolumn:name="Pub.",type=boolean,JSONPath=`.spec.public`
// +kubebuilder:printcolumn:name="Description",type=string,JSONPath=`.spec.description`
// +kubebuilder:printcolumn:name="Display",type=string,JSONPath=`.spec.displayName`
// +kubebuilder:printcolumn:name="Link",type=string,JSONPath=`.spec.entryURL`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

type OidcClient struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of OidcClient
	// +required
	Spec OidcClientSpec `json:"spec"`

	// status defines the observed state of OidcClient
	// +optional
	Status OidcClientStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// OidcClientList contains a list of OidcClient
type OidcClientList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OidcClient `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OidcClient{}, &OidcClientList{})
}
