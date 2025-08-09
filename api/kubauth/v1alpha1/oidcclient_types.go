/*
Copyright 2025 Kubotal

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

// OidcClientSpec defines the desired state of OidcClient
type OidcClientSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// The following markers will use OpenAPI v3 schema to validate the value
	// More info: https://book.kubebuilder.io/reference/markers/crd-validation.html

	// The client ID.
	// +required
	Id string `json:"id"`

	// A human oriented description
	// +optional
	Description string `json:"description,omitempty"`

	// The hashed secret. (Required if !public)
	// +optional
	HashedSecret string `json:"hashedSecret,omitempty"`

	// The client's allowed redirect URIs.
	// +required
	RedirectUris []string `json:"redirectUris"`

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
	Public bool `json:"public"`

	// The allowed audience(s) for this client.
	// +optional
	Audiences []string `json:"audiences"`
}

// OidcClientStatus defines the observed state of OidcClient.
type OidcClientStatus struct {
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// OidcClient is the Schema for the oidcclients API
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
