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
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type LoginDetailProvider struct {
	Name                string `json:"name"`
	ClaimAuthority      bool   `json:"claimAuthority"`
	CredentialAuthority bool   `json:"credentialAuthority"`
	EmailAuthority      bool   `json:"emailAuthority"`
	GroupAuthority      bool   `json:"groupAuthority"`
	NameAuthority       bool   `json:"nameAuthority"`
}

type LoginDetailTranslated struct {
	Claims apiextensionsv1.JSON `json:"claims"`
	Groups []string             `json:"groups"`
	// +optional
	Uid *int `json:"uid"`
}

type LoginDetail struct {
	Provider   LoginDetailProvider   `json:"provider"`
	User       LoginUser             `json:"user"`
	Status     string                `json:"status"`
	Translated LoginDetailTranslated `json:"translated"`
}

type LoginUser struct {
	Login string `json:"login"`
	// +optional
	Uid *int `json:"uid"`
	// +optional
	Name string `json:"name"`
	// +optional
	Emails []string `json:"emails"`
	// +optional
	Groups []string `json:"groups"`
	// +optional
	Claims *apiextensionsv1.JSON `json:"claims"`
}

type LoginSpec struct {

	//
	When metav1.Time `json:"when"`

	// The resulting user
	User LoginUser `json:"user"`

	// The module which validate the credentials
	Authority string `json:"authority"`

	// The current status
	Status string `json:"status"`

	Details []LoginDetail `json:"details"`
}

// LoginStatus defines the observed state of Login
type LoginStatus struct {
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:printcolumn:name="Login",type=string,JSONPath=`.spec.user.login`
// +kubebuilder:printcolumn:name="Name",type=string,JSONPath=`.spec.user.name`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.spec.status`
// +kubebuilder:printcolumn:name="Authority",type=string,JSONPath=`.spec.authority`
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

type Login struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   LoginSpec   `json:"spec,omitempty"`
	Status LoginStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// LoginList contains a list of Group
type LoginList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Login `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Login{}, &LoginList{})
}
