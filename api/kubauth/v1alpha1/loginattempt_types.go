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

type LoginAttemptDetailProvider struct {
	Name                string `json:"name"`
	ClaimAuthority      bool   `json:"claimAuthority"`
	CredentialAuthority bool   `json:"credentialAuthority"`
	EmailAuthority      bool   `json:"emailAuthority"`
	GroupAuthority      bool   `json:"groupAuthority"`
	NameAuthority       bool   `json:"nameAuthority"`
}

type LoginAttemptDetailTranslated struct {
	Claims apiextensionsv1.JSON `json:"claims"`
	Groups []string             `json:"groups"`
	// +optional
	Uid *int `json:"uid"`
}

type LoginAttemptDetail struct {
	Provider   LoginAttemptDetailProvider   `json:"provider"`
	User       LoginAttemptUser             `json:"user"`
	Status     string                       `json:"status"`
	Translated LoginAttemptDetailTranslated `json:"translated"`
}

type LoginAttemptUser struct {
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

type LoginAttemptSpec struct {

	//
	When metav1.Time `json:"when"`

	// The resulting user
	User LoginAttemptUser `json:"user"`

	// The module which validate the credentials
	// +optional
	Authority string `json:"authority,omitempty"`

	// The current status
	Status string `json:"status"`

	// +optional
	Details []LoginAttemptDetail `json:"details,omitempty"`
}

// LoginAttemptStatus defines the observed state of LoginAttempt
type LoginAttemptStatus struct {
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=la
// +kubebuilder:printcolumn:name="Login",type=string,JSONPath=`.spec.user.login`
// +kubebuilder:printcolumn:name="Name",type=string,JSONPath=`.spec.user.name`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.spec.status`
// +kubebuilder:printcolumn:name="Authority",type=string,JSONPath=`.spec.authority`
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

type LoginAttempt struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   LoginAttemptSpec   `json:"spec,omitempty"`
	Status LoginAttemptStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// LoginAttemptList contains a list of Group
type LoginAttemptList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []LoginAttempt `json:"items"`
}

func init() {
	SchemeBuilder.Register(&LoginAttempt{}, &LoginAttemptList{})
}
