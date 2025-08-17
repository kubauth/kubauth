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
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type UserSpec struct {
	// The user login is the Name of the resource.

	// The user common name(s).
	// First is used as fullName
	// +optional
	CommonNames []string `json:"commonNames,omitempty"`

	// The user email(s).
	// +optional
	Emails []string `json:"emails,omitempty"`

	// The user password, Hashed. Using golang.org/x/crypto/bcrypt.GenerateFromPassword()
	// Is optional, in case we only enrich a user from another directory
	// +optional
	PasswordHash string `json:"passwordHash,omitempty"`

	// Numerical user id
	// +optional
	Uid *int `json:"uid,omitempty"`

	// Whatever extra information related to this user.
	// +optional
	Comment string `json:"comment,omitempty"`

	// The oidc Claims
	// +optional
	Claims *apiextensionsv1.JSON `json:"claims,omitempty"`

	// Prevent this user to login. Even if this user is managed by an external provider (i.e. LDAP)
	// +optional
	Disabled *bool `json:"disabled,omitempty"`
}

// UserStatus defines the observed state of User
type UserStatus struct {
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=kuser;kusers
// +kubebuilder:printcolumn:name="Common names",type=string,JSONPath=`.spec.commonNames`
// +kubebuilder:printcolumn:name="Emails",type=string,JSONPath=`.spec.emails`
// +kubebuilder:printcolumn:name="Uid",type=integer,JSONPath=`.spec.uid`
// +kubebuilder:printcolumn:name="Comment",type=string,JSONPath=`.spec.comment`
// +kubebuilder:printcolumn:name="Disabled",type=boolean,JSONPath=`.spec.disabled`
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// User is the Schema for the users API
type User struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   UserSpec   `json:"spec,omitempty"`
	Status UserStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// UserList contains a list of User
type UserList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []User `json:"items"`
}

func init() {
	SchemeBuilder.Register(&User{}, &UserList{})
}
