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

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// SsoSessionSpec defines the desired state of SsoSession
type SsoSessionSpec struct {

	// +required
	Login string `json:"login"`

	// The user full name
	// +optional
	FullName string `json:"fullName"`

	// The absolute deadline, from SessionManager.Lifetime
	Deadline metav1.Time `json:"deadline"`

	// time limit from SessionManage.IdleTimeout
	// IdleTimeout is meaningless, as this session is cross application. So it is unactivated in most case.
	// Anyway, we store this for technical coherency, even if it will be same as deadLine in all cases.
	// +required
	Expiry metav1.Time `json:"expiry"`

	// The OIDC Claims
	// +optional
	Claims *apiextensionsv1.JSON `json:"claims,omitempty"`

	// The original token (cookie value) of the web session.
	// Used as the SsoSession name in a sanitized non-reversible version of this
	// +required
	WebToken string `json:"webToken"`
}

// SsoSessionStatus defines the observed state of SsoSession.
type SsoSessionStatus struct {
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:printcolumn:name="Login",type=string,JSONPath=`.spec.login`
// +kubebuilder:printcolumn:name="Name",type=string,JSONPath=`.spec.fullName`
// +kubebuilder:printcolumn:name="Deadline",type=string,JSONPath=`.spec.deadline`
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// SsoSession is the Schema for the ssosessions API
// The name is the session token (The session cookie value)
type SsoSession struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of SsoSession
	// +required
	Spec SsoSessionSpec `json:"spec"`

	// status defines the observed state of SsoSession
	// +optional
	Status SsoSessionStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// SsoSessionList contains a list of SsoSession
type SsoSessionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SsoSession `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SsoSession{}, &SsoSessionList{})
}
