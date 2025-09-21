/*
Copyright 2025.

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

package proto

import (
	"fmt"
	"io"
)

type Status string

// If password is not provided in the request and there is no password in the user definition, status should be 'passwordMissing' (Not 'passwordUnchecked')
const (
	// ---- Following for identity and login response
	UserNotFound      = "userNotFound"
	Disabled          = "disabled"
	PasswordChecked   = "passwordChecked"
	PasswordFail      = "passwordFail"
	PasswordUnchecked = "passwordUnchecked" // Because password was not provided in the request
	PasswordMissing   = "passwordMissing"   // Because this provider does not store a password for this user
	Undefined         = "undefined"         // Used to mark a non-critical failing provider in userDescribe
	// ---- Following is specific to passwordChange
	PasswordChanged    = "passwordChanged"
	UnknownProvider    = "unknownProvider"
	InvalidOldPassword = "invalidOldPassword"
	InvalidNewPassword = "invalidNewPassword" // If some password rules are implemented
	Unsupported        = "unsupported"        // This provider does not support password change
)

type ProviderSpec struct {
	Name                string `json:"name"`
	CredentialAuthority bool   `json:"credentialAuthority"` // Is this provider Authority for authentication (password) for this user
	GroupAuthority      bool   `json:"groupAuthority"`      // Should we take groups in account
	ClaimAuthority      bool   `json:"claimAuthority"`      // Should we take claims in account
}

type User struct {
	Login       string                 `json:"login"`
	Uid         int                    `json:"uid"`
	CommonNames []string               `json:"commonNames"`
	Emails      []string               `json:"emails"`
	Groups      []string               `json:"groups"`
	Claims      map[string]interface{} `json:"claims"`
}

func InitUser(login string) User {
	return User{
		Login:       login,
		Uid:         0,
		CommonNames: []string{},
		Emails:      []string{},
		Groups:      []string{},
		Claims:      map[string]interface{}{},
	}
}

type Translated struct {
	Groups []string `yaml:"groups"`
	Uid    int      `yaml:"uid"`
}

type UserDetail struct {
	User
	Status     Status       `json:"status"`
	Provider   ProviderSpec `json:"provider"`
	Translated Translated   `json:"translated"`
}

type IdentityRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
	Detailed bool   `json:"detailed"`
}

var _ RequestPayload = &IdentityRequest{}

type IdentityResponse struct {
	User
	Status    Status       `json:"status"`
	Details   []UserDetail `json:"details"`   // Empty is IdentityRequest.Detail == False
	Authority string       `json:"authority"` // "" if from an identity provider
}

var _ ResponsePayload = &IdentityResponse{}

// ------------------------------------------

func (u *IdentityRequest) String() string {
	return fmt.Sprintf("IdentityRequest(login=%s", u.Login)
}
func (u *IdentityRequest) ToJson() ([]byte, error) {
	return toJson(u)
}
func (u *IdentityRequest) FromJson(r io.Reader) error {
	return fromJson(r, u)
}

func (u *IdentityResponse) FromJson(r io.Reader) error {
	return fromJson(r, u)
}
