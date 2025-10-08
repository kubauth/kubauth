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

package proto

type Translated struct {
	Groups []string               `yaml:"groups"`
	Claims map[string]interface{} `yaml:"claims"`
	Uid    int                    `yaml:"uid"`
}

type ProviderSpec struct {
	Name                string `json:"name"`
	CredentialAuthority bool   `json:"credentialAuthority"` // Is this provider Authority for authentication (password) for this user
	GroupAuthority      bool   `json:"groupAuthority"`      // Should we take groups in account
	ClaimAuthority      bool   `json:"claimAuthority"`      // Should we take claims in account
	NameAuthority       bool   `json:"nameAuthority"`
	EmailAuthority      bool   `json:"emailAuthority"`
}

type UserDetail struct {
	User       User         `json:"user"`
	Status     Status       `json:"status"`
	Provider   ProviderSpec `json:"provider"`
	Translated Translated   `json:"translated"`
}
