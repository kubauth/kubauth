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

package global

var DefaultPorts = struct {
	Oidc struct {
		Entry       int
		HealthProbe int
		Webhook     int
		Metrics     int
	}
	Crd struct {
		Entry       int
		HealthProbe int
		Webhook     int
		Metrics     int
	}
	Ldap struct {
		Entry int
	}
	Merger struct {
		Entry int
	}
	Logger struct {
		Entry int
	}
}{}

func init() {
	DefaultPorts.Oidc.Entry = 6801
	DefaultPorts.Crd.Entry = 6802
	DefaultPorts.Ldap.Entry = 6803
	DefaultPorts.Merger.Entry = 6804
	DefaultPorts.Logger.Entry = 6805

	DefaultPorts.Oidc.HealthProbe = 8110
	DefaultPorts.Oidc.Webhook = 9443
	DefaultPorts.Oidc.Metrics = 0 // 8443

	DefaultPorts.Crd.HealthProbe = 8111
	DefaultPorts.Crd.Webhook = 9444
	DefaultPorts.Crd.Metrics = 0 // 8444

}
