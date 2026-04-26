/*
Copyright (c) 2025 Kubotal.

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

package oidcserver

import (
	"context"
	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"
	"kubauth/cmd/oidc/oidcstorage"
	"kubauth/cmd/oidc/upstreams"
	"kubauth/internal/global"
	"net/http"
	"net/url"
	"sort"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
)

type UpstreamButtonModel struct {
	Name        string
	DisplayName string
}

type LoginModel struct {
	InvalidLogin          bool
	Style                 string
	Version               string
	BuildTs               string
	UpstreamButtons       []UpstreamButtonModel
	ShowLoginForm         bool
	FieldsetLabel         string
	ShowNoProviderMessage bool
	ShowSsoCheck          bool
}

func (s *OIDCServer) displayLoginResponse(ctx context.Context, w http.ResponseWriter, r *http.Request, clientId string, invalidLogin bool) {
	model := &LoginModel{
		InvalidLogin: invalidLogin,
		Style:        s.getStyle(ctx, clientId),
		Version:      global.Version,
		BuildTs:      global.BuildTs,
		ShowSsoCheck: s.SsoMode == SsoOnDemand,
	}
	if clientId != "" {
		if kubauthClient, err := s.Storage.GetKubauthClient(ctx, clientId); err == nil && kubauthClient != nil {
			s.populateLoginModelWithUpstreams(ctx, kubauthClient, model)
		}
	}
	if !invalidLogin && !model.ShowLoginForm && !model.ShowNoProviderMessage && len(model.UpstreamButtons) == 1 {
		q := url.Values{}
		q.Set("upstreamProvider", model.UpstreamButtons[0].Name)
		http.Redirect(w, r, "/upstream/go?"+q.Encode(), http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.LoginTemplate.Execute(w, model); err != nil {
		logr.FromContextAsSlogLogger(ctx).Error("Template error", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func (s *OIDCServer) getStyle(ctx context.Context, clientId string) string {
	if clientId == "" {
		return s.DefaultStyle
	}
	client, err := s.Storage.GetKubauthClient(ctx, clientId)
	if err != nil || client == nil {
		logr.FromContextAsSlogLogger(ctx).Error("Failed to get KubauthClient", "error", err)
		return s.DefaultStyle
	}
	return client.GetStyle()
}

func (s *OIDCServer) populateLoginModelWithUpstreams(ctx context.Context, kubauthClient oidcstorage.KubauthClient, model *LoginModel) {
	logger := logr.FromContextAsSlogLogger(ctx)

	var internal upstreams.Upstream = nil
	upstreamButtons := make([]UpstreamButtonModel, 0, 5)

	clientUpstreamNameList := kubauthClient.GetUpstreamProviders()
	if clientUpstreamNameList != nil && len(clientUpstreamNameList) > 0 {
		// ------------------------------------------------- The upstream list is provided by the client
		for _, upstreamName := range clientUpstreamNameList {
			upstream := s.Storage.GetUpstream(ctx, upstreamName)
			if upstream == nil {
				logger.Error("Upstream unexisting or disabled", "oidcClient", kubauthClient.GetK8sId(), "upstream", upstreamName)
				s.EventRecorder.Eventf(kubauthClient.GetK8sObject(), corev1.EventTypeWarning, "InvalidUpstreamProvider",
					"Referenced UpstreamProvider %q is not available (unexisting or disabled)", upstreamName)
				continue
			}
			if upstream.GetProviderType() == kubauthv1alpha1.UpstreamProviderTypeInternal {
				internal = upstream
			} else {
				upstreamButtons = append(upstreamButtons, UpstreamButtonModel{
					Name:        upstream.GetName(),
					DisplayName: upstream.GetDisplayName(),
				})
			}
		}
	} else {
		globalUpstreamList := s.Storage.GetUpstreams(ctx)
		if globalUpstreamList != nil && len(globalUpstreamList) > 0 {
			// Sort by name (Not display name)
			sort.Slice(globalUpstreamList, func(i, j int) bool {
				return globalUpstreamList[i].GetName() < globalUpstreamList[j].GetName()
			})
			// A loop to extract internal and remove clientSpecific ones
			for _, upstream := range globalUpstreamList {
				if !upstream.IsClientSpecific() {
					if upstream.GetProviderType() == kubauthv1alpha1.UpstreamProviderTypeInternal {
						internal = upstream
					} else {
						upstreamButtons = append(upstreamButtons, UpstreamButtonModel{
							Name:        upstream.GetName(),
							DisplayName: upstream.GetDisplayName(),
						})
					}
				}
			}
		} else {
			// No upstreams list defined for this client, and no upstreamProviders at all: Setup default internal provider
			internal = upstreams.NewInternalUpstream(s.InternalWelcomeMessage)
		}
	}
	if len(upstreamButtons) > 0 {
		model.UpstreamButtons = upstreamButtons
	}
	if internal != nil {
		model.ShowLoginForm = true
		model.FieldsetLabel = internal.GetDisplayName()
	}
	if len(upstreamButtons) == 0 && internal == nil {
		model.ShowNoProviderMessage = true
	}
}
