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
	"html"
	"net/http"

	"github.com/go-logr/logr"
)

// handleUpstreamGo is a placeholder that echoes the selected upstream provider.
// It will later start the upstream OIDC authorization code flow.
func (s *OIDCServer) handleUpstreamGo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := logr.FromContextAsSlogLogger(ctx)
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := r.URL.Query().Get("upstreamProvider")
	if name == "" {
		logger.Info("handleUpstreamGo: missing upstreamProvider query parameter")
		http.Error(w, "missing upstreamProvider parameter", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Upstream</title></head><body><p>Selected upstream provider: "))
	_, _ = w.Write([]byte(html.EscapeString(name)))
	_, _ = w.Write([]byte("</p></body></html>"))
}
