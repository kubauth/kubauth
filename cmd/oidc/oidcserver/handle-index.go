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

package oidcserver

import (
	"net/http"
	"sort"

	"github.com/go-logr/logr"
)

type indexEntry struct {
	DisplayName string
	Description string
	EntryURL    string
}

// Handle index page displaying available OIDC applications
func (s *OIDCServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := logr.FromContextAsSlogLogger(ctx)

	// Collect applications with non-empty name and entryURL
	var entries []indexEntry
	for _, client := range s.Storage.Clients {
		displayName := client.GetDisplayName()
		entryURL := client.GetEntryURL()

		// Only include clients with both name and entryURL
		if displayName != "" && entryURL != "" {
			entries = append(entries, indexEntry{
				DisplayName: displayName,
				Description: client.GetDescription(),
				EntryURL:    entryURL,
			})
		}
	}

	// Sort entries by DisplayName, then by EntryURL
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].DisplayName == entries[j].DisplayName {
			return entries[i].EntryURL < entries[j].EntryURL
		}
		return entries[i].DisplayName < entries[j].DisplayName
	})

	data := struct {
		Entries []indexEntry
	}{
		Entries: entries,
	}

	if err := s.IndexTemplate.Execute(w, data); err != nil {
		logger.Error("Failed to execute index template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}
