package oidcserver

import (
	"kubauth/cmd/kubauth/cmd/oidc/oidcstorage"
	"net/http"

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
		if fositeClient, ok := client.(oidcstorage.FositeClient); ok {
			displayName := fositeClient.GetDisplayName()
			entryURL := fositeClient.GetEntryURL()

			// Only include clients with both name and entryURL
			if displayName != "" && entryURL != "" {
				entries = append(entries, indexEntry{
					DisplayName: displayName,
					Description: fositeClient.GetDescription(),
					EntryURL:    entryURL,
				})
			}
		}
	}

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
