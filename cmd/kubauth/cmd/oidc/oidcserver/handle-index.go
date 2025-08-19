package oidcserver

import (
	"html/template"
	"net/http"
	"path"

	"kubauth/cmd/kubauth/cmd/oidc/oidcstorage"

	"github.com/go-logr/logr"
)

type indexEntry struct {
	Name        string
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
			name := fositeClient.GetName()
			entryURL := fositeClient.GetEntryURL()

			// Only include clients with both name and entryURL
			if name != "" && entryURL != "" {
				entries = append(entries, indexEntry{
					Name:        name,
					Description: fositeClient.GetDescription(),
					EntryURL:    entryURL,
				})
			}
		}
	}

	// Parse and execute template
	tmplPath := path.Join(s.Resources, "templates", "index.gohtml")
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		logger.Error("Failed to parse index template", "path", tmplPath, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Title   string
		Entries []indexEntry
	}{
		Title:   "Kubauth - Applications",
		Entries: entries,
	}

	if err := tmpl.Execute(w, data); err != nil {
		logger.Error("Failed to execute index template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}
