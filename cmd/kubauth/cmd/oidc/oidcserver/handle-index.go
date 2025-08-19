package oidcserver

import (
	"net/http"

	"github.com/go-logr/logr"
)

// Handle SsoSession logout
func (s *OIDCServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_ = logr.FromContextAsSlogLogger(ctx)
}
