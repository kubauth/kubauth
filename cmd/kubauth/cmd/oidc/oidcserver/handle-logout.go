package oidcserver

import (
	"fmt"
	"net/http"

	"github.com/go-logr/logr"
)

// Handle SsoSession logout
func (s *OIDCServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := logr.FromContextAsSlogLogger(ctx)

	if err := s.SessionManager.Destroy(ctx); err != nil {
		logger.Error("failed to destroy session", "error", err, "errType", fmt.Sprintf("%T", err))
		//http.Error(w, "internal error", http.StatusInternalServerError)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
