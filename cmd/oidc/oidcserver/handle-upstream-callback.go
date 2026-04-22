package oidcserver

import "net/http"

// Handle dedicated login endpoint for GET (render) and POST (authenticate)
func (s *OIDCServer) handleUpstreamCallback(w http.ResponseWriter, r *http.Request) {
	// TODO: Handle callback from upstream provider
}
