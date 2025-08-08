package oidcserver

import (
	"encoding/json"
	"net/http"
)

// Handle userinfo endpoint
func (s *OIDCServer) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	// For simplicity, return basic user info
	userInfo := map[string]interface{}{
		"sub":   "user123",
		"name":  "John Doe",
		"email": "john.doe@example.com",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}
