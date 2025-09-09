package handlers

import (
	"net/http"
	"os"
)

func FaviconHandler(iconPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile(iconPath)
		if err != nil {
			http.Error(w, "Favicon not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "image/x-icon")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})
}
