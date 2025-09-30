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

package httpsrv

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/go-logr/logr"
)

// NotFoundHandler returns an HTTP handler that logs request information
// and responds with a 404 Not Found error
func NotFoundHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get logger from context
		logger := logr.FromContextAsSlogLogger(r.Context())
		if logger != nil {
			// Log request information as warning
			logger.Warn("404 Not Found",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("raw_query", r.URL.RawQuery),
				slog.String("remote_addr", r.RemoteAddr),
				slog.String("user_agent", r.UserAgent()),
				slog.String("host", r.Host),
				slog.String("referer", r.Referer()),
				slog.Any("headers", r.Header),
			)
		}
		// Write error response
		requestURL := &url.URL{
			Scheme:   getScheme(r),
			Host:     r.Host,
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
		}
		http.Error(w, fmt.Sprintf("The requested URL %s %s was not found on this server.", r.Method, requestURL.String()), http.StatusNotFound)
	}
}

// getScheme determines the scheme (http/https) from the request
func getScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}

	// Check for forwarded protocol headers
	if scheme := r.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}

	if scheme := r.Header.Get("X-Forwarded-Protocol"); scheme != "" {
		return scheme
	}

	// Check if forwarded for HTTPS
	if r.Header.Get("X-Forwarded-Ssl") == "on" {
		return "https"
	}

	return "http"
}
