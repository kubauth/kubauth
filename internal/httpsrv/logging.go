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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
)

// responseWriter wraps http.ResponseWriter to capture response details
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
	size       int64
}

// newResponseWriter creates a new response writer wrapper
func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		statusCode:     200, // default status code
		body:           new(bytes.Buffer),
	}
}

// Write captures the response body and calculates size
func (rw *responseWriter) Write(b []byte) (int, error) {
	// Write to the actual response
	n, err := rw.ResponseWriter.Write(b)

	// Capture for logging (limit size to prevent memory issues)
	if rw.body.Len() < 4096 { // limit to 4KB for logging
		rw.body.Write(b[:n])
	}

	rw.size += int64(n)
	return n, err
}

// WriteHeader captures the status code
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

var globalExchangeCount int64 = 0

type requestLog struct {
	Id            int64                  `yaml:"id" json:"id"`
	Method        string                 `yaml:"method" json:"method"`
	Path          string                 `yaml:"path" json:"path"`
	RawQuery      string                 `yaml:"rawQuery" json:"rawQuery"`
	BodySize      int64                  `yaml:"bodySize" json:"bodySize"`
	BodyAsString  string                 `yaml:"bodyAsString" json:"bodyAsString,omitempty"`
	BodyAsJson    map[string]interface{} `yaml:"bodyAsJson" json:"bodyAsJson,omitempty"`
	RemoteAddr    string                 `yaml:"remoteAddr" json:"remoteAddr"`
	UserAgent     string                 `yaml:"userAgent" json:"userAgent"`
	Referer       string                 `yaml:"referer" json:"referer"`
	Host          string                 `yaml:"host" json:"host"`
	ContentType   string                 `yaml:"contentType" json:"contentType"`
	ContentLength int64                  `yaml:"contentLength" json:"contentLength"`
	Header        http.Header            `yaml:"header" json:"header"`
	Cookies       []*http.Cookie         `yaml:"cookies" json:"cookies"`
}

type responseLog struct {
	Id           int64                  `yaml:"id" json:"id"`
	StatusCode   int                    `yaml:"statusCode" json:"statusCode"`
	ResponseSize int64                  `yaml:"responseSize" json:"responseSize"`
	Duration     time.Duration          `yaml:"duration" json:"duration"`
	Headers      http.Header            `yaml:"headers" json:"headers"`
	ContentType  string                 `yaml:"contentType" json:"contentType"`
	BodyAsString string                 `yaml:"bodyAsString" json:"bodyAsString,omitempty"`
	BodyAsJson   map[string]interface{} `yaml:"bodyAsJson" json:"bodyAsJson,omitempty"`
}

// LoggingMiddleware wraps an HTTP handler to log request and response details
// level == 1: Short info message
// level == 2: long info message
// level >= 3: full dump
func LoggingMiddleware(next http.Handler, level int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Get logger from context
		logger := logr.FromContextAsSlogLogger(r.Context())

		// Read and capture request body (if present)
		var requestBody []byte
		var requestBodySize int64
		if r.Body != nil {
			requestBody, _ = io.ReadAll(r.Body)
			requestBodySize = int64(len(requestBody))
			// Restore the body for the next handler
			r.Body = io.NopCloser(bytes.NewBuffer(requestBody))
		}

		// Log request information
		if logger != nil && level == 1 {
			logger.Info("HTTP Request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("raw_query", r.URL.RawQuery),
			)
		} else if logger != nil && level == 2 {
			logger.Info("HTTP Request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("raw_query", r.URL.RawQuery),
				slog.String("remote_addr", r.RemoteAddr),
				slog.String("user_agent", r.UserAgent()),
				slog.String("host", r.Host),
				slog.String("referer", r.Referer()),
				slog.Int64("content_length", r.ContentLength),
				slog.Int64("request_body_size", requestBodySize),
				slog.String("content_type", r.Header.Get("Content-Type")),
				slog.Any("request_headers", r.Header),
				slog.String("request_body", getSafeBodyString(requestBody)),
			)
		} else if level >= 3 {
			reqLog := &requestLog{
				Id:            atomic.AddInt64(&globalExchangeCount, 1),
				Method:        r.Method,
				Path:          r.URL.Path,
				RawQuery:      r.URL.RawQuery,
				BodySize:      requestBodySize,
				RemoteAddr:    r.RemoteAddr,
				UserAgent:     r.UserAgent(),
				Referer:       r.Referer(),
				Host:          r.Host,
				ContentType:   r.Header.Get("Content-Type"),
				ContentLength: r.ContentLength,
				Header:        r.Header,
				Cookies:       r.Cookies(),
			}
			if strings.HasPrefix(reqLog.ContentType, "application/json") {
				err := json.Unmarshal(requestBody, &reqLog.BodyAsJson)
				if err != nil {
					fmt.Printf("Error unmarshalling request body: %s\n", err.Error())
					reqLog.BodyAsString = getSafeBodyString(requestBody)
				}
			} else {
				reqLog.BodyAsString = getSafeBodyString(requestBody)
			}
			fmt.Println()
			reqJson, err := json.MarshalIndent(reqLog, "", "  ")
			if err != nil {
				fmt.Printf("\nERROR marshalling request log to json: %v\n", err)
			} else {
				fmt.Printf("-----------> REQUEST\n")
				fmt.Println(string(reqJson))
			}
		}

		// Wrap the response writer to capture response details
		rw := newResponseWriter(w)

		// Call the next handler
		next.ServeHTTP(rw, r)

		// Calculate duration
		duration := time.Since(start)

		// Log response information
		if logger != nil && level == 1 {
			logger.Info("HTTP Response",
				slog.Int("status_code", rw.statusCode),
				slog.Int64("response_size", rw.size),
			)
		} else if logger != nil && level == 2 {
			logger.Info("HTTP Response",
				slog.Int("status_code", rw.statusCode),
				slog.Int64("response_size", rw.size),
				slog.Duration("duration", duration),
				slog.Any("response_headers", w.Header()),
				slog.String("response_body", getSafeBodyString(rw.body.Bytes())),
			)
		} else if level >= 3 {
			respLog := &responseLog{
				Id:           atomic.AddInt64(&globalExchangeCount, 1),
				StatusCode:   rw.statusCode,
				ResponseSize: rw.size,
				Duration:     duration,
				Headers:      rw.Header(),
			}
			respLog.ContentType = respLog.Headers.Get("Content-Type")

			responseBody := rw.body.Bytes()
			if strings.HasPrefix(respLog.ContentType, "application/json") {
				err := json.Unmarshal(responseBody, &respLog.BodyAsJson)
				if err != nil {
					fmt.Printf("Error unmarshalling response body: %s\n", err.Error())
					respLog.BodyAsString = getSafeBodyString(responseBody)
				}
			} else {
				respLog.BodyAsString = getSafeBodyString(responseBody)
			}
			respJson, err := json.MarshalIndent(respLog, "", "  ")
			if err != nil {
				fmt.Printf("\nERROR marshalling response to json: %v\n", err)
			} else {
				fmt.Printf("<----------- RESPONSE\n")
				fmt.Println(string(respJson))
			}

		}
	})
}

// getSafeBodyString returns a safe string representation of the body
// Truncates long bodies and handles binary content
func getSafeBodyString(body []byte) string {
	if len(body) == 0 {
		return ""
	}

	// Check if it's likely binary content
	if !isPrintable(body) {
		return "[binary content]"
	}

	// Truncate if too long
	const maxBodyLogSize = 192
	if len(body) > maxBodyLogSize {
		return string(body[:maxBodyLogSize]) + "... [truncated]"
	}

	return string(body)
}

// isPrintable checks if the byte slice contains mostly printable characters
func isPrintable(data []byte) bool {
	if len(data) == 0 {
		return true
	}

	printableCount := 0
	for _, b := range data {
		if (b >= 32 && b <= 126) || b == '\n' || b == '\r' || b == '\t' {
			printableCount++
		}
	}

	// Consider it printable if at least 80% of characters are printable
	return float64(printableCount)/float64(len(data)) >= 0.8
}

// formatDuration formats duration in a human-readable way
func formatDuration(d time.Duration) string {
	if d < time.Microsecond {
		return d.String()
	}
	if d < time.Millisecond {
		return d.Truncate(time.Microsecond).String()
	}
	if d < time.Second {
		return d.Truncate(time.Millisecond).String()
	}
	return d.Truncate(time.Millisecond).String()
}
