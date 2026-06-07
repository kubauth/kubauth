/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package httpclient

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// New() — URL validation -------------------------------------------------

func TestNew_RejectsMalformedURL(t *testing.T) {
	_, err := New(&Config{BaseURL: "://not-a-url"})
	if err == nil {
		t.Error("expected error on malformed URL")
	}
}

func TestNew_RejectsUnsupportedScheme(t *testing.T) {
	_, err := New(&Config{BaseURL: "ftp://example.org/"})
	if err == nil {
		t.Fatal("expected error on ftp:// scheme")
	}
	if !strings.Contains(err.Error(), "scheme") {
		t.Errorf("error should mention 'scheme', got %q", err.Error())
	}
}

func TestNew_AcceptsHTTPAndHTTPS(t *testing.T) {
	for _, base := range []string{"http://example.org", "https://example.org", "HTTP://example.org", "HTTPS://example.org"} {
		_, err := New(&Config{BaseURL: base})
		if err != nil {
			t.Errorf("unexpected error for %s: %v", base, err)
		}
	}
}

// New() — CA loading -----------------------------------------------------

func TestNew_RejectsEmptyPEMBundle(t *testing.T) {
	_, err := New(&Config{
		BaseURL:     "https://example.org",
		RootCaBytes: [][]byte{[]byte("")}, // empty entries are skipped, this should be fine
	})
	if err != nil {
		t.Errorf("empty PEM entries should be skipped silently, got %v", err)
	}
}

func TestNew_RejectsGarbagePEM(t *testing.T) {
	_, err := New(&Config{
		BaseURL:     "https://example.org",
		RootCaBytes: [][]byte{[]byte("not pem data at all")},
	})
	if err == nil {
		t.Fatal("expected error on garbage PEM")
	}
	if !strings.Contains(err.Error(), "PEM") && !strings.Contains(err.Error(), "CERTIFICATE") {
		t.Errorf("error should mention PEM/CERTIFICATE, got %q", err.Error())
	}
}

func TestNew_RejectsInvalidBase64(t *testing.T) {
	_, err := New(&Config{
		BaseURL:     "https://example.org",
		RootCaDatas: []string{"!!!not-base64!!!"},
	})
	if err == nil {
		t.Fatal("expected error on invalid base64")
	}
	if !strings.Contains(err.Error(), "base64") {
		t.Errorf("error should mention 'base64', got %q", err.Error())
	}
}

func TestNew_RejectsBase64ButNotPEM(t *testing.T) {
	// Valid base64, but the decoded bytes aren't PEM.
	garbage := base64.StdEncoding.EncodeToString([]byte("hello world, not pem"))
	_, err := New(&Config{
		BaseURL:     "https://example.org",
		RootCaDatas: []string{garbage},
	})
	if err == nil {
		t.Fatal("expected error when base64 decodes to non-PEM")
	}
}

func TestNew_RejectsCAFileNotFound(t *testing.T) {
	_, err := New(&Config{
		BaseURL:     "https://example.org",
		RootCaPaths: []string{"/no/such/ca/file/please.pem"},
	})
	if err == nil {
		t.Fatal("expected error on missing CA file")
	}
	if !strings.Contains(err.Error(), "CA file") {
		t.Errorf("error should mention 'CA file', got %q", err.Error())
	}
}

func TestNew_HTTPSchemeSkipsCASetup(t *testing.T) {
	// Plain http:// shouldn't try to load any CA — even invalid CA paths
	// should be ignored because no TLS is configured.
	_, err := New(&Config{
		BaseURL:     "http://example.org",
		RootCaPaths: []string{"/no/such/file.pem"}, // would error if validated
	})
	if err != nil {
		t.Errorf("plain http should skip CA validation, got %v", err)
	}
}

// appendCaFromPEM ---------------------------------------------------------

func TestAppendCaFromPEM_RejectsEmptyInput(t *testing.T) {
	pool := x509.NewCertPool()
	_, err := appendCaFromPEM(pool, []byte{})
	if err == nil {
		t.Error("expected error on empty PEM")
	}
}

func TestAppendCaFromPEM_RejectsNoCertificateBlock(t *testing.T) {
	pool := x509.NewCertPool()
	// Valid PEM structure but with a non-CERTIFICATE block type. Using
	// a fictional `KUBAUTH TEST BLOCK` type rather than `PRIVATE KEY`
	// so the literal doesn't trip secret-scanning hooks (gitleaks etc.)
	// during commit — same parser path either way (block.Type !=
	// "CERTIFICATE" ⇒ skipped ⇒ no subjects ⇒ error).
	pem := []byte("-----BEGIN KUBAUTH TEST BLOCK-----\nZm9v\n-----END KUBAUTH TEST BLOCK-----\n")
	_, err := appendCaFromPEM(pool, pem)
	if err == nil {
		t.Error("expected error when PEM has no CERTIFICATE blocks")
	}
}

// Do() — HTTP behaviour --------------------------------------------------

func newTestClient(t *testing.T, srv *httptest.Server, auth *HttpAuth) HttpClient {
	t.Helper()
	c, err := New(&Config{
		BaseURL:  srv.URL,
		HttpAuth: auth,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestDo_HappyPathReturns200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	c := newTestClient(t, srv, nil)

	resp, err := c.Do("GET", "/foo", "application/json", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestDo_401ReturnsUnauthorizedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, nil)

	_, err := c.Do("GET", "/", "application/json", nil)
	if err == nil {
		t.Fatal("expected UnauthorizedError")
	}
	var ue *UnauthorizedError
	if !errors.As(err, &ue) {
		t.Errorf("expected *UnauthorizedError, got %T: %v", err, err)
	}
}

func TestDo_404ReturnsNotFoundError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, nil)

	_, err := c.Do("GET", "/missing", "application/json", nil)
	if err == nil {
		t.Fatal("expected NotFoundError")
	}
	var nfe *NotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected *NotFoundError, got %T: %v", err, err)
	}
	if !strings.Contains(nfe.Error(), "/missing") {
		t.Errorf("NotFoundError should include the URL, got %q", nfe.Error())
	}
}

func TestDo_500ReturnsGenericError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, nil)

	_, err := c.Do("GET", "/", "application/json", nil)
	if err == nil {
		t.Fatal("expected error on 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention 500, got %q", err.Error())
	}
}

func TestDo_SetsContentTypeHeader(t *testing.T) {
	var seenCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenCT = r.Header.Get("Content-Type")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, nil)

	resp, err := c.Do("POST", "/", "application/x-www-form-urlencoded", strings.NewReader("a=1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if seenCT != "application/x-www-form-urlencoded" {
		t.Errorf("content-type not propagated: got %q", seenCT)
	}
}

func TestDo_BasicAuth(t *testing.T) {
	var seenUser, seenPass string
	var seenOK bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenUser, seenPass, seenOK = r.BasicAuth()
		w.WriteHeader(200)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, &HttpAuth{Login: "alice", Password: "s3cret"})

	resp, err := c.Do("GET", "/", "application/json", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if !seenOK || seenUser != "alice" || seenPass != "s3cret" {
		t.Errorf("basic auth not set: ok=%v user=%q pass=%q", seenOK, seenUser, seenPass)
	}
}

func TestDo_BearerToken(t *testing.T) {
	var seenAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, &HttpAuth{Token: "abc.def.ghi"})

	resp, err := c.Do("GET", "/", "application/json", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if seenAuth != "Bearer abc.def.ghi" {
		t.Errorf("expected 'Bearer abc.def.ghi', got %q", seenAuth)
	}
}

func TestDo_NoAuthSetIfNotConfigured(t *testing.T) {
	var seenAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, nil)

	resp, err := c.Do("GET", "/", "application/json", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if seenAuth != "" {
		t.Errorf("expected no Authorization header, got %q", seenAuth)
	}
}

func TestDo_JoinsBaseURLAndPath(t *testing.T) {
	var seenPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		w.WriteHeader(200)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, nil)

	resp, err := c.Do("GET", "/api/v1/users", "application/json", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if seenPath != "/api/v1/users" {
		t.Errorf("expected /api/v1/users, got %q", seenPath)
	}
}

func TestDo_ConnectionRefusedSurfacesAsError(t *testing.T) {
	// Bind a port, immediately close the server → next request gets refused.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	srv.Close() // server gone — its URL is a refused connection
	c := newTestClient(t, srv, nil)

	_, err := c.Do("GET", "/", "application/json", nil)
	if err == nil {
		t.Fatal("expected error on closed server")
	}
	if !strings.Contains(err.Error(), "http connection") {
		t.Errorf("error should mention 'http connection', got %q", err.Error())
	}
}

// Error types' Error() messages ------------------------------------------

func TestUnauthorizedError_Message(t *testing.T) {
	err := &UnauthorizedError{}
	if err.Error() != "Unauthorized" {
		t.Errorf("unexpected message: %q", err.Error())
	}
}

func TestNotFoundError_MessageIncludesURL(t *testing.T) {
	err := &NotFoundError{url: "https://example.org/nope"}
	if !strings.Contains(err.Error(), "https://example.org/nope") {
		t.Errorf("NotFoundError message should include URL, got %q", err.Error())
	}
}

// GetBaseHttpDotClient ---------------------------------------------------

func TestGetBaseHttpDotClient_ReturnsConfiguredClient(t *testing.T) {
	c, err := New(&Config{BaseURL: "http://example.org"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.GetBaseHttpDotClient() == nil {
		t.Error("GetBaseHttpDotClient returned nil")
	}
}
