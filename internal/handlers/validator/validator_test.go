/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package validator

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"kubauth/internal/proto"

	"github.com/go-logr/logr"
)

func testCtx() context.Context {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return logr.NewContextWithSlogLogger(context.Background(), logger)
}

func TestOnlyGet_AllowsGET(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/identity", nil)
	if ok := (OnlyGetValidator{}).Validate(rec, req, &proto.IdentityRequest{}); !ok {
		t.Error("Validate(GET) = false, want true")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("code = %d, want 200 (nothing written for an allowed method)", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("an allowed method must not write a body, got %q", rec.Body.String())
	}
}

func TestOnlyGet_RejectsNonGET(t *testing.T) {
	// The reject path logs via the context logger, so the request must carry one.
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/v1/identity", nil).WithContext(testCtx())
		if ok := (OnlyGetValidator{}).Validate(rec, req, &proto.IdentityRequest{}); ok {
			t.Errorf("Validate(%s) = true, want false", method)
		}
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: code = %d, want 405", method, rec.Code)
		}
	}
}
