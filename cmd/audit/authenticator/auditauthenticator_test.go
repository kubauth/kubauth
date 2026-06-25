/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package authenticator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"
	"kubauth/internal/httpclient"
	"kubauth/internal/proto"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const testNS = "kubauth-ns"

func testCtx() context.Context {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return logr.NewContextWithSlogLogger(context.Background(), logger)
}

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := kubauthv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	return s
}

// idpServer answers the v1/identity exchange with resp.
func idpServer(t *testing.T, resp proto.IdentityResponse) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func listAttempts(t *testing.T, c client.Client) []kubauthv1alpha1.LoginAttempt {
	t.Helper()
	var list kubauthv1alpha1.LoginAttemptList
	if err := c.List(context.Background(), &list, client.InNamespace(testNS)); err != nil {
		t.Fatalf("List: %v", err)
	}
	return list.Items
}

func TestAuthenticate_PassThroughAndCreatesRecord(t *testing.T) {
	uid := 501
	resp := proto.IdentityResponse{
		Status:    proto.PasswordChecked,
		Authority: "ldap",
		User: proto.User{
			Login:  "alice",
			Name:   "Alice",
			Uid:    &uid,
			Emails: []string{"a@corp.io"},
			Groups: []string{"dev"},
			Claims: map[string]interface{}{"team": "blue"},
		},
	}
	fc := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	a, err := New(&httpclient.Config{BaseURL: idpServer(t, resp).URL}, fc, testNS)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := a.Authenticate(testCtx(), &proto.IdentityRequest{Login: "alice", Password: "pw"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	// Pass-through of the upstream response.
	if got.User.Login != "alice" || got.Status != proto.PasswordChecked {
		t.Errorf("response = {login:%q status:%q}, want {alice passwordChecked}", got.User.Login, got.Status)
	}
	// A LoginAttempt record was written.
	items := listAttempts(t, fc)
	if len(items) != 1 {
		t.Fatalf("LoginAttempt count = %d, want 1", len(items))
	}
	la := items[0]
	if la.Spec.User.Login != "alice" {
		t.Errorf("record login = %q, want alice", la.Spec.User.Login)
	}
	if la.Spec.Status != string(proto.PasswordChecked) {
		t.Errorf("record status = %q, want passwordChecked", la.Spec.Status)
	}
	if la.Spec.Authority != "ldap" {
		t.Errorf("record authority = %q, want ldap", la.Spec.Authority)
	}
	if la.Labels["kubauth.kubotal.io/login"] != "alice" {
		t.Errorf("record login label = %q, want alice", la.Labels["kubauth.kubotal.io/login"])
	}
	if la.Spec.User.Claims == nil {
		t.Fatal("record claims JSON not stored")
	}
	var gotClaims map[string]interface{}
	if err := json.Unmarshal(la.Spec.User.Claims.Raw, &gotClaims); err != nil {
		t.Fatalf("record claims JSON unmarshal: %v", err)
	}
	if gotClaims["team"] != "blue" {
		t.Errorf("record claims = %v, want team=blue", gotClaims)
	}
}

func TestAuthenticate_FailOpenWhenRecordCreationFails(t *testing.T) {
	resp := proto.IdentityResponse{
		Status: proto.PasswordChecked,
		User:   proto.User{Login: "bob", Claims: map[string]interface{}{}},
	}
	fc := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.CreateOption) error {
				return errors.New("apiserver down")
			},
		}).
		Build()
	a, err := New(&httpclient.Config{BaseURL: idpServer(t, resp).URL}, fc, testNS)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := a.Authenticate(testCtx(), &proto.IdentityRequest{Login: "bob", Password: "pw"})
	if err != nil {
		t.Fatalf("audit-record failure must NOT fail authentication (fail-open): %v", err)
	}
	if got == nil || got.User.Login != "bob" {
		t.Errorf("response = %+v, want authenticated bob despite record failure", got)
	}
}

func TestAuthenticate_HTTPErrorPropagatesAndWritesNoRecord(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	fc := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	a, err := New(&httpclient.Config{BaseURL: srv.URL}, fc, testNS)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := a.Authenticate(testCtx(), &proto.IdentityRequest{Login: "x", Password: "pw"})
	if err == nil {
		t.Fatal("upstream HTTP failure must propagate as an error")
	}
	if got != nil {
		t.Errorf("want nil response on HTTP failure, got %+v", got)
	}
	if n := len(listAttempts(t, fc)); n != 0 {
		t.Errorf("LoginAttempt count = %d, want 0 (no record on failed exchange)", n)
	}
}

func TestAuthenticate_MapsDetails(t *testing.T) {
	uid, tuid := 7, 8
	resp := proto.IdentityResponse{
		Status: proto.PasswordChecked,
		User:   proto.User{Login: "carol", Claims: map[string]interface{}{}},
		Details: []*proto.UserDetail{{
			Provider: proto.ProviderSpec{Name: "ldap", GroupAuthority: true, ClaimAuthority: true},
			User:     proto.User{Login: "carol", Uid: &uid, Name: "Carol", Groups: []string{"g1"}, Emails: []string{"c@corp.io"}, Claims: map[string]interface{}{"k": "v"}},
			Status:   proto.PasswordChecked,
			Translated: proto.Translated{
				Groups: []string{"ext:g1"},
				Uid:    &tuid,
				Claims: map[string]interface{}{"tk": "tv"},
			},
		}},
	}
	fc := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	a, err := New(&httpclient.Config{BaseURL: idpServer(t, resp).URL}, fc, testNS)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := a.Authenticate(testCtx(), &proto.IdentityRequest{Login: "carol", Password: "pw"}); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	items := listAttempts(t, fc)
	if len(items) != 1 {
		t.Fatalf("LoginAttempt count = %d, want 1", len(items))
	}
	la := items[0]
	if len(la.Spec.Details) != 1 {
		t.Fatalf("details count = %d, want 1", len(la.Spec.Details))
	}
	d := la.Spec.Details[0]
	if d.Provider.Name != "ldap" {
		t.Errorf("detail provider = %q, want ldap", d.Provider.Name)
	}
	if d.User.Login != "carol" {
		t.Errorf("detail user = %q, want carol", d.User.Login)
	}
	if d.Status != string(proto.PasswordChecked) {
		t.Errorf("detail status = %q, want passwordChecked", d.Status)
	}
	if !slices.Equal(d.Translated.Groups, []string{"ext:g1"}) {
		t.Errorf("detail translated groups = %v, want [ext:g1]", d.Translated.Groups)
	}
	if d.Translated.Uid == nil || *d.Translated.Uid != tuid {
		t.Errorf("detail translated uid = %v, want %d", d.Translated.Uid, tuid)
	}
}
