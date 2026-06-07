/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package sessionstore

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// testCtx returns a context wired with a discard slog logger — required
// by KubeSsoStore methods, which call `logr.FromContextAsSlogLogger(ctx)`
// and panic on nil. Replaces plain `context.Background()` everywhere
// in this file.
func testCtx() context.Context {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return logr.NewContextWithSlogLogger(context.Background(), logger)
}

// helpers ----------------------------------------------------------------

const testNS = "kubauth-system"

func newStore(t *testing.T, seed ...client.Object) (*KubeSsoStore, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := kubauthv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(seed...).Build()
	return NewKubeSsoStore(c, testNS), c
}

func envelopeBytes(t *testing.T, login string, claims map[string]interface{}, fullName string) []byte {
	t.Helper()
	env := sessionEnvelope{
		Deadline: time.Now().Add(time.Hour),
		Values: map[string]interface{}{
			"ssoUser": map[string]interface{}{
				"Login":    login,
				"Claims":   claims,
				"FullName": fullName,
			},
		},
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return b
}

// CommitCtx --------------------------------------------------------------

func TestCommitCtx_CreatesSsoSessionWithMirroredFields(t *testing.T) {
	store, c := newStore(t)
	ctx := testCtx()
	expiry := time.Now().Add(2 * time.Hour)

	if err := store.CommitCtx(ctx, "tok-1", envelopeBytes(t, "alice", map[string]interface{}{"sub": "alice"}, "Alice Wonderland"), expiry); err != nil {
		t.Fatalf("CommitCtx: %v", err)
	}

	var got kubauthv1alpha1.SsoSession
	if err := c.Get(ctx, types.NamespacedName{Namespace: testNS, Name: encodeName("tok-1")}, &got); err != nil {
		t.Fatalf("get created session: %v", err)
	}
	if got.Spec.Login != "alice" {
		t.Errorf("login mirrored: got %q", got.Spec.Login)
	}
	if got.Spec.FullName != "Alice Wonderland" {
		t.Errorf("fullName mirrored: got %q", got.Spec.FullName)
	}
	if got.Spec.WebToken != "tok-1" {
		t.Errorf("webToken mirrored: got %q", got.Spec.WebToken)
	}
	if got.Annotations[annotationRawSession] == "" {
		t.Error("raw session annotation must be set")
	}
}

func TestCommitCtx_EmptyLoginSkipsStore(t *testing.T) {
	// `extractUser` returning "" login → CommitCtx returns nil without
	// creating anything. Useful for unauthenticated browser sessions.
	store, c := newStore(t)
	ctx := testCtx()

	// Envelope with Values containing no recognisable user.
	env := sessionEnvelope{Values: map[string]interface{}{"foo": "bar"}}
	b, _ := json.Marshal(env)

	if err := store.CommitCtx(ctx, "tok-empty", b, time.Now()); err != nil {
		t.Fatalf("CommitCtx on empty user: %v", err)
	}

	var list kubauthv1alpha1.SsoSessionList
	_ = c.List(ctx, &list)
	if len(list.Items) != 0 {
		t.Errorf("no session should have been created, got %d", len(list.Items))
	}
}

func TestCommitCtx_UpdatesExisting(t *testing.T) {
	// First commit creates; second commit on the same token updates
	// the same SsoSession object (same name, no duplicate created).
	store, c := newStore(t)
	ctx := testCtx()

	if err := store.CommitCtx(ctx, "tok-2", envelopeBytes(t, "alice", nil, "Alice"), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	if err := store.CommitCtx(ctx, "tok-2", envelopeBytes(t, "alice", nil, "Alice Updated"), time.Now().Add(2*time.Hour)); err != nil {
		t.Fatalf("second commit: %v", err)
	}

	var list kubauthv1alpha1.SsoSessionList
	if err := c.List(ctx, &list); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("expected exactly 1 session after update, got %d", len(list.Items))
	}
	if list.Items[0].Spec.FullName != "Alice Updated" {
		t.Errorf("update didn't propagate: %q", list.Items[0].Spec.FullName)
	}
}

func TestCommitCtx_InvalidJSONErrors(t *testing.T) {
	store, _ := newStore(t)
	if err := store.CommitCtx(testCtx(), "tok-bad", []byte("{not json"), time.Now()); err == nil {
		t.Error("expected error on invalid JSON")
	}
}

// FindCtx ----------------------------------------------------------------

func TestFindCtx_RoundTripPreservesRawBytes(t *testing.T) {
	store, _ := newStore(t)
	ctx := testCtx()
	raw := envelopeBytes(t, "alice", nil, "Alice")

	if err := store.CommitCtx(ctx, "tok-rt", raw, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, found, err := store.FindCtx(ctx, "tok-rt")
	if err != nil {
		t.Fatalf("FindCtx: %v", err)
	}
	if !found {
		t.Fatal("expected found=true")
	}
	if !reflect.DeepEqual(got, raw) {
		t.Errorf("raw bytes not preserved\n got:  %s\n want: %s", got, raw)
	}
}

func TestFindCtx_MissingTokenReturnsNotFound(t *testing.T) {
	store, _ := newStore(t)
	got, found, err := store.FindCtx(testCtx(), "no-such-token")
	if err != nil {
		t.Fatalf("FindCtx of missing token should not error: %v", err)
	}
	if found {
		t.Error("expected found=false")
	}
	if got != nil {
		t.Errorf("expected nil bytes, got %v", got)
	}
}

func TestFindCtx_SessionWithoutAnnotationReturnsNotFound(t *testing.T) {
	// An SsoSession that exists but lacks the kubauth annotation —
	// could happen if someone hand-creates a CRD. Should treat as
	// "no session" so the SCS layer creates a fresh one.
	store, _ := newStore(t, &kubauthv1alpha1.SsoSession{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNS,
			Name:      encodeName("tok-bare"),
			// no annotations at all
		},
	})
	_, found, err := store.FindCtx(testCtx(), "tok-bare")
	if err != nil {
		t.Fatalf("FindCtx: %v", err)
	}
	if found {
		t.Error("session without raw-session annotation should be treated as not-found")
	}
}

// DeleteCtx --------------------------------------------------------------

func TestDeleteCtx_RemovesSession(t *testing.T) {
	store, c := newStore(t)
	ctx := testCtx()

	_ = store.CommitCtx(ctx, "tok-del", envelopeBytes(t, "alice", nil, ""), time.Now().Add(time.Hour))
	if err := store.DeleteCtx(ctx, "tok-del"); err != nil {
		t.Fatalf("DeleteCtx: %v", err)
	}

	var got kubauthv1alpha1.SsoSession
	err := c.Get(ctx, types.NamespacedName{Namespace: testNS, Name: encodeName("tok-del")}, &got)
	if err == nil {
		t.Error("expected NotFound after Delete, got existing session")
	}
}

// AllCtx -----------------------------------------------------------------

func TestAllCtx_ReturnsWebTokensInNamespace(t *testing.T) {
	store, _ := newStore(t)
	ctx := testCtx()
	for _, tok := range []string{"tok-A", "tok-B", "tok-C"} {
		_ = store.CommitCtx(ctx, tok, envelopeBytes(t, "alice", nil, ""), time.Now().Add(time.Hour))
	}
	got, err := store.AllCtx(ctx)
	if err != nil {
		t.Fatalf("AllCtx: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("expected 3 tokens, got %d: %v", len(got), got)
	}
	have := map[string]bool{}
	for _, t := range got {
		have[t] = true
	}
	for _, want := range []string{"tok-A", "tok-B", "tok-C"} {
		if !have[want] {
			t.Errorf("missing token: %q", want)
		}
	}
}

func TestAllCtx_EmptyNamespaceReturnsEmpty(t *testing.T) {
	store, _ := newStore(t)
	got, err := store.AllCtx(testCtx())
	if err != nil {
		t.Fatalf("AllCtx: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty list, got %v", got)
	}
}

func TestAllCtx_SkipsSessionsWithoutWebToken(t *testing.T) {
	// Sessions without spec.webToken (older or hand-crafted) shouldn't
	// surface in All() — there's no usable token to return.
	store, _ := newStore(t, &kubauthv1alpha1.SsoSession{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNS,
			Name:      "without-token",
		},
		Spec: kubauthv1alpha1.SsoSessionSpec{
			Login:    "alice",
			Deadline: metav1.NewTime(time.Now().Add(time.Hour)),
			Expiry:   metav1.NewTime(time.Now().Add(time.Hour)),
			// no WebToken
		},
	})
	got, err := store.AllCtx(testCtx())
	if err != nil {
		t.Fatalf("AllCtx: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty list (the session has no webToken), got %v", got)
	}
}

// extractUser ------------------------------------------------------------

func TestExtractUser_PrefersSsoUserKey(t *testing.T) {
	values := map[string]interface{}{
		"ssoUser": map[string]interface{}{"Login": "alice", "FullName": "Alice"},
		"other":   map[string]interface{}{"Login": "bob"},
	}
	login, _, fullName := extractUser(values)
	if login != "alice" || fullName != "Alice" {
		t.Errorf("ssoUser key not preferred: login=%q fullName=%q", login, fullName)
	}
}

func TestExtractUser_FallbackToFirstUserShape(t *testing.T) {
	values := map[string]interface{}{
		"some-key": map[string]interface{}{"Login": "carol", "FullName": "Carol"},
	}
	login, _, fullName := extractUser(values)
	if login != "carol" || fullName != "Carol" {
		t.Errorf("fallback to first user-shape failed: login=%q fullName=%q", login, fullName)
	}
}

func TestExtractUser_LowerCaseFieldNames(t *testing.T) {
	// JSON-encoded sessions sometimes round-trip with lower-case
	// field names. Helper accepts both.
	values := map[string]interface{}{
		"ssoUser": map[string]interface{}{
			"login":    "dan",
			"claims":   map[string]interface{}{"sub": "dan"},
			"fullName": "Dan",
		},
	}
	login, claims, fullName := extractUser(values)
	if login != "dan" || fullName != "Dan" || claims["sub"] != "dan" {
		t.Errorf("lower-case fallback failed: login=%q fullName=%q claims=%v", login, fullName, claims)
	}
}

func TestExtractUser_NilOrEmpty(t *testing.T) {
	if l, c, f := extractUser(nil); l != "" || c != nil || f != "" {
		t.Errorf("nil values should yield zeros, got %q/%v/%q", l, c, f)
	}
	if l, c, f := extractUser(map[string]interface{}{}); l != "" || c != nil || f != "" {
		t.Errorf("empty values should yield zeros, got %q/%v/%q", l, c, f)
	}
}

func TestExtractUser_UnrelatedShapeIgnored(t *testing.T) {
	// A value that's not a map[string]interface{} or doesn't have
	// Login/login is ignored (no panic, no false match).
	values := map[string]interface{}{
		"a": "not-a-map",
		"b": 42,
	}
	if l, _, _ := extractUser(values); l != "" {
		t.Errorf("non-user-shape values should yield empty login, got %q", l)
	}
}

// encodeName -------------------------------------------------------------

func TestEncodeName_DeterministicAndPrefixed(t *testing.T) {
	a := encodeName("tok-abc")
	b := encodeName("tok-abc")
	if a != b {
		t.Errorf("encodeName not deterministic: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, "h-") {
		t.Errorf("expected 'h-' prefix, got %q", a)
	}
	// SHA-256 hex = 64 chars; full name = 2 + 64 = 66.
	if len(a) != 66 {
		t.Errorf("expected length 66 (h- + 64 hex), got %d", len(a))
	}
}

func TestEncodeName_DifferentTokensYieldDifferentNames(t *testing.T) {
	if encodeName("a") == encodeName("b") {
		t.Error("different tokens should yield different names")
	}
}

func TestEncodeName_ProducesRFC1123CompliantName(t *testing.T) {
	// h- prefix + lowercase hex → all chars are RFC1123-compliant
	// (alphanumeric + -). Verify on a sample.
	got := encodeName("token-with-special!@#$%^&*()_+chars")
	for _, c := range got {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			t.Errorf("non-RFC1123 char in encoded name: %q", c)
		}
	}
}
