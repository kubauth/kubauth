/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package audit

import (
	"bytes"
	"context"
	"errors"
	"io"
	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// helpers ----------------------------------------------------------------

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newFakeClient returns a controller-runtime fake client wired with the
// kubauth v1alpha1 scheme and the supplied seed objects. Sub-tests use
// this to build deterministic LoginAttempt fixtures without standing up
// a real apiserver.
func newFakeClient(t *testing.T, seed ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := kubauthv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(seed...).
		Build()
}

func loginAttempt(name, ns string, when time.Time) *kubauthv1alpha1.LoginAttempt {
	return &kubauthv1alpha1.LoginAttempt{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: kubauthv1alpha1.LoginAttemptSpec{
			When: metav1.NewTime(when),
			User: kubauthv1alpha1.LoginAttemptUser{Login: "alice"},
		},
	}
}

// withAuditParams sets the global audit params for the duration of the
// test, restoring the previous values on cleanup. Required because
// cleanupAudit reads them directly (no DI) — keeping tests hermetic
// without changing the production signature.
func withAuditParams(t *testing.T, ns string, lifetime time.Duration) {
	t.Helper()
	prevNs := auditParams.namespace
	prevLifetime := auditParams.recordLifetime
	auditParams.namespace = ns
	auditParams.recordLifetime = lifetime
	t.Cleanup(func() {
		auditParams.namespace = prevNs
		auditParams.recordLifetime = prevLifetime
	})
}

func listAttempts(t *testing.T, c client.Client, ns string) []string {
	t.Helper()
	var list kubauthv1alpha1.LoginAttemptList
	if err := c.List(context.Background(), &list, client.InNamespace(ns)); err != nil {
		t.Fatalf("list: %v", err)
	}
	out := make([]string, 0, len(list.Items))
	for _, a := range list.Items {
		out = append(out, a.Name)
	}
	return out
}

// tests ------------------------------------------------------------------

func TestCleanupAudit_DeletesOnlyExpired(t *testing.T) {
	ns := "kubauth-system"
	withAuditParams(t, ns, time.Hour) // lifetime = 1h

	now := time.Now()
	c := newFakeClient(t,
		loginAttempt("old-1", ns, now.Add(-2*time.Hour)),    // expired
		loginAttempt("old-2", ns, now.Add(-90*time.Minute)), // expired
		loginAttempt("fresh", ns, now.Add(-5*time.Minute)),  // kept
	)

	cleanupAudit(context.Background(), c, discardLogger())

	got := listAttempts(t, c, ns)
	if len(got) != 1 || got[0] != "fresh" {
		t.Errorf("expected only 'fresh' to remain, got %v", got)
	}
}

func TestCleanupAudit_NoExpiredKeepsAll(t *testing.T) {
	ns := "kubauth-system"
	withAuditParams(t, ns, time.Hour)

	now := time.Now()
	c := newFakeClient(t,
		loginAttempt("a", ns, now.Add(-10*time.Minute)),
		loginAttempt("b", ns, now.Add(-30*time.Minute)),
	)

	cleanupAudit(context.Background(), c, discardLogger())

	got := listAttempts(t, c, ns)
	if len(got) != 2 {
		t.Errorf("expected both records to remain, got %v", got)
	}
}

func TestCleanupAudit_AllExpiredDeletesAll(t *testing.T) {
	ns := "kubauth-system"
	withAuditParams(t, ns, time.Minute) // very short lifetime

	now := time.Now()
	c := newFakeClient(t,
		loginAttempt("a", ns, now.Add(-1*time.Hour)),
		loginAttempt("b", ns, now.Add(-2*time.Hour)),
		loginAttempt("c", ns, now.Add(-30*time.Minute)),
	)

	cleanupAudit(context.Background(), c, discardLogger())

	got := listAttempts(t, c, ns)
	if len(got) != 0 {
		t.Errorf("expected all records deleted, got %v", got)
	}
}

func TestCleanupAudit_RespectsNamespace(t *testing.T) {
	// cleanupAudit must only touch records in auditParams.namespace —
	// LoginAttempts in other namespaces (multi-tenant kubauth deploys)
	// must not be touched.
	target := "ns-target"
	other := "ns-other"
	withAuditParams(t, target, time.Hour)

	now := time.Now()
	c := newFakeClient(t,
		loginAttempt("expired-target", target, now.Add(-2*time.Hour)),
		loginAttempt("expired-other", other, now.Add(-2*time.Hour)),
	)

	cleanupAudit(context.Background(), c, discardLogger())

	if got := listAttempts(t, c, target); len(got) != 0 {
		t.Errorf("target namespace not cleaned: %v", got)
	}
	if got := listAttempts(t, c, other); len(got) != 1 || got[0] != "expired-other" {
		t.Errorf("other namespace should be untouched, got %v", got)
	}
}

func TestCleanupAudit_EmptyListIsNoOp(t *testing.T) {
	ns := "kubauth-system"
	withAuditParams(t, ns, time.Hour)

	c := newFakeClient(t)

	// Should not panic, should not error.
	cleanupAudit(context.Background(), c, discardLogger())

	if got := listAttempts(t, c, ns); len(got) != 0 {
		t.Errorf("expected empty list, got %v", got)
	}
}

// failure tolerance: List/Delete errors must not crash the cleaner -------

// safeBuf is an io.Writer safe for the (single-goroutine here, but
// belt-and-suspenders) slog handler to write into while a test reads it.
type safeBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// capturingLogger returns a slog.Logger writing into buf, so a test can
// assert on the structured fields cleanupAudit logs (e.g. deletedCount,
// errorCount) which are otherwise not externally observable.
func capturingLogger(buf io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestCleanupAudit_ListErrorIsSafeNoOp(t *testing.T) {
	// SECURITY/robustness: a List failure (apiserver hiccup, RBAC) must be
	// a safe no-op: zero deletions, no panic, and the records left intact.
	// Deleting on a failed list would be data loss against a partial/empty
	// view; here we assert nothing is deleted at all.
	ns := "kubauth-system"
	withAuditParams(t, ns, time.Minute) // everything below is "expired"

	now := time.Now()
	seeded := newFakeClient(t,
		loginAttempt("old-1", ns, now.Add(-2*time.Hour)),
		loginAttempt("old-2", ns, now.Add(-3*time.Hour)),
	)
	listErr := errors.New("list boom")
	c := interceptor.NewClient(seeded.(client.WithWatch), interceptor.Funcs{
		List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
			return listErr
		},
	})

	var buf safeBuf
	// Must not panic despite the failing List.
	cleanupAudit(context.Background(), c, capturingLogger(&buf))

	// Records survive: verify directly against the underlying client whose
	// List still works (the interceptor only wraps `c`).
	if got := listAttempts(t, seeded, ns); len(got) != 2 {
		t.Errorf("List error must delete nothing, got survivors=%v", got)
	}
	logs := buf.String()
	if !strings.Contains(logs, "Failed to list login records for cleanup") {
		t.Errorf("expected the list-failure to be logged, logs=%q", logs)
	}
	// And it returned early: no "cleanup completed" summary line.
	if strings.Contains(logs, "cleanup completed") {
		t.Errorf("List error path must return before the completion summary, logs=%q", logs)
	}
}

func TestCleanupAudit_DeleteErrorIsToleratedAndTallied(t *testing.T) {
	// Robustness: a Delete failure on one expired record must NOT abort the
	// run. The cleaner continues, deletes the records it can, tolerates the
	// error (no panic, normal return) and tallies it as errorCount=1.
	ns := "kubauth-system"
	withAuditParams(t, ns, time.Minute) // all three records are expired

	now := time.Now()
	seeded := newFakeClient(t,
		loginAttempt("boom", ns, now.Add(-2*time.Hour)),    // Delete will fail
		loginAttempt("ok-1", ns, now.Add(-3*time.Hour)),    // deletable
		loginAttempt("ok-2", ns, now.Add(-90*time.Minute)), // deletable
	)
	delErr := errors.New("delete boom")
	c := interceptor.NewClient(seeded.(client.WithWatch), interceptor.Funcs{
		Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if obj.GetName() == "boom" {
				return delErr
			}
			return cl.Delete(ctx, obj, opts...) // delegate: actually delete the others
		},
	})

	var buf safeBuf
	// Must not panic, must return normally despite the Delete error.
	cleanupAudit(context.Background(), c, capturingLogger(&buf))

	// "boom" survives (its delete failed), the two deletable ones are gone:
	// proof that the loop CONTINUED past the failing record.
	got := listAttempts(t, seeded, ns)
	if len(got) != 1 || got[0] != "boom" {
		t.Errorf("expected only 'boom' to survive a tolerated delete error, got %v", got)
	}
	logs := buf.String()
	// The error is tallied (errorCount=1) and 2 deletions succeeded.
	if !strings.Contains(logs, "errorCount=1") {
		t.Errorf("delete error should be tallied as errorCount=1, logs=%q", logs)
	}
	if !strings.Contains(logs, "deletedCount=2") {
		t.Errorf("cleaner should have deleted the other 2 records, logs=%q", logs)
	}
	if !strings.Contains(logs, "Failed to delete expired loginAttempt record") {
		t.Errorf("the per-record delete failure should be logged, logs=%q", logs)
	}
}
