/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package audit

import (
	"context"
	"io"
	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"
	"log/slog"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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
		loginAttempt("old-1", ns, now.Add(-2*time.Hour)),  // expired
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
