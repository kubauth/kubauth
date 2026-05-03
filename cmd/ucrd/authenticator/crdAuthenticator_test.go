/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package authenticator

import (
	"context"
	"io"
	"log/slog"
	"testing"

	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"
	"kubauth/internal/proto"

	"github.com/go-logr/logr"
	"golang.org/x/crypto/bcrypt"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// helpers ----------------------------------------------------------------

const userNS = "kubauth-users"

// newAuthenticator returns a crdAuthenticator wired to a fake client
// pre-loaded with the supplied seed and the same `userkey` field index
// the production code (cmd/ucrd/ucrd.go) registers on the manager —
// without it, `client.MatchingFields{"userkey": login}` returns nothing.
func newAuthenticator(t *testing.T, seed ...client.Object) *crdAuthenticator {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := kubauthv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(seed...).
		WithIndex(&kubauthv1alpha1.GroupBinding{}, "userkey", func(o client.Object) []string {
			gb := o.(*kubauthv1alpha1.GroupBinding)
			return []string{gb.Spec.User}
		}).
		Build()
	return &crdAuthenticator{k8sClient: c, userNamespace: userNS}
}

func testCtx() context.Context {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return logr.NewContextWithSlogLogger(context.Background(), logger)
}

func mustHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return string(h)
}

func userObj(login string, modify func(*kubauthv1alpha1.User)) *kubauthv1alpha1.User {
	u := &kubauthv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Namespace: userNS, Name: login},
		Spec:       kubauthv1alpha1.UserSpec{Name: login},
	}
	if modify != nil {
		modify(u)
	}
	return u
}

func bindingObj(name, user, group string) *kubauthv1alpha1.GroupBinding {
	return &kubauthv1alpha1.GroupBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: userNS, Name: name},
		Spec:       kubauthv1alpha1.GroupBindingSpec{User: user, Group: group},
	}
}

func groupObj(name string, claimsJSON string) *kubauthv1alpha1.Group {
	g := &kubauthv1alpha1.Group{
		ObjectMeta: metav1.ObjectMeta{Namespace: userNS, Name: name},
	}
	if claimsJSON != "" {
		g.Spec.Claims = &apiextensionsv1.JSON{Raw: []byte(claimsJSON)}
	}
	return g
}

// tests ------------------------------------------------------------------

func TestAuthenticate_UserNotFound(t *testing.T) {
	a := newAuthenticator(t)
	resp, err := a.Authenticate(testCtx(), &proto.IdentityRequest{Login: "ghost"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp.Status != proto.UserNotFound {
		t.Errorf("expected UserNotFound, got %v", resp.Status)
	}
	if resp.User.Login != "ghost" {
		t.Errorf("response should echo login, got %q", resp.User.Login)
	}
}

func TestAuthenticate_PasswordMissing(t *testing.T) {
	// User exists but spec.passwordHash is empty — kubauth says
	// PasswordMissing (provider has nothing to check against).
	a := newAuthenticator(t, userObj("alice", nil))
	resp, err := a.Authenticate(testCtx(), &proto.IdentityRequest{Login: "alice", Password: "anything"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp.Status != proto.PasswordMissing {
		t.Errorf("expected PasswordMissing, got %v", resp.Status)
	}
}

func TestAuthenticate_PasswordUnchecked(t *testing.T) {
	// User has a hash, but request omits the password (e.g. an
	// upstream OIDC trust scenario). Status = PasswordUnchecked.
	a := newAuthenticator(t, userObj("alice", func(u *kubauthv1alpha1.User) {
		u.Spec.PasswordHash = mustHash(t, "secret")
	}))
	resp, err := a.Authenticate(testCtx(), &proto.IdentityRequest{Login: "alice", Password: ""})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp.Status != proto.PasswordUnchecked {
		t.Errorf("expected PasswordUnchecked, got %v", resp.Status)
	}
}

func TestAuthenticate_PasswordChecked(t *testing.T) {
	a := newAuthenticator(t, userObj("alice", func(u *kubauthv1alpha1.User) {
		u.Spec.PasswordHash = mustHash(t, "secret")
	}))
	resp, err := a.Authenticate(testCtx(), &proto.IdentityRequest{Login: "alice", Password: "secret"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp.Status != proto.PasswordChecked {
		t.Errorf("expected PasswordChecked, got %v", resp.Status)
	}
}

func TestAuthenticate_PasswordFail(t *testing.T) {
	a := newAuthenticator(t, userObj("alice", func(u *kubauthv1alpha1.User) {
		u.Spec.PasswordHash = mustHash(t, "secret")
	}))
	resp, err := a.Authenticate(testCtx(), &proto.IdentityRequest{Login: "alice", Password: "WRONG"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp.Status != proto.PasswordFail {
		t.Errorf("expected PasswordFail, got %v", resp.Status)
	}
}

func TestAuthenticate_DisabledUser(t *testing.T) {
	// Disabled flag overrides any password check.
	disabled := true
	a := newAuthenticator(t, userObj("alice", func(u *kubauthv1alpha1.User) {
		u.Spec.PasswordHash = mustHash(t, "secret")
		u.Spec.Disabled = &disabled
	}))
	resp, err := a.Authenticate(testCtx(), &proto.IdentityRequest{Login: "alice", Password: "secret"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp.Status != proto.Disabled {
		t.Errorf("expected Disabled, got %v", resp.Status)
	}
}

func TestAuthenticate_PopulatesUidNameEmails(t *testing.T) {
	uid := 1042
	a := newAuthenticator(t, userObj("alice", func(u *kubauthv1alpha1.User) {
		u.Spec.PasswordHash = mustHash(t, "secret")
		u.Spec.Uid = &uid
		u.Spec.Name = "Alice Wonderland"
		u.Spec.Emails = []string{"alice@example.org", "alice@personal.com"}
	}))
	resp, err := a.Authenticate(testCtx(), &proto.IdentityRequest{Login: "alice", Password: "secret"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp.User.Name != "Alice Wonderland" {
		t.Errorf("name not populated: %q", resp.User.Name)
	}
	if resp.User.Uid == nil || *resp.User.Uid != 1042 {
		t.Errorf("uid not populated: %v", resp.User.Uid)
	}
	if len(resp.User.Emails) != 2 || resp.User.Emails[0] != "alice@example.org" {
		t.Errorf("emails not populated: %v", resp.User.Emails)
	}
}

func TestAuthenticate_GroupsFromBindings(t *testing.T) {
	// Two GroupBindings for alice, alphabetically not sorted in the
	// fixture. The code sorts by group name → response groups are sorted.
	a := newAuthenticator(t,
		userObj("alice", nil),
		bindingObj("b1", "alice", "viewers"),
		bindingObj("b2", "alice", "admins"),
		// noise: a binding for someone else, must NOT appear in alice's response
		bindingObj("b3", "bob", "admins"),
	)
	resp, err := a.Authenticate(testCtx(), &proto.IdentityRequest{Login: "alice"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if len(resp.User.Groups) != 2 {
		t.Fatalf("expected 2 groups, got %v", resp.User.Groups)
	}
	if resp.User.Groups[0] != "admins" || resp.User.Groups[1] != "viewers" {
		t.Errorf("groups not sorted: %v", resp.User.Groups)
	}
}

func TestAuthenticate_GroupClaimsMergedUserClaimsWin(t *testing.T) {
	// Group provides shared claims; User overrides shared keys.
	// The contract: User.Claims take precedence on conflict.
	a := newAuthenticator(t,
		userObj("alice", func(u *kubauthv1alpha1.User) {
			u.Spec.Claims = &apiextensionsv1.JSON{
				Raw: []byte(`{"role":"user","extra":"u"}`),
			}
		}),
		bindingObj("b", "alice", "admins"),
		groupObj("admins", `{"role":"admin","org":"kubauth"}`),
	)
	resp, err := a.Authenticate(testCtx(), &proto.IdentityRequest{Login: "alice"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	// User wins on `role`, group's `org` survives, User's `extra` survives.
	if resp.User.Claims["role"] != "user" {
		t.Errorf("user claim should override group: role=%v", resp.User.Claims["role"])
	}
	if resp.User.Claims["org"] != "kubauth" {
		t.Errorf("group claim should survive: org=%v", resp.User.Claims["org"])
	}
	if resp.User.Claims["extra"] != "u" {
		t.Errorf("user-only claim missing: %v", resp.User.Claims["extra"])
	}
}

func TestAuthenticate_GroupBindingPointsToMissingGroupIsTolerated(t *testing.T) {
	// A GroupBinding referencing a Group that doesn't exist must NOT
	// fail authentication — the binding's group name still goes into
	// the response, the missing group just contributes no claims.
	a := newAuthenticator(t,
		userObj("alice", nil),
		bindingObj("b", "alice", "ghost-group"), // no Group "ghost-group" CR
	)
	resp, err := a.Authenticate(testCtx(), &proto.IdentityRequest{Login: "alice"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if len(resp.User.Groups) != 1 || resp.User.Groups[0] != "ghost-group" {
		t.Errorf("group name should appear despite missing CR: %v", resp.User.Groups)
	}
}

func TestAuthenticate_NoBindingsForUser(t *testing.T) {
	// Other bindings exist but none for alice → empty groups.
	a := newAuthenticator(t,
		userObj("alice", nil),
		bindingObj("b", "bob", "admins"),
	)
	resp, err := a.Authenticate(testCtx(), &proto.IdentityRequest{Login: "alice"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if len(resp.User.Groups) != 0 {
		t.Errorf("alice should have no groups, got %v", resp.User.Groups)
	}
}
