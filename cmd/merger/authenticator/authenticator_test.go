/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package authenticator

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"testing"

	"kubauth/cmd/merger/provider"
	"kubauth/internal/proto"

	"github.com/go-logr/logr"
)

// ---------------------------------------------------------------------------
// Fakes & helpers
// ---------------------------------------------------------------------------

// fakeProvider is a canned provider.Provider. GetUserDetail ignores the
// login/password and returns the pre-built detail (or err). It records how
// many times it was called so we can assert short-circuit behaviour.
type fakeProvider struct {
	name   string
	detail *proto.UserDetail
	err    error
	calls  int
}

var _ provider.Provider = (*fakeProvider)(nil)

func (f *fakeProvider) GetUserDetail(_ context.Context, _, _ string) (*proto.UserDetail, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.detail, nil
}

func (f *fakeProvider) GetName() string { return f.name }

// testCtx mirrors the sibling authenticator tests: a discarding slog logger
// wired into the context so Authenticate's logr.FromContextOrDiscard is happy.
func testCtx() context.Context {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return logr.NewContextWithSlogLogger(context.Background(), logger)
}

// detailOpt mutates a UserDetail under construction.
type detailOpt func(*proto.UserDetail)

func withCredentialAuthority(v bool) detailOpt {
	return func(d *proto.UserDetail) { d.Provider.CredentialAuthority = v }
}
func withGroupAuthority(v bool) detailOpt {
	return func(d *proto.UserDetail) { d.Provider.GroupAuthority = v }
}
func withEmailAuthority(v bool) detailOpt {
	return func(d *proto.UserDetail) { d.Provider.EmailAuthority = v }
}
func withNameAuthority(v bool) detailOpt {
	return func(d *proto.UserDetail) { d.Provider.NameAuthority = v }
}
func withClaimAuthority(v bool) detailOpt {
	return func(d *proto.UserDetail) { d.Provider.ClaimAuthority = v }
}
func withTranslatedUID(uid int) detailOpt {
	return func(d *proto.UserDetail) { d.Translated.Uid = &uid }
}
func withTranslatedGroups(g ...string) detailOpt {
	return func(d *proto.UserDetail) { d.Translated.Groups = g }
}
func withTranslatedClaims(c map[string]interface{}) detailOpt {
	return func(d *proto.UserDetail) { d.Translated.Claims = c }
}
func withUserEmails(e ...string) detailOpt {
	return func(d *proto.UserDetail) { d.User.Emails = e }
}
func withUserName(n string) detailOpt {
	return func(d *proto.UserDetail) { d.User.Name = n }
}

// newDetail builds a UserDetail with the given provider name + status and
// applies the options. The embedded User.Login is always the supplied login.
func newDetail(name, login string, status proto.Status, opts ...detailOpt) *proto.UserDetail {
	d := &proto.UserDetail{
		User:   proto.InitUser(login),
		Status: status,
		Provider: proto.ProviderSpec{
			Name: name,
		},
		Translated: proto.Translated{
			Groups: []string{},
			Claims: map[string]interface{}{},
		},
	}
	for _, o := range opts {
		o(d)
	}
	return d
}

// newMerger wires a mergerAuthenticator from raw providers (same package, so
// we can reach the unexported field directly).
func newMerger(ps ...provider.Provider) *mergerAuthenticator {
	return &mergerAuthenticator{providers: ps}
}

const login = "alice"

// ---------------------------------------------------------------------------
// Empty / baseline
// ---------------------------------------------------------------------------

func TestAuthenticate_NoProviders(t *testing.T) {
	m := newMerger()
	resp, err := m.Authenticate(testCtx(), &proto.IdentityRequest{Login: login})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != proto.UserNotFound {
		t.Errorf("status = %q, want %q", resp.Status, proto.UserNotFound)
	}
	if resp.Authority != "" {
		t.Errorf("authority = %q, want empty", resp.Authority)
	}
	if resp.User.Login != login {
		t.Errorf("login = %q, want %q", resp.User.Login, login)
	}
	if resp.User.Uid != nil {
		t.Errorf("uid = %v, want nil", *resp.User.Uid)
	}
	if len(resp.Details) != 0 {
		t.Errorf("details len = %d, want 0", len(resp.Details))
	}
	// InitUser gives empty (non-nil) groups; DedupAndSort keeps them empty.
	if len(resp.User.Groups) != 0 {
		t.Errorf("groups = %v, want empty", resp.User.Groups)
	}
}

// ---------------------------------------------------------------------------
// CredentialAuthority gating — the core contract
// ---------------------------------------------------------------------------

// A NON-authority provider must never move response.Status, even when it
// reports a strictly higher-priority outcome (here Disabled, the max).
func TestAuthenticate_NonAuthorityCannotOverrideStatus(t *testing.T) {
	nonAuth := &fakeProvider{
		name:   "ldap-readonly",
		detail: newDetail("ldap-readonly", login, proto.Disabled, withCredentialAuthority(false), withTranslatedUID(999)),
	}
	m := newMerger(nonAuth)
	resp, err := m.Authenticate(testCtx(), &proto.IdentityRequest{Login: login})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Status stays at the initial UserNotFound — the Disabled was ignored.
	if resp.Status != proto.UserNotFound {
		t.Errorf("status = %q, want %q (non-authority must not override)", resp.Status, proto.UserNotFound)
	}
	if resp.Authority != "" {
		t.Errorf("authority = %q, want empty (non-authority must not set authority)", resp.Authority)
	}
	if resp.User.Uid != nil {
		t.Errorf("uid = %v, want nil (non-authority must not set uid)", *resp.User.Uid)
	}
}

// The decisive case: an authority provider says PasswordChecked, a
// non-authority provider (ordered AFTER it) says Disabled. The non-authority
// Disabled must NOT override the authority's PasswordChecked decision.
func TestAuthenticate_NonAuthorityDoesNotOverrideAuthorityDecision(t *testing.T) {
	authority := &fakeProvider{
		name:   "authority",
		detail: newDetail("authority", login, proto.PasswordChecked, withCredentialAuthority(true), withTranslatedUID(42)),
	}
	bystander := &fakeProvider{
		name:   "bystander",
		detail: newDetail("bystander", login, proto.Disabled, withCredentialAuthority(false), withTranslatedUID(7)),
	}
	m := newMerger(authority, bystander)
	resp, err := m.Authenticate(testCtx(), &proto.IdentityRequest{Login: login})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != proto.PasswordChecked {
		t.Errorf("status = %q, want %q (authority decision must stand)", resp.Status, proto.PasswordChecked)
	}
	if resp.Authority != "authority" {
		t.Errorf("authority = %q, want %q", resp.Authority, "authority")
	}
	if resp.User.Uid == nil || *resp.User.Uid != 42 {
		t.Errorf("uid = %v, want 42 (from authority's Translated.Uid)", resp.User.Uid)
	}
}

// Symmetric ordering check: even when the non-authority Disabled provider is
// walked FIRST, the later authority PasswordChecked is what wins the status.
func TestAuthenticate_OrderIndependent_AuthorityWins(t *testing.T) {
	bystander := &fakeProvider{
		name:   "bystander",
		detail: newDetail("bystander", login, proto.Disabled, withCredentialAuthority(false)),
	}
	authority := &fakeProvider{
		name:   "authority",
		detail: newDetail("authority", login, proto.PasswordChecked, withCredentialAuthority(true), withTranslatedUID(42)),
	}
	m := newMerger(bystander, authority)
	resp, err := m.Authenticate(testCtx(), &proto.IdentityRequest{Login: login})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != proto.PasswordChecked {
		t.Errorf("status = %q, want %q", resp.Status, proto.PasswordChecked)
	}
	if resp.Authority != "authority" {
		t.Errorf("authority = %q, want %q", resp.Authority, "authority")
	}
}

// ---------------------------------------------------------------------------
// Priority resolution across multiple AUTHORITY providers
// ---------------------------------------------------------------------------

// Disabled (5) out-ranks PasswordChecked (4); the Disabled provider becomes
// the authority and its uid is taken (Disabled > PasswordMissing).
func TestAuthenticate_HigherPriorityAuthorityWins(t *testing.T) {
	checked := &fakeProvider{
		name:   "checked",
		detail: newDetail("checked", login, proto.PasswordChecked, withCredentialAuthority(true), withTranslatedUID(1)),
	}
	disabled := &fakeProvider{
		name:   "disabled",
		detail: newDetail("disabled", login, proto.Disabled, withCredentialAuthority(true), withTranslatedUID(2)),
	}
	m := newMerger(checked, disabled)
	resp, err := m.Authenticate(testCtx(), &proto.IdentityRequest{Login: login})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != proto.Disabled {
		t.Errorf("status = %q, want %q", resp.Status, proto.Disabled)
	}
	if resp.Authority != "disabled" {
		t.Errorf("authority = %q, want %q", resp.Authority, "disabled")
	}
	if resp.User.Uid == nil || *resp.User.Uid != 2 {
		t.Errorf("uid = %v, want 2 (from the winning Disabled provider)", resp.User.Uid)
	}
}

// PasswordChecked and PasswordFail tie at priority 4: strict-greater means the
// FIRST one walked wins; the tying second provider can't displace it.
func TestAuthenticate_TieKeepsFirstAuthority(t *testing.T) {
	first := &fakeProvider{
		name:   "first-fail",
		detail: newDetail("first-fail", login, proto.PasswordFail, withCredentialAuthority(true), withTranslatedUID(11)),
	}
	second := &fakeProvider{
		name:   "second-checked",
		detail: newDetail("second-checked", login, proto.PasswordChecked, withCredentialAuthority(true), withTranslatedUID(22)),
	}
	m := newMerger(first, second)
	resp, err := m.Authenticate(testCtx(), &proto.IdentityRequest{Login: login})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != proto.PasswordFail {
		t.Errorf("status = %q, want %q (first writer wins on tie)", resp.Status, proto.PasswordFail)
	}
	if resp.Authority != "first-fail" {
		t.Errorf("authority = %q, want %q (tie must not displace first)", resp.Authority, "first-fail")
	}
	if resp.User.Uid == nil || *resp.User.Uid != 11 {
		t.Errorf("uid = %v, want 11 (from first provider)", resp.User.Uid)
	}
}

// ---------------------------------------------------------------------------
// Uid / Authority gating around the PasswordMissing threshold
// ---------------------------------------------------------------------------

// An authority provider whose status is exactly PasswordMissing (priority 2)
// DOES raise response.Status above UserNotFound, but must NOT set uid/authority
// because the gate is strictly `> priority(PasswordMissing)`.
func TestAuthenticate_PasswordMissingRaisesStatusButNotUidOrAuthority(t *testing.T) {
	p := &fakeProvider{
		name:   "missing",
		detail: newDetail("missing", login, proto.PasswordMissing, withCredentialAuthority(true), withTranslatedUID(77)),
	}
	m := newMerger(p)
	resp, err := m.Authenticate(testCtx(), &proto.IdentityRequest{Login: login})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != proto.PasswordMissing {
		t.Errorf("status = %q, want %q", resp.Status, proto.PasswordMissing)
	}
	if resp.Authority != "" {
		t.Errorf("authority = %q, want empty (PasswordMissing must not set authority)", resp.Authority)
	}
	if resp.User.Uid != nil {
		t.Errorf("uid = %v, want nil (PasswordMissing must not set uid)", *resp.User.Uid)
	}
}

// Just above the threshold: PasswordUnchecked (priority 3) DOES set uid and
// authority.
func TestAuthenticate_PasswordUncheckedSetsUidAndAuthority(t *testing.T) {
	p := &fakeProvider{
		name:   "unchecked",
		detail: newDetail("unchecked", login, proto.PasswordUnchecked, withCredentialAuthority(true), withTranslatedUID(55)),
	}
	m := newMerger(p)
	resp, err := m.Authenticate(testCtx(), &proto.IdentityRequest{Login: login})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != proto.PasswordUnchecked {
		t.Errorf("status = %q, want %q", resp.Status, proto.PasswordUnchecked)
	}
	if resp.Authority != "unchecked" {
		t.Errorf("authority = %q, want %q", resp.Authority, "unchecked")
	}
	if resp.User.Uid == nil || *resp.User.Uid != 55 {
		t.Errorf("uid = %v, want 55", resp.User.Uid)
	}
}

// ---------------------------------------------------------------------------
// Enrichment authorities are independent of CredentialAuthority
// ---------------------------------------------------------------------------

// A provider that is NOT a credential authority can still contribute groups,
// emails, name and claims when it holds those authority flags. This proves the
// enrichment is gated on its own flags, not on CredentialAuthority.
func TestAuthenticate_NonCredentialProviderStillEnriches(t *testing.T) {
	enricher := &fakeProvider{
		name: "enricher",
		detail: newDetail("enricher", login, proto.UserNotFound,
			withCredentialAuthority(false),
			withGroupAuthority(true), withTranslatedGroups("dev", "ops"),
			withEmailAuthority(true), withUserEmails("a@x.io"),
			withNameAuthority(true), withUserName("Alice"),
			withClaimAuthority(true), withTranslatedClaims(map[string]interface{}{"dept": "eng"}),
		),
	}
	m := newMerger(enricher)
	resp, err := m.Authenticate(testCtx(), &proto.IdentityRequest{Login: login})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Credential decision untouched.
	if resp.Status != proto.UserNotFound {
		t.Errorf("status = %q, want %q", resp.Status, proto.UserNotFound)
	}
	if resp.Authority != "" {
		t.Errorf("authority = %q, want empty", resp.Authority)
	}
	// Enrichment applied.
	if !reflect.DeepEqual(resp.User.Groups, []string{"dev", "ops"}) {
		t.Errorf("groups = %v, want [dev ops]", resp.User.Groups)
	}
	if !reflect.DeepEqual(resp.User.Emails, []string{"a@x.io"}) {
		t.Errorf("emails = %v, want [a@x.io]", resp.User.Emails)
	}
	if resp.User.Name != "Alice" {
		t.Errorf("name = %q, want Alice", resp.User.Name)
	}
	if got, ok := resp.User.Claims["dept"]; !ok || got != "eng" {
		t.Errorf("claims[dept] = %v (ok=%v), want eng", got, ok)
	}
}

// When the authority flags are OFF, nothing is enriched even though the
// provider carries groups/emails/name/claims payloads.
func TestAuthenticate_AuthorityFlagsOffSuppressEnrichment(t *testing.T) {
	p := &fakeProvider{
		name: "silent",
		detail: newDetail("silent", login, proto.UserNotFound,
			withCredentialAuthority(false),
			withGroupAuthority(false), withTranslatedGroups("dev"),
			withEmailAuthority(false), withUserEmails("a@x.io"),
			withNameAuthority(false), withUserName("Alice"),
			withClaimAuthority(false), withTranslatedClaims(map[string]interface{}{"dept": "eng"}),
		),
	}
	m := newMerger(p)
	resp, err := m.Authenticate(testCtx(), &proto.IdentityRequest{Login: login})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.User.Groups) != 0 {
		t.Errorf("groups = %v, want empty", resp.User.Groups)
	}
	if len(resp.User.Emails) != 0 {
		t.Errorf("emails = %v, want empty", resp.User.Emails)
	}
	if resp.User.Name != "" {
		t.Errorf("name = %q, want empty", resp.User.Name)
	}
	if len(resp.User.Claims) != 0 {
		t.Errorf("claims = %v, want empty", resp.User.Claims)
	}
}

// ---------------------------------------------------------------------------
// Group merge: dedup + sort across providers
// ---------------------------------------------------------------------------

func TestAuthenticate_GroupsDedupedAndSortedAcrossProviders(t *testing.T) {
	p1 := &fakeProvider{
		name:   "p1",
		detail: newDetail("p1", login, proto.UserNotFound, withGroupAuthority(true), withTranslatedGroups("zeta", "alpha")),
	}
	p2 := &fakeProvider{
		name:   "p2",
		detail: newDetail("p2", login, proto.UserNotFound, withGroupAuthority(true), withTranslatedGroups("alpha", "mid")),
	}
	m := newMerger(p1, p2)
	resp, err := m.Authenticate(testCtx(), &proto.IdentityRequest{Login: login})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"alpha", "mid", "zeta"} // deduped + lexically sorted
	if !reflect.DeepEqual(resp.User.Groups, want) {
		t.Errorf("groups = %v, want %v", resp.User.Groups, want)
	}
}

// ---------------------------------------------------------------------------
// Name merge: first non-empty writer wins
// ---------------------------------------------------------------------------

func TestAuthenticate_NameFirstWriterWins(t *testing.T) {
	p1 := &fakeProvider{
		name:   "p1",
		detail: newDetail("p1", login, proto.UserNotFound, withNameAuthority(true), withUserName("First")),
	}
	p2 := &fakeProvider{
		name:   "p2",
		detail: newDetail("p2", login, proto.UserNotFound, withNameAuthority(true), withUserName("Second")),
	}
	m := newMerger(p1, p2)
	resp, err := m.Authenticate(testCtx(), &proto.IdentityRequest{Login: login})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.User.Name != "First" {
		t.Errorf("name = %q, want %q (first non-empty wins)", resp.User.Name, "First")
	}
}

// A name-authority provider with an EMPTY name does not block a later
// name-authority provider from filling it.
func TestAuthenticate_EmptyNameDoesNotBlockLaterProvider(t *testing.T) {
	p1 := &fakeProvider{
		name:   "p1",
		detail: newDetail("p1", login, proto.UserNotFound, withNameAuthority(true), withUserName("")),
	}
	p2 := &fakeProvider{
		name:   "p2",
		detail: newDetail("p2", login, proto.UserNotFound, withNameAuthority(true), withUserName("Second")),
	}
	m := newMerger(p1, p2)
	resp, err := m.Authenticate(testCtx(), &proto.IdentityRequest{Login: login})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.User.Name != "Second" {
		t.Errorf("name = %q, want %q", resp.User.Name, "Second")
	}
}

// ---------------------------------------------------------------------------
// Email merge: append-if-not-present (order preserved, dups dropped)
// ---------------------------------------------------------------------------

func TestAuthenticate_EmailsAppendedWithoutDuplicates(t *testing.T) {
	p1 := &fakeProvider{
		name:   "p1",
		detail: newDetail("p1", login, proto.UserNotFound, withEmailAuthority(true), withUserEmails("a@x.io", "b@x.io")),
	}
	p2 := &fakeProvider{
		name:   "p2",
		detail: newDetail("p2", login, proto.UserNotFound, withEmailAuthority(true), withUserEmails("b@x.io", "c@x.io")),
	}
	m := newMerger(p1, p2)
	resp, err := m.Authenticate(testCtx(), &proto.IdentityRequest{Login: login})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"a@x.io", "b@x.io", "c@x.io"} // order preserved, b deduped
	if !reflect.DeepEqual(resp.User.Emails, want) {
		t.Errorf("emails = %v, want %v", resp.User.Emails, want)
	}
}

// ---------------------------------------------------------------------------
// Claim merge: later provider overrides earlier (MergeMaps semantics)
// ---------------------------------------------------------------------------

// MergeMaps is called as MergeMaps(userDetail.Translated.Claims, response.User.Claims)
// i.e. the ALREADY-ACCUMULATED claims override the incoming provider's. So for a
// scalar key set by two providers, the EARLIER provider's value survives.
func TestAuthenticate_ClaimsEarlierProviderWinsOnScalarConflict(t *testing.T) {
	p1 := &fakeProvider{
		name:   "p1",
		detail: newDetail("p1", login, proto.UserNotFound, withClaimAuthority(true), withTranslatedClaims(map[string]interface{}{"role": "admin", "team": "blue"})),
	}
	p2 := &fakeProvider{
		name:   "p2",
		detail: newDetail("p2", login, proto.UserNotFound, withClaimAuthority(true), withTranslatedClaims(map[string]interface{}{"role": "user", "dept": "eng"})),
	}
	m := newMerger(p1, p2)
	resp, err := m.Authenticate(testCtx(), &proto.IdentityRequest{Login: login})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// role: p1 set it first; accumulated value overrides p2 -> "admin".
	if got := resp.User.Claims["role"]; got != "admin" {
		t.Errorf("claims[role] = %v, want admin (earlier provider wins)", got)
	}
	// Non-conflicting keys from both providers survive.
	if got := resp.User.Claims["team"]; got != "blue" {
		t.Errorf("claims[team] = %v, want blue", got)
	}
	if got := resp.User.Claims["dept"]; got != "eng" {
		t.Errorf("claims[dept] = %v, want eng", got)
	}
}

// ---------------------------------------------------------------------------
// Details bookkeeping
// ---------------------------------------------------------------------------

func TestAuthenticate_DetailsPopulatedInOrder(t *testing.T) {
	d1 := newDetail("p1", login, proto.UserNotFound, withCredentialAuthority(false))
	d2 := newDetail("p2", login, proto.PasswordChecked, withCredentialAuthority(true), withTranslatedUID(9))
	p1 := &fakeProvider{name: "p1", detail: d1}
	p2 := &fakeProvider{name: "p2", detail: d2}
	m := newMerger(p1, p2)
	resp, err := m.Authenticate(testCtx(), &proto.IdentityRequest{Login: login})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Details) != 2 {
		t.Fatalf("details len = %d, want 2", len(resp.Details))
	}
	if resp.Details[0] != d1 || resp.Details[1] != d2 {
		t.Errorf("details not stored in provider order: got [%v %v]", resp.Details[0], resp.Details[1])
	}
}

// ---------------------------------------------------------------------------
// Error propagation
// ---------------------------------------------------------------------------

// A provider error aborts the whole merge: nil response, the error is returned
// verbatim, and providers AFTER the failing one are never called.
func TestAuthenticate_ProviderErrorAbortsAndShortCircuits(t *testing.T) {
	sentinel := errors.New("boom")
	failing := &fakeProvider{name: "failing", err: sentinel}
	after := &fakeProvider{
		name:   "after",
		detail: newDetail("after", login, proto.PasswordChecked, withCredentialAuthority(true)),
	}
	m := newMerger(failing, after)
	resp, err := m.Authenticate(testCtx(), &proto.IdentityRequest{Login: login})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel %v", err, sentinel)
	}
	if resp != nil {
		t.Errorf("response = %+v, want nil on error", resp)
	}
	if failing.calls != 1 {
		t.Errorf("failing.calls = %d, want 1", failing.calls)
	}
	if after.calls != 0 {
		t.Errorf("after.calls = %d, want 0 (must short-circuit on error)", after.calls)
	}
}

// ---------------------------------------------------------------------------
// Login propagation into the request reaching providers
// ---------------------------------------------------------------------------

// recordingProvider captures the login/password it was handed, to prove the
// merger forwards request fields unchanged.
type recordingProvider struct {
	gotLogin    string
	gotPassword string
	detail      *proto.UserDetail
}

var _ provider.Provider = (*recordingProvider)(nil)

func (r *recordingProvider) GetUserDetail(_ context.Context, l, p string) (*proto.UserDetail, error) {
	r.gotLogin, r.gotPassword = l, p
	return r.detail, nil
}
func (r *recordingProvider) GetName() string { return "recorder" }

func TestAuthenticate_ForwardsLoginAndPasswordToProviders(t *testing.T) {
	rec := &recordingProvider{
		detail: newDetail("recorder", "bob", proto.UserNotFound, withCredentialAuthority(true)),
	}
	m := newMerger(rec)
	_, err := m.Authenticate(testCtx(), &proto.IdentityRequest{Login: "bob", Password: "s3cr3t"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.gotLogin != "bob" {
		t.Errorf("provider got login %q, want bob", rec.gotLogin)
	}
	if rec.gotPassword != "s3cr3t" {
		t.Errorf("provider got password %q, want s3cr3t", rec.gotPassword)
	}
}

// ---------------------------------------------------------------------------
// Combined realistic scenario: authority for credentials, separate enrichers
// ---------------------------------------------------------------------------

// A typical deployment: an LDAP authority checks the password and provides uid;
// a directory enricher (non-credential) adds groups/email/name; a claims
// provider adds claims. Asserts all merge facets at once.
func TestAuthenticate_CombinedRealisticMerge(t *testing.T) {
	ldap := &fakeProvider{
		name: "ldap",
		detail: newDetail("ldap", login, proto.PasswordChecked,
			withCredentialAuthority(true), withTranslatedUID(1000),
			withGroupAuthority(true), withTranslatedGroups("ldap-users"),
		),
	}
	directory := &fakeProvider{
		name: "directory",
		detail: newDetail("directory", login, proto.Disabled, // higher priority but NOT authority
			withCredentialAuthority(false),
			withGroupAuthority(true), withTranslatedGroups("staff", "ldap-users"),
			withEmailAuthority(true), withUserEmails("alice@corp.io"),
			withNameAuthority(true), withUserName("Alice Liddell"),
		),
	}
	claims := &fakeProvider{
		name: "claims",
		detail: newDetail("claims", login, proto.UserNotFound,
			withCredentialAuthority(false),
			withClaimAuthority(true), withTranslatedClaims(map[string]interface{}{"tier": "gold"}),
		),
	}
	m := newMerger(ldap, directory, claims)
	resp, err := m.Authenticate(testCtx(), &proto.IdentityRequest{Login: login, Password: "pw"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Credential decision comes from ldap; directory's Disabled is ignored.
	if resp.Status != proto.PasswordChecked {
		t.Errorf("status = %q, want %q", resp.Status, proto.PasswordChecked)
	}
	if resp.Authority != "ldap" {
		t.Errorf("authority = %q, want ldap", resp.Authority)
	}
	if resp.User.Uid == nil || *resp.User.Uid != 1000 {
		t.Errorf("uid = %v, want 1000", resp.User.Uid)
	}
	// Groups merged from ldap + directory, deduped + sorted.
	wantGroups := []string{"ldap-users", "staff"}
	if !reflect.DeepEqual(resp.User.Groups, wantGroups) {
		t.Errorf("groups = %v, want %v", resp.User.Groups, wantGroups)
	}
	if !reflect.DeepEqual(resp.User.Emails, []string{"alice@corp.io"}) {
		t.Errorf("emails = %v, want [alice@corp.io]", resp.User.Emails)
	}
	if resp.User.Name != "Alice Liddell" {
		t.Errorf("name = %q, want Alice Liddell", resp.User.Name)
	}
	if got := resp.User.Claims["tier"]; got != "gold" {
		t.Errorf("claims[tier] = %v, want gold", got)
	}
	if len(resp.Details) != 3 {
		t.Errorf("details len = %d, want 3", len(resp.Details))
	}
}
