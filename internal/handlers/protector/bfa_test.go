/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package protector

import (
	"context"
	"io"
	"kubauth/internal/proto"
	"log/slog"
	"testing"
	"time"

	"github.com/go-logr/logr"
)

func testCtx() context.Context {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return logr.NewContextWithSlogLogger(context.Background(), logger)
}

// newBareProtector returns a *bfaProtector with the same defaults as
// the production constructor but WITHOUT the cleaner goroutine — tests
// drive `clean()` directly. Free failures = 0 and penaltyByFailure = 0
// keep `failure()` from sleeping, so `ProtectLoginResult` returns
// instantly. Override per test if needed.
func newBareProtector() *bfaProtector {
	return &bfaProtector{
		stateByLogin:      make(map[string]*loginState),
		cleanerPeriod:     60 * time.Second,
		cleanDelay:        30 * time.Minute,
		freeFailure:       0, // no free failures (so test penalties at all counts)
		maxPenalty:        15 * time.Second,
		penaltyByFailure:  0, // no actual sleep
		maxPendingFailure: 20,
	}
}

// delayFromFailureCount — pure function -----------------------------------

func TestDelayFromFailureCount_BelowOrEqualFreeIsZero(t *testing.T) {
	p := newBareProtector()
	p.freeFailure = 4
	p.penaltyByFailure = time.Second
	p.maxPenalty = 15 * time.Second
	for _, n := range []int64{0, 1, 2, 3, 4} {
		if d := p.delayFromFailureCount(n); d != 0 {
			t.Errorf("count=%d: expected 0 delay, got %v", n, d)
		}
	}
}

func TestDelayFromFailureCount_LinearAfterFree(t *testing.T) {
	p := newBareProtector()
	p.freeFailure = 4
	p.penaltyByFailure = time.Second
	p.maxPenalty = 15 * time.Second
	for n, want := range map[int64]time.Duration{
		5: 1 * time.Second,
		6: 2 * time.Second,
		7: 3 * time.Second,
	} {
		if d := p.delayFromFailureCount(n); d != want {
			t.Errorf("count=%d: expected %v, got %v", n, want, d)
		}
	}
}

func TestDelayFromFailureCount_CappedAtMaxPenalty(t *testing.T) {
	p := newBareProtector()
	p.freeFailure = 4
	p.penaltyByFailure = time.Second
	p.maxPenalty = 5 * time.Second
	if d := p.delayFromFailureCount(100); d != 5*time.Second {
		t.Errorf("expected 5s cap, got %v", d)
	}
}

func TestDelayFromFailureCount_ZeroPenaltyByFailureGivesZero(t *testing.T) {
	p := newBareProtector() // penaltyByFailure = 0
	p.freeFailure = 0
	if d := p.delayFromFailureCount(50); d != 0 {
		t.Errorf("zero penaltyByFailure should yield zero delay, got %v", d)
	}
}

// empty Protector ---------------------------------------------------------

func TestEmpty_AllOperationsAreNoOps(t *testing.T) {
	e := empty{}
	ctx := testCtx()
	if e.EntryForLogin(ctx, "alice") {
		t.Error("empty.EntryForLogin should never lock")
	}
	if e.EntryForToken(ctx) {
		t.Error("empty.EntryForToken should never lock")
	}
	// These return nothing — just verify no panic.
	e.TokenNotFound(ctx)
	e.ProtectLoginResult(ctx, "alice", proto.PasswordFail)
}

// EntryForLogin / EntryForToken (locking) ---------------------------------

func TestEntryForLogin_NoStateNotLocked(t *testing.T) {
	p := newBareProtector()
	if p.EntryForLogin(testCtx(), "alice") {
		t.Error("fresh protector should not lock")
	}
}

func TestEntryForLogin_LockedWhenPendingExceedsThreshold(t *testing.T) {
	p := newBareProtector()
	p.maxPendingFailure = 5
	st := &loginState{}
	st.pendingFailures.Add(6) // > 5
	p.stateByLogin["alice"] = st
	if !p.EntryForLogin(testCtx(), "alice") {
		t.Error("expected lock when pending > maxPendingFailure")
	}
}

func TestEntryForLogin_NotLockedAtThreshold(t *testing.T) {
	// Strictly greater-than: at threshold exactly, NOT locked.
	p := newBareProtector()
	p.maxPendingFailure = 5
	st := &loginState{}
	st.pendingFailures.Add(5) // == 5
	p.stateByLogin["alice"] = st
	if p.EntryForLogin(testCtx(), "alice") {
		t.Error("at-threshold should NOT lock (strict >)")
	}
}

func TestEntryForLogin_UnknownUserPendingBlocksAllUsers(t *testing.T) {
	// An attack against UnknownUser (probing random logins) should
	// also lock specific user logins to defend the apiserver.
	p := newBareProtector()
	p.maxPendingFailure = 5
	st := &loginState{}
	st.pendingFailures.Add(10)
	p.stateByLogin[UnknownUser] = st
	if !p.EntryForLogin(testCtx(), "alice") {
		t.Error("UnknownUser pending should lock specific logins")
	}
}

func TestEntryForToken_NoStateNotLocked(t *testing.T) {
	p := newBareProtector()
	if p.EntryForToken(testCtx()) {
		t.Error("fresh protector should not lock token entry")
	}
}

func TestEntryForToken_LockedWhenUnknownTokenPendingHigh(t *testing.T) {
	p := newBareProtector()
	p.maxPendingFailure = 5
	st := &loginState{}
	st.pendingFailures.Add(10)
	p.stateByLogin[UnknownToken] = st
	if !p.EntryForToken(testCtx()) {
		t.Error("UnknownToken pending should lock token entry")
	}
}

// ProtectLoginResult ------------------------------------------------------

func TestProtectLoginResult_PasswordFailRegistersFailure(t *testing.T) {
	p := newBareProtector() // penaltyByFailure=0 → no sleep
	p.ProtectLoginResult(testCtx(), "alice", proto.PasswordFail)
	st, ok := p.stateByLogin["alice"]
	if !ok {
		t.Fatal("expected alice's state to exist after PasswordFail")
	}
	if st.nbrOfFailure != 1 {
		t.Errorf("expected nbrOfFailure=1, got %d", st.nbrOfFailure)
	}
}

func TestProtectLoginResult_InvalidOldPasswordRegistersFailure(t *testing.T) {
	p := newBareProtector()
	p.ProtectLoginResult(testCtx(), "alice", proto.InvalidOldPassword)
	if _, ok := p.stateByLogin["alice"]; !ok {
		t.Error("expected state after InvalidOldPassword")
	}
}

func TestProtectLoginResult_NonFailureStatusesIgnored(t *testing.T) {
	p := newBareProtector()
	for _, st := range []proto.Status{
		proto.PasswordChecked,
		proto.PasswordMissing,
		proto.PasswordUnchecked,
		proto.UserNotFound,
		proto.Disabled,
		proto.Undefined,
	} {
		p.ProtectLoginResult(testCtx(), "alice", st)
	}
	if _, ok := p.stateByLogin["alice"]; ok {
		t.Error("non-failure statuses should NOT register a failure")
	}
}

func TestProtectLoginResult_RepeatedFailuresAccumulate(t *testing.T) {
	p := newBareProtector()
	for i := 0; i < 5; i++ {
		p.ProtectLoginResult(testCtx(), "alice", proto.PasswordFail)
	}
	st := p.stateByLogin["alice"]
	if st == nil || st.nbrOfFailure != 5 {
		t.Errorf("expected 5 failures, got state=%v", st)
	}
}

// TokenNotFound -----------------------------------------------------------

func TestTokenNotFound_RegistersUnderUnknownTokenKey(t *testing.T) {
	p := newBareProtector()
	p.TokenNotFound(testCtx())
	st, ok := p.stateByLogin[UnknownToken]
	if !ok {
		t.Fatal("expected state under UnknownToken key")
	}
	if st.nbrOfFailure != 1 {
		t.Errorf("expected nbrOfFailure=1, got %d", st.nbrOfFailure)
	}
}

// clean -------------------------------------------------------------------

func TestClean_RemovesStaleStates(t *testing.T) {
	p := newBareProtector()
	p.cleanDelay = time.Hour
	old := time.Now().Add(-2 * time.Hour) // way past cleanDelay
	p.stateByLogin["alice"] = &loginState{lastFailure: old, nbrOfFailure: 3}
	p.stateByLogin["bob"] = &loginState{lastFailure: old, nbrOfFailure: 1}

	p.clean(testCtx())

	if len(p.stateByLogin) != 0 {
		t.Errorf("expected all stale states cleaned, got %v", p.stateByLogin)
	}
}

func TestClean_KeepsRecentStates(t *testing.T) {
	p := newBareProtector()
	p.cleanDelay = time.Hour
	recent := time.Now().Add(-5 * time.Minute) // well within cleanDelay
	p.stateByLogin["alice"] = &loginState{lastFailure: recent, nbrOfFailure: 1}

	p.clean(testCtx())

	if _, ok := p.stateByLogin["alice"]; !ok {
		t.Error("recent state should be kept")
	}
}

func TestClean_MixedKeepsRecentDropsStale(t *testing.T) {
	p := newBareProtector()
	p.cleanDelay = time.Hour
	now := time.Now()
	p.stateByLogin["fresh"] = &loginState{lastFailure: now.Add(-10 * time.Minute)}
	p.stateByLogin["stale"] = &loginState{lastFailure: now.Add(-3 * time.Hour)}

	p.clean(testCtx())

	if _, ok := p.stateByLogin["fresh"]; !ok {
		t.Error("'fresh' should be kept")
	}
	if _, ok := p.stateByLogin["stale"]; ok {
		t.Error("'stale' should be cleaned")
	}
}

// New (constructor) -------------------------------------------------------

func TestNew_DeactivatedReturnsEmpty(t *testing.T) {
	ctx, cancel := context.WithCancel(testCtx())
	defer cancel()
	p := New(false, ctx)
	if _, ok := p.(*empty); !ok {
		t.Errorf("activated=false should return *empty, got %T", p)
	}
}

func TestNew_ActivatedReturnsBfaProtector(t *testing.T) {
	ctx, cancel := context.WithCancel(testCtx())
	defer cancel() // cancel stops the cleaner goroutine
	p := New(true, ctx)
	if _, ok := p.(*bfaProtector); !ok {
		t.Errorf("activated=true should return *bfaProtector, got %T", p)
	}
}

// real lockout delay / decay path ----------------------------------------

func TestProtectLoginResult_AppliesRealDelayAndDecaysPending(t *testing.T) {
	// Exercise the *real* penalty path (non-zero penaltyByFailure), not the
	// instant no-op variant used elsewhere. We assert three things at once:
	//   1. failure() actually sleeps for the computed delay (wall-clock),
	//   2. pendingFailures is incremented for the duration of the sleep,
	//   3. pendingFailures decays back to 0 once the call returns, while
	//      nbrOfFailure (the persistent counter) keeps its increment.
	const penalty = 60 * time.Millisecond
	p := newBareProtector()
	p.freeFailure = 0 // first failure already incurs a penalty
	p.penaltyByFailure = penalty
	p.maxPenalty = time.Second // well above a single step, so no capping here

	// Run the (blocking, sleeping) failure on a goroutine so we can observe
	// the in-flight pendingFailures increment from the test goroutine.
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		p.ProtectLoginResult(testCtx(), "alice", proto.PasswordFail)
		done <- time.Since(start)
	}()

	// While the goroutine is mid-sleep, pendingFailures must read 1. Poll
	// briefly to avoid racing the goroutine's startup.
	sawPending := false
	deadline := time.Now().Add(penalty) // generous: whole penalty window
	for time.Now().Before(deadline) {
		p.mu.Lock()
		st := p.stateByLogin["alice"]
		p.mu.Unlock()
		if st != nil && st.pendingFailures.Load() == 1 {
			sawPending = true
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !sawPending {
		t.Error("expected pendingFailures to be incremented to 1 during the lockout sleep")
	}

	elapsed := <-done
	if elapsed < penalty {
		t.Errorf("failure() should have slept at least %v (real delay path), slept %v", penalty, elapsed)
	}

	// After return: pending decayed to 0, persistent failure count is 1.
	st := p.stateByLogin["alice"]
	if st == nil {
		t.Fatal("expected alice state after a real failure")
	}
	if got := st.pendingFailures.Load(); got != 0 {
		t.Errorf("pendingFailures should decay to 0 after the call, got %d", got)
	}
	if st.nbrOfFailure != 1 {
		t.Errorf("nbrOfFailure should be 1, got %d", st.nbrOfFailure)
	}
	if st.lastFailure.IsZero() {
		t.Error("lastFailure should have been stamped")
	}

	// Decay/growth: a second failure (count=2) yields a strictly larger
	// delay than the first (count=1), confirming the linear ramp is live.
	start := time.Now()
	p.ProtectLoginResult(testCtx(), "alice", proto.PasswordFail)
	second := time.Since(start)
	if second < 2*penalty {
		t.Errorf("second failure (count=2) should sleep >= %v, slept %v", 2*penalty, second)
	}
	if st.nbrOfFailure != 2 {
		t.Errorf("nbrOfFailure should be 2 after second failure, got %d", st.nbrOfFailure)
	}
	if got := st.pendingFailures.Load(); got != 0 {
		t.Errorf("pendingFailures should again decay to 0, got %d", got)
	}
}

func TestProtectLoginResult_DelayCappedAtMaxPenalty(t *testing.T) {
	// The real path must honour the maxPenalty cap: with a huge per-failure
	// step but a tiny cap, the inflicted sleep stays bounded by the cap and
	// does not blow up to penaltyByFailure.
	const cap = 40 * time.Millisecond
	p := newBareProtector()
	p.freeFailure = 0
	p.penaltyByFailure = 10 * time.Second // would be enormous if uncapped
	p.maxPenalty = cap

	start := time.Now()
	p.ProtectLoginResult(testCtx(), "alice", proto.PasswordFail)
	elapsed := time.Since(start)

	if elapsed < cap {
		t.Errorf("delay should be at least the cap %v, got %v", cap, elapsed)
	}
	// Loose upper bound: nowhere near the uncapped 10s. Generous to absorb
	// scheduler jitter on a busy CI box.
	if elapsed > 2*time.Second {
		t.Errorf("delay should be capped near %v, but slept %v (cap not applied?)", cap, elapsed)
	}
}

func TestNew_OptionsApplied(t *testing.T) {
	ctx, cancel := context.WithCancel(testCtx())
	defer cancel()
	p := New(true, ctx,
		WithFreeFailure(7),
		WithMaxPenalty(20*time.Second),
		WithPenaltyByFailure(2*time.Second),
		WithMaxPendingFailure(99),
		WithCleanerPeriod(5*time.Minute),
		WithCleanDelay(1*time.Hour),
	).(*bfaProtector)
	if p.freeFailure != 7 {
		t.Errorf("freeFailure: %d", p.freeFailure)
	}
	if p.maxPenalty != 20*time.Second {
		t.Errorf("maxPenalty: %v", p.maxPenalty)
	}
	if p.penaltyByFailure != 2*time.Second {
		t.Errorf("penaltyByFailure: %v", p.penaltyByFailure)
	}
	if p.maxPendingFailure != 99 {
		t.Errorf("maxPendingFailure: %d", p.maxPendingFailure)
	}
	if p.cleanerPeriod != 5*time.Minute {
		t.Errorf("cleanerPeriod: %v", p.cleanerPeriod)
	}
	if p.cleanDelay != 1*time.Hour {
		t.Errorf("cleanDelay: %v", p.cleanDelay)
	}
}
