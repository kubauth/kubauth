/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package authenticator

import (
	"kubauth/internal/proto"
	"testing"
)

// The merger walks providers and chooses the response Status whose
// `priority(...)` is highest. The ordering is the contract that lets a
// single LDAP "Disabled" override a UCRD "PasswordChecked", and so on.
// If anyone reorders priorityByStatus, this test fails.
func TestPriorityOrdering(t *testing.T) {
	// Strict-greater-than chain: each step MUST out-rank the previous.
	chain := []proto.Status{
		proto.Undefined,
		proto.UserNotFound,
		proto.PasswordMissing,
		proto.PasswordUnchecked,
		proto.PasswordChecked, // tied with PasswordFail (both 4)
		proto.Disabled,
	}
	for i := 1; i < len(chain); i++ {
		if priority(chain[i]) <= priority(chain[i-1]) {
			t.Errorf("priority(%s)=%d should be > priority(%s)=%d",
				chain[i], priority(chain[i]),
				chain[i-1], priority(chain[i-1]))
		}
	}
}

func TestPriority_PasswordCheckedAndFailAreEqual(t *testing.T) {
	// Documented tie: PasswordChecked and PasswordFail share priority.
	// The merger relies on this — a provider that says "fail" doesn't
	// get out-ranked by another saying "checked", and vice versa.
	if priority(proto.PasswordChecked) != priority(proto.PasswordFail) {
		t.Errorf("PasswordChecked and PasswordFail must tie: got %d vs %d",
			priority(proto.PasswordChecked), priority(proto.PasswordFail))
	}
}

func TestPriority_DisabledOutranksEverything(t *testing.T) {
	disabled := priority(proto.Disabled)
	for _, s := range []proto.Status{
		proto.Undefined,
		proto.UserNotFound,
		proto.PasswordMissing,
		proto.PasswordUnchecked,
		proto.PasswordChecked,
		proto.PasswordFail,
	} {
		if priority(s) >= disabled {
			t.Errorf("Disabled (%d) must out-rank %s (%d)", disabled, s, priority(s))
		}
	}
}

func TestPriority_UndefinedIsLowest(t *testing.T) {
	undef := priority(proto.Undefined)
	for _, s := range []proto.Status{
		proto.UserNotFound,
		proto.PasswordMissing,
		proto.PasswordUnchecked,
		proto.PasswordChecked,
		proto.PasswordFail,
		proto.Disabled,
	} {
		if priority(s) <= undef {
			t.Errorf("Undefined (%d) must be lowest, but %s = %d", undef, s, priority(s))
		}
	}
}

func TestPriority_UnknownStatusReturnsZero(t *testing.T) {
	// Unmapped string → zero value (Go map default). This is the
	// degraded but non-panicking behaviour callers rely on.
	if got := priority(proto.Status("not-a-real-status")); got != 0 {
		t.Errorf("priority of unknown status should be 0, got %d", got)
	}
}
