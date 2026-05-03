/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package misc

import (
	"errors"
	"strings"
	"testing"
)

func TestExpandEnv_NoVariables(t *testing.T) {
	got, err := ExpandEnv("plain text without dollars")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "plain text without dollars" {
		t.Errorf("got %q, want passthrough", got)
	}
}

func TestExpandEnv_EmptyInput(t *testing.T) {
	got, err := ExpandEnv("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExpandEnv_SingleVariable(t *testing.T) {
	t.Setenv("KUBAUTH_TEST_X", "hello")
	got, err := ExpandEnv("greet=${KUBAUTH_TEST_X}")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "greet=hello" {
		t.Errorf("got %q, want %q", got, "greet=hello")
	}
}

func TestExpandEnv_MultipleVariables(t *testing.T) {
	t.Setenv("KUBAUTH_TEST_HOST", "localhost")
	t.Setenv("KUBAUTH_TEST_PORT", "443")
	got, err := ExpandEnv("https://${KUBAUTH_TEST_HOST}:${KUBAUTH_TEST_PORT}/oauth")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "https://localhost:443/oauth" {
		t.Errorf("got %q", got)
	}
}

func TestExpandEnv_LoneDollarIsLiteral(t *testing.T) {
	// "Difference from os.ExpandEnv: A single '$' is not taken in account."
	// Documented as a deliberate divergence — verify it stays that way.
	got, err := ExpandEnv("price is $5 not ${X}")
	// `${X}` is undefined → MissingVariableError. The lone $ before is
	// passed through literally (the contract under test).
	if err == nil {
		t.Fatalf("expected error for missing X, got nil with output %q", got)
	}
	var mv MissingVariableError
	if !errors.As(err, &mv) {
		t.Errorf("expected MissingVariableError, got %T: %v", err, err)
	}
}

func TestExpandEnv_LoneDollarPassesThrough(t *testing.T) {
	got, err := ExpandEnv("price is $5 net")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "price is $5 net" {
		t.Errorf("lone `$` should pass through as-is, got %q", got)
	}
}

func TestExpandEnv_MissingVariableError(t *testing.T) {
	t.Setenv("KUBAUTH_TEST_DEFINED", "ok")
	_, err := ExpandEnv("foo=${KUBAUTH_TEST_NOT_DEFINED_XYZ_42}")
	if err == nil {
		t.Fatal("expected MissingVariableError")
	}
	var mv MissingVariableError
	if !errors.As(err, &mv) {
		t.Fatalf("expected MissingVariableError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "KUBAUTH_TEST_NOT_DEFINED_XYZ_42") {
		t.Errorf("error should mention the missing var name, got %q", err.Error())
	}
}

func TestExpandEnv_MissingVariableErrorReportsLineNumber(t *testing.T) {
	input := "line1: ok\nline2: ok\nline3: ${KUBAUTH_TEST_MISSING_LINE_TEST}"
	_, err := ExpandEnv(input)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "line 3") {
		t.Errorf("expected error to report 'line 3', got %q", err.Error())
	}
}

func TestExpandEnv_VariableInsideText(t *testing.T) {
	t.Setenv("KUBAUTH_TEST_NAME", "alice")
	got, err := ExpandEnv("hello ${KUBAUTH_TEST_NAME}, welcome")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hello alice, welcome" {
		t.Errorf("got %q", got)
	}
}

// TestExpandEnv_AdjacentVariables verifies that two `${...}` blocks with
// no separator between them both expand correctly. Prior to the
// `state = STATE_NOMINAL` reset after the closing `}`, the parser
// stayed in STATE_IN_VAR and consumed the next `$` as a non-`}` non-
// alphanumeric → silently dropped the second variable, producing
// `<A-value>${B}` instead of the concatenation.
func TestExpandEnv_AdjacentVariables(t *testing.T) {
	t.Setenv("KUBAUTH_TEST_A", "ab")
	t.Setenv("KUBAUTH_TEST_B", "cd")
	got, err := ExpandEnv("${KUBAUTH_TEST_A}${KUBAUTH_TEST_B}")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "abcd" {
		t.Errorf("got %q, want %q", got, "abcd")
	}
}

func TestExpandEnv_VariableNamesAcceptUnderscoreAndDigits(t *testing.T) {
	t.Setenv("KUBAUTH_TEST_VAR_42", "ok")
	got, err := ExpandEnv("v=${KUBAUTH_TEST_VAR_42}")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "v=ok" {
		t.Errorf("got %q", got)
	}
}

func TestExpandEnv_InvalidCharInVariableNameRejected(t *testing.T) {
	// `${FOO-BAR}` is not a valid variable name (hyphen not alphanumeric).
	// Per the parser: the whole `${...}` chunk is dropped from output and
	// treated as if no expansion happened. No error raised — by design.
	got, err := ExpandEnv("v=${FOO-BAR}")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "FOO-BAR") {
		t.Errorf("invalid var name should be passed through literally, got %q", got)
	}
}

func TestMissingVariableError_FormatsHumanReadable(t *testing.T) {
	err := MissingVariableError{line: 7, variable: "MY_VAR"}
	msg := err.Error()
	if !strings.Contains(msg, "MY_VAR") || !strings.Contains(msg, "line 7") {
		t.Errorf("error message should mention var name and line number, got %q", msg)
	}
}
