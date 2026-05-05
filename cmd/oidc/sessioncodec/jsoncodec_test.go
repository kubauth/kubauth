/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package sessioncodec

import (
	"reflect"
	"testing"
	"time"
)

func TestJSONCodec_RoundTripPreservesDeadlineAndValues(t *testing.T) {
	deadline := time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)
	values := map[string]interface{}{
		"login":   "alice",
		"groups":  []interface{}{"admin", "users"},
		"counter": float64(42), // JSON numbers decode as float64
	}

	codec := JSONCodec{}
	encoded, err := codec.Encode(deadline, values)
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}
	if len(encoded) == 0 {
		t.Fatalf("Encode produced empty payload")
	}

	gotDeadline, gotValues, err := codec.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if !gotDeadline.Equal(deadline) {
		t.Errorf("deadline mismatch: got %v, want %v", gotDeadline, deadline)
	}
	if !reflect.DeepEqual(gotValues, values) {
		t.Errorf("values mismatch:\n got  %v\n want %v", gotValues, values)
	}
}

func TestJSONCodec_DecodeEmptyBytesReturnsZeroDeadlineAndEmptyMap(t *testing.T) {
	codec := JSONCodec{}
	gotDeadline, gotValues, err := codec.Decode(nil)
	if err != nil {
		t.Fatalf("Decode(nil) returned error: %v", err)
	}
	if !gotDeadline.IsZero() {
		t.Errorf("Decode(nil) deadline should be zero, got %v", gotDeadline)
	}
	if gotValues == nil {
		t.Errorf("Decode(nil) values should be empty map, not nil")
	}
	if len(gotValues) != 0 {
		t.Errorf("Decode(nil) values should be empty, got %v", gotValues)
	}

	// Same expectations for an empty-byte slice (distinct from nil in Go).
	gotDeadline, gotValues, err = codec.Decode([]byte{})
	if err != nil {
		t.Fatalf("Decode([]) returned error: %v", err)
	}
	if !gotDeadline.IsZero() {
		t.Errorf("Decode([]) deadline should be zero, got %v", gotDeadline)
	}
	if gotValues == nil || len(gotValues) != 0 {
		t.Errorf("Decode([]) values should be empty map, got %v", gotValues)
	}
}

func TestJSONCodec_DecodeInvalidJSONErrors(t *testing.T) {
	codec := JSONCodec{}
	_, _, err := codec.Decode([]byte("not-valid-json{{"))
	if err == nil {
		t.Errorf("Decode of invalid JSON should error")
	}
}

func TestJSONCodec_DecodeNilValuesYieldsEmptyMap(t *testing.T) {
	// Hand-craft a payload where Values is JSON null — Decode must
	// normalise to an empty (non-nil) map so downstream
	// `session.Get(...)` is safe to call.
	codec := JSONCodec{}
	payload := []byte(`{"deadline":"2025-01-01T00:00:00Z","values":null}`)
	_, gotValues, err := codec.Decode(payload)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if gotValues == nil {
		t.Errorf("expected empty map for null values, got nil")
	}
	if len(gotValues) != 0 {
		t.Errorf("expected empty map for null values, got %v", gotValues)
	}
}

func TestJSONCodec_EncodeNilValuesDoesNotPanic(t *testing.T) {
	codec := JSONCodec{}
	deadline := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	encoded, err := codec.Encode(deadline, nil)
	if err != nil {
		t.Fatalf("Encode(nil values) error: %v", err)
	}
	// Round-trip and confirm Decode normalises back to empty map.
	_, gotValues, err := codec.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if gotValues == nil || len(gotValues) != 0 {
		t.Errorf("expected empty map after round-trip from nil, got %v", gotValues)
	}
}

func TestJSONCodec_EncodeProducesValidJSON(t *testing.T) {
	codec := JSONCodec{}
	deadline := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	values := map[string]interface{}{"key": "value"}
	encoded, err := codec.Encode(deadline, values)
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}
	// Sanity: must be ASCII JSON object starting with {.
	if len(encoded) < 2 || encoded[0] != '{' || encoded[len(encoded)-1] != '}' {
		t.Errorf("encoded payload doesn't look like a JSON object: %s", encoded)
	}
}
