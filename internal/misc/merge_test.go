/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package misc

import (
	"reflect"
	"testing"
)

func TestMergeMaps_BOverridesA(t *testing.T) {
	a := map[string]interface{}{"name": "alice", "uid": 1000}
	b := map[string]interface{}{"name": "bob"}
	got := MergeMaps(a, b)
	want := map[string]interface{}{"name": "bob", "uid": 1000}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestMergeMaps_DisjointKeys(t *testing.T) {
	a := map[string]interface{}{"x": 1}
	b := map[string]interface{}{"y": 2}
	got := MergeMaps(a, b)
	want := map[string]interface{}{"x": 1, "y": 2}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestMergeMaps_NestedMapsRecursivelyMerged(t *testing.T) {
	a := map[string]interface{}{
		"profile": map[string]interface{}{
			"name":  "alice",
			"email": "alice@example.org",
		},
	}
	b := map[string]interface{}{
		"profile": map[string]interface{}{
			"name":   "alice-renamed",
			"groups": []string{"admin"},
		},
	}
	got := MergeMaps(a, b)
	want := map[string]interface{}{
		"profile": map[string]interface{}{
			"name":   "alice-renamed",
			"email":  "alice@example.org",
			"groups": []string{"admin"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestMergeMaps_NestedTypeMismatchOverwrites(t *testing.T) {
	// `a` has a map under "k", `b` has a scalar — `b` wins, no merge.
	a := map[string]interface{}{
		"k": map[string]interface{}{"inner": 1},
	}
	b := map[string]interface{}{
		"k": "scalar-now",
	}
	got := MergeMaps(a, b)
	want := map[string]interface{}{"k": "scalar-now"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestMergeMaps_DoesNotMutateInputs(t *testing.T) {
	a := map[string]interface{}{"x": 1}
	aCopy := map[string]interface{}{"x": 1}
	b := map[string]interface{}{"y": 2}
	bCopy := map[string]interface{}{"y": 2}
	_ = MergeMaps(a, b)
	if !reflect.DeepEqual(a, aCopy) {
		t.Errorf("a was mutated: got %v, want %v", a, aCopy)
	}
	if !reflect.DeepEqual(b, bCopy) {
		t.Errorf("b was mutated: got %v, want %v", b, bCopy)
	}
}

func TestMergeMaps_EmptyInputs(t *testing.T) {
	if got := MergeMaps(map[string]interface{}{}, map[string]interface{}{}); len(got) != 0 {
		t.Errorf("two empty maps → expected empty, got %v", got)
	}
	a := map[string]interface{}{"k": "v"}
	if got := MergeMaps(a, map[string]interface{}{}); !reflect.DeepEqual(got, a) {
		t.Errorf("empty b → expected a unchanged, got %v", got)
	}
	if got := MergeMaps(map[string]interface{}{}, a); !reflect.DeepEqual(got, a) {
		t.Errorf("empty a → expected b unchanged, got %v", got)
	}
}
