/*
Copyright (c) 2025 Kubotal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package misc

import (
	"reflect"
	"strings"
	"testing"
)

func TestBoolPtrFalse(t *testing.T) {
	tt := true
	ff := false
	cases := []struct {
		name string
		in   *bool
		want bool
	}{
		{"nil → false", nil, false},
		{"&true → true", &tt, true},
		{"&false → false", &ff, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := BoolPtrFalse(tc.in); got != tc.want {
				t.Errorf("BoolPtrFalse(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestBoolPtrTrue(t *testing.T) {
	tt := true
	ff := false
	cases := []struct {
		name string
		in   *bool
		want bool
	}{
		{"nil → true (default)", nil, true},
		{"&true → true", &tt, true},
		{"&false → false", &ff, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := BoolPtrTrue(tc.in); got != tc.want {
				t.Errorf("BoolPtrTrue(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestShortenString(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty stays empty", "", ""},
		{"30 chars stays whole", strings.Repeat("a", 30), strings.Repeat("a", 30)},
		{"31 chars gets shortened", strings.Repeat("a", 31), "aaaaaaaaaa.......aaaaaaaaaa"},
		{"long token is shortened with marker", "abcdefghij" + strings.Repeat("Z", 50) + "0123456789", "abcdefghij.......0123456789"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ShortenString(tc.in)
			if got != tc.want {
				t.Errorf("ShortenString(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestDedupAndSort(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil input → empty slice", nil, []string{}},
		{"empty input → empty slice", []string{}, []string{}},
		{"unique already sorted", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"sorts unsorted unique", []string{"c", "a", "b"}, []string{"a", "b", "c"}},
		{"removes duplicates", []string{"b", "a", "b", "c", "a"}, []string{"a", "b", "c"}},
		{"single element", []string{"x"}, []string{"x"}},
		{"all duplicates", []string{"x", "x", "x"}, []string{"x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DedupAndSort(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("DedupAndSort(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestAppendIfNotPresent(t *testing.T) {
	cases := []struct {
		name  string
		slice []string
		items []string
		want  []string
	}{
		{
			name:  "appends new items in order",
			slice: []string{"a", "b"},
			items: []string{"c", "d"},
			want:  []string{"a", "b", "c", "d"},
		},
		{
			name:  "skips items already in slice",
			slice: []string{"a", "b"},
			items: []string{"b", "c"},
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "deduplicates within items",
			slice: []string{"a"},
			items: []string{"b", "b", "c", "c"},
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "empty items: slice unchanged",
			slice: []string{"a", "b"},
			items: nil,
			want:  []string{"a", "b"},
		},
		{
			name:  "empty slice: items dedup'd into result",
			slice: nil,
			items: []string{"x", "y", "x"},
			want:  []string{"x", "y"},
		},
		{
			name:  "preserves slice order even when items reordered",
			slice: []string{"z", "a"},
			items: []string{"a", "z", "b"},
			want:  []string{"z", "a", "b"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AppendIfNotPresent(tc.slice, tc.items)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("AppendIfNotPresent(%v, %v) = %v, want %v", tc.slice, tc.items, got, tc.want)
			}
		})
	}
}

func TestCountTrue(t *testing.T) {
	cases := []struct {
		name string
		in   []bool
		want int
	}{
		{"none", nil, 0},
		{"all false", []bool{false, false, false}, 0},
		{"all true", []bool{true, true, true}, 3},
		{"mixed", []bool{true, false, true, false, true}, 3},
		{"single true", []bool{true}, 1},
		{"single false", []bool{false}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CountTrue(tc.in...)
			if got != tc.want {
				t.Errorf("CountTrue(%v) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}
