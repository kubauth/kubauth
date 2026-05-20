/*
Copyright (c) 2025 Kubotal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package misc

import (
	"reflect"
	"testing"
)

func TestMergeMaps_secondOverridesScalarsAndAddsKeys(t *testing.T) {
	a := map[string]interface{}{
		"x": 1,
		"y": "from-a",
	}
	b := map[string]interface{}{
		"x": 2,
		"z": true,
	}
	got := MergeMaps(a, b)
	want := map[string]interface{}{
		"x": 2,
		"y": "from-a",
		"z": true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MergeMaps() = %#v, want %#v", got, want)
	}
}

func TestMergeMaps_nestedMapsMergedRecursively(t *testing.T) {
	a := map[string]interface{}{
		"nested": map[string]interface{}{
			"k1": "a1",
			"k2": "a2",
		},
	}
	b := map[string]interface{}{
		"nested": map[string]interface{}{
			"k2": "b2",
			"k3": "b3",
		},
	}
	got := MergeMaps(a, b)
	want := map[string]interface{}{
		"nested": map[string]interface{}{
			"k1": "a1",
			"k2": "b2",
			"k3": "b3",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MergeMaps() = %#v, want %#v", got, want)
	}
}

func TestMergeMaps_nestedMapInBReplacesNonMapInA(t *testing.T) {
	a := map[string]interface{}{
		"nested": "scalar",
	}
	b := map[string]interface{}{
		"nested": map[string]interface{}{"k": "v"},
	}
	got := MergeMaps(a, b)
	want := map[string]interface{}{
		"nested": map[string]interface{}{"k": "v"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MergeMaps() = %#v, want %#v", got, want)
	}
}

func TestMergeMaps_stringSlicesDedupedConcatenation(t *testing.T) {
	tests := []struct {
		name string
		a, b map[string]interface{}
		want []string
	}{
		{
			name: "dedupe across both with order a then new from b",
			a:    map[string]interface{}{"scopes": []string{"openid", "profile"}},
			b:    map[string]interface{}{"scopes": []string{"email", "openid"}},
			want: []string{"openid", "profile", "email"},
		},
		{
			name: "duplicates within first slice",
			a:    map[string]interface{}{"scopes": []string{"a", "a", "b"}},
			b:    map[string]interface{}{"scopes": []string{"c"}},
			want: []string{"a", "b", "c"},
		},
		{
			name: "only in b still merged when a has empty slice",
			a:    map[string]interface{}{"scopes": []string{}},
			b:    map[string]interface{}{"scopes": []string{"x", "y"}},
			want: []string{"x", "y"},
		},
		{
			name: "key only in b",
			a:    map[string]interface{}{},
			b:    map[string]interface{}{"scopes": []string{"offline"}},
			want: []string{"offline"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeMaps(tt.a, tt.b)
			raw, ok := got["scopes"]
			if !ok {
				t.Fatal("missing scopes key")
			}
			gotSlice, ok := raw.([]string)
			if !ok {
				t.Fatalf("scopes type %T, want []string", raw)
			}
			if !reflect.DeepEqual(gotSlice, tt.want) {
				t.Fatalf("scopes = %#v, want %#v", gotSlice, tt.want)
			}
		})
	}
}

func TestMergeMaps_nonStringSliceOverridesStringSlice(t *testing.T) {
	a := map[string]interface{}{
		"scopes": []string{"openid"},
	}
	b := map[string]interface{}{
		"scopes": "not-a-slice",
	}
	got := MergeMaps(a, b)
	if got["scopes"] != "not-a-slice" {
		t.Fatalf("MergeMaps() scopes = %#v, want string override", got["scopes"])
	}
}

func TestMergeMaps_stringSliceOverridesNonSlice(t *testing.T) {
	a := map[string]interface{}{
		"scopes": 42,
	}
	b := map[string]interface{}{
		"scopes": []string{"openid"},
	}
	got := MergeMaps(a, b)
	raw := got["scopes"]
	gotSlice, ok := raw.([]string)
	if !ok {
		t.Fatalf("scopes type %T, want []string", raw)
	}
	if !reflect.DeepEqual(gotSlice, []string{"openid"}) {
		t.Fatalf("scopes = %#v", gotSlice)
	}
}

func TestMergeMaps_emptyInputs(t *testing.T) {
	if got := MergeMaps(nil, nil); len(got) != 0 {
		t.Fatalf("MergeMaps(nil,nil) = %#v, want empty map", got)
	}
	a := map[string]interface{}{"k": "v"}
	if got := MergeMaps(a, nil); !reflect.DeepEqual(got, a) {
		t.Fatalf("MergeMaps(a,nil) = %#v, want %#v", got, a)
	}
	if got := MergeMaps(nil, a); !reflect.DeepEqual(got, a) {
		t.Fatalf("MergeMaps(nil,a) = %#v, want %#v", got, a)
	}
}

func TestMergeMaps_doesNotMutateInputs(t *testing.T) {
	a := map[string]interface{}{
		"nested": map[string]interface{}{"k": "a"},
		"scopes": []string{"openid"},
	}
	b := map[string]interface{}{
		"nested": map[string]interface{}{"k": "b"},
		"scopes": []string{"profile"},
	}
	aCopy := map[string]interface{}{
		"nested": map[string]interface{}{"k": "a"},
		"scopes": []string{"openid"},
	}
	bCopy := map[string]interface{}{
		"nested": map[string]interface{}{"k": "b"},
		"scopes": []string{"profile"},
	}
	_ = MergeMaps(a, b)
	if !reflect.DeepEqual(a, aCopy) {
		t.Errorf("first map mutated: %#v", a)
	}
	if !reflect.DeepEqual(b, bCopy) {
		t.Errorf("second map mutated: %#v", b)
	}
}

func TestNormalizeStringArray_allStringSlice(t *testing.T) {
	in := map[string]interface{}{
		"scopes": []interface{}{"openid", "email"},
	}
	got := NormalizeStringArray(in)
	want := map[string]interface{}{
		"scopes": []string{"openid", "email"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	if !reflect.DeepEqual(in, map[string]interface{}{
		"scopes": []interface{}{"openid", "email"},
	}) {
		t.Fatal("input mutated")
	}
}

func TestNormalizeStringArray_nestedMapAndMixedSlice(t *testing.T) {
	in := map[string]interface{}{
		"nested": map[string]interface{}{
			"roles": []interface{}{"a", "b"},
		},
		"mixed": []interface{}{"x", 1},
	}
	got := NormalizeStringArray(in)
	nested := got["nested"].(map[string]interface{})
	if roles, ok := nested["roles"].([]string); !ok || !reflect.DeepEqual(roles, []string{"a", "b"}) {
		t.Fatalf("nested roles = %#v", nested["roles"])
	}
	mixed, ok := got["mixed"].([]interface{})
	if !ok || len(mixed) != 2 {
		t.Fatalf("mixed = %#v", got["mixed"])
	}
	if mixed[0] != "x" || mixed[1] != 1 {
		t.Fatalf("mixed elements = %#v", mixed)
	}
}

func TestNormalizeStringArray_nilMap(t *testing.T) {
	if got := NormalizeStringArray(nil); got != nil {
		t.Fatalf("got %#v, want nil", got)
	}
}
