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

// MergeMaps merge two maps and return a new one.
// Second parameter map will override the first one, except:
// for a given key, if both values are []string, the result is deduplicated concatenation
// (elements from the first map in order, then from the second, skipping duplicates).
// Nested map[string]interface{} values are merged recursively.
// Initial version from https://github.com/helm/helm/blob/v3.14.1/pkg/cli/values/options.go
func MergeMaps(a, b map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(a))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		if v, ok := v.(map[string]interface{}); ok {
			if bv, ok := out[k]; ok {
				if bv, ok := bv.(map[string]interface{}); ok {
					out[k] = MergeMaps(bv, v)
					continue
				}
			}
		}
		if vb, ok := v.([]string); ok {
			if va, ok := out[k].([]string); ok {
				out[k] = mergeStringSlicesDeduped(va, vb)
				continue
			}
		}
		out[k] = v
	}
	return out
}

func mergeStringSlicesDeduped(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, s := range b {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// NormalizeStringArray walks the map recursively. For each value of type []interface{},
// if every element is a string, it is replaced with []string; otherwise the slice is
// left as []interface{} but its elements are still normalized when they are maps or slices.
// Nested map[string]interface{} values are normalized recursively.
// The input map is not modified; a new map is returned.
// We need this function as json/yaml unmarshalling may return []interface{} for what can be a []string
func NormalizeStringArray(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = normalizeStringArrayValue(v)
	}
	return out
}

func normalizeStringArrayValue(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		return NormalizeStringArray(t)
	case []interface{}:
		if ss, ok := interfaceSliceToStringSlice(t); ok {
			return ss
		}
		out := make([]interface{}, len(t))
		for i, e := range t {
			out[i] = normalizeStringArrayValue(e)
		}
		return out
	default:
		return v
	}
}

// interfaceSliceToStringSlice reports whether every element of in is a string and returns that []string.
// A nil slice yields (nil, true).
func interfaceSliceToStringSlice(in []interface{}) ([]string, bool) {
	if in == nil {
		return nil, true
	}
	out := make([]string, len(in))
	for i, e := range in {
		s, ok := e.(string)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}
