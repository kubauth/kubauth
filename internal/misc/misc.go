/*
Copyright (c) 2025 Kubotal.

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
	"fmt"
	"sort"
)

func SafeBoolPtr(p *bool) bool {
	if p == nil {
		return false
	}
	return *p
}

func ShortenString(str string) string {
	if len(str) <= 30 {
		return str
	} else {
		return fmt.Sprintf("%s.......%s", str[:10], str[len(str)-10:])
	}
}

func DedupAndSort(stringSlice []string) []string {
	keys := make(map[string]bool)
	list := make([]string, 0, len(stringSlice))
	for _, entry := range stringSlice {
		if _, exists := keys[entry]; !exists {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	sort.Strings(list)
	return list
}

// AppendIfNotPresent Aim is to preserve order
// append items at the end of slice, if item is not already present is slice
func AppendIfNotPresent(slice []string, items []string) []string {
	// Create a map to track existing items for O(1) lookup
	existing := make(map[string]bool, len(slice))
	for _, item := range slice {
		existing[item] = true
	}

	// Append items that are not already present
	for _, item := range items {
		if !existing[item] {
			slice = append(slice, item)
			existing[item] = true // Mark as added to avoid duplicates within items
		}
	}

	return slice
}
