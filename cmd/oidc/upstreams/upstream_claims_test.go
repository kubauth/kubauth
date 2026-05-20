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

package upstreams

import (
	"reflect"
	"testing"

	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"
)

func TestPerformRenaming_renameAndCopyOrder(t *testing.T) {
	u := &upstream{
		spec: kubauthv1alpha1.UpstreamProviderSpec{
			ClaimRenamings: []kubauthv1alpha1.ClaimRenamingSpec{
				{OldName: "a", NewName: "b", Operation: kubauthv1alpha1.RenamingOperationRename},
				{OldName: "b", NewName: "c", Operation: kubauthv1alpha1.RenamingOperationRename},
				{OldName: "x", NewName: "y", Operation: kubauthv1alpha1.RenamingOperationCopy},
			},
		},
	}
	in := ClaimSet{"a": "1", "x": "2", "keep": "k"}
	wantIn := cloneClaimSet(in)
	got := u.PerformRenaming(in)
	want := ClaimSet{"c": "1", "x": "2", "y": "2", "keep": "k"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
	if !reflect.DeepEqual(in, wantIn) {
		t.Fatalf("PerformRenaming mutated input: %#v", in)
	}
}

func TestPerformRenaming_newNameOverrides(t *testing.T) {
	u := &upstream{
		spec: kubauthv1alpha1.UpstreamProviderSpec{
			ClaimRenamings: []kubauthv1alpha1.ClaimRenamingSpec{
				{OldName: "from", NewName: "collision", Operation: kubauthv1alpha1.RenamingOperationRename},
			},
		},
	}
	got := u.PerformRenaming(ClaimSet{"from": "new", "collision": "old"})
	want := ClaimSet{"collision": "new"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestPerformRenaming_defaultOperationIsRename(t *testing.T) {
	u := &upstream{
		spec: kubauthv1alpha1.UpstreamProviderSpec{
			ClaimRenamings: []kubauthv1alpha1.ClaimRenamingSpec{
				{OldName: "a", NewName: "b"},
			},
		},
	}
	got := u.PerformRenaming(ClaimSet{"a": 1})
	want := ClaimSet{"b": 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestCleanupClaims_preservesSubRemovesRegisteredAndCustom(t *testing.T) {
	u := &upstream{
		spec: kubauthv1alpha1.UpstreamProviderSpec{
			ClaimRemovals: []string{"email", ""},
		},
	}
	in := ClaimSet{
		"sub":   "user-1",
		"iss":   "https://idp",
		"nonce": "n",
		"email": "a@b",
		"name":  "Ann",
	}
	wantIn := cloneClaimSet(in)
	got := u.CleanupClaims(in)
	want := ClaimSet{"sub": "user-1", "name": "Ann"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
	if !reflect.DeepEqual(in, wantIn) {
		t.Fatalf("CleanupClaims mutated input: %#v", in)
	}
}
