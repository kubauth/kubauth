/*
Copyright (c) Kubotal 2025.

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

package protector

import (
	"context"
	"kubauth/internal/proto"
)

var _ Protector = &empty{}

type empty struct{}

func (e empty) ProtectLoginResult(ctx context.Context, login string, status proto.Status) {
}

func (e empty) EntryForLogin(ctx context.Context, login string) (locked bool) {
	return false
}

func (e empty) EntryForToken(ctx context.Context) (locked bool) {
	return false
}

func (e empty) TokenNotFound(ctx context.Context) {
}
