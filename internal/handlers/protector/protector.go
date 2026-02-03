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

// The Protector is a mechanism of protection against BFA.
// It introduce an increasing delay on response in case of failure on a given login
// After some period without failure, the history is cleanup up.
//

type LoginProtector interface {
	EntryForLogin(ctx context.Context, login string) (locked bool)
	ProtectLoginResult(ctx context.Context, login string, status proto.Status)
}

type TokenProtector interface {
	EntryForToken(ctx context.Context) (locked bool)
	TokenNotFound(ctx context.Context)
}

type Protector interface {
	LoginProtector
	TokenProtector
}
