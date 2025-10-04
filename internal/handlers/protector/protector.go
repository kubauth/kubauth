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
