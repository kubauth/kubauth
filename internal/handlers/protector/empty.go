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
