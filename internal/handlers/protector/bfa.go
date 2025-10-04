package protector

import (
	"context"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/util/wait"
	"kubauth/internal/proto"
	"sync"
	"sync/atomic"
	"time"
)

var _ Protector = &bfaProtector{}

type loginState struct {
	lastFailure     time.Time
	nbrOfFailure    int64
	pendingFailures atomic.Int64 // Access is NOT protected by some mutex
}

type bfaProtector struct {
	mu                sync.Mutex
	stateByLogin      map[string]*loginState
	cleanerPeriod     time.Duration
	cleanDelay        time.Duration
	freeFailure       int64 // No delay introduced up to this value
	maxPenalty        time.Duration
	penaltyByFailure  time.Duration
	maxPendingFailure int64
}

const UnknownUser = "_unknownUser_"
const UnknownToken = "_unknownToken_"

type Option func(*bfaProtector)

// WithCleanerPeriod define the period if the cleanup processing
func WithCleanerPeriod(cleanerPeriod time.Duration) Option {
	return func(p *bfaProtector) {
		p.cleanerPeriod = cleanerPeriod
	}
}

// WithCleanDelay For a login, the failure history is cleaned up if there no new failure during this delay
func WithCleanDelay(cd time.Duration) Option {
	return func(p *bfaProtector) {
		p.cleanDelay = cd
	}
}

// WithFreeFailure Nbr of failure allowed before introducing a delay
func WithFreeFailure(ff int64) Option {
	return func(p *bfaProtector) {
		p.freeFailure = ff
	}
}

// WithMaxPenalty The introduced delay is capped to this value
func WithMaxPenalty(mp time.Duration) Option {
	return func(p *bfaProtector) {
		p.maxPenalty = mp
	}
}

// WithPenaltyByFailure Increment step introduced by failure
func WithPenaltyByFailure(pbf time.Duration) Option {
	return func(p *bfaProtector) {
		p.penaltyByFailure = pbf
	}
}

func WithMaxPendingFailure(mpf int64) Option {
	return func(p *bfaProtector) {
		p.maxPendingFailure = mpf
	}
}

// New build a new bfaProtector against Brut Force Attack.
// Return nil if !activated. It is up to the caller to test at run time
func New(activated bool, ctx context.Context, opts ...Option) Protector {
	logger := logr.FromContextAsSlogLogger(ctx)
	if !activated {
		logger.Info("BFA Protection NOT activated")
		return &empty{}
	}
	logger.Info("BFA Protection activated")
	p := &bfaProtector{
		stateByLogin:      make(map[string]*loginState),
		cleanerPeriod:     60 * time.Second,
		cleanDelay:        30 * time.Minute,
		freeFailure:       4,
		maxPenalty:        15 * time.Second,
		penaltyByFailure:  1 * time.Second,
		maxPendingFailure: 20,
	}
	for _, opt := range opts {
		opt(p)
	}
	logger.Info("BFA Cleaner start")
	go wait.Until(func() {
		p.clean(ctx)
	}, p.cleanerPeriod, ctx.Done())
	return p
}

func (p *bfaProtector) EntryForLogin(ctx context.Context, login string) bool /*locked*/ {
	logger := logr.FromContextAsSlogLogger(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	state, ok := p.stateByLogin[login]
	if ok && state.pendingFailures.Load() > p.maxPendingFailure {
		logger.Info("*******WARNING: Too many pending password failing request. May be an attack ", "login", login)
		return true
	}
	state, ok = p.stateByLogin[UnknownUser]
	if ok && state.pendingFailures.Load() > p.maxPendingFailure {
		logger.Info("*******WARNING: Too many pending user failing request. May be an attack ", "login", login)
		return true
	}
	logger.Debug("bfaProtector.EntryForLogin()", "login", login)
	return false
}

func (p *bfaProtector) EntryForToken(ctx context.Context) bool /*locked*/ {
	p.mu.Lock()
	defer p.mu.Unlock()
	logger := logr.FromContextAsSlogLogger(ctx)
	state, ok := p.stateByLogin[UnknownToken]
	if ok && state.pendingFailures.Load() > p.maxPendingFailure {
		logger.Info("*******WARNING: Too many pending token failing request. May be an attack ")
		return true
	}
	logger.Debug("bfaProtector.EntryForToken()")
	return false
}

func (p *bfaProtector) failure(ctx context.Context, login string) {
	logger := logr.FromContextAsSlogLogger(ctx)
	logger.Debug("bfaProtector.Failure(1/2)", "login", login)
	p.mu.Lock()
	state, ok := p.stateByLogin[login]
	if !ok {
		state = &loginState{}
		p.stateByLogin[login] = state
	}
	state.lastFailure = time.Now()
	state.nbrOfFailure++
	nbrOfFailure := state.nbrOfFailure
	p.mu.Unlock()
	delay := p.delayFromFailureCount(nbrOfFailure)
	logger.Info("bfaProtector.failure", "login", login, "failureCount", nbrOfFailure, "delay", delay.String(), "pendingFailure", state.pendingFailures.Load())
	state.pendingFailures.Add(1)
	time.Sleep(delay)
	state.pendingFailures.Add(-1)
	logger.Debug("bfaProtector.Failure(2/2)", "login", login)
}

func (p *bfaProtector) TokenNotFound(ctx context.Context) {
	p.failure(ctx, UnknownToken)
}

//func (p *bfaProtector) ProtectLoginResult(login string, status proto.Status) {
//	if status == proto.UserNotFound {
//		p.failure(UnknownUser)
//	} else if status == proto.PasswordFail || status == proto.InvalidOldPassword {
//		p.failure(login)
//	}
//}

// We removed protection against UserNotFound, as this is a normal case in a multi-provider context

func (p *bfaProtector) ProtectLoginResult(ctx context.Context, login string, status proto.Status) {
	if status == proto.PasswordFail || status == proto.InvalidOldPassword {
		p.failure(ctx, login)
	}
}

func (p *bfaProtector) clean(ctx context.Context) {
	logger := logr.FromContextAsSlogLogger(ctx)
	logger.Debug("bfaProtector.clean.tick")
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for k, v := range p.stateByLogin {
		if v.lastFailure.Add(p.cleanDelay).Before(now) {
			logger.Info("bfaProtector.clean", "login", k)
			delete(p.stateByLogin, k)
		}
	}
}

func (p *bfaProtector) delayFromFailureCount(count int64) time.Duration {
	if count <= p.freeFailure {
		return 0
	}
	penalty := time.Duration(count-p.freeFailure) * p.penaltyByFailure
	if penalty > p.maxPenalty {
		penalty = p.maxPenalty
	}
	return penalty
}
