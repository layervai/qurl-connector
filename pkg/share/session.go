package share

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	qurl "github.com/layervai/qurl-go/qurl"
)

// ErrResourceGone reports an authenticated permanent denial for a resource
// that no longer exists or is no longer assigned to this agent. Durable
// managers must stop retrying that resource without disturbing siblings.
var ErrResourceGone = errors.New("qURL share resource is permanently unavailable")

// Admission is one resource-bound NHP authorization. KnockResourceID is the
// q_ catalog key used to select ACTokens and ResourceHost from the ACK, while
// ResourceID is the public management resource sent in FRP metadata. They are
// intentionally separate identities.
type Admission struct {
	KnockResourceID string
	ResourceID      string
	RunID           string
	RunAttempt      uint64
	Token           string
	ResourceHost    string
	SessionID       uint64
	SessionReceipt  qurl.NativeSessionReceipt
	OpenTime        time.Duration
}

// String keeps the bearer AC token out of logs, assertions, and diagnostics.
// The remaining fields identify the exact session without granting access.
func (a Admission) String() string {
	return fmt.Sprintf("share.Admission{KnockResourceID:%q, ResourceID:%q, RunID:%q, RunAttempt:%d, Token:[REDACTED], ResourceHost:%q, SessionID:%d, SessionReceipt:{CellID:%q, SessionID:%d, SessionIssuedAtMillis:%d, RunID:%q, RunAttempt:%d}, OpenTime:%s}",
		a.KnockResourceID, a.ResourceID, a.RunID, a.RunAttempt, a.ResourceHost, a.SessionID,
		a.SessionReceipt.CellID, a.SessionReceipt.SessionID, a.SessionReceipt.SessionIssuedAtMillis,
		a.SessionReceipt.RunID, a.SessionReceipt.RunAttempt, a.OpenTime)
}

// GoString applies the same bearer redaction to %#v formatting.
func (a Admission) GoString() string { return a.String() }

// Admitter owns the native NHP runtime and creates immutable, resource-bound
// admissions. Retire closes only the exact receipt carried by its admission;
// it must never close a sibling or replacement session.
type Admitter interface {
	Admit(context.Context, string, string) (Admission, error)
	Retire(context.Context, Admission) error
}

// ServingSession is one FRP control session for one Admission. Ready closes
// only after every configured proxy reaches FRP's running phase, which occurs
// after NewProxy admission and RegisterProxy success.
type ServingSession interface {
	Ready() <-chan struct{}
	Done() <-chan struct{}
	Err() error
	Stop(context.Context) error
}

// drainingSession is implemented by sessions that can stop accepting new
// work while allowing an already-started request to finish.
type drainingSession interface {
	Drain(context.Context) error
}

// cycleDrainSet tracks retired cycles that are still draining. A drain retires
// the cycle's admission only after the session exits or the cleanup budget ends.
type cycleDrainSet struct {
	mu     sync.Mutex
	cycles map[*cycleDrain]struct{}
}

type cycleDrain struct {
	done   <-chan struct{}
	cancel context.CancelFunc
}

func (d *cycleDrainSet) start(session ServingSession, stopTimeout time.Duration, retire func()) {
	if session == nil {
		return
	}
	done := make(chan struct{})
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), stopTimeout)
	drainCtx, cancelDrain := context.WithCancel(cleanupCtx)
	drain := &cycleDrain{done: done, cancel: cancelDrain}
	d.mu.Lock()
	if d.cycles == nil {
		d.cycles = make(map[*cycleDrain]struct{})
	}
	d.cycles[drain] = struct{}{}
	d.mu.Unlock()
	go func() {
		defer func() {
			cancelDrain()
			cleanupCancel()
			close(done)
			d.mu.Lock()
			delete(d.cycles, drain)
			d.mu.Unlock()
		}()
		if draining, ok := session.(drainingSession); ok {
			_ = draining.Drain(drainCtx)
		} else {
			_ = session.Stop(drainCtx)
		}
		// Drain may return as soon as its context is canceled while the
		// underlying FRP control is still completing its bounded grace period.
		// Keep the cycle tracked until the session itself exits or the cleanup
		// budget is exhausted.
		select {
		case <-session.Done():
		case <-cleanupCtx.Done():
		}
		if retire != nil {
			retire()
		}
	}()
}

func (d *cycleDrainSet) stopAndWait(timeout time.Duration) {
	d.mu.Lock()
	drains := make([]*cycleDrain, 0, len(d.cycles))
	for drain := range d.cycles {
		drains = append(drains, drain)
	}
	d.mu.Unlock()
	if len(drains) == 0 {
		return
	}
	for _, drain := range drains {
		drain.cancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for _, drain := range drains {
		select {
		case <-drain.done:
		case <-ctx.Done():
			return
		}
	}
}

// retryAfter reports one failed attempt and sleeps the bounded delay. Time the
// callback consumes counts against the delay, and a canceled attempt is never
// reported as a retry.
func retryAfter(ctx context.Context, onRetry func(error, time.Duration), attemptErr error, wait time.Duration) error {
	retryAt := time.Now().Add(wait)
	if ctx.Err() == nil && attemptErr != nil && onRetry != nil {
		onRetry(attemptErr, wait)
	}
	remaining := time.Until(retryAt)
	if remaining <= 0 {
		// The callback consumed the delay, so the next attempt can start now.
		return ctx.Err()
	}
	return sleepWithContext(ctx, remaining)
}

func validateAdmission(a Admission, knockResourceID, resourceID string) error {
	if a.KnockResourceID != knockResourceID {
		return fmt.Errorf("NHP admission knock resource %q does not match requested %q", a.KnockResourceID, knockResourceID)
	}
	if a.ResourceID != resourceID {
		return fmt.Errorf("NHP admission public resource %q does not match requested %q", a.ResourceID, resourceID)
	}
	if a.RunID == "" || a.Token == "" {
		return errors.New("NHP admission is missing run ID or token")
	}
	if err := validateAdmissionReceipt(a); err != nil {
		return err
	}
	if a.SessionID == 0 {
		return errors.New("NHP admission session ID is zero")
	}
	if a.OpenTime <= 0 {
		return errors.New("NHP admission open time is not positive")
	}
	if _, _, err := net.SplitHostPort(a.ResourceHost); err != nil {
		return fmt.Errorf("NHP admission resource host is not canonical host:port: %w", err)
	}
	return nil
}

func validateAdmissionReceipt(a Admission) error {
	receipt := a.SessionReceipt
	if a.RunAttempt == 0 || receipt.CellID == "" || receipt.SessionID == 0 ||
		receipt.SessionIssuedAtMillis <= 0 || receipt.RunID == "" || receipt.RunAttempt == 0 ||
		receipt.SessionID != a.SessionID || receipt.RunID != a.RunID || receipt.RunAttempt != a.RunAttempt {
		return errors.New("NHP admission has an invalid exact-session receipt")
	}
	return nil
}

func rotationLead(openTime, configured time.Duration) time.Duration {
	if configured > 0 {
		if configured >= openTime {
			return openTime / 2
		}
		return configured
	}
	lead := openTime / 4
	if lead < time.Second {
		lead = time.Second
	}
	if lead > 30*time.Second {
		lead = 30 * time.Second
	}
	if lead >= openTime {
		lead = openTime / 2
	}
	return lead
}

func retireAdmission(admitter Admitter, admission Admission, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return admitter.Retire(ctx, admission)
}

func stopServingSession(session ServingSession, timeout time.Duration) {
	if session == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_ = session.Stop(ctx)
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func jitter(d time.Duration) time.Duration {
	if d <= time.Nanosecond {
		return d
	}
	half := d / 2
	return half + time.Duration(rand.Int64N(int64(d-half)))
}

func nextBackoff(current, maximum time.Duration) time.Duration {
	if current >= maximum/2 {
		return maximum
	}
	return current * 2
}

func stopTimer(timer *time.Timer) {
	if timer == nil || !timer.Stop() {
		return
	}
}
