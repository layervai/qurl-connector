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

// SerialAdmitter protects native runtimes whose binding cannot safely execute
// concurrent knocks. The lock covers both admission and local retirement, but
// never the lifetime of the resulting FRP session.
type SerialAdmitter struct {
	inner Admitter
	mu    sync.Mutex
}

func NewSerialAdmitter(inner Admitter) (*SerialAdmitter, error) {
	if inner == nil {
		return nil, errors.New("build serialized NHP admitter: admitter is nil")
	}
	return &SerialAdmitter{inner: inner}, nil
}

func (a *SerialAdmitter) Admit(ctx context.Context, knockResourceID, resourceID string) (Admission, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.inner.Admit(ctx, knockResourceID, resourceID)
}

func (a *SerialAdmitter) Retire(ctx context.Context, admission Admission) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.inner.Retire(ctx, admission)
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
// work while allowing an already-started request to finish. ResourceRunner
// uses it only after a replacement has reached serving.
type drainingSession interface {
	Drain(context.Context) error
}

// SessionFactory starts an FRP session from one immutable admission. The
// context bounds construction and readiness setup; a returned session owns
// its serving lifetime until Stop or Drain. A factory must stamp
// Admission.ResourceID into FRP metadata and use the token, run ID, session
// ID, and ResourceHost from that same Admission.
type SessionFactory interface {
	Start(context.Context, Admission) (ServingSession, error)
}

type ResourceConfig struct {
	KnockResourceID string
	ResourceID      string
	Admitter        Admitter
	Sessions        SessionFactory

	MinBackoff   time.Duration
	MaxBackoff   time.Duration
	RotationLead time.Duration
	StopTimeout  time.Duration
	OnServing    func(Admission)
	// OnRetry reports a failed admission or connection attempt and the
	// bounded delay before the next attempt. The error may come from the
	// configured Admitter or SessionFactory, connector-side validation, cleanup,
	// or deadline handling; it is not guaranteed to be safe for persistent logs.
	// It does not report terminal rotation expiry or a serving session exit. The
	// callback must return promptly.
	OnRetry func(error, time.Duration)
}

// ResourceRunner maintains one resource-bound NHP/FRP route. Renewal is
// make-before-break: a replacement must become serving before the prior FRP
// session is retired.
type ResourceRunner struct {
	cfg ResourceConfig
}

func NewResourceRunner(cfg ResourceConfig) (*ResourceRunner, error) {
	if cfg.KnockResourceID == "" {
		return nil, errors.New("build resource session: knock resource ID is empty")
	}
	if cfg.ResourceID == "" {
		return nil, errors.New("build resource session: public resource ID is empty")
	}
	if cfg.Admitter == nil {
		return nil, errors.New("build resource session: admitter is nil")
	}
	if cfg.Sessions == nil {
		return nil, errors.New("build resource session: session factory is nil")
	}
	if cfg.MinBackoff < 0 || cfg.MaxBackoff < 0 || cfg.RotationLead < 0 || cfg.StopTimeout < 0 {
		return nil, errors.New("build resource session: durations cannot be negative")
	}
	if cfg.MinBackoff == 0 {
		cfg.MinBackoff = time.Second
	}
	if cfg.MaxBackoff == 0 {
		cfg.MaxBackoff = 30 * time.Second
	}
	if cfg.MaxBackoff < cfg.MinBackoff {
		return nil, errors.New("build resource session: max backoff is below min backoff")
	}
	if cfg.StopTimeout == 0 {
		cfg.StopTimeout = 5 * time.Second
	}
	return &ResourceRunner{cfg: cfg}, nil
}

// Run serves until ctx ends. Admission and connection failures retry forever
// with bounded jitter so sleep, wake, and transient network loss require no
// operator action.
func (r *ResourceRunner) Run(ctx context.Context) (retErr error) {
	if ctx == nil {
		return errors.New("run resource session: context is nil")
	}
	var active *resourceCycle
	var drains cycleDrainSet
	backoff := r.cfg.MinBackoff
	defer drains.stopAndWait(r.cfg.StopTimeout)
	defer func() { retErr = errors.Join(retErr, r.stopCycle(active)) }()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if active == nil {
			cycle, err := r.startReadyCycle(ctx, nil)
			if err != nil {
				if errors.Is(err, ErrResourceGone) {
					return err
				}
				wait := jitter(backoff)
				if retryErr := r.waitToRetry(ctx, err, wait); retryErr != nil {
					return retryErr
				}
				backoff = nextBackoff(backoff, r.cfg.MaxBackoff)
				continue
			}
			active = cycle
			backoff = r.cfg.MinBackoff
			if r.cfg.OnServing != nil {
				r.cfg.OnServing(active.admission)
			}
		}

		rotate := time.NewTimer(time.Until(active.rotateAt))
		select {
		case <-ctx.Done():
			stopTimer(rotate)
			return ctx.Err()
		case <-active.session.Done():
			stopTimer(rotate)
			sessionErr := active.session.Err()
			retireErr := r.stopCycle(active)
			active = nil
			if errors.Is(sessionErr, ErrResourceGone) {
				return errors.Join(sessionErr, retireErr)
			}
			if retireErr != nil {
				return errors.Join(sessionErr, retireErr)
			}
		case <-rotate.C:
			replacement, err := r.startReadyCycle(ctx, active)
			if err != nil {
				if errors.Is(err, ErrResourceGone) {
					return err
				}
				// Keep the old serving session while a replacement is still
				// possible. startReadyCycle already bounds its attempt by the
				// old authorization deadline.
				if time.Now().Before(active.expiresAt) {
					continue
				}
				if retireErr := r.stopCycle(active); retireErr != nil {
					return errors.Join(err, retireErr)
				}
				active = nil
				continue
			}
			old := active
			active = replacement
			if r.cfg.OnServing != nil {
				r.cfg.OnServing(active.admission)
			}
			drains.start(old.session, r.cfg.StopTimeout, func() { _ = r.retireAdmission(old.admission) })
		}
	}
}

// cycleDrainSet tracks retired cycles that are still draining. It is shared
// by ResourceRunner and SessionGroupRunner; a drain retires the cycle's
// admission only after the session itself exits or the cleanup budget ends.
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

type resourceCycle struct {
	admission Admission
	session   ServingSession
	expiresAt time.Time
	rotateAt  time.Time
}

func (r *ResourceRunner) startReadyCycle(ctx context.Context, old *resourceCycle) (*resourceCycle, error) {
	backoff := r.cfg.MinBackoff
	for {
		cycle, err := r.startCycleAttempt(ctx, old)
		if err == nil || old == nil {
			return cycle, err
		}
		if errors.Is(err, ErrResourceGone) {
			return nil, err
		}
		remaining := time.Until(old.expiresAt)
		if remaining <= 0 {
			return nil, err
		}
		wait := jitter(backoff)
		if wait > remaining {
			wait = remaining
		}
		if retryErr := r.waitToRetry(ctx, err, wait); retryErr != nil {
			return nil, retryErr
		}
		backoff = nextBackoff(backoff, r.cfg.MaxBackoff)
	}
}

func (r *ResourceRunner) waitToRetry(ctx context.Context, attemptErr error, wait time.Duration) error {
	return retryAfter(ctx, r.cfg.OnRetry, attemptErr, wait)
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

func (r *ResourceRunner) startCycleAttempt(ctx context.Context, old *resourceCycle) (*resourceCycle, error) {
	attemptCtx := ctx
	cancelAttempt := func() {}
	if old != nil {
		attemptCtx, cancelAttempt = context.WithDeadline(ctx, old.expiresAt)
	}
	defer cancelAttempt()

	started := time.Now()
	admission, err := r.cfg.Admitter.Admit(attemptCtx, r.cfg.KnockResourceID, r.cfg.ResourceID)
	if err != nil {
		return nil, err
	}
	if err := validateAdmission(admission, r.cfg.KnockResourceID, r.cfg.ResourceID); err != nil {
		return nil, errors.Join(err, r.retireAdmission(admission))
	}
	expiresAt := started.Add(admission.OpenTime)
	lead := rotationLead(admission.OpenTime, r.cfg.RotationLead)
	rotateAt := expiresAt.Add(-lead)
	session, err := r.cfg.Sessions.Start(attemptCtx, admission)
	if err != nil {
		return nil, errors.Join(err, r.retireAdmission(admission))
	}

	readyDeadline := expiresAt
	if old != nil && old.expiresAt.Before(readyDeadline) {
		readyDeadline = old.expiresAt
	}
	readyCtx, cancel := context.WithDeadline(attemptCtx, readyDeadline)
	defer cancel()
	select {
	case <-session.Done():
		err := session.Err()
		r.stopSession(session)
		err = errors.Join(err, r.retireAdmission(admission))
		if err == nil {
			err = errors.New("FRP session ended before serving")
		}
		return nil, err
	default:
	}
	select {
	case <-readyCtx.Done():
		r.stopSession(session)
		return nil, errors.Join(readyCtx.Err(), r.retireAdmission(admission))
	case <-session.Done():
		err := session.Err()
		r.stopSession(session)
		err = errors.Join(err, r.retireAdmission(admission))
		if err == nil {
			err = errors.New("FRP session ended before serving")
		}
		return nil, err
	case <-session.Ready():
		select {
		case <-session.Done():
			err := session.Err()
			r.stopSession(session)
			err = errors.Join(err, r.retireAdmission(admission))
			if err == nil {
				err = errors.New("FRP session ended while reporting serving")
			}
			return nil, err
		default:
		}
		return &resourceCycle{admission: admission, session: session, expiresAt: expiresAt, rotateAt: rotateAt}, nil
	}
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

func (r *ResourceRunner) stopCycle(cycle *resourceCycle) error {
	if cycle == nil {
		return nil
	}
	r.stopSession(cycle.session)
	return r.retireAdmission(cycle.admission)
}

func (r *ResourceRunner) retireAdmission(admission Admission) error {
	return retireAdmission(r.cfg.Admitter, admission, r.cfg.StopTimeout)
}

func (r *ResourceRunner) stopSession(session ServingSession) {
	stopServingSession(session, r.cfg.StopTimeout)
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
