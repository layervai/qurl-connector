package share

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	frpproxy "github.com/fatedier/frp/client/proxy"
	qurl "github.com/layervai/qurl-go/qurl"
)

func testSessionReceipt(sessionID uint64, runID string, runAttempt uint64) qurl.NativeSessionReceipt {
	return qurl.NativeSessionReceipt{
		CellID: "cell0", SessionID: sessionID, SessionIssuedAtMillis: 1,
		RunID: runID, RunAttempt: runAttempt,
	}
}

func TestAdmissionFormattingRedactsBearerToken(t *testing.T) {
	admission := Admission{
		KnockResourceID: "q_catalog", ResourceID: "resource-public", RunID: "run-one", RunAttempt: 3,
		Token: "bearer-must-never-appear", ResourceHost: "frp.example:7000", SessionID: 42,
		SessionReceipt: qurl.NativeSessionReceipt{
			CellID: "cell0", SessionID: 42, SessionIssuedAtMillis: 1234, RunID: "run-one", RunAttempt: 3,
		},
		OpenTime: time.Minute,
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		formatted := fmt.Sprintf(format, admission)
		if strings.Contains(formatted, admission.Token) || !strings.Contains(formatted, "Token:[REDACTED]") {
			t.Fatalf("format %q leaked or omitted redaction: %s", format, formatted)
		}
		for _, useful := range []string{admission.ResourceID, admission.RunID, admission.ResourceHost, "cell0"} {
			if !strings.Contains(formatted, useful) {
				t.Fatalf("format %q omitted non-secret identity %q: %s", format, useful, formatted)
			}
		}
	}
}

type rotatingAdmitter struct {
	mu       sync.Mutex
	next     uint64
	retired  []uint64
	openTime time.Duration
}

type retryReport struct {
	err  error
	wait time.Duration
}

func (a *rotatingAdmitter) Admit(_ context.Context, knockResourceID, resourceID string) (Admission, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.next++
	return Admission{
		KnockResourceID: knockResourceID,
		ResourceID:      resourceID,
		RunID:           "run",
		RunAttempt:      1,
		Token:           "token",
		ResourceHost:    "127.0.0.1:7000",
		SessionID:       a.next,
		SessionReceipt:  testSessionReceipt(a.next, "run", 1),
		OpenTime:        a.openTime,
	}, nil
}

func (a *rotatingAdmitter) Retire(_ context.Context, admission Admission) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.retired = append(a.retired, admission.SessionID)
	return nil
}

type overlapFactory struct {
	mu            sync.Mutex
	next          int
	latest        int
	serving       int
	gap           bool
	failStartOnce bool
}

func (f *overlapFactory) Start(context.Context, Admission) (ServingSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	if f.failStartOnce && f.next == 2 {
		return nil, errors.New("replacement network unavailable")
	}
	f.latest = f.next
	f.serving++
	s := &overlapSession{id: f.next, factory: f, ready: make(chan struct{}), done: make(chan struct{})}
	close(s.ready)
	return s, nil
}

type overlapSession struct {
	id      int
	factory *overlapFactory
	ready   chan struct{}
	done    chan struct{}
	once    sync.Once
}

func (s *overlapSession) Ready() <-chan struct{} { return s.ready }
func (s *overlapSession) Done() <-chan struct{}  { return s.done }
func (s *overlapSession) Err() error             { return nil }
func (s *overlapSession) Stop(context.Context) error {
	s.once.Do(func() {
		s.factory.mu.Lock()
		if s.id != s.factory.latest && s.factory.serving < 2 {
			s.factory.gap = true
		}
		s.factory.serving--
		s.factory.mu.Unlock()
		close(s.done)
	})
	return nil
}

func TestResourceRunnerRenewsMakeBeforeBreak(t *testing.T) {
	admitter := &rotatingAdmitter{openTime: 80 * time.Millisecond}
	factory := &overlapFactory{failStartOnce: true}
	var serving atomic.Int32
	runner, err := NewResourceRunner(ResourceConfig{
		KnockResourceID: "q_catalog_key",
		ResourceID:      "public-resource-id",
		Admitter:        admitter,
		Sessions:        factory,
		MinBackoff:      time.Millisecond,
		MaxBackoff:      4 * time.Millisecond,
		RotationLead:    40 * time.Millisecond,
		StopTimeout:     time.Second,
		OnServing:       func(Admission) { serving.Add(1) },
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 175*time.Millisecond)
	defer cancel()
	err = runner.Run(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run() = %v, want context deadline", err)
	}
	if got := serving.Load(); got < 3 {
		t.Fatalf("serving admissions = %d, want at least 3 rotations", got)
	}
	factory.mu.Lock()
	gap := factory.gap
	starts := factory.next
	factory.mu.Unlock()
	if gap {
		t.Fatal("old FRP session stopped before its replacement was serving")
	}
	if starts < 4 {
		t.Fatalf("FRP start attempts = %d, want failed replacement plus successful renewals", starts)
	}
	admitter.mu.Lock()
	retired := append([]uint64(nil), admitter.retired...)
	admitter.mu.Unlock()
	if len(retired) < 3 {
		t.Fatalf("retired admissions = %v, want old cycles and final shutdown", retired)
	}
}

type staleReadmissionFactory struct {
	mu          sync.Mutex
	starts      int
	firstStatus *lockedStatus
}

type freshCycleAdmitter struct {
	mu      sync.Mutex
	next    uint64
	retired []Admission
}

func (a *freshCycleAdmitter) Admit(_ context.Context, knockResourceID, resourceID string) (Admission, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.next++
	runID := fmt.Sprintf("%016x", a.next)
	return Admission{
		KnockResourceID: knockResourceID,
		ResourceID:      resourceID,
		RunID:           runID,
		RunAttempt:      1,
		Token:           fmt.Sprintf("token-%d", a.next),
		ResourceHost:    "127.0.0.1:7000",
		SessionID:       a.next,
		SessionReceipt:  testSessionReceipt(a.next, runID, 1),
		OpenTime:        time.Second,
	}, nil
}

func (a *freshCycleAdmitter) Retire(_ context.Context, admission Admission) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.retired = append(a.retired, admission)
	return nil
}

func (f *staleReadmissionFactory) Start(context.Context, Admission) (ServingSession, error) {
	f.mu.Lock()
	f.starts++
	status := &lockedStatus{item: &frpproxy.WorkingStatus{Phase: frpproxy.ProxyPhaseRunning}}
	if f.starts == 1 {
		f.firstStatus = status
	}
	f.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	session := &frpServingSession{
		svc: blockingFRPService{}, status: status, names: []string{"cycle"}, poll: time.Millisecond,
		ready: make(chan struct{}), done: make(chan struct{}), cancel: cancel,
	}
	go session.run(ctx)
	return session, nil
}

func (f *staleReadmissionFactory) staleFirst() bool {
	f.mu.Lock()
	status := f.firstStatus
	f.mu.Unlock()
	if status == nil {
		return false
	}
	status.set(frpproxy.ProxyPhaseStartErr, "session_stale: serving session is stale")
	return true
}

func TestResourceRunnerReknocksAfterSessionStaleNewProxyStatus(t *testing.T) {
	admitter := &freshCycleAdmitter{}
	factory := &staleReadmissionFactory{}
	secondServing := make(chan struct{})
	callbackErr := make(chan error, 1)
	var servingMu sync.Mutex
	var servingAdmissions []Admission
	runner, err := NewResourceRunner(ResourceConfig{
		KnockResourceID: "q_catalog_key",
		ResourceID:      "public-resource-id",
		Admitter:        admitter,
		Sessions:        factory,
		MinBackoff:      time.Millisecond,
		MaxBackoff:      2 * time.Millisecond,
		RotationLead:    500 * time.Millisecond,
		StopTimeout:     time.Second,
		OnServing: func(admission Admission) {
			servingMu.Lock()
			servingAdmissions = append(servingAdmissions, admission)
			count := len(servingAdmissions)
			servingMu.Unlock()
			switch count {
			case 1:
				if !factory.staleFirst() {
					callbackErr <- errors.New("first FRP status was not installed")
				}
			case 2:
				close(secondServing)
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	select {
	case <-secondServing:
	case err := <-callbackErr:
		cancel()
		t.Fatal(err)
	case <-time.After(time.Second):
		cancel()
		t.Fatal("ResourceRunner did not acquire a fresh admission after session_stale")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() = %v, want context cancellation", err)
	}

	servingMu.Lock()
	gotServing := append([]Admission(nil), servingAdmissions...)
	servingMu.Unlock()
	if len(gotServing) < 2 || gotServing[0].SessionID != 1 || gotServing[0].RunID != "0000000000000001" ||
		gotServing[1].SessionID != 2 || gotServing[1].RunID != "0000000000000002" {
		t.Fatalf("serving admissions = %+v, want fresh session/run sequence 1/0000000000000001 then 2/0000000000000002", gotServing)
	}
	admitter.mu.Lock()
	retired := append([]Admission(nil), admitter.retired...)
	admitter.mu.Unlock()
	if len(retired) < 2 || retired[0].SessionID != 1 || retired[0].RunID != "0000000000000001" {
		t.Fatalf("retired admissions = %+v, want stale session/run 1/0000000000000001 retired before shutdown", retired)
	}
}

type drainTrackingFactory struct {
	mu      sync.Mutex
	next    int
	started chan struct{}
	done    chan struct{}
	release chan struct{}
}

func (f *drainTrackingFactory) Start(context.Context, Admission) (ServingSession, error) {
	f.mu.Lock()
	f.next++
	id := f.next
	f.mu.Unlock()
	s := &drainTrackingSession{
		id: id, ready: make(chan struct{}), done: make(chan struct{}),
	}
	if id == 1 {
		s.drainStarted = f.started
		s.drainDone = f.done
		s.release = f.release
	}
	close(s.ready)
	return s, nil
}

type drainTrackingSession struct {
	id           int
	ready        chan struct{}
	done         chan struct{}
	drainStarted chan struct{}
	drainDone    chan struct{}
	release      chan struct{}
	once         sync.Once
	startOnce    sync.Once
	drainOnce    sync.Once
}

func (s *drainTrackingSession) Ready() <-chan struct{} { return s.ready }
func (s *drainTrackingSession) Done() <-chan struct{}  { return s.done }
func (*drainTrackingSession) Err() error               { return nil }
func (s *drainTrackingSession) Stop(context.Context) error {
	s.once.Do(func() { close(s.done) })
	return nil
}
func (s *drainTrackingSession) Drain(ctx context.Context) error {
	if s.drainStarted != nil {
		s.startOnce.Do(func() { close(s.drainStarted) })
	}
	<-ctx.Done()
	if s.drainDone != nil {
		s.drainOnce.Do(func() { close(s.drainDone) })
	}
	if s.release != nil {
		go func() {
			<-s.release
			s.once.Do(func() { close(s.done) })
		}()
	} else {
		s.once.Do(func() { close(s.done) })
	}
	return ctx.Err()
}

func TestResourceRunnerTracksDrainUntilBoundedFinalShutdown(t *testing.T) {
	admitter := &rotatingAdmitter{openTime: 40 * time.Millisecond}
	factory := &drainTrackingFactory{
		started: make(chan struct{}), done: make(chan struct{}), release: make(chan struct{}),
	}
	runner, err := NewResourceRunner(ResourceConfig{
		KnockResourceID: "q_catalog_key",
		ResourceID:      "public-resource-id",
		Admitter:        admitter,
		Sessions:        factory,
		MinBackoff:      time.Millisecond,
		MaxBackoff:      time.Millisecond,
		RotationLead:    30 * time.Millisecond,
		StopTimeout:     50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- runner.Run(ctx) }()
	select {
	case <-factory.started:
	case <-time.After(time.Second):
		t.Fatal("old cycle did not begin its asynchronous drain")
	}
	cancel()
	select {
	case <-factory.done:
	case <-time.After(time.Second):
		t.Fatal("final shutdown did not cancel the old cycle's drain")
	}
	select {
	case err := <-runDone:
		t.Fatalf("Run returned before the draining session itself exited: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	close(factory.release)
	select {
	case err := <-runDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() = %v, want context cancellation", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Run did not bound final drain shutdown by StopTimeout")
	}
	select {
	case <-factory.done:
	default:
		t.Fatal("Run returned before the drain goroutine exited")
	}
}

func TestResourceRunnerRejectsInvalidNativeLifetimeBeforeFRP(t *testing.T) {
	admitter := &rotatingAdmitter{openTime: 0}
	factory := &overlapFactory{}
	retries := make(chan retryReport, 1)
	runner, err := NewResourceRunner(ResourceConfig{
		KnockResourceID: "q_catalog_key",
		ResourceID:      "public-resource-id",
		Admitter:        admitter,
		Sessions:        factory,
		MinBackoff:      time.Millisecond,
		MaxBackoff:      time.Millisecond,
		OnRetry: func(err error, wait time.Duration) {
			select {
			case retries <- retryReport{err: err, wait: wait}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	var retry retryReport
	select {
	case retry = <-retries:
	case <-time.After(time.Second):
		t.Fatal("retry callback was not called")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() = %v, want context cancellation", err)
	}
	factory.mu.Lock()
	starts := factory.next
	factory.mu.Unlock()
	if starts != 0 {
		t.Fatalf("FRP starts = %d, want zero for open_time=0", starts)
	}
	if retry.err == nil || !strings.Contains(retry.err.Error(), "open time is not positive") ||
		retry.wait <= 0 || retry.wait > time.Millisecond {
		t.Fatalf("retry callback = (%v, %s), want bounded invalid-admission report", retry.err, retry.wait)
	}
}

func TestResourceRunnerReportsClampedReplacementRetryDelay(t *testing.T) {
	const backoff = 10 * time.Second
	admitter := &rotatingAdmitter{openTime: 2 * time.Second}
	factory := &overlapFactory{failStartOnce: true}
	retries := make(chan retryReport, 1)
	runner, err := NewResourceRunner(ResourceConfig{
		KnockResourceID: "q_catalog_key",
		ResourceID:      "public-resource-id",
		Admitter:        admitter,
		Sessions:        factory,
		MinBackoff:      backoff,
		MaxBackoff:      backoff,
		RotationLead:    1900 * time.Millisecond,
		OnRetry: func(err error, wait time.Duration) {
			select {
			case retries <- retryReport{err: err, wait: wait}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	var retry retryReport
	select {
	case retry = <-retries:
	case <-time.After(time.Second):
		t.Fatal("replacement retry callback was not called")
	}
	if retry.err == nil || !strings.Contains(retry.err.Error(), "replacement network unavailable") ||
		retry.wait <= 0 || retry.wait >= backoff/2 {
		t.Fatalf("replacement retry callback = (%v, %s), want expiry-clamped delay", retry.err, retry.wait)
	}
	admitter.mu.Lock()
	retired := append([]uint64(nil), admitter.retired...)
	admitter.mu.Unlock()
	if len(retired) != 1 || retired[0] != 2 {
		t.Fatalf("retired admissions before shutdown = %v, want only failed replacement 2", retired)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() = %v, want context cancellation", err)
	}
}

func TestResourceRunnerRetryCallbackOverrunDoesNotAddBackoff(t *testing.T) {
	const (
		wait          = time.Second
		callbackDelay = 1500 * time.Millisecond
		maxElapsed    = 2 * time.Second
	)
	runner := &ResourceRunner{cfg: ResourceConfig{OnRetry: func(error, time.Duration) {
		timer := time.NewTimer(callbackDelay)
		defer timer.Stop()
		<-timer.C
	}}}
	started := time.Now()
	if err := runner.waitToRetry(context.Background(), errors.New("retry attempt failed"), wait); err != nil {
		t.Fatalf("waitToRetry() = %v, want retry without a context error", err)
	}
	if elapsed := time.Since(started); elapsed >= maxElapsed {
		t.Fatalf("waitToRetry() elapsed = %s, want callback time to consume the retry delay", elapsed)
	}
}

type canceledAttemptAdmitter struct{ entered chan struct{} }

func (a *canceledAttemptAdmitter) Admit(ctx context.Context, _, _ string) (Admission, error) {
	close(a.entered)
	<-ctx.Done()
	return Admission{}, ctx.Err()
}

func (*canceledAttemptAdmitter) Retire(context.Context, Admission) error { return nil }

func TestResourceRunnerDoesNotReportCanceledAttemptAsRetry(t *testing.T) {
	admitter := &canceledAttemptAdmitter{entered: make(chan struct{})}
	var retries atomic.Int32
	runner, err := NewResourceRunner(ResourceConfig{
		KnockResourceID: "q_catalog_key",
		ResourceID:      "public-resource-id",
		Admitter:        admitter,
		Sessions:        &overlapFactory{},
		OnRetry:         func(error, time.Duration) { retries.Add(1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	<-admitter.entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() = %v, want context cancellation", err)
	}
	if got := retries.Load(); got != 0 {
		t.Fatalf("retry callbacks = %d, want zero during shutdown", got)
	}
}

type blockingReplacementAdmitter struct {
	mu      sync.Mutex
	calls   int
	initial time.Time
}

func (a *blockingReplacementAdmitter) Admit(ctx context.Context, knockResourceID, resourceID string) (Admission, error) {
	a.mu.Lock()
	a.calls++
	call := a.calls
	if call == 1 {
		a.initial = time.Now()
	}
	a.mu.Unlock()
	if call > 1 {
		<-ctx.Done()
		return Admission{}, ctx.Err()
	}
	return Admission{
		KnockResourceID: knockResourceID,
		ResourceID:      resourceID,
		RunID:           "run",
		RunAttempt:      1,
		Token:           "token",
		ResourceHost:    "127.0.0.1:7000",
		SessionID:       1,
		SessionReceipt:  testSessionReceipt(1, "run", 1),
		OpenTime:        60 * time.Millisecond,
	}, nil
}

func (*blockingReplacementAdmitter) Retire(context.Context, Admission) error { return nil }

type stopObservedFactory struct{ stopped chan time.Time }

func (f *stopObservedFactory) Start(context.Context, Admission) (ServingSession, error) {
	s := &stopObservedSession{ready: make(chan struct{}), done: make(chan struct{}), stopped: f.stopped}
	close(s.ready)
	return s, nil
}

type stopObservedSession struct {
	ready   chan struct{}
	done    chan struct{}
	stopped chan time.Time
	once    sync.Once
}

func (s *stopObservedSession) Ready() <-chan struct{} { return s.ready }
func (s *stopObservedSession) Done() <-chan struct{}  { return s.done }
func (*stopObservedSession) Err() error               { return nil }
func (s *stopObservedSession) Stop(context.Context) error {
	s.once.Do(func() {
		s.stopped <- time.Now()
		close(s.done)
	})
	return nil
}

func TestResourceRunnerBoundsBlockedReplacementByOldExpiry(t *testing.T) {
	admitter := &blockingReplacementAdmitter{}
	stopped := make(chan time.Time, 2)
	runner, err := NewResourceRunner(ResourceConfig{
		KnockResourceID: "q_catalog_key",
		ResourceID:      "public-resource-id",
		Admitter:        admitter,
		Sessions:        &stopObservedFactory{stopped: stopped},
		RotationLead:    35 * time.Millisecond,
		MinBackoff:      time.Millisecond,
		MaxBackoff:      2 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()

	var stoppedAt time.Time
	select {
	case stoppedAt = <-stopped:
	case <-time.After(90 * time.Millisecond):
		t.Fatal("old session was not retired at its admission deadline")
	}
	admitter.mu.Lock()
	initial := admitter.initial
	admitter.mu.Unlock()
	if elapsed := stoppedAt.Sub(initial); elapsed < 50*time.Millisecond {
		t.Fatalf("old session retired after %v, want it retained until near 60ms expiry", elapsed)
	}
	if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run() = %v, want context deadline", err)
	}
}

type admissionConfirmationFactory struct {
	mu      sync.Mutex
	starts  int
	stopped chan int
}

func (f *admissionConfirmationFactory) Start(context.Context, Admission) (ServingSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts++
	s := &admissionConfirmationSession{
		id: f.starts, ready: make(chan struct{}), done: make(chan struct{}), stopped: f.stopped,
	}
	if s.id == 1 {
		close(s.ready)
	}
	return s, nil
}

type admissionConfirmationSession struct {
	id      int
	ready   chan struct{}
	done    chan struct{}
	stopped chan int
	once    sync.Once
}

func (s *admissionConfirmationSession) Ready() <-chan struct{} { return s.ready }
func (s *admissionConfirmationSession) Done() <-chan struct{}  { return s.done }
func (*admissionConfirmationSession) Err() error               { return nil }
func (s *admissionConfirmationSession) Stop(context.Context) error {
	s.once.Do(func() {
		s.stopped <- s.id
		close(s.done)
	})
	return nil
}

func TestResourceRunnerKeepsOldSessionWhenReplacementAdmissionNeverConfirms(t *testing.T) {
	admitter := &rotatingAdmitter{openTime: 60 * time.Millisecond}
	factory := &admissionConfirmationFactory{stopped: make(chan int, 8)}
	var serving atomic.Int32
	runner, err := NewResourceRunner(ResourceConfig{
		KnockResourceID: "q_catalog_key", ResourceID: "public-resource-id",
		Admitter: admitter, Sessions: factory,
		RotationLead: 35 * time.Millisecond, MinBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond,
		OnServing: func(Admission) { serving.Add(1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	started := time.Now()
	go func() { done <- runner.Run(ctx) }()

	var firstStoppedAt time.Time
	for firstStoppedAt.IsZero() {
		select {
		case id := <-factory.stopped:
			if id == 1 {
				firstStoppedAt = time.Now()
			}
		case <-time.After(85 * time.Millisecond):
			t.Fatal("old session was not retired at expiry after replacement admission failed")
		}
	}
	if elapsed := firstStoppedAt.Sub(started); elapsed < 50*time.Millisecond {
		t.Fatalf("old session stopped after %v, before its 60ms admission expiry", elapsed)
	}
	if got := serving.Load(); got != 1 {
		t.Fatalf("serving notifications = %d, want only the admitted initial session", got)
	}
	if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run() = %v, want context deadline", err)
	}
}

type deadOnArrivalFactory struct{}

func (*deadOnArrivalFactory) Start(context.Context, Admission) (ServingSession, error) {
	s := &deadOnArrivalSession{ready: make(chan struct{}), done: make(chan struct{})}
	close(s.ready)
	close(s.done)
	return s, nil
}

type deadOnArrivalSession struct {
	ready chan struct{}
	done  chan struct{}
}

func (s *deadOnArrivalSession) Ready() <-chan struct{}   { return s.ready }
func (s *deadOnArrivalSession) Done() <-chan struct{}    { return s.done }
func (*deadOnArrivalSession) Err() error                 { return nil }
func (*deadOnArrivalSession) Stop(context.Context) error { return nil }

func TestResourceRunnerDoesNotReportDeadReplacementServing(t *testing.T) {
	admitter := &rotatingAdmitter{openTime: time.Second}
	var serving atomic.Int32
	runner, err := NewResourceRunner(ResourceConfig{
		KnockResourceID: "q_catalog_key",
		ResourceID:      "public-resource-id",
		Admitter:        admitter,
		Sessions:        &deadOnArrivalFactory{},
		MinBackoff:      time.Millisecond,
		MaxBackoff:      time.Millisecond,
		OnServing:       func(Admission) { serving.Add(1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := runner.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run() = %v, want context deadline", err)
	}
	if got := serving.Load(); got != 0 {
		t.Fatalf("serving notifications = %d, want zero for dead sessions", got)
	}
}

type concurrentAdmitter struct {
	active atomic.Int32
	max    atomic.Int32
}

func (a *concurrentAdmitter) Admit(ctx context.Context, knockResourceID, resourceID string) (Admission, error) {
	n := a.active.Add(1)
	for current := a.max.Load(); n > current && !a.max.CompareAndSwap(current, n); current = a.max.Load() {
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Millisecond):
	}
	a.active.Add(-1)
	return Admission{KnockResourceID: knockResourceID, ResourceID: resourceID}, nil
}

func (*concurrentAdmitter) Retire(context.Context, Admission) error { return nil }

func TestSerialAdmitterSerializesNativeRuntimeAccess(t *testing.T) {
	inner := &concurrentAdmitter{}
	admitter, err := NewSerialAdmitter(inner)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = admitter.Admit(context.Background(), "q_key", "resource")
		}()
	}
	wg.Wait()
	if got := inner.max.Load(); got != 1 {
		t.Fatalf("maximum concurrent native operations = %d, want 1", got)
	}
}
