package share

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type heldDrainSession struct {
	*fakeGroupSession
	entered  chan struct{}
	deadline chan time.Time
}

func (s *heldDrainSession) Drain(ctx context.Context) error {
	deadline, _ := ctx.Deadline()
	s.deadline <- deadline
	close(s.entered)
	<-ctx.Done()
	return ctx.Err()
}

func newHeldDrainSession() *heldDrainSession {
	return &heldDrainSession{fakeGroupSession: &fakeGroupSession{ready: make(chan struct{}), done: make(chan struct{}), changes: make(chan struct{}, 1)}, entered: make(chan struct{}), deadline: make(chan time.Time, 1)}
}

func TestCycleDrainUsesOriginalAuthorizationDeadline(t *testing.T) {
	session := newHeldDrainSession()
	drains := cycleDrainSet{changed: make(chan struct{}, 1)}
	var retired atomic.Bool
	deadline := time.Now().Add(120 * time.Millisecond)
	drains.start(session, deadline, 20*time.Millisecond, func() error { retired.Store(true); return nil })
	<-session.entered
	if got := <-session.deadline; !got.Equal(deadline) {
		t.Fatalf("deadline = %v, want original %v", got, deadline)
	}
	time.Sleep(40 * time.Millisecond)
	if retired.Load() {
		t.Fatal("original admission retired at stop budget before authorization deadline")
	}
	select {
	case <-drains.changed:
	case <-time.After(time.Second):
		t.Fatal("authorization deadline did not finish teardown")
	}
	if !retired.Load() {
		t.Fatal("original admission not retired")
	}
	if err := drains.stopAndWait(time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestCycleDrainStopCancelsHeldWorkAndRetainsRetirementError(t *testing.T) {
	session := newHeldDrainSession()
	var drains cycleDrainSet
	expected := errors.New("original receipt retirement failed")
	drains.start(session, time.Now().Add(time.Hour), time.Second, func() error { return expected })
	<-session.entered
	if err := drains.stopAndWait(time.Second); !errors.Is(err, expected) {
		t.Fatalf("cleanup error = %v", err)
	}
	select {
	case <-session.Done():
	default:
		t.Fatal("forced stop left original control alive")
	}
}

func TestCycleDrainBoundsRetiredControls(t *testing.T) {
	var drains cycleDrainSet
	defer func() {
		if err := drains.stopAndWait(time.Second); err != nil {
			t.Error(err)
		}
	}()
	var retired atomic.Int32
	sessions := []*heldDrainSession{newHeldDrainSession(), newHeldDrainSession(), newHeldDrainSession()}
	for _, session := range sessions {
		if err := drains.start(session, time.Now().Add(time.Hour), time.Second, func() error { retired.Add(1); return nil }); err != nil {
			t.Fatal(err)
		}
		<-session.entered
	}
	for _, session := range sessions[:2] {
		select {
		case <-session.Done():
		default:
			t.Fatal("third retired control left older controls alive")
		}
	}
	if retired.Load() != 2 {
		t.Fatalf("retired admissions = %d, want original two", retired.Load())
	}
	drains.mu.Lock()
	count := len(drains.cycles)
	drains.mu.Unlock()
	if count > 2 {
		t.Fatalf("retired controls = %d", count)
	}
}

type failedDrainSession struct {
	*fakeGroupSession
	failure     error
	stopFailure error
}

func (s *failedDrainSession) Drain(context.Context) error {
	return errors.Join(context.DeadlineExceeded, s.failure)
}
func (s *failedDrainSession) Stop(ctx context.Context) error {
	_ = s.fakeGroupSession.Stop(ctx)
	return s.stopFailure
}

func TestCycleDrainKeepsJoinedCancellationFailure(t *testing.T) {
	expected := errors.New("transport failure")
	session := &failedDrainSession{fakeGroupSession: newHeldDrainSession().fakeGroupSession, failure: expected}
	drains := cycleDrainSet{changed: make(chan struct{}, 1)}
	if err := drains.start(session, time.Now().Add(time.Hour), time.Second, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-drains.changed:
	case <-time.After(time.Second):
		t.Fatal("drain did not finish")
	}
	if err := drains.stopAndWait(time.Second); !errors.Is(err, expected) {
		t.Fatalf("joined error lost: %v", err)
	}
}

func TestGroupStopCycleKeepsStopFailureAndRetiresOriginal(t *testing.T) {
	expected := errors.New("stop failed")
	session := &failedDrainSession{fakeGroupSession: newHeldDrainSession().fakeGroupSession, stopFailure: expected}
	admitter := &rotatingAdmitter{openTime: time.Hour}
	runner := &SessionGroupRunner{cfg: SessionGroupConfig{Admitter: admitter, StopTimeout: time.Second}}
	cycle := &groupCycle{session: session, admission: Admission{SessionID: 77}}
	if err := runner.stopCycle(cycle); !errors.Is(err, expected) {
		t.Fatalf("stop failure lost: %v", err)
	}
	admitter.mu.Lock()
	defer admitter.mu.Unlock()
	if len(admitter.retired) != 1 || admitter.retired[0] != 77 {
		t.Fatalf("original retirement = %v", admitter.retired)
	}
}
