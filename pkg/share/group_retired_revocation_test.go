package share

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

type retainedGroupSession struct {
	*fakeGroupSession
	revoked      map[string]bool
	prepared     bool
	drainFailure error
}

func (s *retainedGroupSession) prepareDrain() {
	s.mu.Lock()
	s.prepared = true
	s.mu.Unlock()
}

func (s *retainedGroupSession) Drain(ctx context.Context) error {
	s.mu.Lock()
	s.stopped = true
	s.drained = true
	s.mu.Unlock()
	if s.drainFailure != nil {
		return s.drainFailure
	}
	<-ctx.Done()
	return ctx.Err()
}
func (s *retainedGroupSession) retainDrainedRoutes(routes []LocalHTTPRoute) {
	keep := make(map[string]bool, len(routes))
	for _, route := range routes {
		keep[route.RouteID] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.routes {
		if !keep[id] {
			s.revoked[id] = true
		}
	}
}
func (s *retainedGroupSession) wasRevoked(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revoked[id]
}

type retainedGroupFactory struct {
	base         fakeGroupFactory
	mu           sync.Mutex
	sessions     []*retainedGroupSession
	drainFailure error
}

func (f *retainedGroupFactory) Start(ctx context.Context, admission Admission, routes []GroupRoute) (GroupServingSession, error) {
	session, err := f.base.Start(ctx, admission, routes)
	if err != nil {
		return nil, err
	}
	retained := &retainedGroupSession{fakeGroupSession: session.(*fakeGroupSession), revoked: make(map[string]bool), drainFailure: f.drainFailure}
	f.mu.Lock()
	f.sessions = append(f.sessions, retained)
	f.mu.Unlock()
	return retained, nil
}
func (f *retainedGroupFactory) session(index int) *retainedGroupSession {
	f.mu.Lock()
	defer f.mu.Unlock()
	if index >= len(f.sessions) {
		return nil
	}
	return f.sessions[index]
}

func TestGroupRunnerRevokesRetiredWorkThroughPromotionAndPermanentDenial(t *testing.T) {
	for _, scenario := range []string{"promotion remove and readd", "permanent denial"} {
		t.Run(scenario, func(t *testing.T) {
			factory := &retainedGroupFactory{}
			admitter := &rotatingAdmitter{openTime: 600 * time.Millisecond}
			promoted := make(chan struct{})
			var runner *SessionGroupRunner
			var err error
			runner, err = NewSessionGroupRunner(SessionGroupConfig{
				KnockResourceID: "catalog", ResourcePublicKey: "resource", Routes: groupTestRoutes("a", "b"), Admitter: admitter, Sessions: factory,
				MinBackoff: time.Millisecond, MaxBackoff: time.Millisecond, StopTimeout: time.Second,
				OnServing: func(admission Admission) {
					if admission.SessionID != 2 {
						return
					}
					original := factory.session(0)
					original.mu.Lock()
					prepared := original.prepared
					original.mu.Unlock()
					if !prepared {
						t.Error("promotion callback ran before old reconnect fence")
					}
					if scenario == "promotion remove and readd" {
						if err := runner.SetRoutes(t.Context(), groupTestRoutes("b")); err != nil {
							t.Error(err)
						}
						if err := runner.SetRoutes(t.Context(), groupTestRoutes("a", "b")); err != nil {
							t.Error(err)
						}
					}
					close(promoted)
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { done <- runner.Run(ctx) }()
			defer func() {
				cancel()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("runner did not stop")
				}
			}()
			select {
			case <-promoted:
			case <-time.After(3 * time.Second):
				t.Fatal("replacement did not promote")
			}
			original := factory.session(0)
			replacement := factory.session(1)
			if scenario == "permanent denial" {
				replacement.failRoute("a", errors.Join(ErrResourceGone, errors.New("denied")))
			}
			waitUntil(t, time.Second, func() bool { return original.wasRevoked("a") }, "retired route a revocation")
			if original.wasRevoked("b") {
				t.Fatal("revocation closed retired sibling")
			}
			if replacement.isStopped() {
				t.Fatal("revocation stopped replacement control")
			}
			if state, ok := replacement.RouteStates()["b"]; !ok || state.Phase != RouteServing {
				t.Fatal("revocation disturbed replacement sibling")
			}
		})
	}
}

type failingRetirementSequenceAdmitter struct {
	rotatingAdmitter
	failure error
}

func (a *failingRetirementSequenceAdmitter) Admit(ctx context.Context, knockID, publicKey string) (Admission, error) {
	a.mu.Lock()
	switch a.next {
	case 0:
		a.openTime = 2 * time.Second
	case 1:
		a.openTime = 200 * time.Millisecond
	default:
		a.openTime = 20 * time.Millisecond
	}
	a.mu.Unlock()
	return a.rotatingAdmitter.Admit(ctx, knockID, publicKey)
}
func (a *failingRetirementSequenceAdmitter) Retire(ctx context.Context, admission Admission) error {
	if err := a.rotatingAdmitter.Retire(ctx, admission); err != nil {
		return err
	}
	if admission.SessionID == 1 {
		return a.failure
	}
	return nil
}

func TestGroupDrainCapacityFailureRetiresReadyReplacement(t *testing.T) {
	expected := errors.New("old original retirement failed")
	admitter := &failingRetirementSequenceAdmitter{failure: expected}
	factory := &retainedGroupFactory{}
	runner, err := NewSessionGroupRunner(SessionGroupConfig{
		KnockResourceID: "catalog", ResourcePublicKey: "resource", Routes: groupTestRoutes("a"), Admitter: admitter, Sessions: factory,
		MinBackoff: time.Millisecond, MaxBackoff: time.Millisecond, StopTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	if err := runner.Run(ctx); !errors.Is(err, expected) {
		t.Fatalf("capacity cleanup failure = %v", err)
	}
	factory.mu.Lock()
	sessions := append([]*retainedGroupSession(nil), factory.sessions...)
	factory.mu.Unlock()
	if len(sessions) != 4 {
		t.Fatalf("sessions=%d, want ready fourth replacement", len(sessions))
	}
	for _, session := range sessions {
		if !session.isStopped() {
			t.Fatalf("session %d leaked after failed promotion", session.admission.SessionID)
		}
	}
	runner.mu.Lock()
	pending, active := runner.pending, runner.active
	runner.mu.Unlock()
	if pending != nil || active != nil {
		t.Fatal("failed promotion retained pending or active control")
	}
	admitter.mu.Lock()
	retired := append([]uint64(nil), admitter.retired...)
	admitter.mu.Unlock()
	counts := make(map[uint64]int)
	for _, id := range retired {
		counts[id]++
	}
	for id := uint64(1); id <= 4; id++ {
		if counts[id] != 1 {
			t.Fatalf("exact retirement counts=%v", counts)
		}
	}
}

func TestGroupRetiredControlLossKeepsReplacementAndJoinedFailures(t *testing.T) {
	sentinel := errors.New("additional cleanup failure")
	for _, scenario := range []struct {
		name        string
		failure     error
		wantFailure bool
	}{
		{"closed", net.ErrClosed, false},
		{"wrapped closed", fmt.Errorf("retired transport: %w", net.ErrClosed), false},
		{"wrapped deadline", fmt.Errorf("retired grant: %w", context.DeadlineExceeded), false},
		{"wrapped canceled", fmt.Errorf("retired drain: %w", context.Canceled), false},
		{"joined", errors.Join(net.ErrClosed, sentinel), true},
		{"wrapped joined", fmt.Errorf("retired transport: %w", errors.Join(net.ErrClosed, sentinel)), true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			factory := &retainedGroupFactory{drainFailure: scenario.failure}
			admitter := &rotatingAdmitter{openTime: 600 * time.Millisecond}
			promoted := make(chan struct{})
			runner, err := NewSessionGroupRunner(SessionGroupConfig{
				KnockResourceID: "catalog", ResourcePublicKey: "resource", Routes: groupTestRoutes("a", "b"), Admitter: admitter, Sessions: factory,
				MinBackoff: time.Millisecond, MaxBackoff: time.Millisecond, StopTimeout: time.Second,
				OnServing: func(a Admission) {
					if a.SessionID == 2 {
						close(promoted)
					}
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { done <- runner.Run(ctx) }()
			defer cancel()
			select {
			case <-promoted:
			case <-time.After(3 * time.Second):
				t.Fatal("replacement did not promote")
			}
			if scenario.wantFailure {
				select {
				case err := <-done:
					if !errors.Is(err, sentinel) {
						t.Fatalf("joined failure lost: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("joined failure not reported")
				}
				return
			}
			waitUntil(t, time.Second, func() bool {
				admitter.mu.Lock()
				defer admitter.mu.Unlock()
				return len(admitter.retired) >= 1 && admitter.retired[0] == 1
			}, "original retirement")
			admitter.mu.Lock()
			retired := append([]uint64(nil), admitter.retired...)
			admitter.mu.Unlock()
			if len(retired) != 1 {
				t.Fatalf("retired control loss retired the replacement: %v", retired)
			}
			select {
			case <-factory.session(0).Done():
			default:
				t.Fatal("retired control was not stopped")
			}
			for _, id := range []string{"a", "b"} {
				if factory.session(1).RouteStates()[id].Phase != RouteServing {
					t.Fatalf("replacement route %s stopped", id)
				}
			}
			select {
			case err := <-done:
				t.Fatalf("retired control loss stopped replacement: %v", err)
			case <-time.After(30 * time.Millisecond):
			}
			cancel()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("runner did not stop")
			}
		})
	}
}
