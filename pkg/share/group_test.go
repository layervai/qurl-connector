package share

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeGroupFactory starts fake group sessions. Routes serve immediately
// unless hold reports that the route must stay pending on that session.
type fakeGroupFactory struct {
	mu       sync.Mutex
	sessions []*fakeGroupSession
	starts   int
	hold     func(sessionIndex int, routeID string) bool
}

func (f *fakeGroupFactory) Start(_ context.Context, admission Admission, routes []GroupRoute) (GroupServingSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts++
	session := &fakeGroupSession{
		index: len(f.sessions) + 1, hold: f.hold, admission: admission,
		routes: make(map[string]RouteState, len(routes)),
		ready:  make(chan struct{}), done: make(chan struct{}), changes: make(chan struct{}, 1),
	}
	session.install(routes)
	f.sessions = append(f.sessions, session)
	return session, nil
}

func (f *fakeGroupFactory) session(index int) *fakeGroupSession {
	f.mu.Lock()
	defer f.mu.Unlock()
	if index < 1 || index > len(f.sessions) {
		return nil
	}
	return f.sessions[index-1]
}

func (f *fakeGroupFactory) startCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts
}

type fakeGroupSession struct {
	index     int
	hold      func(int, string) bool
	admission Admission

	mu      sync.Mutex
	routes  map[string]RouteState
	updates [][]GroupRoute
	err     error
	stopped bool
	drained bool

	ready    chan struct{}
	done     chan struct{}
	changes  chan struct{}
	stopOnce sync.Once
}

func (s *fakeGroupSession) install(routes []GroupRoute) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make(map[string]RouteState, len(routes))
	for _, route := range routes {
		name := groupProxyName(route, s.admission.SessionID)
		if current, ok := s.routes[route.RouteID]; ok && current.ProxyName == name && current.Route == route {
			next[route.RouteID] = current
			continue
		}
		phase := RouteServing
		if s.hold != nil && s.hold(s.index, route.RouteID) {
			phase = RoutePending
		}
		next[route.RouteID] = RouteState{Route: route, ProxyName: name, Phase: phase}
	}
	s.routes = next
	s.notifyLocked()
}

func (s *fakeGroupSession) notifyLocked() {
	select {
	case s.changes <- struct{}{}:
	default:
	}
}

func (s *fakeGroupSession) serve(routeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.routes[routeID]
	state.Phase, state.Err = RouteServing, nil
	s.routes[routeID] = state
	s.notifyLocked()
}

func (s *fakeGroupSession) failRoute(routeID string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.routes[routeID]
	state.Phase, state.Err = RouteFailed, err
	s.routes[routeID] = state
	s.notifyLocked()
}

func (s *fakeGroupSession) Update(_ context.Context, routes []GroupRoute) error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return errGroupSessionEnded
	}
	s.updates = append(s.updates, append([]GroupRoute(nil), routes...))
	s.mu.Unlock()
	s.install(routes)
	return nil
}

func (s *fakeGroupSession) RouteStates() map[string]RouteState {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]RouteState, len(s.routes))
	for id, state := range s.routes {
		out[id] = state
	}
	return out
}

func (s *fakeGroupSession) Changes() <-chan struct{} { return s.changes }
func (s *fakeGroupSession) Ready() <-chan struct{}   { return s.ready }
func (s *fakeGroupSession) Done() <-chan struct{}    { return s.done }
func (s *fakeGroupSession) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *fakeGroupSession) Stop(context.Context) error {
	s.end(nil)
	return nil
}

func (s *fakeGroupSession) Drain(context.Context) error {
	s.mu.Lock()
	s.drained = true
	s.mu.Unlock()
	s.end(nil)
	return nil
}

func (s *fakeGroupSession) end(err error) {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.stopped = true
		if s.err == nil {
			s.err = err
		}
		s.notifyLocked()
		s.mu.Unlock()
		close(s.done)
	})
}

func (s *fakeGroupSession) isStopped() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopped
}

func (s *fakeGroupSession) isDrained() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.drained
}

func (s *fakeGroupSession) proxyName(routeID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.routes[routeID].ProxyName
}

type groupServingEvent struct {
	routeID   string
	sessionID uint64
}

type groupFailedEvent struct {
	routeID string
	err     error
}

type groupEvents struct {
	mu       sync.Mutex
	serving  []groupServingEvent
	failed   []groupFailedEvent
	promoted []uint64
	retries  []retryReport
}

func (e *groupEvents) callbacks() (func(Admission), func(string, Admission), func(string, error), func(error, time.Duration)) {
	return func(admission Admission) {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.promoted = append(e.promoted, admission.SessionID)
		}, func(routeID string, admission Admission) {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.serving = append(e.serving, groupServingEvent{routeID: routeID, sessionID: admission.SessionID})
		}, func(routeID string, err error) {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.failed = append(e.failed, groupFailedEvent{routeID: routeID, err: err})
		}, func(err error, wait time.Duration) {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.retries = append(e.retries, retryReport{err: err, wait: wait})
		}
}

func (e *groupEvents) servingCount(routeID string, sessionID uint64) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	count := 0
	for _, event := range e.serving {
		if event.routeID == routeID && event.sessionID == sessionID {
			count++
		}
	}
	return count
}

func (e *groupEvents) failedFor(routeID string) []error {
	e.mu.Lock()
	defer e.mu.Unlock()
	var errs []error
	for _, event := range e.failed {
		if event.routeID == routeID {
			errs = append(errs, event.err)
		}
	}
	return errs
}

func (e *groupEvents) promotions() []uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]uint64(nil), e.promoted...)
}

func (e *groupEvents) retryCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.retries)
}

func waitUntil(t *testing.T, timeout time.Duration, condition func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if condition() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

type groupHarness struct {
	admitter *rotatingAdmitter
	factory  *fakeGroupFactory
	events   *groupEvents
	runner   *SessionGroupRunner
	cancel   context.CancelFunc
	done     chan error
}

func startGroupHarness(t *testing.T, openTime, rotationLead time.Duration, hold func(int, string) bool, routes ...string) *groupHarness {
	t.Helper()
	h := &groupHarness{
		admitter: &rotatingAdmitter{openTime: openTime},
		factory:  &fakeGroupFactory{hold: hold},
		events:   &groupEvents{},
		done:     make(chan error, 1),
	}
	onServing, onRouteServing, onRouteFailed, onRetry := h.events.callbacks()
	runner, err := NewSessionGroupRunner(SessionGroupConfig{
		KnockResourceID: "q_catalog_key", ResourceID: "group-resource",
		Routes: groupTestRoutes(routes...), Admitter: h.admitter, Sessions: h.factory,
		MinBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond,
		RotationLead: rotationLead, StopTimeout: time.Second,
		OnServing: onServing, OnRouteServing: onRouteServing, OnRouteFailed: onRouteFailed, OnRetry: onRetry,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.runner = runner
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.done <- runner.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-h.done:
		case <-time.After(5 * time.Second):
			t.Error("session group runner did not stop")
		}
	})
	return h
}

func (h *groupHarness) admissions() uint64 {
	h.admitter.mu.Lock()
	defer h.admitter.mu.Unlock()
	return h.admitter.next
}

func (h *groupHarness) retired() []uint64 {
	h.admitter.mu.Lock()
	defer h.admitter.mu.Unlock()
	return append([]uint64(nil), h.admitter.retired...)
}

func (h *groupHarness) waitServing(t *testing.T, sessionID uint64, routes ...string) {
	t.Helper()
	for _, routeID := range routes {
		waitUntil(t, 2*time.Second, func() bool { return h.events.servingCount(routeID, sessionID) >= 1 },
			fmt.Sprintf("route %q serving on session %d", routeID, sessionID))
	}
}

func (h *groupHarness) stop(t *testing.T) error {
	t.Helper()
	h.cancel()
	select {
	case err := <-h.done:
		h.done <- err
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("session group runner did not stop")
		return nil
	}
}

func TestSessionGroupRunnerServesEveryRouteOnOneAdmission(t *testing.T) {
	h := startGroupHarness(t, time.Hour, 0, nil, "a", "b", "c")
	h.waitServing(t, 1, "a", "b", "c")
	if got := h.admissions(); got != 1 {
		t.Fatalf("admissions = %d, want exactly one knock for three routes", got)
	}
	if got := h.factory.startCount(); got != 1 {
		t.Fatalf("FRP session starts = %d, want one shared session", got)
	}
	session := h.factory.session(1)
	for _, routeID := range []string{"a", "b", "c"} {
		if got, want := session.proxyName(routeID), routeID+"-nhp1"; got != want {
			t.Fatalf("route %q proxy name = %q, want %q", routeID, got, want)
		}
	}
	if got := h.events.promotions(); len(got) != 1 || got[0] != 1 {
		t.Fatalf("promoted admissions = %v, want [1]", got)
	}
	if err := h.stop(t); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() = %v, want context cancellation", err)
	}
	if got := h.retired(); len(got) != 1 || got[0] != 1 {
		t.Fatalf("retired admissions = %v, want exactly the group's one admission", got)
	}
}

func TestSessionGroupRunnerSetRoutesChangesProxiesWithoutReadmission(t *testing.T) {
	h := startGroupHarness(t, time.Hour, 0, nil, "a", "b", "c")
	h.waitServing(t, 1, "a", "b", "c")
	session := h.factory.session(1)

	if err := h.runner.SetRoutes(context.Background(), groupTestRoutes("a", "b", "c", "d")); err != nil {
		t.Fatal(err)
	}
	h.waitServing(t, 1, "d")
	if got := h.admissions(); got != 1 {
		t.Fatalf("admissions after adding a route = %d, want no second knock", got)
	}
	if got := h.factory.startCount(); got != 1 {
		t.Fatalf("FRP session starts after adding a route = %d, want the same live session", got)
	}
	states := session.RouteStates()
	for _, routeID := range []string{"a", "b", "c"} {
		if states[routeID].ProxyName != routeID+"-nhp1" || states[routeID].Phase != RouteServing {
			t.Fatalf("sibling %q after add = %+v, want untouched", routeID, states[routeID])
		}
		if got := h.events.servingCount(routeID, 1); got != 1 {
			t.Fatalf("route %q reported serving %d times after add, want once", routeID, got)
		}
	}

	if err := h.runner.SetRoutes(context.Background(), groupTestRoutes("a", "c", "d")); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, time.Second, func() bool { _, present := session.RouteStates()["b"]; return !present }, "route b withdrawn")
	states = session.RouteStates()
	for _, routeID := range []string{"a", "c", "d"} {
		if states[routeID].ProxyName != routeID+"-nhp1" || states[routeID].Phase != RouteServing {
			t.Fatalf("sibling %q after remove = %+v, want untouched", routeID, states[routeID])
		}
	}
	if got := h.admissions(); got != 1 {
		t.Fatalf("admissions after removing a route = %d, want one", got)
	}
	if len(h.runner.RouteStates()) != 3 {
		t.Fatalf("runner route states = %+v, want a, c, d", h.runner.RouteStates())
	}
	if err := h.runner.SetRoutes(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "no routes") {
		t.Fatalf("SetRoutes(nil) = %v, want a clear refusal", err)
	}
}

func TestSessionGroupRunnerRestartRouteRenamesOnlyThatProxy(t *testing.T) {
	h := startGroupHarness(t, time.Hour, 0, nil, "a", "b", "c")
	h.waitServing(t, 1, "a", "b", "c")
	session := h.factory.session(1)

	if err := h.runner.RestartRoute(context.Background(), "b"); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, time.Second, func() bool { return h.events.servingCount("b", 1) == 2 }, "restarted route b serving again")
	states := session.RouteStates()
	if states["b"].ProxyName != "b-nhp1-r1" {
		t.Fatalf("restarted route b proxy name = %q, want b-nhp1-r1", states["b"].ProxyName)
	}
	for _, routeID := range []string{"a", "c"} {
		if states[routeID].ProxyName != routeID+"-nhp1" || h.events.servingCount(routeID, 1) != 1 {
			t.Fatalf("sibling %q after restart = %+v (serving reports %d), want untouched", routeID, states[routeID], h.events.servingCount(routeID, 1))
		}
	}
	if got := h.admissions(); got != 1 {
		t.Fatalf("admissions after restart = %d, want one", got)
	}
	if err := h.runner.RestartRoute(context.Background(), "zzz"); err == nil {
		t.Fatal("RestartRoute accepted a route outside the group")
	}
}

func TestSessionGroupRunnerWithdrawsGoneRouteWithoutDisturbingSiblings(t *testing.T) {
	h := startGroupHarness(t, time.Hour, 0, nil, "a", "b", "c")
	h.waitServing(t, 1, "a", "b", "c")
	session := h.factory.session(1)

	session.failRoute("b", fmt.Errorf("%w: resource_not_found: resource not found", ErrResourceGone))
	waitUntil(t, time.Second, func() bool { return len(h.events.failedFor("b")) == 1 }, "route b reported gone")
	if err := h.events.failedFor("b")[0]; !errors.Is(err, ErrResourceGone) {
		t.Fatalf("route b failure = %v, want ErrResourceGone", err)
	}
	waitUntil(t, time.Second, func() bool { _, present := session.RouteStates()["b"]; return !present }, "route b withdrawn from the session")
	if session.isStopped() {
		t.Fatal("a gone route tore down the shared session")
	}
	if got := h.admissions(); got != 1 {
		t.Fatalf("admissions after a gone route = %d, want no re-admission", got)
	}
	states := session.RouteStates()
	for _, routeID := range []string{"a", "c"} {
		if states[routeID].Phase != RouteServing || states[routeID].ProxyName != routeID+"-nhp1" {
			t.Fatalf("sibling %q after gone route = %+v, want still serving", routeID, states[routeID])
		}
	}
	select {
	case err := <-h.done:
		t.Fatalf("runner exited on a per-route failure: %v", err)
	default:
	}

	// Re-adding the route registers a fresh proxy rather than reviving the
	// rejected registration.
	if err := h.runner.SetRoutes(context.Background(), groupTestRoutes("a", "b", "c")); err != nil {
		t.Fatal(err)
	}
	h.waitServing(t, 1, "b")
	if got := session.proxyName("b"); got != "b-nhp1-r1" {
		t.Fatalf("re-added route b proxy name = %q, want a fresh generation", got)
	}
}

func TestSessionGroupRunnerRotationRegistersEveryRouteBeforeRetiringOld(t *testing.T) {
	hold := func(sessionIndex int, _ string) bool { return sessionIndex == 2 }
	h := startGroupHarness(t, time.Second, 0, hold, "a", "b", "c")
	h.waitServing(t, 1, "a", "b", "c")
	first := h.factory.session(1)

	waitUntil(t, 2*time.Second, func() bool { return h.factory.startCount() == 2 }, "replacement session start")
	second := h.factory.session(2)
	if got := h.admissions(); got != 2 {
		t.Fatalf("admissions at rotation = %d, want the replacement's one knock", got)
	}
	for _, routeID := range []string{"a", "b", "c"} {
		if got, want := second.proxyName(routeID), routeID+"-nhp2"; got != want {
			t.Fatalf("replacement route %q proxy name = %q, want %q", routeID, got, want)
		}
	}
	time.Sleep(20 * time.Millisecond)
	if first.isDrained() || first.isStopped() {
		t.Fatal("old session retired before any replacement route was running")
	}
	second.serve("a")
	second.serve("b")
	time.Sleep(20 * time.Millisecond)
	if first.isDrained() || first.isStopped() {
		t.Fatal("old session retired while replacement route c was still pending")
	}
	if got := h.events.promotions(); len(got) != 1 {
		t.Fatalf("promotions before the replacement served every route = %v, want only [1]", got)
	}
	second.serve("c")
	waitUntil(t, time.Second, func() bool { return len(h.events.promotions()) == 2 }, "replacement promotion")
	waitUntil(t, time.Second, first.isDrained, "old session drain")
	h.waitServing(t, 2, "a", "b", "c")
	if got := h.events.promotions(); got[1] != 2 {
		t.Fatalf("promotions = %v, want [1 2]", got)
	}
	if got := h.events.failedFor("a"); len(got) != 0 {
		t.Fatalf("clean rotation reported failures: %v", got)
	}
}

func TestSessionGroupRunnerKeepsOldUntilExpiryWhenReplacementRouteNeverServes(t *testing.T) {
	const openTime = 600 * time.Millisecond
	hold := func(sessionIndex int, routeID string) bool { return sessionIndex == 2 && routeID == "b" }
	h := startGroupHarness(t, openTime, 0, hold, "a", "b", "c")
	h.waitServing(t, 1, "a", "b", "c")
	admittedAt := time.Now()
	first := h.factory.session(1)

	waitUntil(t, 2*time.Second, func() bool { return h.factory.startCount() == 2 }, "replacement session start")
	second := h.factory.session(2)
	time.Sleep(100 * time.Millisecond)
	if first.isDrained() || first.isStopped() {
		t.Fatal("old session retired before its admission expired although route b never came up")
	}
	if got := h.events.promotions(); len(got) != 1 {
		t.Fatalf("replacement promoted before the old admission expired: %v", got)
	}

	waitUntil(t, 2*time.Second, func() bool { return len(h.events.promotions()) >= 2 }, "expiry-bounded promotion")
	if elapsed := time.Since(admittedAt); elapsed < openTime-150*time.Millisecond {
		t.Fatalf("replacement promoted after %s, want the old admission retained until near its %s expiry", elapsed, openTime)
	}
	waitUntil(t, time.Second, first.isDrained, "old session drain")
	h.waitServing(t, 2, "a", "c")
	failures := h.events.failedFor("b")
	if len(failures) != 1 || !errors.Is(failures[0], ErrRouteNotServing) {
		t.Fatalf("route b failures = %v, want one ErrRouteNotServing report", failures)
	}
	if got := h.events.servingCount("b", 2); got != 0 {
		t.Fatalf("route b reported serving on the replacement %d times, want none", got)
	}
	if state := second.RouteStates()["b"]; state.Phase != RoutePending {
		t.Fatalf("route b on the replacement = %+v, want still pending (kept for retry)", state)
	}
	if states := h.runner.RouteStates(); len(states) != 3 {
		t.Fatalf("runner still tracks %d routes, want all three", len(states))
	}
}

func TestSessionGroupRunnerAddsDuringRotationOnlyToReplacement(t *testing.T) {
	hold := func(sessionIndex int, _ string) bool { return sessionIndex == 2 }
	h := startGroupHarness(t, time.Second, 0, hold, "a", "b", "c")
	h.waitServing(t, 1, "a", "b", "c")
	first := h.factory.session(1)
	waitUntil(t, 2*time.Second, func() bool { return h.factory.startCount() == 2 }, "replacement session start")
	second := h.factory.session(2)

	if err := h.runner.SetRoutes(context.Background(), groupTestRoutes("a", "b", "c", "d")); err != nil {
		t.Fatal(err)
	}
	if _, present := second.RouteStates()["d"]; !present {
		t.Fatal("route added during rotation did not reach the replacement session")
	}
	if _, present := first.RouteStates()["d"]; present {
		t.Fatal("route added during rotation was registered on the expiring session")
	}
	if err := h.runner.SetRoutes(context.Background(), groupTestRoutes("a", "c", "d")); err != nil {
		t.Fatal(err)
	}
	if _, present := first.RouteStates()["b"]; present {
		t.Fatal("route removed during rotation stayed on the expiring session")
	}
	if _, present := second.RouteStates()["b"]; present {
		t.Fatal("route removed during rotation stayed on the replacement session")
	}
	if first.isDrained() || first.isStopped() {
		t.Fatal("old session retired while the replacement had no route running")
	}
	second.serve("a")
	second.serve("c")
	waitUntil(t, time.Second, func() bool { return len(h.events.promotions()) == 2 }, "replacement promotion")
	h.waitServing(t, 2, "a", "c")
	second.serve("d")
	h.waitServing(t, 2, "d")
	if got := h.admissions(); got != 2 {
		t.Fatalf("admissions = %d, want one per cycle", got)
	}
}

func TestSessionGroupRunnerRetriesWhenNoRouteServesBeforeExpiry(t *testing.T) {
	hold := func(sessionIndex int, _ string) bool { return sessionIndex == 1 }
	h := startGroupHarness(t, 60*time.Millisecond, 0, hold, "a", "b")
	h.waitServing(t, 2, "a", "b")
	if h.events.retryCount() == 0 {
		t.Fatal("first cycle that never served was not reported as a retry")
	}
	retired := h.retired()
	if len(retired) == 0 || retired[0] != 1 {
		t.Fatalf("retired admissions = %v, want the never-serving first cycle retired before the retry", retired)
	}
	if !h.factory.session(1).isStopped() {
		t.Fatal("never-serving first session was left running")
	}
}

func TestGroupRotationLeadScalesWithRouteCount(t *testing.T) {
	tests := []struct {
		openTime, configured time.Duration
		routes               int
		want                 time.Duration
	}{
		{openTime: 5 * time.Minute, routes: 1, want: 30 * time.Second},
		{openTime: 5 * time.Minute, routes: 3, want: 30 * time.Second},
		{openTime: 5 * time.Minute, routes: 600, want: 30 * time.Second},
		{openTime: 5 * time.Minute, routes: 1000, want: 50 * time.Second},
		{openTime: 5 * time.Minute, routes: 2000, want: 100 * time.Second},
		{openTime: 5 * time.Minute, configured: 45 * time.Second, routes: 100, want: 45 * time.Second},
		{openTime: 5 * time.Minute, configured: 45 * time.Second, routes: 1000, want: 50 * time.Second},
		{openTime: time.Minute, routes: 2000, want: 30 * time.Second},
		{openTime: 3 * time.Second, routes: 1, want: 1500 * time.Millisecond},
		{openTime: 1500 * time.Millisecond, routes: 1, want: time.Second},
		{openTime: time.Second, routes: 1, want: 500 * time.Millisecond},
		{openTime: 100 * time.Millisecond, routes: 1, want: 50 * time.Millisecond},
	}
	for _, test := range tests {
		got := groupRotationLead(test.openTime, test.configured, test.routes)
		if got != test.want {
			t.Errorf("groupRotationLead(%s, %s, %d) = %s, want %s", test.openTime, test.configured, test.routes, got, test.want)
		}
		if got >= test.openTime {
			t.Errorf("groupRotationLead(%s, %s, %d) = %s is not inside the admission window", test.openTime, test.configured, test.routes, got)
		}
	}
}

func TestNewSessionGroupRunnerRejectsInvalidGroups(t *testing.T) {
	valid := SessionGroupConfig{
		KnockResourceID: "q_catalog_key", ResourceID: "group-resource",
		Routes: groupTestRoutes("a", "b"), Admitter: &rotatingAdmitter{openTime: time.Minute}, Sessions: &fakeGroupFactory{},
	}
	if _, err := NewSessionGroupRunner(valid); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*SessionGroupConfig){
		"no knock resource": func(c *SessionGroupConfig) { c.KnockResourceID = "" },
		"no group resource": func(c *SessionGroupConfig) { c.ResourceID = "" },
		"no admitter":       func(c *SessionGroupConfig) { c.Admitter = nil },
		"no factory":        func(c *SessionGroupConfig) { c.Sessions = nil },
		"no routes":         func(c *SessionGroupConfig) { c.Routes = nil },
		"over bound":        func(c *SessionGroupConfig) { c.Routes = thousandRoutes(MaxGroupRoutes + 1) },
		"duplicate route":   func(c *SessionGroupConfig) { c.Routes = append(c.Routes, c.Routes[0]) },
		"negative duration": func(c *SessionGroupConfig) { c.RotationLead = -1 },
		"inverted backoff":  func(c *SessionGroupConfig) { c.MinBackoff, c.MaxBackoff = time.Second, time.Millisecond },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := valid
			cfg.Routes = groupTestRoutes("a", "b")
			mutate(&cfg)
			if _, err := NewSessionGroupRunner(cfg); err == nil {
				t.Fatal("invalid group was accepted")
			}
		})
	}
	if _, err := NewSessionGroupRunner(SessionGroupConfig{
		KnockResourceID: "q_catalog_key", ResourceID: "group-resource",
		Routes: thousandRoutes(MaxGroupRoutes), Admitter: &rotatingAdmitter{openTime: time.Minute}, Sessions: &fakeGroupFactory{},
	}); err != nil {
		t.Fatalf("group at the bound was rejected: %v", err)
	}
}

type goneGroupAdmitter struct{}

func (goneGroupAdmitter) Admit(context.Context, string, string) (Admission, error) {
	return Admission{}, fmt.Errorf("%w: protected resource is not assigned", ErrResourceGone)
}

func (goneGroupAdmitter) Retire(context.Context, Admission) error { return nil }

func TestSessionGroupRunnerReturnsWhenGroupAdmissionIsGone(t *testing.T) {
	runner, err := NewSessionGroupRunner(SessionGroupConfig{
		KnockResourceID: "q_catalog_key", ResourceID: "group-resource",
		Routes: groupTestRoutes("a"), Admitter: goneGroupAdmitter{}, Sessions: &fakeGroupFactory{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runner.Run(ctx); !errors.Is(err, ErrResourceGone) {
		t.Fatalf("Run() = %v, want ErrResourceGone", err)
	}
}

func TestSessionGroupRunnerRefusesConcurrentRun(t *testing.T) {
	h := startGroupHarness(t, time.Hour, 0, nil, "a")
	h.waitServing(t, 1, "a")
	if err := h.runner.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("second Run() = %v, want refusal", err)
	}
}
