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

	mu          sync.Mutex
	routes      map[string]RouteState
	updates     [][]GroupRoute
	err         error
	stopped     bool
	drained     bool
	failUpdates int

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

func (s *fakeGroupSession) Update(ctx context.Context, routes []GroupRoute) error {
	// Mirror the real session: a canceled caller context is refused before
	// the table changes.
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return ErrSessionGroupEnded
	}
	if s.failUpdates > 0 {
		s.failUpdates--
		s.mu.Unlock()
		return errors.New("fake update failure")
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

// end mirrors the real session's exit: serving routes are demoted because
// a dead session serves nothing.
func (s *fakeGroupSession) end(err error) {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.stopped = true
		if s.err == nil {
			s.err = err
		}
		for routeID, state := range s.routes {
			if state.Phase == RouteServing {
				state.Phase, state.Err = RoutePending, ErrSessionGroupEnded
				s.routes[routeID] = state
			}
		}
		s.notifyLocked()
		s.mu.Unlock()
		close(s.done)
	})
}

// retire mimics the real session between shutdown and exit: Update is
// refused while Done has not closed yet.
func (s *fakeGroupSession) retire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped = true
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

type groupLeadCap struct {
	routes     int
	need, lead time.Duration
}

type groupEvents struct {
	mu       sync.Mutex
	serving  []groupServingEvent
	failed   []groupFailedEvent
	promoted []uint64
	retries  []retryReport
	capped   []groupLeadCap
}

func (e *groupEvents) onLeadCapped(routes int, need, lead time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.capped = append(e.capped, groupLeadCap{routes: routes, need: need, lead: lead})
}

func (e *groupEvents) leadCaps() []groupLeadCap {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]groupLeadCap(nil), e.capped...)
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
		OnRotationLeadCapped: h.events.onLeadCapped,
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

	four := groupTestRoutes("a", "b", "c", "d")
	if err := h.runner.SetRoutes(context.Background(), four); err != nil {
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

	// Remove b with every other route's target unchanged; a changed target
	// would (correctly) regenerate that route.
	if err := h.runner.SetRoutes(context.Background(), []LocalHTTPRoute{four[0], four[2], four[3]}); err != nil {
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

func TestSessionGroupRunnerRegeneratesChangedTargetAndRejectsIdentityChange(t *testing.T) {
	h := startGroupHarness(t, time.Hour, 0, nil, "a", "b")
	h.waitServing(t, 1, "a", "b")
	session := h.factory.session(1)

	// A changed local target registers under a fresh name: the server still
	// holds the old registration, so the same name would report it serving.
	moved := groupTestRoutes("a", "b")
	moved[0].LocalPort = 4000
	if err := h.runner.SetRoutes(context.Background(), moved); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, time.Second, func() bool { return h.events.servingCount("a", 1) == 2 }, "moved route a serving under its new registration")
	states := session.RouteStates()
	if states["a"].ProxyName != "a-nhp1-r1" || states["a"].Route.LocalPort != 4000 {
		t.Fatalf("moved route a = %+v, want a fresh generation carrying the new target", states["a"])
	}
	if states["b"].ProxyName != "b-nhp1" || h.events.servingCount("b", 1) != 1 {
		t.Fatalf("sibling b after a's target change = %+v (serving reports %d), want untouched", states["b"], h.events.servingCount("b", 1))
	}
	if got := h.admissions(); got != 1 {
		t.Fatalf("admissions = %d, want no knock for a target change", got)
	}

	// Resource identities are immutable in place.
	for name, mutate := range map[string]func(*LocalHTTPRoute){
		"resource ID": func(r *LocalHTTPRoute) { r.ResourceID = "resource-other" },
		"routing ID":  func(r *LocalHTTPRoute) { r.ConnectorRoutingID = "routing-other" },
	} {
		changed := groupTestRoutes("a", "b")
		changed[0].LocalPort = 4000
		mutate(&changed[1])
		err := h.runner.SetRoutes(context.Background(), changed)
		if err == nil || !strings.Contains(err.Error(), "resource identity in place") {
			t.Fatalf("SetRoutes changing b's %s in place = %v, want a refusal", name, err)
		}
	}
	if after := session.RouteStates(); after["b"].ProxyName != "b-nhp1" || after["b"].Route.LocalHTTPRoute != groupTestRoutes("a", "b")[1] {
		t.Fatalf("refused identity change still reached the session: %+v", after["b"])
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

func TestSessionGroupRunnerReturnsWhenEveryRouteIsGone(t *testing.T) {
	h := startGroupHarness(t, time.Hour, 0, nil, "a", "b", "c")
	h.waitServing(t, 1, "a", "b", "c")
	session := h.factory.session(1)
	gone := fmt.Errorf("%w: resource_not_found: resource not found", ErrResourceGone)
	session.failRoute("a", gone)
	waitUntil(t, time.Second, func() bool { return len(h.events.failedFor("a")) == 1 }, "route a reported gone")
	select {
	case err := <-h.done:
		t.Fatalf("runner exited while routes b and c were still serving: %v", err)
	default:
	}
	session.failRoute("b", gone)
	session.failRoute("c", gone)
	select {
	case err := <-h.done:
		if !errors.Is(err, ErrGroupEmpty) {
			t.Fatalf("Run() = %v, want ErrGroupEmpty once every route is gone", err)
		}
		h.done <- err
	case <-time.After(2 * time.Second):
		t.Fatal("runner kept running (and would keep knocking) with no routes left")
	}
	for _, routeID := range []string{"a", "b", "c"} {
		if got := h.events.failedFor(routeID); len(got) != 1 || !errors.Is(got[0], ErrResourceGone) {
			t.Fatalf("route %q failures = %v, want one ErrResourceGone", routeID, got)
		}
	}
	if got := h.admissions(); got != 1 {
		t.Fatalf("admissions = %d, want no knock for an empty group", got)
	}
	if got := h.retired(); len(got) != 1 || got[0] != 1 {
		t.Fatalf("retired admissions = %v, want the group's one admission retired on exit", got)
	}
	if !session.isStopped() {
		t.Fatal("session left running after the group emptied")
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

	four := groupTestRoutes("a", "b", "c", "d")
	if err := h.runner.SetRoutes(context.Background(), four); err != nil {
		t.Fatal(err)
	}
	if _, present := second.RouteStates()["d"]; !present {
		t.Fatal("route added during rotation did not reach the replacement session")
	}
	if _, present := first.RouteStates()["d"]; present {
		t.Fatal("route added during rotation was registered on the expiring session")
	}
	if err := h.runner.SetRoutes(context.Background(), []LocalHTTPRoute{four[0], four[2], four[3]}); err != nil {
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
		measured             time.Duration
		want, need           time.Duration
	}{
		{openTime: 5 * time.Minute, routes: 1, want: 30 * time.Second, need: 30 * time.Second},
		{openTime: 5 * time.Minute, routes: 3, want: 30 * time.Second, need: 30 * time.Second},
		{openTime: 5 * time.Minute, routes: 600, want: 30 * time.Second, need: 30 * time.Second},
		{openTime: 5 * time.Minute, routes: 1000, want: 50 * time.Second, need: 50 * time.Second},
		{openTime: 5 * time.Minute, routes: 2000, want: 100 * time.Second, need: 100 * time.Second},
		{openTime: 5 * time.Minute, configured: 45 * time.Second, routes: 100, want: 45 * time.Second, need: 45 * time.Second},
		{openTime: 5 * time.Minute, configured: 45 * time.Second, routes: 1000, want: 50 * time.Second, need: 50 * time.Second},
		{openTime: time.Minute, routes: 2000, want: 30 * time.Second, need: 100 * time.Second},
		{openTime: 3 * time.Second, routes: 1, want: 1500 * time.Millisecond, need: 30 * time.Second},
		{openTime: 1500 * time.Millisecond, routes: 1, want: 750 * time.Millisecond, need: 30 * time.Second},
		{openTime: time.Second, routes: 1, want: 500 * time.Millisecond, need: 30 * time.Second},
		{openTime: 100 * time.Millisecond, routes: 1, want: 50 * time.Millisecond, need: 30 * time.Second},
		// A measured per-route cost above the 50ms estimate replaces it: a
		// platform that registers 600 routes at 125ms each (margin included)
		// needs 75s, not the 30s floor, and 1000 routes need 125s.
		{openTime: 5 * time.Minute, routes: 600, measured: 125 * time.Millisecond, want: 75 * time.Second, need: 75 * time.Second},
		{openTime: 5 * time.Minute, routes: 1000, measured: 125 * time.Millisecond, want: 125 * time.Second, need: 125 * time.Second},
		{openTime: 5 * time.Minute, routes: 2000, measured: 125 * time.Millisecond, want: 150 * time.Second, need: 250 * time.Second},
		// A measured cost below the estimate does not shorten the lead.
		{openTime: 5 * time.Minute, routes: 1000, measured: 10 * time.Millisecond, want: 50 * time.Second, need: 50 * time.Second},
		{openTime: 5 * time.Minute, configured: 45 * time.Second, routes: 100, measured: 300 * time.Millisecond, want: 45 * time.Second, need: 45 * time.Second},
	}
	for _, test := range tests {
		got, need := groupRotationLead(test.openTime, test.configured, test.routes, test.measured)
		if got != test.want || need != test.need {
			t.Errorf("groupRotationLead(%s, %s, %d, %s) = (%s, %s), want (%s, %s)", test.openTime, test.configured, test.routes, test.measured, got, need, test.want, test.need)
		}
		if got > test.openTime/2 || got < min(time.Second, test.openTime/2) {
			t.Errorf("groupRotationLead(%s, %s, %d, %s) = %s is outside [min(1s, openTime/2), openTime/2]", test.openTime, test.configured, test.routes, test.measured, got)
		}
	}
}

func TestSessionGroupRunnerRotationLeadFollowsMeasuredRegistration(t *testing.T) {
	// A 20ms a-priori estimate keeps the 100ms floor binding for three
	// routes (60ms) while leaving an instant replacement's measured cost,
	// the gap between two Run-goroutine observations, well below it.
	floor, perRoute := groupLeadFloor, groupLeadPerRoute
	groupLeadFloor, groupLeadPerRoute = 100*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { groupLeadFloor, groupLeadPerRoute = floor, perRoute })

	// The first session registers a at once and b and c only `spacing`
	// later, the way a slow server works down its NewProxy queue. The
	// measured cost is spacing × 3/2 over the two routes that followed the
	// first, 900ms per route, so three routes need 2.7s of lead inside a 4s
	// cap: the replacement must start about 5.3s after admission, not the
	// 7.9s the a-priori estimate would arm.
	const (
		openTime = 8 * time.Second
		spacing  = 1200 * time.Millisecond
	)
	hold := func(sessionIndex int, routeID string) bool { return sessionIndex == 1 && routeID != "a" }
	h := startGroupHarness(t, openTime, 0, hold, "a", "b", "c")
	h.waitServing(t, 1, "a")
	admittedAt := time.Now()
	session := h.factory.session(1)
	time.Sleep(spacing)
	session.serve("b")
	session.serve("c")
	h.waitServing(t, 1, "b", "c")
	waitUntil(t, openTime, func() bool { return h.factory.startCount() == 2 }, "replacement start")
	elapsed := time.Since(admittedAt)
	if elapsed < spacing+time.Second || elapsed > openTime-1500*time.Millisecond {
		t.Fatalf("replacement started %s after admission, want about %s (8s window less the 2.7s the measured registration needs), not the %s the a-priori estimate arms",
			elapsed, openTime-2700*time.Millisecond, openTime-100*time.Millisecond)
	}
	if caps := h.events.leadCaps(); len(caps) != 0 {
		t.Fatalf("lead cap reports = %+v, want none for a 2.7s need inside a 4s cap", caps)
	}
	waitUntil(t, 3*time.Second, func() bool { return len(h.events.promotions()) == 2 }, "replacement promotion")
	for _, routeID := range []string{"a", "b", "c"} {
		if failed := h.events.failedFor(routeID); len(failed) != 0 {
			t.Fatalf("route %q reported failed across the rotation: %v", routeID, failed)
		}
	}
	// The replacement registered everything at once, which measures below
	// the a-priori estimate: the next lead is the estimate's again, not the
	// slow first cycle's.
	h.runner.mu.Lock()
	measured := h.runner.measuredPerRoute
	h.runner.mu.Unlock()
	if measured >= groupLeadPerRoute {
		t.Fatalf("measured per-route cost after an instant replacement = %s, want below the %s estimate", measured, groupLeadPerRoute)
	}
}

func TestSessionGroupRunnerRecomputesRotationLeadWhenGroupGrows(t *testing.T) {
	floor, perRoute := groupLeadFloor, groupLeadPerRoute
	groupLeadFloor, groupLeadPerRoute = 100*time.Millisecond, 2*time.Millisecond
	t.Cleanup(func() { groupLeadFloor, groupLeadPerRoute = floor, perRoute })

	const openTime = 6 * time.Second
	h := startGroupHarness(t, openTime, 0, nil, "a", "b", "c")
	h.waitServing(t, 1, "a", "b", "c")
	admittedAt := time.Now()
	// Three routes need the 100ms floor, clamped up to 1s, so rotation is
	// armed for 5s after admission. A group of 2000 needs 4s, capped at half
	// the window: rotation must move to 3s and the cap must be reported.
	if err := h.runner.SetRoutes(context.Background(), thousandRoutes(2000)); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, openTime, func() bool { return h.factory.startCount() == 2 }, "replacement start")
	elapsed := time.Since(admittedAt)
	if elapsed < openTime/2-500*time.Millisecond || elapsed >= openTime-1500*time.Millisecond {
		t.Fatalf("replacement started %s after admission, want about %s for 2000 routes, not the 5s the 3-route admission armed", elapsed, openTime/2)
	}
	caps := h.events.leadCaps()
	if len(caps) != 1 || caps[0] != (groupLeadCap{routes: 2000, need: 4 * time.Second, lead: openTime / 2}) {
		t.Fatalf("lead cap reports = %+v, want one report of 2000 routes needing 4s and getting 3s", caps)
	}
	waitUntil(t, 3*time.Second, func() bool { return len(h.events.promotions()) == 2 }, "replacement promotion")
	if got := len(h.factory.session(2).RouteStates()); got != 2000 {
		t.Fatalf("replacement carries %d routes, want all 2000", got)
	}
}

func TestSessionGroupRunnerHealsFailedSetRoutesApply(t *testing.T) {
	h := startGroupHarness(t, time.Hour, 0, nil, "a", "b", "c")
	h.waitServing(t, 1, "a", "b", "c")
	session := h.factory.session(1)

	// A caller context that is already canceled: the desired set is recorded
	// but the live session refuses the update, so SetRoutes reports it and
	// Run must converge the session under its own context.
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := h.runner.SetRoutes(canceled, groupTestRoutes("a", "b", "c", "d")); !errors.Is(err, context.Canceled) {
		t.Fatalf("SetRoutes with a canceled context = %v, want the context error surfaced", err)
	}
	h.waitServing(t, 1, "d")
	if _, present := session.RouteStates()["d"]; !present {
		t.Fatal("route added under a canceled context never reached the live session")
	}
	if got := h.admissions(); got != 1 {
		t.Fatalf("admissions = %d, want convergence without a new knock", got)
	}

	// A transient session-side failure heals the same way.
	session.mu.Lock()
	session.failUpdates = 1
	session.mu.Unlock()
	_ = h.runner.SetRoutes(context.Background(), groupTestRoutes("a", "b", "c", "d", "e"))
	h.waitServing(t, 1, "e")
}

func TestSessionGroupRunnerPromotesWhenOldSessionDiesMidRotation(t *testing.T) {
	hold := func(sessionIndex int, _ string) bool { return sessionIndex == 2 }
	h := startGroupHarness(t, 2*time.Second, 0, hold, "a", "b", "c")
	h.waitServing(t, 1, "a", "b", "c")
	first := h.factory.session(1)
	waitUntil(t, 3*time.Second, func() bool { return h.factory.startCount() == 2 }, "replacement session start")
	second := h.factory.session(2)

	// The old session dies with the replacement still registering: nothing
	// is left to regress, so one serving route is enough to promote.
	first.end(errors.New("control connection lost"))
	second.serve("a")
	waitUntil(t, time.Second, func() bool { return len(h.events.promotions()) == 2 }, "promotion after the old session died")
	h.waitServing(t, 2, "a")
	if h.events.servingCount("b", 2) != 0 || h.events.servingCount("c", 2) != 0 {
		t.Fatal("routes still pending on the replacement were reported serving")
	}
	if got := h.admissions(); got != 2 {
		t.Fatalf("admissions = %d, want the replacement's one knock and no re-admission for the dead session", got)
	}
	second.serve("b")
	second.serve("c")
	h.waitServing(t, 2, "b", "c")
}

func TestSessionGroupRunnerSetRoutesToleratesRetiringSession(t *testing.T) {
	h := startGroupHarness(t, time.Hour, 0, nil, "a")
	h.waitServing(t, 1, "a")
	first := h.factory.session(1)
	first.retire()
	if err := h.runner.SetRoutes(context.Background(), groupTestRoutes("a", "b")); err != nil {
		t.Fatalf("SetRoutes against a retiring session = %v, want nil", err)
	}
	first.end(nil)
	h.waitServing(t, 2, "a", "b")
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

func TestSessionGroupRunnerRotationLeadMeasuresWithoutEveryRouteServing(t *testing.T) {
	floor, perRoute := groupLeadFloor, groupLeadPerRoute
	groupLeadFloor, groupLeadPerRoute = 100*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { groupLeadFloor, groupLeadPerRoute = floor, perRoute })

	// Route c never registers on the first session, the way a route the
	// server keeps refusing never does. The measurement must still follow
	// the routes that did: b served `spacing` after a, 1.8s per route with
	// the margin, so three routes need 5.4s, which the 4s cap binds. The
	// replacement therefore starts at the cap, about 4s after admission,
	// not the 7.9s the a-priori estimate would arm, and the cap is reported.
	const (
		openTime = 8 * time.Second
		spacing  = 1200 * time.Millisecond
	)
	hold := func(sessionIndex int, routeID string) bool { return sessionIndex == 1 && routeID != "a" }
	h := startGroupHarness(t, openTime, 0, hold, "a", "b", "c")
	h.waitServing(t, 1, "a")
	admittedAt := time.Now()
	session := h.factory.session(1)
	time.Sleep(spacing)
	session.serve("b")
	h.waitServing(t, 1, "b")
	waitUntil(t, openTime, func() bool { return h.factory.startCount() == 2 }, "replacement start")
	elapsed := time.Since(admittedAt)
	if elapsed < openTime/2-500*time.Millisecond || elapsed > openTime-1500*time.Millisecond {
		t.Fatalf("replacement started %s after admission, want about %s (the cap), not the %s the a-priori estimate arms",
			elapsed, openTime/2, openTime-100*time.Millisecond)
	}
	caps := h.events.leadCaps()
	if len(caps) == 0 || caps[0].routes != 3 || caps[0].lead != openTime/2 || caps[0].need < 5*time.Second {
		t.Fatalf("lead cap reports = %+v, want three routes needing about 5.4s and getting 4s", caps)
	}
	waitUntil(t, 3*time.Second, func() bool { return len(h.events.promotions()) == 2 }, "replacement promotion")
	h.waitServing(t, 2, "a", "b", "c")
}

func TestSessionGroupRunnerRotationLeadIgnoresRoutesAddedAfterStart(t *testing.T) {
	floor, perRoute := groupLeadFloor, groupLeadPerRoute
	groupLeadFloor, groupLeadPerRoute = 100*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { groupLeadFloor, groupLeadPerRoute = floor, perRoute })

	// The cycle starts with a, b, and c; c never registers, b serves
	// `spacing` after a (450ms per route with the margin), and d joins the
	// group `later` on and serves at once. d is not part of the cycle's
	// initial set, so it neither completes the measurement in c's place nor
	// stretches the spacing to the cycle's wall-clock age: four routes need
	// 4 × 450ms = 1.8s and the replacement starts about 6.2s after
	// admission with no cap report. Counting d would measure `later` over
	// two routes, 1.5s each, need 6s, and rotate at the 4s cap.
	const (
		openTime = 8 * time.Second
		spacing  = 300 * time.Millisecond
		later    = 2 * time.Second
	)
	hold := func(sessionIndex int, routeID string) bool {
		return sessionIndex == 1 && (routeID == "b" || routeID == "c")
	}
	h := startGroupHarness(t, openTime, 0, hold, "a", "b", "c")
	h.waitServing(t, 1, "a")
	admittedAt := time.Now()
	session := h.factory.session(1)
	time.Sleep(spacing)
	session.serve("b")
	h.waitServing(t, 1, "b")
	time.Sleep(later - time.Since(admittedAt))
	if err := h.runner.SetRoutes(context.Background(), groupTestRoutes("a", "b", "c", "d")); err != nil {
		t.Fatal(err)
	}
	h.waitServing(t, 1, "d")
	waitUntil(t, openTime, func() bool { return h.factory.startCount() == 2 }, "replacement start")
	// The measured spacing is amplified sixfold into the need (four routes,
	// 1.5x margin), so the band below the 6.2s target leaves 200ms of
	// observation lag on a and b before it is crossed; the cap a wall-clock
	// measurement over d would arm sits a full second below the band.
	elapsed := time.Since(admittedAt)
	if elapsed < openTime-3000*time.Millisecond || elapsed > openTime-1200*time.Millisecond {
		t.Fatalf("replacement started %s after admission, want about %s (four routes at the 450ms measured on a and b), not the %s cap a wall-clock measurement over d would arm",
			elapsed, openTime-1800*time.Millisecond, openTime/2)
	}
	if caps := h.events.leadCaps(); len(caps) != 0 {
		t.Fatalf("lead cap reports = %+v, want none for a 1.8s need inside a 4s cap", caps)
	}
	waitUntil(t, 3*time.Second, func() bool { return len(h.events.promotions()) == 2 }, "replacement promotion")
	h.waitServing(t, 2, "a", "b", "c", "d")
}

func TestSessionGroupRunnerSingleRouteCycleKeepsPriorMeasurement(t *testing.T) {
	runner, err := NewSessionGroupRunner(SessionGroupConfig{
		KnockResourceID: "q_catalog_key", ResourceID: "group-resource",
		Routes: groupTestRoutes("a"), Admitter: &rotatingAdmitter{openTime: time.Hour}, Sessions: &fakeGroupFactory{},
	})
	if err != nil {
		t.Fatal(err)
	}
	const prior = 900 * time.Millisecond
	runner.measuredPerRoute = prior
	now := time.Now()
	serving := func(ids ...string) map[string]RouteState {
		states := make(map[string]RouteState, len(ids))
		for _, id := range ids {
			states[id] = RouteState{Phase: RouteServing}
		}
		return states
	}
	// A cycle with one route (or a replacement promoted at expiry with one
	// route up) has no spacing to measure and leaves the prior estimate in
	// place, whether or not that finishes its initial set.
	single := &groupCycle{initial: map[string]struct{}{"a": {}}}
	runner.observeRegistration(single, serving("a"), now)
	if runner.measuredPerRoute != prior || !single.measured {
		t.Fatalf("after a single-route cycle: measured = %s (want the prior %s), frozen = %t (want true)", runner.measuredPerRoute, prior, single.measured)
	}
	partial := &groupCycle{initial: map[string]struct{}{"a": {}, "b": {}}}
	runner.observeRegistration(partial, serving("a"), now)
	if runner.measuredPerRoute != prior || partial.measured {
		t.Fatalf("after one of two routes served: measured = %s (want the prior %s), frozen = %t (want false)", runner.measuredPerRoute, prior, partial.measured)
	}
	// Two routes inside one observation do measure: below the estimate,
	// recorded as zero.
	runner.observeRegistration(partial, serving("a", "b"), now)
	if runner.measuredPerRoute != 0 || !partial.measured {
		t.Fatalf("after both routes served at once: measured = %s (want 0), frozen = %t (want true)", runner.measuredPerRoute, partial.measured)
	}
}
