package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	qurl "github.com/layervai/qurl-go/qurl"

	"github.com/layervai/qurl-connector/pkg/audit"
	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
	"github.com/layervai/qurl-connector/pkg/share"
)

// The shared runtime is exercised the way pkg/share's own tests exercise the
// group runner: a fake admitter that mints valid admissions and counts every
// knock, and a fake session factory whose sessions the test can drive route
// by route. Nothing here touches the network or FRP.

// fakeSharedAdmitter mints one valid admission per Admit and counts every
// call, so a test can prove how many knocks a route set costs.
type fakeSharedAdmitter struct {
	mu      sync.Mutex
	admits  int
	retired []uint64
	healthy int
	// openTime is the admission window; zero means an hour, long enough
	// that no test rotates unless it asks to.
	openTime time.Duration
	// deny refuses admission for a protected resource ID with that error.
	deny map[string]error
	// knocks records the knock resource of every Admit, in order.
	knocks []string
	// gate, when set, holds every Admit until it is closed (or ctx ends);
	// held counts the Admit calls that reached the gate.
	gate chan struct{}
	held int
}

func (a *fakeSharedAdmitter) Admit(ctx context.Context, knockResourceID, resourceID string) (share.Admission, error) {
	a.mu.Lock()
	gate := a.gate
	if gate != nil {
		a.held++
	}
	a.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return share.Admission{}, ctx.Err()
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.knocks = append(a.knocks, knockResourceID)
	if err := a.deny[resourceID]; err != nil {
		return share.Admission{}, err
	}
	a.admits++
	sessionID := uint64(a.admits)
	openTime := a.openTime
	if openTime == 0 {
		openTime = time.Hour
	}
	return share.Admission{
		KnockResourceID: knockResourceID, ResourceID: resourceID,
		RunID: "run", RunAttempt: 1, Token: "token", ResourceHost: "frp.example:7000",
		SessionID: sessionID,
		SessionReceipt: qurl.NativeSessionReceipt{
			CellID: "cell0", SessionID: sessionID, SessionIssuedAtMillis: 1, RunID: "run", RunAttempt: 1,
		},
		OpenTime: openTime,
	}, nil
}

func (a *fakeSharedAdmitter) Retire(_ context.Context, admission share.Admission) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.retired = append(a.retired, admission.SessionID)
	return nil
}

func (a *fakeSharedAdmitter) MarkServingHealthy() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.healthy++
	return nil
}

func (a *fakeSharedAdmitter) counts() (admits, retired, healthy int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.admits, len(a.retired), a.healthy
}

// holdAdmissions makes every later Admit wait until the returned release
// function is called.
func (a *fakeSharedAdmitter) holdAdmissions() (release func()) {
	a.mu.Lock()
	defer a.mu.Unlock()
	gate := make(chan struct{})
	a.gate = gate
	var once sync.Once
	return func() { once.Do(func() { close(gate) }) }
}

func (a *fakeSharedAdmitter) heldAdmits() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.held
}

func (a *fakeSharedAdmitter) knockResources() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.knocks...)
}

// fakeGroupFactory starts fake group sessions. Every route serves as soon as
// it is installed unless hold reports it held on that session (1-based
// index), in which case it stays pending until the test serves or fails it.
type fakeGroupFactory struct {
	mu       sync.Mutex
	hold     func(sessionIndex int, routeID string) bool
	sessions []*fakeGroupSession
}

func (f *fakeGroupFactory) Start(_ context.Context, admission share.Admission, routes []share.GroupRoute) (share.GroupServingSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	session := &fakeGroupSession{
		index: len(f.sessions) + 1, admission: admission, hold: f.hold,
		routes:  make(map[string]share.RouteState, len(routes)),
		ready:   make(chan struct{}),
		done:    make(chan struct{}),
		changes: make(chan struct{}, 1),
	}
	session.install(routes)
	f.sessions = append(f.sessions, session)
	return session, nil
}

func (f *fakeGroupFactory) starts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sessions)
}

// session returns the index-th (1-based) session started, or nil.
func (f *fakeGroupFactory) session(index int) *fakeGroupSession {
	f.mu.Lock()
	defer f.mu.Unlock()
	if index < 1 || index > len(f.sessions) {
		return nil
	}
	return f.sessions[index-1]
}

type fakeGroupSession struct {
	index     int
	admission share.Admission
	hold      func(int, string) bool

	mu      sync.Mutex
	routes  map[string]share.RouteState
	updates [][]share.GroupRoute
	err     error
	stopped bool

	ready    chan struct{}
	done     chan struct{}
	changes  chan struct{}
	stopOnce sync.Once
}

func fakeProxyName(route share.GroupRoute, sessionID uint64) string {
	return fmt.Sprintf("%s-s%d-g%d", route.RouteID, sessionID, route.Generation)
}

func (s *fakeGroupSession) install(routes []share.GroupRoute) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make(map[string]share.RouteState, len(routes))
	for _, route := range routes {
		name := fakeProxyName(route, s.admission.SessionID)
		if current, ok := s.routes[route.RouteID]; ok && current.ProxyName == name && current.Route == route {
			next[route.RouteID] = current
			continue
		}
		phase := share.RouteServing
		if s.hold != nil && s.hold(s.index, route.RouteID) {
			phase = share.RoutePending
		}
		next[route.RouteID] = share.RouteState{Route: route, ProxyName: name, Phase: phase}
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
	state.Phase, state.Err = share.RouteServing, nil
	s.routes[routeID] = state
	s.notifyLocked()
}

func (s *fakeGroupSession) failRoute(routeID string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.routes[routeID]
	state.Phase, state.Err = share.RouteFailed, err
	s.routes[routeID] = state
	s.notifyLocked()
}

func (s *fakeGroupSession) Update(ctx context.Context, routes []share.GroupRoute) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return share.ErrSessionGroupEnded
	}
	s.updates = append(s.updates, append([]share.GroupRoute(nil), routes...))
	s.mu.Unlock()
	s.install(routes)
	return nil
}

// lastUpdate returns the route IDs of the most recent proxy set pushed to
// the session, or nil when nothing has been pushed since Start.
func (s *fakeGroupSession) lastUpdate() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.updates) == 0 {
		return nil
	}
	last := s.updates[len(s.updates)-1]
	ids := make([]string, 0, len(last))
	for _, route := range last {
		ids = append(ids, route.RouteID)
	}
	return ids
}

func (s *fakeGroupSession) RouteStates() map[string]share.RouteState {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]share.RouteState, len(s.routes))
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
		for routeID, state := range s.routes {
			if state.Phase == share.RouteServing {
				state.Phase, state.Err = share.RoutePending, share.ErrSessionGroupEnded
				s.routes[routeID] = state
			}
		}
		s.notifyLocked()
		s.mu.Unlock()
		close(s.done)
	})
}

// captureAuditLogger records every entry so a test can assert what the
// runtime put on the audit stream.
type captureAuditLogger struct {
	mu      sync.Mutex
	entries []audit.Entry
}

func (l *captureAuditLogger) Log(entry audit.Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, entry)
}

func (l *captureAuditLogger) Close() error { return nil }

func (l *captureAuditLogger) byEvent(event string) []audit.Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []audit.Entry
	for _, entry := range l.entries {
		if entry.Event == event {
			out = append(out, entry)
		}
	}
	return out
}

// captureLogHandler records every slog record so a test can assert on the
// runtime's log lines without scraping stdout.
type captureLogHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureLogHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureLogHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *captureLogHandler) WithGroup(string) slog.Handler            { return h }
func (h *captureLogHandler) Handle(_ context.Context, record slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, record.Clone())
	return nil
}

// matching returns the records whose message contains substr, each folded
// to its attributes by key.
func (h *captureLogHandler) matching(substr string) []map[string]string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []map[string]string
	for _, record := range h.records {
		if !strings.Contains(record.Message, substr) {
			continue
		}
		attrs := map[string]string{"msg": record.Message}
		record.Attrs(func(attr slog.Attr) bool {
			attrs[attr.Key] = attr.Value.String()
			return true
		})
		out = append(out, attrs)
	}
	return out
}

func installCaptureLogger(t *testing.T) *captureLogHandler {
	t.Helper()
	handler := &captureLogHandler{}
	previous := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return handler
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// sharedServiceTestConfig is a resolved config: every route carries its own
// public resource and routing identity, and every resource maps to the one
// knock resource the Connector session is admitted through.
func sharedServiceTestConfig(ids ...string) *nhpconfig.Config {
	cfg := &nhpconfig.Config{}
	for i, id := range ids {
		cfg.Routes = append(cfg.Routes, nhpconfig.Route{
			ID: id, Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 3000 + i,
			ResourceID: "resource-" + id, ConnectorRoutingID: "routing-" + id,
		})
		cfg.SetKnockResourceID("resource-"+id, "q_knock")
	}
	return cfg
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

type sharedServiceHarness struct {
	admitter  *fakeSharedAdmitter
	factory   *fakeGroupFactory
	out       *lockedBuffer
	announcer *readyAnnouncer
	cancel    context.CancelFunc

	done     chan error
	mu       sync.Mutex
	returned bool
	err      error
}

type sharedServiceHarnessOptions struct {
	// openTime is the fake admission window; zero means an hour.
	openTime time.Duration
	// hold keeps a route pending on a given session until the test acts.
	hold func(sessionIndex int, routeID string) bool
	// deny refuses admission for a protected resource ID with that error.
	deny map[string]error
}

// startSharedServiceHarness runs the shared runtime over cfg with every
// route in hold pending on every session until the test serves or fails it.
func startSharedServiceHarness(t *testing.T, cfg *nhpconfig.Config, hold ...string) *sharedServiceHarness {
	t.Helper()
	held := make(map[string]bool, len(hold))
	for _, id := range hold {
		held[id] = true
	}
	return startSharedServiceHarnessWith(t, cfg, sharedServiceHarnessOptions{
		hold: func(_ int, routeID string) bool { return held[routeID] },
	})
}

func startSharedServiceHarnessWith(t *testing.T, cfg *nhpconfig.Config, opts sharedServiceHarnessOptions) *sharedServiceHarness {
	t.Helper()
	t.Setenv(EnvKnockResourceID, "")
	h := &sharedServiceHarness{
		admitter: &fakeSharedAdmitter{openTime: opts.openTime, deny: opts.deny},
		factory:  &fakeGroupFactory{hold: opts.hold},
		out:      &lockedBuffer{},
		done:     make(chan error, 1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.announcer = newReadyAnnouncer(readyRoutes(cfg), h.out, false)
	go func() { h.done <- runSharedService(ctx, cfg, h.admitter, h.factory, h.announcer) }()
	t.Cleanup(func() {
		cancel()
		if _, returned := h.result(5 * time.Second); !returned {
			t.Error("shared service did not stop")
		}
	})
	return h
}

// result waits up to timeout for the runtime to return, caching the outcome
// so every later call reports the same thing.
func (h *sharedServiceHarness) result(timeout time.Duration) (err error, returned bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.returned {
		return h.err, true
	}
	select {
	case err := <-h.done:
		h.returned, h.err = true, err
		return err, true
	case <-time.After(timeout):
		return nil, false
	}
}

// session waits for the index-th (1-based) session to start and returns it.
func (h *sharedServiceHarness) session(t *testing.T, index int) *fakeGroupSession {
	t.Helper()
	waitFor(t, 5*time.Second, func() bool { return h.factory.session(index) != nil }, fmt.Sprintf("session %d", index))
	return h.factory.session(index)
}

func (h *sharedServiceHarness) waitReadyBlock(t *testing.T) string {
	t.Helper()
	waitFor(t, 2*time.Second, func() bool { return strings.Contains(h.out.String(), "Connector is running") }, "the ready block")
	return h.out.String()
}

func (h *sharedServiceHarness) requireStillRunning(t *testing.T) {
	t.Helper()
	if err, returned := h.result(100 * time.Millisecond); returned {
		t.Fatalf("shared service returned %v; it should keep serving", err)
	}
}

func (h *sharedServiceHarness) stop(t *testing.T) error {
	t.Helper()
	h.cancel()
	err, returned := h.result(5 * time.Second)
	if !returned {
		t.Fatal("shared service did not stop")
	}
	return err
}

func TestSharedServiceAdmitsOnceForEveryRoute(t *testing.T) {
	h := startSharedServiceHarness(t, sharedServiceTestConfig("a", "b", "c"))
	block := h.waitReadyBlock(t)

	// Three routes cost one knock, one Login, and one session: the
	// per-route shape cost three of each, every rotation.
	admits, retired, healthy := h.admitter.counts()
	if admits != 1 || retired != 0 {
		t.Fatalf("admits = %d, retired = %d; want one admission for the whole route set", admits, retired)
	}
	if healthy < 1 {
		t.Fatal("MarkServingHealthy was not called after the group started serving")
	}
	if starts := h.factory.starts(); starts != 1 {
		t.Fatalf("FRP sessions started = %d, want 1", starts)
	}
	states := h.session(t, 1).RouteStates()
	if len(states) != 3 {
		t.Fatalf("session carries %d routes, want 3", len(states))
	}
	for id, state := range states {
		if state.Phase != share.RouteServing {
			t.Errorf("route %q phase = %s, want serving", id, state.Phase)
		}
		// Each proxy carries its own route's public resource identity; only
		// the admission is shared.
		if state.Route.ResourceID != "resource-"+id || state.Route.ConnectorRoutingID != "routing-"+id {
			t.Errorf("route %q registered with identities %q/%q", id, state.Route.ResourceID, state.Route.ConnectorRoutingID)
		}
	}
	if !strings.Contains(block, "3 route(s) live") {
		t.Errorf("ready block should report every route live; got:\n%s", block)
	}

	if err := h.stop(t); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v after cancel, want context.Canceled", err)
	}
	if admits, retired, _ := h.admitter.counts(); admits != 1 || retired != 1 {
		t.Fatalf("after stop: admits = %d, retired = %d; want the one admission retired", admits, retired)
	}
}

func TestSharedServiceRetiresGoneRouteWithoutDisturbingSiblings(t *testing.T) {
	logger := &captureAuditLogger{}
	previous := audit.SetDefault(logger)
	t.Cleanup(func() { audit.SetDefault(previous) })

	h := startSharedServiceHarness(t, sharedServiceTestConfig("a", "b", "c"))
	h.waitReadyBlock(t)
	session := h.session(t, 1)

	// The platform revoked b: qRTS answers its NewProxy with
	// resource_not_found, which the session reports as a failed route.
	session.failRoute("b", fmt.Errorf("%w: resource_not_found", share.ErrResourceGone))

	waitFor(t, 2*time.Second, func() bool { return len(logger.byEvent(audit.EventProxyDeny)) == 1 }, "the route retirement audit event")
	waitFor(t, 2*time.Second, func() bool { return strings.Join(session.lastUpdate(), ",") == "a,c" }, "b withdrawn from the live session")

	// Siblings keep serving on the same admission; nothing was re-knocked or
	// retired, and the process is still running.
	h.requireStillRunning(t)
	states := session.RouteStates()
	for _, id := range []string{"a", "c"} {
		if states[id].Phase != share.RouteServing {
			t.Errorf("route %q phase = %s after sibling b was revoked, want serving", id, states[id].Phase)
		}
	}
	if _, present := states["b"]; present {
		t.Error("route b is still registered on the session after it was retired")
	}
	if admits, retired, _ := h.admitter.counts(); admits != 1 || retired != 0 {
		t.Fatalf("admits = %d, retired = %d; retiring one route must not touch the shared admission", admits, retired)
	}
	entry := logger.byEvent(audit.EventProxyDeny)[0]
	if entry.Outcome != audit.OutcomeDeny || entry.Reason != "resource_not_found" || entry.RouteID != "b" || entry.ResourceID != "resource-b" {
		t.Errorf("retirement audit entry = %+v", entry)
	}

	if err := h.stop(t); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v after cancel, want context.Canceled", err)
	}
}

func TestSharedServiceReturnsOnlyWhenEveryRouteIsGone(t *testing.T) {
	h := startSharedServiceHarness(t, sharedServiceTestConfig("a", "b"))
	h.waitReadyBlock(t)
	session := h.session(t, 1)

	session.failRoute("a", fmt.Errorf("%w: resource_not_found", share.ErrResourceGone))
	waitFor(t, 2*time.Second, func() bool { return strings.Join(session.lastUpdate(), ",") == "b" }, "a withdrawn")
	h.requireStillRunning(t)

	session.failRoute("b", fmt.Errorf("%w: resource_not_found", share.ErrResourceGone))
	err, returned := h.result(5 * time.Second)
	if !returned {
		t.Fatal("shared service kept running with no route left to serve")
	}
	if !errors.Is(err, share.ErrGroupEmpty) {
		t.Fatalf("Run returned %v, want ErrGroupEmpty", err)
	}
	if !strings.Contains(err.Error(), "qurl-connector remove") {
		t.Errorf("empty-group error should tell the operator how to recover; got %q", err)
	}
	if admits, retired, _ := h.admitter.counts(); admits != 1 || retired != 1 {
		t.Fatalf("admits = %d, retired = %d; want the one admission retired on exit", admits, retired)
	}
}

func TestSharedServiceReadyBlockWaitsForEveryRoute(t *testing.T) {
	h := startSharedServiceHarness(t, sharedServiceTestConfig("a", "b", "c"), "c")
	session := h.session(t, 1)

	// a and b are serving (the group promoted and MarkServingHealthy ran),
	// but c is still pending: no block. This cannot race the wrong way,
	// because nothing can print while c is held.
	waitFor(t, 2*time.Second, func() bool { _, _, healthy := h.admitter.counts(); return healthy >= 1 }, "the group to serve")
	if strings.Contains(h.out.String(), "Connector is running") {
		t.Fatalf("ready block printed with route c still pending:\n%s", h.out.String())
	}

	session.serve("c")
	block := h.waitReadyBlock(t)
	if !strings.Contains(block, "3 route(s) live") {
		t.Errorf("ready block should count every route; got:\n%s", block)
	}
	if got := readyBlockRoutes(block); strings.Join(got, ",") != "a,b,c" {
		t.Errorf("ready block routes = %v, want [a b c]", got)
	}
	for _, want := range []string{"127.0.0.1:3000", "127.0.0.1:3001", "127.0.0.1:3002"} {
		if !strings.Contains(block, want) {
			t.Errorf("ready block missing local target %q:\n%s", want, block)
		}
	}
}

func TestSharedServiceReadyBlockNamesOnlyServingRoutes(t *testing.T) {
	h := startSharedServiceHarness(t, sharedServiceTestConfig("a", "b", "c"), "c")
	session := h.session(t, 1)
	waitFor(t, 2*time.Second, func() bool { _, _, healthy := h.admitter.counts(); return healthy >= 1 }, "the group to serve")

	// c never comes up: the platform revoked it. The block must print for
	// the routes that did, without listing c.
	session.failRoute("c", fmt.Errorf("%w: resource_not_found", share.ErrResourceGone))
	block := h.waitReadyBlock(t)
	if !strings.Contains(block, "2 route(s) live") {
		t.Errorf("ready block should count only the serving routes; got:\n%s", block)
	}
	if got := readyBlockRoutes(block); strings.Join(got, ",") != "a,b" {
		t.Errorf("ready block routes = %v, want [a b]", got)
	}
	h.requireStillRunning(t)
}

func TestSharedServiceRendersOneAdminListenerForEveryRoute(t *testing.T) {
	// The desktop's default config enables the admin API on 127.0.0.1:7400.
	// FRP binds that listener inside NewService, at construction, from the
	// session's WebServer config -- so the number of listeners is the number
	// of sessions. One session for three routes renders one WebServer config
	// and three proxies.
	common := &v1.ClientCommonConfig{}
	common.WebServer.Addr, common.WebServer.Port = "127.0.0.1", 7400
	common.WebServer.User, common.WebServer.Password = "admin", "secret"
	if err := common.Complete(); err != nil {
		t.Fatal(err)
	}
	factory, err := newSharedServiceSessions(common, "qurl-proxy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	admission, err := (&fakeSharedAdmitter{}).Admit(context.Background(), "q_knock", "resource-a")
	if err != nil {
		t.Fatal(err)
	}
	cfg := sharedServiceTestConfig("a", "b", "c")
	routes := make([]share.GroupRoute, 0, len(cfg.Routes))
	for _, route := range cfg.Routes {
		routes = append(routes, share.GroupRoute{LocalHTTPRoute: share.LocalHTTPRoute{
			RouteID: route.ID, LocalIP: route.LocalIP, LocalPort: route.LocalPort,
			ResourceID: route.ResourceID, ConnectorRoutingID: route.ConnectorRoutingID,
		}})
	}
	built, proxies, names, err := factory.BuildConfig(admission, routes)
	if err != nil {
		t.Fatal(err)
	}
	if built.WebServer.Addr != "127.0.0.1" || built.WebServer.Port != 7400 {
		t.Fatalf("session WebServer = %s:%d, want the configured admin listener", built.WebServer.Addr, built.WebServer.Port)
	}
	if len(proxies) != 3 || len(names) != 3 {
		t.Fatalf("session renders %d proxies / %d names, want 3 on the one Login", len(proxies), len(names))
	}
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if _, dup := seen[name]; dup {
			t.Fatalf("proxy name %q rendered twice", name)
		}
		seen[name] = struct{}{}
	}

	// And the runtime starts exactly one session for that route set, so the
	// listener is bound exactly once.
	h := startSharedServiceHarness(t, cfg)
	h.waitReadyBlock(t)
	if starts := h.factory.starts(); starts != 1 {
		t.Fatalf("sessions started for 3 routes = %d, want 1", starts)
	}
}

func TestNewSharedServiceRunnerRejectsRoutesOnDifferentKnockResources(t *testing.T) {
	t.Setenv(EnvKnockResourceID, "")
	cfg := sharedServiceTestConfig("a", "b")
	cfg.SetKnockResourceID("resource-b", "q_other")

	_, err := newSharedServiceRunner(context.Background(), cfg, &fakeSharedAdmitter{}, &fakeGroupFactory{}, newReadyAnnouncer(nil, io.Discard, false))
	if err == nil {
		t.Fatal("routes on different NHP knock resources were accepted onto one session")
	}
	for _, want := range []string{`route "b"`, "q_other", "q_knock", "admission targets"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
}

func TestNewSharedServiceRunnerRejectsConfigsWithNothingToAdmit(t *testing.T) {
	t.Setenv(EnvKnockResourceID, "")
	announcer := newReadyAnnouncer(nil, io.Discard, false)

	if _, err := newSharedServiceRunner(context.Background(), &nhpconfig.Config{}, &fakeSharedAdmitter{}, &fakeGroupFactory{}, announcer); err == nil {
		t.Error("an empty route set was accepted")
	}

	unknockable := sharedServiceTestConfig("a")
	unknockable.Runtime.KnockResourceIDs = nil
	_, err := newSharedServiceRunner(context.Background(), unknockable, &fakeSharedAdmitter{}, &fakeGroupFactory{}, announcer)
	if err == nil || !strings.Contains(err.Error(), "missing NHP knock resource") {
		t.Errorf("a route without a knock resource was accepted; err = %v", err)
	}

	// A route that was never hydrated is a missing knock resource, not a
	// second admission target; the error must not send the operator looking
	// for one.
	partial := sharedServiceTestConfig("a", "b")
	delete(partial.Runtime.KnockResourceIDs, "resource-b")
	_, err = newSharedServiceRunner(context.Background(), partial, &fakeSharedAdmitter{}, &fakeGroupFactory{}, announcer)
	if err == nil {
		t.Fatal("a partially hydrated config was accepted")
	}
	for _, want := range []string{`route "b"`, "missing NHP knock resource", `"resource-b"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("partial-hydration error %q should mention %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "admission targets") {
		t.Errorf("partial-hydration error %q misdiagnoses a missing knock resource as a second admission target", err)
	}
}

func TestSharedServiceKeepsRouteThatMissesTheReplacementSession(t *testing.T) {
	logs := installCaptureLogger(t)
	logger := &captureAuditLogger{}
	previous := audit.SetDefault(logger)
	t.Cleanup(func() { audit.SetDefault(previous) })

	// A short admission window forces a rotation; c serves on every session
	// except the first replacement, so the old admission expires with c not
	// yet registered on the new one.
	h := startSharedServiceHarnessWith(t, sharedServiceTestConfig("a", "b", "c"), sharedServiceHarnessOptions{
		openTime: 400 * time.Millisecond,
		hold:     func(session int, routeID string) bool { return session == 2 && routeID == "c" },
	})
	h.waitReadyBlock(t)

	waitFor(t, 5*time.Second, func() bool { return len(logs.matching("did not come up on the replacement session")) >= 1 }, "the not-serving report")
	report := logs.matching("did not come up on the replacement session")[0]
	if report["route"] != "c" || !strings.Contains(report["err"], "not serving") {
		t.Errorf("not-serving report = %v", report)
	}
	// Not a retirement: no audit deny, and c stays in the group's set on the
	// replacement session.
	if denies := logger.byEvent(audit.EventProxyDeny); len(denies) != 0 {
		t.Errorf("a route that merely missed a rotation was audited as denied: %+v", denies)
	}
	if states := h.session(t, 2).RouteStates(); states["c"].Phase == share.RouteFailed {
		t.Errorf("route c was withdrawn from the replacement session: %+v", states["c"])
	}
	h.requireStillRunning(t)
	// c registers on the next rotation, with nothing to do on our side.
	waitFor(t, 5*time.Second, func() bool {
		session := h.factory.session(3)
		return session != nil && session.RouteStates()["c"].Phase == share.RouteServing
	}, "route c serving on the following session")
}

func TestSharedServiceExitsWithoutReadyBlockWhenNoRouteEverServes(t *testing.T) {
	h := startSharedServiceHarness(t, sharedServiceTestConfig("a", "b"), "a", "b")
	session := h.session(t, 1)
	session.failRoute("a", fmt.Errorf("%w: resource_not_found", share.ErrResourceGone))
	session.failRoute("b", fmt.Errorf("%w: resource_not_found", share.ErrResourceGone))

	err, returned := h.result(5 * time.Second)
	if !returned {
		t.Fatal("shared service kept running with every route revoked before serving")
	}
	if !errors.Is(err, share.ErrGroupEmpty) {
		t.Fatalf("Run returned %v, want ErrGroupEmpty", err)
	}
	if out := h.out.String(); strings.Contains(out, "Connector is running") {
		t.Errorf("ready block printed for a Connector that never served:\n%s", out)
	}
}

func TestSharedServiceForgetsRoutesServedByALostSession(t *testing.T) {
	// Session 1 serves a, b, c (d held); it is lost and session 2 comes up
	// with a, b, d serving and c held. The block must not print until c
	// registers on the active session, however long a, b, c served before.
	h := startSharedServiceHarnessWith(t, sharedServiceTestConfig("a", "b", "c", "d"), sharedServiceHarnessOptions{
		hold: func(session int, routeID string) bool {
			return (session == 1 && routeID == "d") || (session == 2 && routeID == "c")
		},
	})
	first := h.session(t, 1)
	waitFor(t, 2*time.Second, func() bool { _, _, healthy := h.admitter.counts(); return healthy >= 1 }, "session 1 promoted")
	first.end(errors.New("control connection lost"))

	second := h.session(t, 2)
	waitFor(t, 2*time.Second, func() bool { _, _, healthy := h.admitter.counts(); return healthy >= 2 }, "session 2 promoted")
	waitFor(t, 2*time.Second, func() bool { return second.RouteStates()["d"].Phase == share.RouteServing }, "d serving on session 2")
	// The stale-serving bug printed synchronously inside the promotion; a
	// short quiet window is ample to observe it.
	time.Sleep(100 * time.Millisecond)
	if out := h.out.String(); strings.Contains(out, "Connector is running") {
		t.Fatalf("block printed with c not serving on the active session:\n%s", out)
	}

	second.serve("c")
	block := h.waitReadyBlock(t)
	if !strings.Contains(block, "4 route(s) live") {
		t.Errorf("block should count every route once all serve on the active session; got:\n%s", block)
	}
	if got := readyBlockRoutes(block); strings.Join(got, ",") != "a,b,c,d" {
		t.Errorf("block routes = %v, want [a b c d]", got)
	}
}

func TestSharedServiceRetiresPrimaryRouteWhoseAdmissionIsGone(t *testing.T) {
	logger := &captureAuditLogger{}
	previous := audit.SetDefault(logger)
	t.Cleanup(func() { audit.SetDefault(previous) })

	// The knock authenticates the primary route's resource; the platform
	// revoked it, so the admission itself is refused. The siblings must be
	// re-admitted under the next route rather than exit with it.
	h := startSharedServiceHarnessWith(t, sharedServiceTestConfig("a", "b", "c"), sharedServiceHarnessOptions{
		deny: map[string]error{"resource-a": fmt.Errorf("%w: authenticated deny", share.ErrResourceGone)},
	})
	block := h.waitReadyBlock(t)
	if !strings.Contains(block, "2 route(s) live") {
		t.Errorf("block should count the two surviving routes; got:\n%s", block)
	}
	if got := readyBlockRoutes(block); strings.Join(got, ",") != "b,c" {
		t.Errorf("block routes = %v, want [b c]", got)
	}
	denies := logger.byEvent(audit.EventProxyDeny)
	if len(denies) != 1 || denies[0].RouteID != "a" || denies[0].ResourceID != "resource-a" || denies[0].Reason != "admission_resource_gone" {
		t.Errorf("retirement audit entries = %+v", denies)
	}
	states := h.session(t, 1).RouteStates()
	if len(states) != 2 || states["b"].Phase != share.RouteServing || states["c"].Phase != share.RouteServing {
		t.Errorf("surviving session states = %+v", states)
	}
	if _, present := states["a"]; present {
		t.Error("the retired primary route was registered on the surviving session")
	}
	// One refused admission for a, one granted for b: the group did not
	// knock for c separately.
	if admits, _, _ := h.admitter.counts(); admits != 1 {
		t.Errorf("granted admissions = %d, want 1", admits)
	}
	if knocks := h.admitter.knockResources(); len(knocks) != 2 {
		t.Errorf("knocks = %v, want one refused and one granted", knocks)
	}
	h.requireStillRunning(t)
}

func TestSharedServiceExitsWhenEveryAdmissionIsGone(t *testing.T) {
	gone := fmt.Errorf("%w: authenticated deny", share.ErrResourceGone)
	h := startSharedServiceHarnessWith(t, sharedServiceTestConfig("a", "b", "c"), sharedServiceHarnessOptions{
		deny: map[string]error{"resource-a": gone, "resource-b": gone, "resource-c": gone},
	})
	err, returned := h.result(5 * time.Second)
	if !returned {
		t.Fatal("shared service kept knocking with every admission refused")
	}
	if !errors.Is(err, share.ErrResourceGone) || !strings.Contains(err.Error(), "qurl-connector remove") {
		t.Fatalf("Run returned %v, want ErrResourceGone with the recovery hint", err)
	}
	// Bounded: one knock per route, then exit.
	if knocks := h.admitter.knockResources(); len(knocks) != 3 {
		t.Errorf("knocks = %v, want exactly one per route", knocks)
	}
	if out := h.out.String(); strings.Contains(out, "Connector is running") {
		t.Errorf("ready block printed for a Connector that never served:\n%s", out)
	}
}

func TestSharedServiceKnockOverrideAppliesToEveryRoute(t *testing.T) {
	// The developer override replaces the knock operand for every route, so
	// a config whose hydrated knock resources disagree is still one session
	// knocking the override.
	t.Setenv(EnvKnockResourceID, "q_override")
	cfg := sharedServiceTestConfig("a", "b")
	cfg.SetKnockResourceID("resource-b", "q_other")
	admitter := &fakeSharedAdmitter{}
	runner, err := newSharedServiceRunner(context.Background(), cfg, admitter, &fakeGroupFactory{}, newReadyAnnouncer(nil, io.Discard, false))
	if err != nil {
		t.Fatalf("override config rejected: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	waitFor(t, 2*time.Second, func() bool { admits, _, _ := admitter.counts(); return admits >= 1 }, "the admission")
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runner did not stop")
	}
	if knocks := admitter.knockResources(); len(knocks) != 1 || knocks[0] != "q_override" {
		t.Errorf("knocks = %v, want one knock of the override resource", knocks)
	}
}

func TestSharedServiceRetiredRoutesStayRetiredAcrossReadmission(t *testing.T) {
	logger := &captureAuditLogger{}
	previous := audit.SetDefault(logger)
	t.Cleanup(func() { audit.SetDefault(previous) })

	h := startSharedServiceHarness(t, sharedServiceTestConfig("a", "b", "c"))
	h.waitReadyBlock(t)
	first := h.session(t, 1)

	// c is revoked per proxy, then the session itself ends as resource-gone
	// (a Login the tunnel server rejected): the primary a is retired and the
	// rest re-admitted -- without c, which is already known dead.
	first.failRoute("c", fmt.Errorf("%w: resource_not_found", share.ErrResourceGone))
	waitFor(t, 2*time.Second, func() bool { return strings.Join(first.lastUpdate(), ",") == "a,b" }, "c withdrawn")
	first.end(fmt.Errorf("%w: login rejected", share.ErrResourceGone))

	second := h.session(t, 2)
	waitFor(t, 2*time.Second, func() bool { return second.RouteStates()["b"].Phase == share.RouteServing }, "b serving on the re-admitted session")
	if states := second.RouteStates(); len(states) != 1 {
		t.Errorf("re-admitted session carries %d routes, want only b: %+v", len(states), states)
	}
	if second.admission.ResourceID != "resource-b" {
		t.Errorf("re-admitted under %q, want resource-b", second.admission.ResourceID)
	}
	denies := logger.byEvent(audit.EventProxyDeny)
	if len(denies) != 2 {
		t.Fatalf("audit denies = %+v, want exactly one for c and one for a", denies)
	}
	if denies[0].RouteID != "c" || denies[0].Reason != "resource_not_found" || denies[1].RouteID != "a" || denies[1].Reason != "admission_resource_gone" {
		t.Errorf("audit denies = %+v", denies)
	}
	h.requireStillRunning(t)
}

func TestSharedServiceRetiresPrimaryRevokedPerProxyOnce(t *testing.T) {
	logger := &captureAuditLogger{}
	previous := audit.SetDefault(logger)
	t.Cleanup(func() { audit.SetDefault(previous) })

	h := startSharedServiceHarness(t, sharedServiceTestConfig("a", "b", "c"))
	h.waitReadyBlock(t)
	first := h.session(t, 1)

	// The primary a is revoked per proxy; the group's admission is still
	// bound to its resource, so the next admission attempt is refused too.
	// That is one retirement, not two.
	first.failRoute("a", fmt.Errorf("%w: resource_not_found", share.ErrResourceGone))
	waitFor(t, 2*time.Second, func() bool { return strings.Join(first.lastUpdate(), ",") == "b,c" }, "a withdrawn")
	first.end(fmt.Errorf("%w: login rejected", share.ErrResourceGone))

	second := h.session(t, 2)
	waitFor(t, 2*time.Second, func() bool { return second.RouteStates()["c"].Phase == share.RouteServing }, "siblings serving on the re-admitted session")
	if second.admission.ResourceID != "resource-b" {
		t.Errorf("re-admitted under %q, want resource-b", second.admission.ResourceID)
	}
	if states := second.RouteStates(); len(states) != 2 {
		t.Errorf("re-admitted session carries %d routes, want b and c: %+v", len(states), states)
	}
	denies := logger.byEvent(audit.EventProxyDeny)
	if len(denies) != 1 || denies[0].RouteID != "a" || denies[0].Reason != "resource_not_found" {
		t.Errorf("audit denies = %+v, want exactly one for a as resource_not_found", denies)
	}
	h.requireStillRunning(t)
}

func TestSharedServiceFallbackIgnoresRoutesFromAnEndedSession(t *testing.T) {
	previous := readyFallbackWait
	readyFallbackWait = 60 * time.Millisecond
	t.Cleanup(func() { readyFallbackWait = previous })

	// d is held everywhere so the block is still waiting when session 1 is
	// lost; re-admission is held back so the wait elapses with no session.
	h := startSharedServiceHarness(t, sharedServiceTestConfig("a", "b", "c", "d"), "d")
	first := h.session(t, 1)
	waitFor(t, 2*time.Second, func() bool { return first.RouteStates()["c"].Phase == share.RouteServing }, "session 1 serving")
	release := h.admitter.holdAdmissions()
	t.Cleanup(release)
	first.end(errors.New("control connection lost"))

	// Once the re-admission is parked at the gate the runner has no active
	// session; fire the wait directly rather than sleeping for it, so the
	// assertion cannot pass merely because the timer had not gone off yet.
	waitFor(t, 2*time.Second, func() bool { return h.admitter.heldAdmits() >= 1 }, "re-admission parked at the gate")
	h.announcer.announceOutstanding()
	if out := h.out.String(); strings.Contains(out, "Connector is running") {
		t.Fatalf("fallback block printed routes from the ended session while nothing served:\n%s", out)
	}

	release()
	block := h.waitReadyBlock(t)
	if !strings.Contains(block, "3 of 4 route(s) live") {
		t.Errorf("fallback block should list the replacement session's routes; got:\n%s", block)
	}
	if got := readyBlockRoutes(block); strings.Join(got, ",") != "a,b,c" {
		t.Errorf("fallback block rows = %v, want [a b c]", got)
	}
}

func TestSharedServiceReadyBlockFallsBackWhenARouteStaysPending(t *testing.T) {
	previous := readyFallbackWait
	readyFallbackWait = 50 * time.Millisecond
	t.Cleanup(func() { readyFallbackWait = previous })

	h := startSharedServiceHarness(t, sharedServiceTestConfig("a", "b", "c"), "c")
	block := h.waitReadyBlock(t)
	if !strings.Contains(block, "2 of 3 route(s) live") {
		t.Errorf("fallback block should count live routes against the configured set; got:\n%s", block)
	}
	if got := readyBlockRoutes(block); strings.Join(got, ",") != "a,b" {
		t.Errorf("fallback block rows = %v, want [a b]", got)
	}
	if !strings.Contains(block, "Still registering:") || !strings.Contains(block, "c") {
		t.Errorf("fallback block should name c as still registering; got:\n%s", block)
	}

	h.session(t, 1).serve("c")
	waitFor(t, 2*time.Second, func() bool { return strings.Contains(h.out.String(), "c is now live") }, "route c narrated live")
	if n := strings.Count(h.out.String(), "Connector is running"); n != 1 {
		t.Errorf("block printed %d times, want exactly 1", n)
	}
	h.requireStillRunning(t)
}
