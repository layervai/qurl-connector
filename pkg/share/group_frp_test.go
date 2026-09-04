package share

import (
	"context"
	"errors"
	"math"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	frpproxy "github.com/fatedier/frp/client/proxy"
	v1 "github.com/fatedier/frp/pkg/config/v1"

	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

func groupTestRoutes(ids ...string) []LocalHTTPRoute {
	routes := make([]LocalHTTPRoute, 0, len(ids))
	for i, id := range ids {
		routes = append(routes, LocalHTTPRoute{
			RouteID: id, LocalIP: "127.0.0.1", LocalPort: 3000 + i,
			ResourceID: "resource-" + id, ConnectorRoutingID: "routing-" + id,
		})
	}
	return routes
}

func groupRoutesOf(routes []LocalHTTPRoute) []GroupRoute {
	out := make([]GroupRoute, 0, len(routes))
	for _, route := range routes {
		out = append(out, GroupRoute{LocalHTTPRoute: route})
	}
	return out
}

func groupTestAdmission(sessionID uint64) Admission {
	return Admission{
		KnockResourceID: "q_catalog_key", ResourceID: "group-resource",
		RunID: "run", RunAttempt: 1, Token: "token", ResourceHost: "frp.example:7000",
		SessionID: sessionID, SessionReceipt: testSessionReceipt(sessionID, "run", 1), OpenTime: 5 * time.Minute,
	}
}

func TestFRPSessionGroupFactoryBuildsOneSessionForManyRoutes(t *testing.T) {
	common := &v1.ClientCommonConfig{Metadatas: map[string]string{"preserved": "value"}}
	factory, err := NewFRPSessionGroupFactory(FRPGroupFactoryConfig{Common: common, ClientVersion: "v1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	routes := groupRoutesOf(groupTestRoutes("alpha", "beta", "gamma"))
	routes[1].Generation = 2
	cycleCommon, proxies, names, err := factory.BuildConfig(groupTestAdmission(101), routes)
	if err != nil {
		t.Fatal(err)
	}
	if cycleCommon.ServerAddr != "frp.example" || cycleCommon.ServerPort != 7000 {
		t.Fatalf("admitted server = %s:%d", cycleCommon.ServerAddr, cycleCommon.ServerPort)
	}
	if cycleCommon.Metadatas[nhpconfig.MetaQURLKnockToken] != "token" || cycleCommon.Metadatas["preserved"] != "value" ||
		cycleCommon.Metadatas[nhpconfig.MetaClientVersion] != "v1.2.3" {
		t.Fatalf("Login metadata = %#v", cycleCommon.Metadatas)
	}
	if cycleCommon.LoginFailExit == nil || !*cycleCommon.LoginFailExit {
		t.Fatal("group Login is not fail-fast")
	}
	if _, ok := common.Metadatas[nhpconfig.MetaQURLKnockToken]; ok {
		t.Fatal("cycle token mutated the caller's common config")
	}
	wantNames := []string{"alpha-nhp2t", "beta-nhp2t-r2", "gamma-nhp2t"}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("proxy names = %q, want %q", names, wantNames)
	}
	if len(proxies) != len(routes) {
		t.Fatalf("proxies = %d, want one per route", len(proxies))
	}
	for i, configurer := range proxies {
		proxy, ok := configurer.(*v1.HTTPProxyConfig)
		if !ok {
			t.Fatalf("proxy[%d] type = %T", i, configurer)
		}
		route := routes[i]
		if proxy.Name != names[i] || proxy.Type != string(v1.ProxyTypeHTTP) {
			t.Errorf("proxy[%d] identity = %s/%s", i, proxy.Name, proxy.Type)
		}
		if proxy.SubDomain != route.ConnectorRoutingID || proxy.LoadBalancer.Group != route.ConnectorRoutingID ||
			proxy.LoadBalancer.GroupKey != route.ConnectorRoutingID {
			t.Errorf("proxy[%d] routing identity = %+v", i, proxy)
		}
		if proxy.LocalIP != route.LocalIP || proxy.LocalPort != route.LocalPort {
			t.Errorf("proxy[%d] target = %s:%d", i, proxy.LocalIP, proxy.LocalPort)
		}
		if got := proxy.Metadatas[nhpconfig.MetaResourceID]; got != route.ResourceID {
			t.Errorf("proxy[%d] public resource metadata = %q, want %q", i, got, route.ResourceID)
		}
	}
}

func TestGroupProxyNameMatchesSingleRouteNameAtGenerationZero(t *testing.T) {
	route := groupTestRoutes("local-app")[0]
	single, err := NewFRPSessionFactory(FRPFactoryConfig{Common: &v1.ClientCommonConfig{}, Route: route})
	if err != nil {
		t.Fatal(err)
	}
	admission := groupTestAdmission(4095)
	admission.ResourceID = route.ResourceID
	_, _, singleNames, err := single.BuildConfig(admission)
	if err != nil {
		t.Fatal(err)
	}
	if got := groupProxyName(GroupRoute{LocalHTTPRoute: route}, 4095); got != singleNames[0] {
		t.Fatalf("generation-0 group proxy name = %q, single-route name = %q", got, singleNames[0])
	}
	restarted := groupProxyName(GroupRoute{LocalHTTPRoute: route, Generation: 1}, 4095)
	if restarted == singleNames[0] || !strings.HasPrefix(restarted, singleNames[0]+"-r") {
		t.Fatalf("restart generation name = %q, want %q plus a restart suffix", restarted, singleNames[0])
	}
	// Session and restart discriminators are both base-36, so only the
	// hyphen keeps a restarted route on one session distinct from a
	// generation-0 route on a later session.
	other := groupProxyName(GroupRoute{LocalHTTPRoute: route}, 4095*36*36+27*36+1)
	if other == restarted {
		t.Fatalf("restart name %q collides with another session's generation-0 name", restarted)
	}
}

func TestGroupProxyNameStaysUniquePastDiscriminatorCap(t *testing.T) {
	// A session ID wide enough to fill the 16-character discriminator cap
	// pushes a restart generation through Normalize's prefix+digest form.
	route := groupTestRoutes("x")[0]
	single, err := NewFRPSessionFactory(FRPFactoryConfig{Common: &v1.ClientCommonConfig{}, Route: route})
	if err != nil {
		t.Fatal(err)
	}
	admission := groupTestAdmission(math.MaxUint64)
	admission.ResourceID = route.ResourceID
	_, _, singleNames, err := single.BuildConfig(admission)
	if err != nil {
		t.Fatal(err)
	}
	names := map[uint64]string{}
	for generation := uint64(0); generation < 3; generation++ {
		name := groupProxyName(GroupRoute{LocalHTTPRoute: route, Generation: generation}, math.MaxUint64)
		if discriminator := strings.TrimPrefix(name, "x-"); len(discriminator) > 16 {
			t.Fatalf("generation %d discriminator %q exceeds the 16-character cap", generation, discriminator)
		}
		for other, otherName := range names {
			if otherName == name {
				t.Fatalf("generation %d and %d render the same proxy name %q", generation, other, name)
			}
		}
		names[generation] = name
	}
	if names[0] != singleNames[0] || names[0] != "x-nhp3w5e11264sgsf" {
		t.Fatalf("generation-0 name = %q, single-route name = %q, want the readable full-width session discriminator", names[0], singleNames[0])
	}
	if !strings.HasPrefix(names[1], "x-nhp3w5e-") || len(names[1]) != len("x-nhp3w5e-")+8 {
		t.Fatalf("capped restart name = %q, want the 7-character prefix plus an 8-hex digest", names[1])
	}
}

func TestNewFRPSessionGroupFactoryRejectsStartFilter(t *testing.T) {
	common := &v1.ClientCommonConfig{Start: []string{"other-proxy"}}
	if _, err := NewFRPSessionGroupFactory(FRPGroupFactoryConfig{Common: common}); err == nil {
		t.Fatal("a Login-level proxy start filter was accepted for a session group")
	}
	// Defense in depth: the completion step itself refuses to drop routes.
	_, proxies, _, err := (&FRPSessionGroupFactory{cfg: FRPGroupFactoryConfig{Common: common}}).BuildConfig(groupTestAdmission(1), groupRoutesOf(groupTestRoutes("a", "b")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := completeGroupProxies(common, proxies); err == nil || !strings.Contains(err.Error(), `"a-nhp1"`) {
		t.Fatalf("completeGroupProxies() = %v, want an error naming the dropped proxies", err)
	}
}

func TestValidateGroupRoutes(t *testing.T) {
	base := groupTestRoutes("a", "b", "c")
	mutate := func(fn func(routes []LocalHTTPRoute)) []LocalHTTPRoute {
		routes := append([]LocalHTTPRoute(nil), base...)
		fn(routes)
		return routes
	}
	tooMany := make([]LocalHTTPRoute, 0, MaxGroupRoutes+1)
	for i := 0; i <= MaxGroupRoutes; i++ {
		id := "r" + strconv.Itoa(i)
		tooMany = append(tooMany, LocalHTTPRoute{RouteID: id, LocalIP: "127.0.0.1", LocalPort: 1 + i%60000, ResourceID: "res-" + id, ConnectorRoutingID: "rt-" + id})
	}
	tests := []struct {
		name   string
		routes []LocalHTTPRoute
		want   string
	}{
		{name: "valid", routes: base},
		{name: "empty", routes: nil, want: "no routes"},
		{name: "over bound", routes: tooMany, want: "at most 2000"},
		{name: "duplicate route ID", routes: mutate(func(r []LocalHTTPRoute) { r[2].RouteID = "a" }), want: `route ID "a" is already used by routes[0]`},
		{name: "duplicate resource ID", routes: mutate(func(r []LocalHTTPRoute) { r[1].ResourceID = "resource-c" }), want: `routes[2] (c): resource ID "resource-c" is already used by routes[1]`},
		{name: "duplicate routing ID", routes: mutate(func(r []LocalHTTPRoute) { r[0].ConnectorRoutingID = "routing-b" }), want: `connector routing ID "routing-b" is already used by routes[0]`},
		{name: "missing identity", routes: mutate(func(r []LocalHTTPRoute) { r[1].ResourceID = "" }), want: "routes[1] (b): route identities are incomplete"},
		{name: "bad target", routes: mutate(func(r []LocalHTTPRoute) { r[2].LocalPort = 70000 }), want: "routes[2] (c): local target is invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateGroupRoutes(test.routes)
			if test.want == "" {
				if err != nil {
					t.Fatalf("ValidateGroupRoutes() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateGroupRoutes() = %v, want %q", err, test.want)
			}
		})
	}
	if _, _, _, err := (&FRPSessionGroupFactory{cfg: FRPGroupFactoryConfig{Common: &v1.ClientCommonConfig{}}}).BuildConfig(groupTestAdmission(1), groupRoutesOf(tooMany)); err == nil {
		t.Fatal("BuildConfig accepted a group over the bound")
	}
}

func thousandRoutes(n int) []LocalHTTPRoute {
	routes := make([]LocalHTTPRoute, 0, n)
	for i := 0; i < n; i++ {
		id := "crid-" + strconv.Itoa(i)
		routes = append(routes, LocalHTTPRoute{RouteID: id, LocalIP: "127.0.0.1", LocalPort: 1 + i%60000, ResourceID: "res-" + id, ConnectorRoutingID: "rt-" + id})
	}
	return routes
}

func TestFRPSessionGroupFactoryBuildsThousandRouteGroupQuickly(t *testing.T) {
	factory, err := NewFRPSessionGroupFactory(FRPGroupFactoryConfig{Common: &v1.ClientCommonConfig{}})
	if err != nil {
		t.Fatal(err)
	}
	routes := thousandRoutes(1000)
	started := time.Now()
	if err := ValidateGroupRoutes(routes); err != nil {
		t.Fatal(err)
	}
	common, proxies, names, err := factory.BuildConfig(groupTestAdmission(1), groupRoutesOf(routes))
	if err != nil {
		t.Fatal(err)
	}
	completed, err := completeGroupProxies(common, proxies)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	if len(proxies) != 1000 || len(names) != 1000 || len(completed) != 1000 {
		t.Fatalf("rendered %d proxies, %d names, %d completed for 1000 routes", len(proxies), len(names), len(completed))
	}
	if elapsed > time.Second {
		t.Fatalf("validating and rendering a 1000-route group took %s, want well under a second", elapsed)
	}
}

func BenchmarkFRPSessionGroupFactoryBuildThousandRoutes(b *testing.B) {
	factory, err := NewFRPSessionGroupFactory(FRPGroupFactoryConfig{Common: &v1.ClientCommonConfig{}})
	if err != nil {
		b.Fatal(err)
	}
	routes := groupRoutesOf(thousandRoutes(1000))
	admission := groupTestAdmission(1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, _, err := factory.BuildConfig(admission, routes); err != nil {
			b.Fatal(err)
		}
	}
}

// recordingGroupService is a live FRP service stand-in that records every
// hot proxy-set update.
type recordingGroupService struct {
	mu      sync.Mutex
	updates [][]v1.ProxyConfigurer
}

func (s *recordingGroupService) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (*recordingGroupService) GracefulClose(time.Duration) {}

func (s *recordingGroupService) UpdateAllConfigurer(proxies []v1.ProxyConfigurer, _ []v1.VisitorConfigurer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updates = append(s.updates, append([]v1.ProxyConfigurer(nil), proxies...))
	return nil
}

func (s *recordingGroupService) updateNames() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]string, 0, len(s.updates))
	for _, update := range s.updates {
		names := make([]string, 0, len(update))
		for _, proxy := range update {
			names = append(names, proxy.GetBaseConfig().Name)
		}
		out = append(out, names)
	}
	return out
}

func (s *recordingGroupService) lastUpdate() []v1.ProxyConfigurer {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.updates) == 0 {
		return nil
	}
	return s.updates[len(s.updates)-1]
}

type lockedStatusMap struct {
	mu    sync.Mutex
	items map[string]*frpproxy.WorkingStatus
}

func (s *lockedStatusMap) GetProxyStatus(name string) (*frpproxy.WorkingStatus, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[name]
	if !ok {
		return nil, false
	}
	copied := *item
	return &copied, true
}

func (s *lockedStatusMap) set(name, phase, err string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.items == nil {
		s.items = make(map[string]*frpproxy.WorkingStatus)
	}
	s.items[name] = &frpproxy.WorkingStatus{Name: name, Phase: phase, Err: err}
}

func startTestGroupSession(t *testing.T, svc frpGroupService, status *lockedStatusMap, routes []GroupRoute) *frpGroupSession {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	session := newFRPGroupSession(svc, status, &v1.ClientCommonConfig{}, 7, time.Millisecond, routes)
	session.cancel = cancel
	go session.run(ctx)
	t.Cleanup(func() { _ = session.Stop(context.Background()) })
	return session
}

func waitForRouteStates(t *testing.T, session GroupServingSession, want func(map[string]RouteState) bool) map[string]RouteState {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		states := session.RouteStates()
		if want(states) {
			return states
		}
		select {
		case <-session.Changes():
		case <-time.After(5 * time.Millisecond):
		case <-deadline:
			t.Fatalf("route states never reached the expected shape: %+v", states)
		}
	}
}

func phaseOf(states map[string]RouteState, routeID string) RoutePhase {
	state, ok := states[routeID]
	if !ok {
		return RoutePhase("absent")
	}
	return state.Phase
}

func TestFRPGroupSessionIsolatesGoneRoute(t *testing.T) {
	svc := &recordingGroupService{}
	status := &lockedStatusMap{}
	routes := groupRoutesOf(groupTestRoutes("a", "b", "c"))
	session := startTestGroupSession(t, svc, status, routes)
	status.set("a-nhp7", frpproxy.ProxyPhaseRunning, "")
	status.set("c-nhp7", frpproxy.ProxyPhaseRunning, "")
	status.set("b-nhp7", frpproxy.ProxyPhaseStartErr, "resource_not_found: resource not found")

	states := waitForRouteStates(t, session, func(s map[string]RouteState) bool {
		return phaseOf(s, "a") == RouteServing && phaseOf(s, "c") == RouteServing && phaseOf(s, "b") == RouteFailed
	})
	if !errors.Is(states["b"].Err, ErrResourceGone) {
		t.Fatalf("route b error = %v, want ErrResourceGone", states["b"].Err)
	}
	select {
	case <-session.Done():
		t.Fatalf("resource_not_found on one route ended the whole session: %v", session.Err())
	default:
	}
	if err := session.Err(); err != nil {
		t.Fatalf("session error = %v, want none for a per-route failure", err)
	}
	select {
	case <-session.Ready():
	case <-time.After(time.Second):
		t.Fatal("session with every live route running did not report ready")
	}
	// The gone proxy is withdrawn from FRP so it stops re-sending NewProxy;
	// the siblings stay registered.
	deadline := time.Now().Add(time.Second)
	for {
		updates := svc.updateNames()
		if len(updates) > 0 && reflect.DeepEqual(updates[len(updates)-1], []string{"a-nhp7", "c-nhp7"}) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("FRP proxy set after resource_not_found = %q, want only the siblings", updates)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestFRPGroupSessionUpdateRegistersOnlyChangedProxies(t *testing.T) {
	svc := &recordingGroupService{}
	status := &lockedStatusMap{}
	routes := groupRoutesOf(groupTestRoutes("a", "b", "c"))
	session := startTestGroupSession(t, svc, status, routes)
	for _, name := range []string{"a-nhp7", "b-nhp7", "c-nhp7"} {
		status.set(name, frpproxy.ProxyPhaseRunning, "")
	}
	waitForRouteStates(t, session, func(s map[string]RouteState) bool {
		return phaseOf(s, "a") == RouteServing && phaseOf(s, "b") == RouteServing && phaseOf(s, "c") == RouteServing
	})

	next := groupRoutesOf(groupTestRoutes("a", "b", "c", "d"))
	next[0].Generation = 1
	next = append(next[:1], next[2:]...) // drop b
	if err := session.Update(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	states := session.RouteStates()
	if _, present := states["b"]; present {
		t.Fatalf("removed route b still tracked: %+v", states["b"])
	}
	if states["a"].ProxyName != "a-nhp7-r1" || states["a"].Phase != RoutePending {
		t.Fatalf("restarted route a = %+v, want a fresh pending registration under a new name", states["a"])
	}
	if states["c"].ProxyName != "c-nhp7" || states["c"].Phase != RouteServing {
		t.Fatalf("unchanged route c = %+v, want its serving state preserved", states["c"])
	}
	if states["d"].ProxyName != "d-nhp7" || states["d"].Phase != RoutePending {
		t.Fatalf("added route d = %+v", states["d"])
	}
	updates := svc.updateNames()
	if want := []string{"a-nhp7-r1", "c-nhp7", "d-nhp7"}; !reflect.DeepEqual(updates[len(updates)-1], want) {
		t.Fatalf("FRP proxy set after update = %q, want %q", updates[len(updates)-1], want)
	}
	status.set("a-nhp7-r1", frpproxy.ProxyPhaseRunning, "")
	status.set("d-nhp7", frpproxy.ProxyPhaseRunning, "")
	waitForRouteStates(t, session, func(s map[string]RouteState) bool {
		return phaseOf(s, "a") == RouteServing && phaseOf(s, "d") == RouteServing
	})
}

func TestFRPGroupSessionUpdatedProxiesMatchServiceCompletedConfigs(t *testing.T) {
	// FRP diffs live proxies against an update with reflect.DeepEqual, so an
	// update must carry the completed shape the start path seeds. This proves
	// the session's Update output is self-consistent with the same completion
	// the start path applies (and that completion changes the shape at all);
	// agreement with FRP's own Service is covered by the FRPS-backed
	// TestHermeticSessionGroupServesManyRoutesOnOneAdmission.
	common := &v1.ClientCommonConfig{}
	factory, err := NewFRPSessionGroupFactory(FRPGroupFactoryConfig{Common: common})
	if err != nil {
		t.Fatal(err)
	}
	routes := groupRoutesOf(groupTestRoutes("a", "b"))
	admission := groupTestAdmission(7)
	_, rendered, _, err := factory.BuildConfig(admission, routes)
	if err != nil {
		t.Fatal(err)
	}
	_, uncompleted, _, err := factory.BuildConfig(admission, routes)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := completeGroupProxies(common, rendered)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(initial[0], uncompleted[0]) {
		t.Fatal("completion changed nothing; this guard no longer proves anything")
	}
	svc := &recordingGroupService{}
	session := startTestGroupSession(t, svc, &lockedStatusMap{}, routes)
	if err := session.Update(context.Background(), append(routes, groupRoutesOf(groupTestRoutes("a", "b", "c"))[2])); err != nil {
		t.Fatal(err)
	}
	update := svc.lastUpdate()
	if len(update) != 3 {
		t.Fatalf("update carried %d proxies, want 3", len(update))
	}
	for i := range initial {
		if !reflect.DeepEqual(update[i], initial[i]) {
			t.Fatalf("unchanged proxy %q differs from the service's completed config:\n update  %+v\n initial %+v",
				initial[i].GetBaseConfig().Name, update[i], initial[i])
		}
	}
}

func TestFRPGroupSessionUpdateRefusesInPlaceRouteChange(t *testing.T) {
	svc := &recordingGroupService{}
	status := &lockedStatusMap{}
	session := startTestGroupSession(t, svc, status, groupRoutesOf(groupTestRoutes("a")))
	status.set("a-nhp7", frpproxy.ProxyPhaseRunning, "")
	waitForRouteStates(t, session, func(s map[string]RouteState) bool { return phaseOf(s, "a") == RouteServing })

	moved := groupRoutesOf(groupTestRoutes("a"))
	moved[0].LocalPort = 4000
	err := session.Update(context.Background(), moved)
	if err == nil || !strings.Contains(err.Error(), "changed in place") {
		t.Fatalf("Update with a changed target under the same name = %v, want a refusal", err)
	}
	if state := session.RouteStates()["a"]; state.Phase != RouteServing || state.Route.LocalPort != 3000 {
		t.Fatalf("refused update altered the table: %+v", state)
	}
	if len(svc.updateNames()) != 0 {
		t.Fatalf("refused update reached FRP: %q", svc.updateNames())
	}
	moved[0].Generation = 1
	if err := session.Update(context.Background(), moved); err != nil {
		t.Fatal(err)
	}
	if state := session.RouteStates()["a"]; state.ProxyName != "a-nhp7-r1" || state.Phase != RoutePending {
		t.Fatalf("regenerated route a = %+v, want a fresh pending registration", state)
	}
}

// gatedStatus blocks status reads on demand so a test can end the session
// while observe is between its snapshot and its write-back.
type gatedStatus struct {
	inner   *lockedStatusMap
	mu      sync.Mutex
	gate    chan struct{}
	entered chan struct{}
	once    sync.Once
}

func (g *gatedStatus) GetProxyStatus(name string) (*frpproxy.WorkingStatus, bool) {
	g.mu.Lock()
	gate := g.gate
	g.mu.Unlock()
	if gate != nil {
		g.once.Do(func() { close(g.entered) })
		<-gate
	}
	return g.inner.GetProxyStatus(name)
}

func (g *gatedStatus) arm() chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gate = make(chan struct{})
	return g.gate
}

func TestFRPGroupSessionDoesNotResurrectServingAfterEnd(t *testing.T) {
	inner := &lockedStatusMap{}
	status := &gatedStatus{inner: inner, entered: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	session := newFRPGroupSession(&recordingGroupService{}, status, &v1.ClientCommonConfig{}, 7, time.Millisecond, groupRoutesOf(groupTestRoutes("a")))
	session.cancel = cancel
	go session.run(ctx)
	inner.set("a-nhp7", frpproxy.ProxyPhaseRunning, "")
	waitForRouteStates(t, session, func(s map[string]RouteState) bool { return phaseOf(s, "a") == RouteServing })

	// Park the scan after its snapshot, end the session (which demotes a),
	// then let the scan finish: it must not write "serving" back.
	gate := status.arm()
	select {
	case <-status.entered:
	case <-time.After(time.Second):
		t.Fatal("observe never entered the gated status scan")
	}
	if err := session.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := session.RouteStates()["a"]; state.Phase != RoutePending {
		t.Fatalf("route a after the session ended = %+v, want demoted", state)
	}
	close(gate)
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		if state := session.RouteStates()["a"]; state.Phase == RouteServing {
			t.Fatalf("a scan that outlived the session resurrected route a: %+v", state)
		}
		time.Sleep(2 * time.Millisecond)
	}
	if len(session.ServingRouteIDs()) != 0 {
		t.Fatal("dead session still lists serving routes")
	}
}

func TestFRPGroupSessionStaleAdmissionEndsWholeSession(t *testing.T) {
	svc := &recordingGroupService{}
	status := &lockedStatusMap{}
	session := startTestGroupSession(t, svc, status, groupRoutesOf(groupTestRoutes("a", "b")))
	status.set("a-nhp7", frpproxy.ProxyPhaseRunning, "")
	status.set("b-nhp7", frpproxy.ProxyPhaseStartErr, "knock_invalid: knock token expired")
	select {
	case <-session.Done():
	case <-time.After(time.Second):
		t.Fatal("admission-level rejection on one proxy did not end the shared session")
	}
	if err := session.Err(); !errors.Is(err, ErrAdmissionStale) || !strings.Contains(err.Error(), `route "b"`) {
		t.Fatalf("session error = %v, want stale admission naming route b", err)
	}
	if err := session.Update(context.Background(), groupRoutesOf(groupTestRoutes("a"))); !errors.Is(err, ErrSessionGroupEnded) {
		t.Fatalf("Update after the session ended = %v, want %v", err, ErrSessionGroupEnded)
	}
}

// flakyGroupService rejects the first N proxy-set pushes.
type flakyGroupService struct {
	recordingGroupService
	failuresLeft int
	attempts     int
}

func (s *flakyGroupService) UpdateAllConfigurer(proxies []v1.ProxyConfigurer, visitors []v1.VisitorConfigurer) error {
	s.mu.Lock()
	s.attempts++
	if s.failuresLeft > 0 {
		s.failuresLeft--
		s.mu.Unlock()
		return errors.New("control connection reset")
	}
	s.mu.Unlock()
	return s.recordingGroupService.UpdateAllConfigurer(proxies, visitors)
}

func (s *flakyGroupService) attemptCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts
}

func TestFRPGroupSessionBacksOffFailedPushRetries(t *testing.T) {
	svc := &flakyGroupService{failuresLeft: 1 << 20}
	session := startTestGroupSession(t, svc, &lockedStatusMap{}, groupRoutesOf(groupTestRoutes("a")))
	if err := session.Update(context.Background(), groupRoutesOf(groupTestRoutes("a", "b"))); err == nil {
		t.Fatal("Update against a failing service returned nil")
	}
	// At a 1ms poll an unbacked retry would fire ~60 times in 60ms; the
	// exponential delay (1, 2, 4, 8, 16, 32ms) allows only a handful.
	time.Sleep(60 * time.Millisecond)
	if got := svc.attemptCount(); got > 12 {
		t.Fatalf("push attempts in 60ms = %d, want a backed-off retry", got)
	}
	if !session.pushOwed() {
		t.Fatal("push no longer owed although FRP never accepted it")
	}
}

func TestFRPGroupSessionSurfacesRenderFailureOnPendingRoutes(t *testing.T) {
	// A common config that filters proxies cannot pass the factory, but the
	// session still reports a render failure through RouteStates rather
	// than retrying invisibly forever.
	svc := &recordingGroupService{}
	ctx, cancel := context.WithCancel(context.Background())
	session := newFRPGroupSession(svc, &lockedStatusMap{}, &v1.ClientCommonConfig{Start: []string{"other"}}, 7, time.Millisecond, groupRoutesOf(groupTestRoutes("a")))
	session.cancel = cancel
	go session.run(ctx)
	t.Cleanup(func() { _ = session.Stop(context.Background()) })
	err := session.Update(context.Background(), groupRoutesOf(groupTestRoutes("a", "b")))
	if err == nil || !strings.Contains(err.Error(), "render FRP proxy set") {
		t.Fatalf("Update with an unrenderable set = %v, want the render error", err)
	}
	for _, routeID := range []string{"a", "b"} {
		if state := session.RouteStates()[routeID]; state.Phase != RoutePending || state.Err == nil || !strings.Contains(state.Err.Error(), "filters out proxies") {
			t.Fatalf("route %q after a render failure = %+v, want pending and carrying the render error", routeID, state)
		}
	}
	if len(svc.updateNames()) != 0 {
		t.Fatalf("a set that failed to render reached FRP: %q", svc.updateNames())
	}
}

func TestFRPGroupSessionServingRouteIDs(t *testing.T) {
	status := &lockedStatusMap{}
	session := startTestGroupSession(t, &recordingGroupService{}, status, groupRoutesOf(groupTestRoutes("a", "b", "c")))
	status.set("a-nhp7", frpproxy.ProxyPhaseRunning, "")
	status.set("c-nhp7", frpproxy.ProxyPhaseRunning, "")
	waitForRouteStates(t, session, func(s map[string]RouteState) bool {
		return phaseOf(s, "a") == RouteServing && phaseOf(s, "c") == RouteServing
	})
	if got := session.ServingRouteIDs(); len(got) != 2 || !hasKey(got, "a") || !hasKey(got, "c") {
		t.Fatalf("ServingRouteIDs() = %v, want a and c", got)
	}
}

func hasKey(set map[string]struct{}, key string) bool {
	_, ok := set[key]
	return ok
}

func TestFRPGroupSessionRetriesFailedProxyPush(t *testing.T) {
	svc := &flakyGroupService{failuresLeft: 2}
	status := &lockedStatusMap{}
	session := startTestGroupSession(t, svc, status, groupRoutesOf(groupTestRoutes("a")))
	status.set("a-nhp7", frpproxy.ProxyPhaseRunning, "")
	waitForRouteStates(t, session, func(s map[string]RouteState) bool { return phaseOf(s, "a") == RouteServing })

	err := session.Update(context.Background(), groupRoutesOf(groupTestRoutes("a", "b")))
	if err == nil || !strings.Contains(err.Error(), "update FRP proxy set") {
		t.Fatalf("Update with a failing push = %v, want the push error", err)
	}
	states := session.RouteStates()
	if state := states["b"]; state.Phase != RoutePending || state.Err == nil || !strings.Contains(state.Err.Error(), "control connection reset") {
		t.Fatalf("route b after a failed push = %+v, want pending and carrying the push error", state)
	}
	if state := states["a"]; state.Phase != RouteServing || state.Err != nil {
		t.Fatalf("registered route a after a failed push = %+v, want still serving with no error", state)
	}
	if !session.pushOwed() {
		t.Fatal("failed push did not leave the table owed to FRP")
	}
	deadline := time.Now().Add(time.Second)
	for session.pushOwed() {
		if time.Now().After(deadline) {
			t.Fatalf("session never retried the failed push; updates = %q", svc.updateNames())
		}
		time.Sleep(time.Millisecond)
	}
	updates := svc.updateNames()
	if want := []string{"a-nhp7", "b-nhp7"}; len(updates) != 1 || !reflect.DeepEqual(updates[0], want) {
		t.Fatalf("accepted pushes = %q, want exactly one carrying %q", updates, want)
	}
	if state := session.RouteStates()["b"]; state.Phase != RoutePending || state.Err != nil {
		t.Fatalf("route b after the accepted push = %+v, want pending with the push error cleared", state)
	}
	status.set("b-nhp7", frpproxy.ProxyPhaseRunning, "")
	waitForRouteStates(t, session, func(s map[string]RouteState) bool { return phaseOf(s, "b") == RouteServing })
}

func TestFRPGroupSessionTransientStartErrorStaysPending(t *testing.T) {
	svc := &recordingGroupService{}
	status := &lockedStatusMap{}
	session := startTestGroupSession(t, svc, status, groupRoutesOf(groupTestRoutes("a")))
	status.set("a-nhp7", frpproxy.ProxyPhaseStartErr, "rate_limited: retry later")
	states := waitForRouteStates(t, session, func(s map[string]RouteState) bool {
		return phaseOf(s, "a") == RoutePending && s["a"].Err != nil
	})
	if states["a"].Err.Error() != "rate_limited: retry later" {
		t.Fatalf("pending route error = %v", states["a"].Err)
	}
	if len(svc.updateNames()) != 0 {
		t.Fatalf("transient start error pushed a proxy-set update: %q", svc.updateNames())
	}
	select {
	case <-session.Done():
		t.Fatalf("transient start error ended the session: %v", session.Err())
	case <-session.Ready():
		t.Fatal("transient start error reported ready")
	case <-time.After(10 * time.Millisecond):
	}
}

func withRegistrationWindow(t *testing.T, window int) {
	t.Helper()
	previous := groupRegistrationWindow
	groupRegistrationWindow = window
	t.Cleanup(func() { groupRegistrationWindow = previous })
}

// liveProxyNames is the proxy set the session currently wants FRP to hold.
func liveProxyNames(session *frpGroupSession) []string {
	session.mu.Lock()
	live := session.liveRoutesLocked()
	session.mu.Unlock()
	names := make([]string, 0, len(live))
	for _, route := range live {
		names = append(names, groupProxyName(route, session.sessionID))
	}
	return names
}

func waitForLastPush(t *testing.T, svc *recordingGroupService, want []string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		updates := svc.updateNames()
		if len(updates) > 0 && reflect.DeepEqual(updates[len(updates)-1], want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("FRP proxy set never became %q; pushes = %q", want, updates)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestFRPGroupSessionRegistersThroughWindow(t *testing.T) {
	withRegistrationWindow(t, 2)
	svc := &recordingGroupService{}
	status := &lockedStatusMap{}
	session := startTestGroupSession(t, svc, status, groupRoutesOf(groupTestRoutes("a", "b", "c", "d", "e")))

	// The Login set is the first window; the rest are pending in the table
	// and unknown to FRP, and no push is owed for them.
	if got := liveProxyNames(session); !reflect.DeepEqual(got, []string{"a-nhp7", "b-nhp7"}) {
		t.Fatalf("initial FRP proxy set = %q, want the first window", got)
	}
	states := session.RouteStates()
	for _, routeID := range []string{"a", "b", "c", "d", "e"} {
		if state := states[routeID]; state.Phase != RoutePending || state.Err != nil {
			t.Fatalf("route %q before registration = %+v, want pending", routeID, state)
		}
	}
	time.Sleep(10 * time.Millisecond)
	if pushes := svc.updateNames(); len(pushes) != 0 {
		t.Fatalf("session pushed %q while the first window was still registering", pushes)
	}
	select {
	case <-session.Ready():
		t.Fatal("session reported ready with routes waiting for the window")
	default:
	}

	// Each registration frees a slot for the next route in ID order.
	status.set("a-nhp7", frpproxy.ProxyPhaseRunning, "")
	waitForLastPush(t, svc, []string{"a-nhp7", "b-nhp7", "c-nhp7"})
	status.set("b-nhp7", frpproxy.ProxyPhaseRunning, "")
	status.set("c-nhp7", frpproxy.ProxyPhaseRunning, "")
	waitForLastPush(t, svc, []string{"a-nhp7", "b-nhp7", "c-nhp7", "d-nhp7", "e-nhp7"})
	status.set("d-nhp7", frpproxy.ProxyPhaseRunning, "")
	status.set("e-nhp7", frpproxy.ProxyPhaseRunning, "")
	waitForRouteStates(t, session, func(s map[string]RouteState) bool {
		for _, routeID := range []string{"a", "b", "c", "d", "e"} {
			if phaseOf(s, routeID) != RouteServing {
				return false
			}
		}
		return true
	})
	select {
	case <-session.Ready():
	case <-time.After(time.Second):
		t.Fatal("session with every route registered did not report ready")
	}
	for _, push := range svc.updateNames() {
		if len(push) > 5 {
			t.Fatalf("push %q carries more proxies than the group has", push)
		}
	}
}

func TestFRPGroupSessionWindowDoesNotWaitOnTransientStartErrors(t *testing.T) {
	withRegistrationWindow(t, 1)
	svc := &recordingGroupService{}
	status := &lockedStatusMap{}
	session := startTestGroupSession(t, svc, status, groupRoutesOf(groupTestRoutes("a", "b")))
	if got := liveProxyNames(session); !reflect.DeepEqual(got, []string{"a-nhp7"}) {
		t.Fatalf("initial FRP proxy set = %q, want only a", got)
	}

	// A proxy the server refused transiently waits out FRP's retry interval
	// on the client; it is not in the server's queue and holds no slot.
	status.set("a-nhp7", frpproxy.ProxyPhaseStartErr, "rate_limited: retry later")
	waitForLastPush(t, svc, []string{"a-nhp7", "b-nhp7"})

	// When FRP re-sends a's NewProxy the error clears and a is in flight
	// again; with b also in flight the window is over-full, so a route added
	// now waits until one of them registers.
	status.set("a-nhp7", frpproxy.ProxyPhaseWaitStart, "")
	waitForRouteStates(t, session, func(s map[string]RouteState) bool { return s["a"].Err == nil })
	if err := session.Update(context.Background(), groupRoutesOf(groupTestRoutes("a", "b", "c"))); err != nil {
		t.Fatal(err)
	}
	if got := liveProxyNames(session); !reflect.DeepEqual(got, []string{"a-nhp7", "b-nhp7"}) {
		t.Fatalf("FRP proxy set after adding c to a full window = %q, want c held back", got)
	}
	if state := session.RouteStates()["c"]; state.Phase != RoutePending {
		t.Fatalf("held-back route c = %+v, want pending", state)
	}
	// One registration leaves the window full with the other; c is released
	// once both are running.
	status.set("b-nhp7", frpproxy.ProxyPhaseRunning, "")
	waitForRouteStates(t, session, func(s map[string]RouteState) bool { return phaseOf(s, "b") == RouteServing })
	if got := liveProxyNames(session); !reflect.DeepEqual(got, []string{"a-nhp7", "b-nhp7"}) {
		t.Fatalf("FRP proxy set with a still in flight = %q, want c still held back", got)
	}
	status.set("a-nhp7", frpproxy.ProxyPhaseRunning, "")
	waitForLastPush(t, svc, []string{"a-nhp7", "b-nhp7", "c-nhp7"})
}

func TestFRPGroupSessionUpdateWithdrawsRoutesWaitingForWindow(t *testing.T) {
	withRegistrationWindow(t, 1)
	svc := &recordingGroupService{}
	status := &lockedStatusMap{}
	routes := groupRoutesOf(groupTestRoutes("a", "b", "c"))
	session := startTestGroupSession(t, svc, status, routes)
	if got := liveProxyNames(session); !reflect.DeepEqual(got, []string{"a-nhp7"}) {
		t.Fatalf("initial FRP proxy set = %q, want only a", got)
	}
	// Withdrawing b, which FRP never saw, is a table change only; c keeps
	// waiting behind a.
	withoutB := []GroupRoute{routes[0], routes[2]}
	if err := session.Update(context.Background(), withoutB); err != nil {
		t.Fatal(err)
	}
	waitForLastPush(t, svc, []string{"a-nhp7"})
	states := session.RouteStates()
	if _, present := states["b"]; present {
		t.Fatalf("withdrawn route b still tracked: %+v", states["b"])
	}
	if state := states["c"]; state.Phase != RoutePending {
		t.Fatalf("waiting route c = %+v, want pending", state)
	}
	status.set("a-nhp7", frpproxy.ProxyPhaseRunning, "")
	waitForLastPush(t, svc, []string{"a-nhp7", "c-nhp7"})
	// A serving route never leaves the pushed set for the window's sake, and
	// a restarted route re-enters the queue under its new name.
	restarted := []GroupRoute{routes[0], routes[2]}
	restarted[0].Generation = 1
	if err := session.Update(context.Background(), restarted); err != nil {
		t.Fatal(err)
	}
	if got := liveProxyNames(session); !reflect.DeepEqual(got, []string{"c-nhp7"}) {
		t.Fatalf("FRP proxy set after restarting a behind in-flight c = %q, want a's new name held back", got)
	}
	status.set("c-nhp7", frpproxy.ProxyPhaseRunning, "")
	waitForLastPush(t, svc, []string{"a-nhp7-r1", "c-nhp7"})
}

func TestFRPGroupSessionReleasedPendingCeilingHoldsErroredProxies(t *testing.T) {
	withRegistrationWindow(t, 1)
	svc := &recordingGroupService{}
	status := &lockedStatusMap{}
	session := startTestGroupSession(t, svc, status, groupRoutesOf(groupTestRoutes("a", "b", "c", "d")))
	// An errored proxy frees its window slot but still counts against the
	// released-pending ceiling (twice the window): a second transient error
	// fills it, and no further route is released until one registers.
	status.set("a-nhp7", frpproxy.ProxyPhaseStartErr, "rate_limited: retry later")
	waitForLastPush(t, svc, []string{"a-nhp7", "b-nhp7"})
	status.set("b-nhp7", frpproxy.ProxyPhaseStartErr, "rate_limited: retry later")
	waitForRouteStates(t, session, func(s map[string]RouteState) bool { return s["b"].Err != nil })
	time.Sleep(10 * time.Millisecond)
	if got := liveProxyNames(session); !reflect.DeepEqual(got, []string{"a-nhp7", "b-nhp7"}) {
		t.Fatalf("FRP proxy set with two errored proxies released = %q, want the ceiling to hold c back", got)
	}
	status.set("a-nhp7", frpproxy.ProxyPhaseRunning, "")
	waitForLastPush(t, svc, []string{"a-nhp7", "b-nhp7", "c-nhp7"})
}

func TestFRPGroupSessionRegeneratedRouteTakesNextSlot(t *testing.T) {
	withRegistrationWindow(t, 1)
	svc := &recordingGroupService{}
	status := &lockedStatusMap{}
	routes := groupRoutesOf(groupTestRoutes("m", "n"))
	session := startTestGroupSession(t, svc, status, routes)
	status.set("m-nhp7", frpproxy.ProxyPhaseRunning, "")
	waitForLastPush(t, svc, []string{"m-nhp7", "n-nhp7"})
	// m serves, n is in flight, and a route added now waits; its ID sorts
	// first among waiting routes.
	added := groupRoutesOf(groupTestRoutes("m", "n", "a"))
	if err := session.Update(context.Background(), added); err != nil {
		t.Fatal(err)
	}
	if got := liveProxyNames(session); !reflect.DeepEqual(got, []string{"m-nhp7", "n-nhp7"}) {
		t.Fatalf("FRP proxy set after adding a to a full window = %q, want a held back", got)
	}
	// Restarting m withdraws its serving proxy, and its new name goes ahead
	// of a despite sorting after it: the route that was up is dark for one
	// slot turnover, not for the backlog.
	restarted := append([]GroupRoute(nil), added...)
	restarted[0].Generation = 1
	if err := session.Update(context.Background(), restarted); err != nil {
		t.Fatal(err)
	}
	waitForLastPush(t, svc, []string{"n-nhp7"})
	status.set("n-nhp7", frpproxy.ProxyPhaseRunning, "")
	waitForLastPush(t, svc, []string{"m-nhp7-r1", "n-nhp7"})
	if state := session.RouteStates()["a"]; state.Phase != RoutePending {
		t.Fatalf("route a while the restarted route registers = %+v, want still waiting", state)
	}
	status.set("m-nhp7-r1", frpproxy.ProxyPhaseRunning, "")
	waitForLastPush(t, svc, []string{"a-nhp7", "m-nhp7-r1", "n-nhp7"})
}

func TestFRPGroupSessionCeilingAgesOutDurableStartErrors(t *testing.T) {
	withRegistrationWindow(t, 1)
	// One second keeps the "still held back" checks below clear of scheduling
	// hiccups on a loaded race-detector runner (they must all land inside
	// the hold measured from a's first refusal) while staying inside
	// waitForLastPush's deadline for the release that follows.
	hold := groupErroredHold
	groupErroredHold = time.Second
	t.Cleanup(func() { groupErroredHold = hold })
	svc := &recordingGroupService{}
	status := &lockedStatusMap{}
	session := startTestGroupSession(t, svc, status, groupRoutesOf(groupTestRoutes("a", "b", "c", "d")))
	erroredAt := func(routeID string) time.Time {
		session.mu.Lock()
		defer session.mu.Unlock()
		return session.routes[routeID].erroredAt
	}
	// Two refusals fill the ceiling; while they are recent, c waits.
	status.set("a-nhp7", frpproxy.ProxyPhaseStartErr, "subdomain_conflict: taken")
	waitForLastPush(t, svc, []string{"a-nhp7", "b-nhp7"})
	status.set("b-nhp7", frpproxy.ProxyPhaseStartErr, "subdomain_conflict: taken")
	waitForRouteStates(t, session, func(s map[string]RouteState) bool { return s["b"].Err != nil })
	if got := liveProxyNames(session); !reflect.DeepEqual(got, []string{"a-nhp7", "b-nhp7"}) {
		t.Fatalf("FRP proxy set with two fresh refusals = %q, want c held back", got)
	}
	firstA, firstB := erroredAt("a"), erroredAt("b")
	if firstA.IsZero() || firstB.IsZero() {
		t.Fatal("refused proxies carry no hold stamp")
	}
	// FRP re-sends a refused NewProxy after its start-error interval, which
	// takes the proxy through wait-start and back to the same refusal. The
	// hold is anchored to the first refusal, so the round trip must not
	// refresh it; otherwise a 30s re-send would keep a 60s hold alive
	// forever and the ceiling would wedge on durable refusals after all.
	for _, name := range []string{"a-nhp7", "b-nhp7"} {
		status.set(name, frpproxy.ProxyPhaseWaitStart, "")
	}
	waitForRouteStates(t, session, func(s map[string]RouteState) bool { return s["a"].Err == nil && s["b"].Err == nil })
	for _, name := range []string{"a-nhp7", "b-nhp7"} {
		status.set(name, frpproxy.ProxyPhaseStartErr, "subdomain_conflict: taken")
	}
	waitForRouteStates(t, session, func(s map[string]RouteState) bool { return s["a"].Err != nil && s["b"].Err != nil })
	if erroredAt("a") != firstA || erroredAt("b") != firstB {
		t.Fatalf("re-sent refusal refreshed the hold: a %s -> %s, b %s -> %s", firstA, erroredAt("a"), firstB, erroredAt("b"))
	}
	// A refusal the server keeps repeating is those routes' own problem:
	// once it is older than the hold, their siblings register through the
	// window as if the errored routes were not there.
	waitForLastPush(t, svc, []string{"a-nhp7", "b-nhp7", "c-nhp7"})
	states := session.RouteStates()
	for _, routeID := range []string{"a", "b"} {
		if state := states[routeID]; state.Phase != RoutePending || state.Err == nil {
			t.Fatalf("durably refused route %q = %+v, want still pending with its error", routeID, state)
		}
	}
	status.set("c-nhp7", frpproxy.ProxyPhaseRunning, "")
	waitForLastPush(t, svc, []string{"a-nhp7", "b-nhp7", "c-nhp7", "d-nhp7"})
	// Registering clears the stamp, so a later refusal of the same proxy
	// starts a fresh hold.
	status.set("a-nhp7", frpproxy.ProxyPhaseRunning, "")
	waitForRouteStates(t, session, func(s map[string]RouteState) bool { return phaseOf(s, "a") == RouteServing })
	if !erroredAt("a").IsZero() {
		t.Fatalf("registered proxy a still carries a hold stamp: %s", erroredAt("a"))
	}
}
