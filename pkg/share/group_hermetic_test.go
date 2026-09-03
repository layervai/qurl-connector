package share

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

func newHermeticEcho(t *testing.T, body string) int {
	t.Helper()
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(echo.Close)
	return echo.Listener.Addr().(*net.TCPAddr).Port
}

func hermeticGroupRoute(t *testing.T, routeID string) LocalHTTPRoute {
	t.Helper()
	return LocalHTTPRoute{
		RouteID: routeID, LocalIP: "127.0.0.1", LocalPort: newHermeticEcho(t, "echo-"+routeID),
		ResourceID: "resource-" + routeID, ConnectorRoutingID: "routing-" + routeID,
	}
}

// TestHermeticSessionGroupServesManyRoutesOnOneAdmission drives the real FRP
// client and server: three routes register on one Login, a fourth joins the
// live session without a second knock or any sibling re-registration, a
// restart re-registers one proxy only, and a rejected route is withdrawn
// while its siblings keep serving.
func TestHermeticSessionGroupServesManyRoutesOnOneAdmission(t *testing.T) {
	const knockResourceID = "q_catalog_resource"
	port := reserveHermeticPort(t)
	plugin := newHermeticQRTSPlugin(t)
	frps := startHermeticFRPS(t, port, port, "example.test", plugin.server.URL)
	t.Cleanup(func() { _ = frps.Close() })

	falseValue := false
	common := &v1.ClientCommonConfig{}
	common.Log.Level = "error"
	common.Transport.TLS.Enable = &falseValue
	if err := common.Complete(); err != nil {
		t.Fatal(err)
	}
	factory, err := NewFRPSessionGroupFactory(FRPGroupFactoryConfig{
		Common: common, ClientVersion: "v1.0.0", ReadyPoll: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	admission := Admission{
		KnockResourceID: knockResourceID, ResourceID: "group-resource",
		RunID: "1111111111111111", RunAttempt: 1, Token: "token-one",
		ResourceHost: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), SessionID: 101,
		SessionReceipt: testSessionReceipt(101, "1111111111111111", 1), OpenTime: 5 * time.Minute,
	}
	admitter := &hermeticAdmitter{admissions: []Admission{admission}}

	var mu sync.Mutex
	serving := make(map[string]int)
	failed := make(map[string][]error)
	servingCount := func(routeID string) int {
		mu.Lock()
		defer mu.Unlock()
		return serving[routeID]
	}
	failures := func(routeID string) []error {
		mu.Lock()
		defer mu.Unlock()
		return append([]error(nil), failed[routeID]...)
	}
	routes := []LocalHTTPRoute{hermeticGroupRoute(t, "a"), hermeticGroupRoute(t, "b"), hermeticGroupRoute(t, "c")}
	runner, err := NewSessionGroupRunner(SessionGroupConfig{
		KnockResourceID: knockResourceID, ResourceID: "group-resource", Routes: routes,
		Admitter: admitter, Sessions: factory,
		MinBackoff: 10 * time.Millisecond, MaxBackoff: 25 * time.Millisecond,
		RotationLead: time.Minute, StopTimeout: 5 * time.Second,
		OnRouteServing: func(routeID string, got Admission) {
			mu.Lock()
			defer mu.Unlock()
			if got.SessionID == admission.SessionID {
				serving[routeID]++
			}
		},
		OnRouteFailed: func(routeID string, err error) {
			mu.Lock()
			defer mu.Unlock()
			failed[routeID] = append(failed[routeID], err)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runnerResult := make(chan error, 1)
	go func() { runnerResult <- runner.Run(ctx) }()
	waitServing := func(routeID string, count int) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for servingCount(routeID) < count {
			select {
			case err := <-runnerResult:
				t.Fatalf("session group exited before route %q served: %v", routeID, err)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatalf("route %q did not reach serving report %d", routeID, count)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	for _, routeID := range []string{"a", "b", "c"} {
		waitServing(routeID, 1)
		pollHermeticRoute(t, port, "routing-"+routeID+".example.test", "echo-"+routeID, runnerResult)
	}
	admitter.mu.Lock()
	admissions := admitter.next
	admitter.mu.Unlock()
	if admissions != 1 {
		t.Fatalf("admissions = %d, want one knock for the whole group", admissions)
	}

	// A fourth route joins the live session: no second knock, and the three
	// existing proxies are not re-registered.
	if err := runner.SetRoutes(ctx, append(append([]LocalHTTPRoute(nil), routes...), hermeticGroupRoute(t, "d"))); err != nil {
		t.Fatal(err)
	}
	waitServing("d", 1)
	pollHermeticRoute(t, port, "routing-d.example.test", "echo-d", runnerResult)
	states := runner.RouteStates()
	counts := plugin.admittedNewProxies()
	for _, routeID := range []string{"a", "b", "c", "d"} {
		if got := counts[states[routeID].ProxyName]; got != 1 {
			t.Fatalf("NewProxy admissions for %q (%s) = %d, want exactly one registration; all: %v", routeID, states[routeID].ProxyName, got, counts)
		}
	}
	admitter.mu.Lock()
	admissions = admitter.next
	admitter.mu.Unlock()
	if admissions != 1 {
		t.Fatalf("admissions after adding a route = %d, want still one", admissions)
	}

	// Restarting one route re-registers that proxy alone under a new name.
	oldB := states["b"].ProxyName
	if err := runner.RestartRoute(ctx, "b"); err != nil {
		t.Fatal(err)
	}
	waitServing("b", 2)
	pollHermeticRoute(t, port, "routing-b.example.test", "echo-b", runnerResult)
	states = runner.RouteStates()
	if states["b"].ProxyName == oldB || !strings.HasSuffix(states["b"].ProxyName, "-r1") {
		t.Fatalf("restarted route b proxy name = %q (was %q), want a fresh restart generation", states["b"].ProxyName, oldB)
	}
	counts = plugin.admittedNewProxies()
	if counts[oldB] != 1 || counts[states["b"].ProxyName] != 1 {
		t.Fatalf("NewProxy admissions around restart = %v, want one for %q and one for %q", counts, oldB, states["b"].ProxyName)
	}
	for _, routeID := range []string{"a", "c", "d"} {
		if counts[states[routeID].ProxyName] != 1 {
			t.Fatalf("sibling %q re-registered during restart: %v", routeID, counts)
		}
	}

	// A route the server rejects as resource_not_found is withdrawn alone.
	gone := hermeticGroupRoute(t, "e")
	plugin.rejectProxy(groupProxyName(GroupRoute{LocalHTTPRoute: gone}, admission.SessionID), "resource_not_found: resource not found")
	if err := runner.SetRoutes(ctx, append(append([]LocalHTTPRoute(nil), routes...), hermeticGroupRoute(t, "d"), gone)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for len(failures("e")) == 0 {
		select {
		case err := <-runnerResult:
			t.Fatalf("session group exited on a rejected route: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("rejected route e was not reported")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := failures("e")[0]; !errors.Is(err, ErrResourceGone) {
		t.Fatalf("route e failure = %v, want ErrResourceGone", err)
	}
	for _, routeID := range []string{"a", "b", "c", "d"} {
		pollHermeticRoute(t, port, "routing-"+routeID+".example.test", "echo-"+routeID, runnerResult)
		if got := failures(routeID); len(got) != 0 {
			t.Fatalf("sibling %q reported failed: %v", routeID, got)
		}
	}
	if _, present := runner.RouteStates()["e"]; present {
		t.Fatal("gone route e is still tracked on the active session")
	}
	admitter.mu.Lock()
	admissions = admitter.next
	admitter.mu.Unlock()
	if admissions != 1 {
		t.Fatalf("admissions after a rejected route = %d, want still one", admissions)
	}

	cancel()
	select {
	case err := <-runnerResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("runner exit = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("session group runner did not stop")
	}
	retired := admitter.retiredSnapshot()
	if len(retired) != 1 || retired[0].SessionID != admission.SessionID {
		t.Fatalf("retired admissions = %s, want exactly the group's one admission", fmt.Sprint(retired))
	}
}
