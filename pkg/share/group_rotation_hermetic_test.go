package share

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

// TestHermeticSessionGroupRotationRegistersEveryRouteOnce reproduces the
// rotation defect seen on a live platform: the FRP server reads a control
// session's messages serially and every NewProxy is a platform authorization
// round trip of hundreds of milliseconds, so a replacement session that hands
// FRP every proxy at once forms a queue that takes longer than the pinned
// client's 20s NewProxy re-send horizon to drain. Every proxy queued behind
// that point is sent to the server a second time: the duplicate costs the
// platform the same authorization and registration round trips to be refused
// as already registered, and its answer lands on a proxy that is already
// running, which FRP logs as "status not wait start, ignore start message".
//
// The plugin answers NewProxy for the replacement RunID only after a
// platform-like delay, the first session registers at loopback speed, and
// the rotation lead leaves the replacement enough time to register the set
// exactly once. Registration through the window keeps the server's queue
// short enough that no proxy is ever re-sent; without it the tail of the set
// registers twice.
func TestHermeticSessionGroupRotationRegistersEveryRouteOnce(t *testing.T) {
	const (
		knockResourceID = "q_catalog_resource"
		groupResourceID = "group-resource"
		// routeCount × the mean service time is how deep the replacement's
		// NewProxy queue is when every proxy is sent at once: about 26s,
		// past the 20s (checked every 3s) re-send horizon by a margin the
		// jitter cannot close. Through the registration window the queue
		// is at most 32 × 500ms = 16s deep.
		routeCount = 58
		serviceMin = 400 * time.Millisecond
		serviceMax = 500 * time.Millisecond
		// The first admission's window and the configured lead: the
		// replacement starts `lead` before the first admission expires and
		// needs routeCount × ~450ms ≈ 26s to register every route.
		firstWindow = 68 * time.Second
		lead        = 34 * time.Second
	)

	backends := make([]int, 2)
	for i := range backends {
		prefix := strconv.Itoa(i) + "|"
		echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, prefix+r.Host)
		}))
		t.Cleanup(echo.Close)
		backends[i] = echo.Listener.Addr().(*net.TCPAddr).Port
	}
	routes := make([]proofRoute, 0, routeCount)
	for i := range routeCount {
		routes = append(routes, proofRouteAt(i, backends))
	}

	port := reserveHermeticPort(t)
	plugin := newHermeticQRTSPlugin(t)
	frps := startHermeticFRPSFromConfig(t, hermeticFRPSConfig(port, port, proofSubdomainHost, plugin.server.URL))
	t.Cleanup(func() { _ = frps.Close() })
	client, transport := newProofClient()
	t.Cleanup(transport.CloseIdleConnections)

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
	resourceHost := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	first := Admission{
		KnockResourceID: knockResourceID, ResourceID: groupResourceID,
		RunID: "1111111111111111", RunAttempt: 1, Token: "token-one",
		ResourceHost: resourceHost, SessionID: 101,
		SessionReceipt: testSessionReceipt(101, "1111111111111111", 1), OpenTime: firstWindow,
	}
	second := Admission{
		KnockResourceID: knockResourceID, ResourceID: groupResourceID,
		RunID: "2222222222222222", RunAttempt: 2, Token: "token-two",
		ResourceHost: resourceHost, SessionID: 102,
		SessionReceipt: testSessionReceipt(102, "2222222222222222", 2), OpenTime: 10 * time.Minute,
	}
	plugin.delayNewProxy(second.RunID, serviceMin, serviceMax)
	admitter := &hermeticAdmitter{admissions: []Admission{first, second}}

	events := &proofEvents{serving: make(map[uint64]int)}
	var runner *SessionGroupRunner
	runner, err = NewSessionGroupRunner(SessionGroupConfig{
		KnockResourceID: knockResourceID, ResourceID: groupResourceID, Routes: localRoutes(routes),
		Admitter: admitter, Sessions: factory,
		MinBackoff: 10 * time.Millisecond, MaxBackoff: 25 * time.Millisecond,
		RotationLead: lead, StopTimeout: 10 * time.Second,
		OnServing: func(admission Admission) {
			serving := 0
			for _, state := range runner.RouteStates() {
				if state.Phase == RouteServing {
					serving++
				}
			}
			events.promote(admission.SessionID, serving)
		},
		OnRouteServing: func(_ string, admission Admission) { events.routeServing(admission.SessionID) },
		OnRouteFailed:  events.routeFailed,
		OnRetry:        func(err error, _ time.Duration) { events.retry(err) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runnerResult := make(chan error, 1)
	go func() { runnerResult <- runner.Run(ctx) }()

	proofWait(t, runnerResult, 30*time.Second,
		func() bool { return events.servingCount(first.SessionID) >= routeCount }, "every route serving on the first session")
	requireProofRegistrations(t, plugin, routeCount)
	// The vhost sweeps are skipped under the race detector: this test runs
	// past the in-process FRP server's 60s idle keep-alive timeout, and the
	// pinned fork closes an idle work connection (StatsConn.Close) without
	// ordering it against the reverse proxy's concurrent read, which the
	// detector reports on the fork's behalf. Registration is what is proven
	// here; the non-race lane still proves the routes answer.
	sweep := func(what string) {
		t.Helper()
		if proofRaceDetector {
			return
		}
		_, failures := proofSweep(client, port, routes, proofSweepConcurrency)
		requireNoProofFailures(t, what, failures)
	}
	sweep("first request through the vhost")

	// The replacement registers at platform speed. Promotion must carry every
	// route, and every proxy must have been sent to the server exactly once.
	promotionDeadline := time.Until(admitter.admittedAtIndex(0).Add(firstWindow)) + 15*time.Second
	proofWait(t, runnerResult, promotionDeadline, func() bool { return len(events.promotionList()) >= 2 }, "replacement promoted")
	promotions := events.promotionList()
	if len(promotions) != 2 || promotions[1].sessionID != second.SessionID {
		t.Fatalf("promotions = %+v, want the first cycle and one replacement on session %d", promotions, second.SessionID)
	}
	rotationAdmitAt := admitter.admittedAtIndex(1)
	lastRegistered, registered := plugin.lastAdmittedAt(second.RunID)
	t.Logf("replacement registered %d proxies in %s and was promoted after %s with %d of %d routes serving",
		registered, lastRegistered.Sub(rotationAdmitAt), promotions[1].at.Sub(rotationAdmitAt), promotions[1].serving, routeCount)
	if promotions[1].serving != routeCount {
		t.Fatalf("replacement promoted with %d of %d routes serving", promotions[1].serving, routeCount)
	}
	if failed := events.failureList(); len(failed) != 0 {
		t.Fatalf("routes reported failed across the rotation: %v", failed)
	}
	if retries := events.retryList(); len(retries) != 0 {
		t.Fatalf("rotation retried %d times: %v", len(retries), retries)
	}
	requireProofRegistrations(t, plugin, 2*routeCount)

	// Once the old admission is retired the drain is over; every route must
	// answer through the replacement.
	proofWait(t, runnerResult, 30*time.Second, func() bool {
		for _, admission := range admitter.retiredSnapshot() {
			if admission.SessionID == first.SessionID {
				return true
			}
		}
		return false
	}, "old admission retired")
	sweep("request through the replacement")
	// A re-sent NewProxy queues behind the originals, so the server may
	// reach it only after promotion: the count is final once the drain is
	// over.
	requireProofRegistrations(t, plugin, 2*routeCount)

	cancel()
	select {
	case err := <-runnerResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("runner exit = %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("session group runner did not stop")
	}
}
