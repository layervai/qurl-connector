package share

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

// The slow-server reproductions below model the registration defect seen on
// a live platform: the FRP server reads a control session's messages
// serially and every NewProxy is a platform authorization round trip of
// hundreds of milliseconds, so a session that hands FRP every proxy at once
// forms a queue that takes longer than the pinned client's 20s NewProxy
// re-send horizon to drain. Every proxy queued behind that point is sent to
// the server a second time: the duplicate costs the platform the same
// authorization and registration round trips to be refused as already
// registered, and its answer lands on a proxy that is already running, which
// FRP logs as "status not wait start, ignore start message". Registration
// through the window keeps the server's queue short enough that no proxy is
// ever re-sent; without it the tail of the set registers twice.
//
// The plugin answers NewProxy for one Login RunID only after a platform-like
// delay. Both reproductions take about routeCount × service time by
// construction, since the re-send horizon is a fixed 20s.
const (
	// slowRouteCount × the mean service time is how deep the NewProxy queue
	// is when every proxy is sent at once: about 26s, past the 20s (checked
	// every 3s) re-send horizon by a margin the jitter cannot close. Through
	// the registration window the queue is at most 16 × 500ms = 8s deep.
	slowRouteCount = 58
	slowServiceMin = 400 * time.Millisecond
	slowServiceMax = 500 * time.Millisecond
)

type slowServerHarness struct {
	routes   []proofRoute
	port     int
	plugin   *hermeticQRTSPlugin
	client   *http.Client
	admitter *hermeticAdmitter
	events   *proofEvents
	runner   *SessionGroupRunner
	result   chan error
	cancel   context.CancelFunc
}

// startSlowServerHarness runs a session group of slowRouteCount routes
// against an in-process FRP server whose plugin answers NewProxy for slowRunID
// at platform speed.
func startSlowServerHarness(t *testing.T, admissions []Admission, slowRunID string, rotationLead time.Duration) *slowServerHarness {
	t.Helper()
	const (
		knockResourceID = "q_catalog_resource"
		groupResourceID = "group-resource"
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
	h := &slowServerHarness{
		events: &proofEvents{serving: make(map[uint64]int)},
		result: make(chan error, 1),
	}
	for i := range slowRouteCount {
		h.routes = append(h.routes, proofRouteAt(i, backends))
	}
	h.port = reserveHermeticPort(t)
	h.plugin = newHermeticQRTSPlugin(t)
	frps := startHermeticFRPSFromConfig(t, hermeticFRPSConfig(h.port, h.port, proofSubdomainHost, h.plugin.server.URL))
	t.Cleanup(func() { _ = frps.Close() })
	var transport *http.Transport
	h.client, transport = newProofClient()
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
	resourceHost := net.JoinHostPort("127.0.0.1", strconv.Itoa(h.port))
	for i := range admissions {
		admissions[i].KnockResourceID, admissions[i].ResourceID = knockResourceID, groupResourceID
		admissions[i].ResourceHost = resourceHost
	}
	h.plugin.delayNewProxy(slowRunID, slowServiceMin, slowServiceMax)
	h.admitter = &hermeticAdmitter{admissions: admissions}

	h.runner, err = NewSessionGroupRunner(SessionGroupConfig{
		KnockResourceID: knockResourceID, ResourceID: groupResourceID, Routes: localRoutes(h.routes),
		Admitter: h.admitter, Sessions: factory,
		MinBackoff: 10 * time.Millisecond, MaxBackoff: 25 * time.Millisecond,
		RotationLead: rotationLead, StopTimeout: 10 * time.Second,
		OnServing: func(admission Admission) {
			serving := 0
			for _, state := range h.runner.RouteStates() {
				if state.Phase == RouteServing {
					serving++
				}
			}
			h.events.promote(admission.SessionID, serving)
		},
		OnRouteServing: func(_ string, admission Admission) { h.events.routeServing(admission.SessionID) },
		OnRouteFailed:  h.events.routeFailed,
		OnRetry:        func(err error, _ time.Duration) { h.events.retry(err) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.result <- h.runner.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-h.result:
		case <-time.After(30 * time.Second):
			t.Error("session group runner did not stop")
		}
	})
	return h
}

// sweep requests every route through the vhost. It is skipped under the
// race detector: these tests run past the in-process FRP server's 60s idle
// keep-alive timeout, and the pinned fork closes an idle work connection
// (StatsConn.Close) without ordering it against the reverse proxy's
// concurrent read, which the detector reports on the fork's behalf.
// Registration is what is proven here; the non-race lane still proves the
// routes answer.
func (h *slowServerHarness) sweep(t *testing.T, what string) {
	t.Helper()
	if proofRaceDetector {
		return
	}
	_, failures := proofSweep(h.client, h.port, h.routes, proofSweepConcurrency)
	requireNoProofFailures(t, what, failures)
}

func (h *slowServerHarness) stop(t *testing.T) {
	t.Helper()
	h.cancel()
	select {
	case err := <-h.result:
		h.result <- err
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("runner exit = %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("session group runner did not stop")
	}
}

// TestHermeticSessionGroupRegistersEveryRouteOnceOnSlowServer is the default
// lane's reproduction: the group's first session registers slowRouteCount
// routes at platform speed, and every proxy must reach the server exactly
// once. It is the same Login-then-register path a rotation replacement
// takes, at about a third of the rotation reproduction's wall time.
func TestHermeticSessionGroupRegistersEveryRouteOnceOnSlowServer(t *testing.T) {
	if testing.Short() {
		t.Skip("the platform-speed registration takes about half a minute by construction")
	}
	first := Admission{
		RunID: "1111111111111111", RunAttempt: 1, Token: "token-one", SessionID: 101,
		SessionReceipt: testSessionReceipt(101, "1111111111111111", 1), OpenTime: 10 * time.Minute,
	}
	h := startSlowServerHarness(t, []Admission{first}, first.RunID, time.Minute)

	started := time.Now()
	proofWait(t, h.result, 90*time.Second,
		func() bool { return h.events.servingCount(first.SessionID) >= slowRouteCount }, "every route serving on the first session")
	lastRegistered, registered := h.plugin.lastAdmittedAt(first.RunID)
	t.Logf("first session registered %d proxies in %s; every route serving after %s",
		registered, lastRegistered.Sub(h.admitter.admittedAtIndex(0)), time.Since(started))
	if failed := h.events.failureList(); len(failed) != 0 {
		t.Fatalf("routes reported failed during registration: %v", failed)
	}
	if retries := h.events.retryList(); len(retries) != 0 {
		t.Fatalf("registration retried %d times: %v", len(retries), retries)
	}
	h.sweep(t, "first request through the vhost")
	// A re-sent NewProxy queues behind the originals, so the server reaches
	// it only after the last original registered; give the queue one
	// service time to surface one before counting.
	time.Sleep(2 * slowServiceMax)
	requireProofRegistrations(t, h.plugin, slowRouteCount)
	h.stop(t)
}

// TestHermeticSessionGroupRotationRegistersEveryRouteOnce is the rotation
// reproduction: the first session registers at loopback speed, the
// replacement at platform speed, and the rotation lead leaves the
// replacement enough time to register the set exactly once before the old
// admission expires. It needs about a minute by construction (the old
// session serves at least half its window before the replacement starts,
// and the replacement then needs slowRouteCount × service time), so it runs
// with the opt-in scaling proof (make proof-1000) rather than in the default
// lanes, which cover the same registration path above.
func TestHermeticSessionGroupRotationRegistersEveryRouteOnce(t *testing.T) {
	if os.Getenv(proofRoutesEnv) == "" {
		t.Skipf("set %s to run the minute-long rotation reproduction (make proof-1000)", proofRoutesEnv)
	}
	const (
		// The first admission's window and the configured lead: the
		// replacement starts `lead` before the first admission expires and
		// needs slowRouteCount × ~450ms ≈ 26s to register every route.
		firstWindow = 72 * time.Second
		lead        = 36 * time.Second
	)
	first := Admission{
		RunID: "1111111111111111", RunAttempt: 1, Token: "token-one", SessionID: 101,
		SessionReceipt: testSessionReceipt(101, "1111111111111111", 1), OpenTime: firstWindow,
	}
	second := Admission{
		RunID: "2222222222222222", RunAttempt: 2, Token: "token-two", SessionID: 102,
		SessionReceipt: testSessionReceipt(102, "2222222222222222", 2), OpenTime: 10 * time.Minute,
	}
	h := startSlowServerHarness(t, []Admission{first, second}, second.RunID, lead)

	proofWait(t, h.result, 30*time.Second,
		func() bool { return h.events.servingCount(first.SessionID) >= slowRouteCount }, "every route serving on the first session")
	requireProofRegistrations(t, h.plugin, slowRouteCount)
	h.sweep(t, "first request through the vhost")

	// The replacement registers at platform speed. Promotion must carry every
	// route, and every proxy must have been sent to the server exactly once.
	promotionDeadline := time.Until(h.admitter.admittedAtIndex(0).Add(firstWindow)) + 15*time.Second
	proofWait(t, h.result, promotionDeadline, func() bool { return len(h.events.promotionList()) >= 2 }, "replacement promoted")
	promotions := h.events.promotionList()
	if len(promotions) != 2 || promotions[1].sessionID != second.SessionID {
		t.Fatalf("promotions = %+v, want the first cycle and one replacement on session %d", promotions, second.SessionID)
	}
	rotationAdmitAt := h.admitter.admittedAtIndex(1)
	lastRegistered, registered := h.plugin.lastAdmittedAt(second.RunID)
	t.Logf("replacement registered %d proxies in %s and was promoted after %s with %d of %d routes serving",
		registered, lastRegistered.Sub(rotationAdmitAt), promotions[1].at.Sub(rotationAdmitAt), promotions[1].serving, slowRouteCount)
	if promotions[1].serving != slowRouteCount {
		t.Fatalf("replacement promoted with %d of %d routes serving", promotions[1].serving, slowRouteCount)
	}
	if failed := h.events.failureList(); len(failed) != 0 {
		t.Fatalf("routes reported failed across the rotation: %v", failed)
	}
	if retries := h.events.retryList(); len(retries) != 0 {
		t.Fatalf("rotation retried %d times: %v", len(retries), retries)
	}
	requireProofRegistrations(t, h.plugin, 2*slowRouteCount)

	// Once the old admission is retired the drain is over; every route must
	// answer through the replacement.
	proofWait(t, h.result, 30*time.Second, func() bool {
		for _, admission := range h.admitter.retiredSnapshot() {
			if admission.SessionID == first.SessionID {
				return true
			}
		}
		return false
	}, "old admission retired")
	h.sweep(t, "request through the replacement")
	// A re-sent NewProxy queues behind the originals, so the server may
	// reach it only after promotion: the count is final once the drain is
	// over.
	requireProofRegistrations(t, h.plugin, 2*slowRouteCount)
	h.stop(t)
}
