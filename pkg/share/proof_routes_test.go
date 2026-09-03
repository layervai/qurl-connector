package share

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	frpmetrics "github.com/fatedier/frp/pkg/metrics"
	frplog "github.com/fatedier/frp/pkg/util/log"
)

// Scaling proof: N Connector routes on ONE NHP admission and ONE FRP control
// session, measured in-process against the real FRP client and the real FRP
// server from the pinned fork. The knock is hermetic (a scripted admitter)
// and the tunnel-auth plugin is hermetic (an HTTP plugin answering NewProxy
// the way the platform does); everything between them is production code on
// loopback, one machine.
//
//	QURL_PROOF_ROUTES  route count. The default keeps the normal suite fast;
//	                   `make proof-1000` runs 1000 (race off) then 200 (race on).
//	QURL_PROOF_REPORT  when set, the measurements are also written there as JSON.
const (
	proofRoutesEnv         = "QURL_PROOF_ROUTES"
	proofReportEnv         = "QURL_PROOF_REPORT"
	proofDefaultRoutes     = 50
	proofBackends          = 8
	proofRouteChurn        = 10
	proofSampleRoutes      = 20
	proofSweepConcurrency  = 32
	proofSteadyRequests    = 2000
	proofSteadyConcurrency = 8
	proofOverlapWorkers    = 4
	proofSubdomainHost     = "example.test"
	// proofDrainSettle bounds how long after a registration or withdrawal
	// instant a request dispatched inside that instant can still be observed
	// failing: one request round trip, padded generously.
	proofDrainSettle = 250 * time.Millisecond
	// proofDrainCeiling bounds the drain itself: the FRP client's admission
	// window is excused only while withdrawing the old proxies stays this
	// short, so a slow drain is a failure rather than a wider exemption.
	proofDrainCeiling = 2 * time.Second
)

func TestMain(m *testing.M) {
	if os.Getenv(proofRoutesEnv) != "" {
		// An opt-in proof registers thousands of proxies; FRP's global logger
		// prints several info lines per proxy, which would bury the summary.
		frplog.InitLogger("console", "warn", 0, true)
	}
	os.Exit(m.Run())
}

var proofFRPMetricsOnce sync.Once

// proofEnableFRPMetrics turns on the FRP server's in-memory proxy statistics,
// which its /api/proxy/{type} endpoint joins with the live proxy manager to
// report each proxy as online or offline.
func proofEnableFRPMetrics() { proofFRPMetricsOnce.Do(frpmetrics.EnableMem) }

// proofRoute is one route plus the exact vhost Host and backend echo that
// prove it answers.
type proofRoute struct {
	LocalHTTPRoute
	host string
	body string
}

// proofRouteAt renders route i. Routes share a small backend pool round-robin,
// and each backend echoes its own index plus the Host it received, so a route
// answered through the wrong proxy names the wrong backend.
func proofRouteAt(i int, backends []int) proofRoute {
	id := "crid-" + strconv.Itoa(i)
	host := "rt-" + id + "." + proofSubdomainHost
	return proofRoute{
		LocalHTTPRoute: LocalHTTPRoute{
			RouteID: id, LocalIP: "127.0.0.1", LocalPort: backends[i%len(backends)],
			ResourceID: "res-" + id, ConnectorRoutingID: "rt-" + id,
		},
		host: host, body: strconv.Itoa(i%len(backends)) + "|" + host,
	}
}

func localRoutes(routes []proofRoute) []LocalHTTPRoute {
	out := make([]LocalHTTPRoute, 0, len(routes))
	for _, route := range routes {
		out = append(out, route.LocalHTTPRoute)
	}
	return out
}

type proofPromotion struct {
	sessionID uint64
	at        time.Time
	serving   int
}

type proofRouteFailure struct {
	routeID string
	err     error
}

type proofEvents struct {
	mu         sync.Mutex
	serving    map[uint64]int
	promotions []proofPromotion
	failed     []proofRouteFailure
	caps       []groupLeadCap
	retries    []error
}

func (e *proofEvents) routeServing(sessionID uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.serving[sessionID]++
}

func (e *proofEvents) servingCount(sessionID uint64) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.serving[sessionID]
}

func (e *proofEvents) promote(sessionID uint64, serving int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.promotions = append(e.promotions, proofPromotion{sessionID: sessionID, at: time.Now(), serving: serving})
}

func (e *proofEvents) promotionList() []proofPromotion {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]proofPromotion(nil), e.promotions...)
}

func (e *proofEvents) routeFailed(routeID string, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.failed = append(e.failed, proofRouteFailure{routeID: routeID, err: err})
}

func (e *proofEvents) failureList() []proofRouteFailure {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]proofRouteFailure(nil), e.failed...)
}

func (e *proofEvents) failureOf(routeID string) error {
	for _, failure := range e.failureList() {
		if failure.routeID == routeID {
			return failure.err
		}
	}
	return nil
}

func (e *proofEvents) capped(routes int, need, lead time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.caps = append(e.caps, groupLeadCap{routes: routes, need: need, lead: lead})
}

func (e *proofEvents) capList() []groupLeadCap {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]groupLeadCap(nil), e.caps...)
}

func (e *proofEvents) retry(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.retries = append(e.retries, err)
}

func (e *proofEvents) retryList() []error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]error(nil), e.retries...)
}

func newProofClient() (*http.Client, *http.Transport) {
	transport := &http.Transport{MaxIdleConns: 256, MaxIdleConnsPerHost: 64, IdleConnTimeout: 30 * time.Second}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}, transport
}

func proofGet(client *http.Client, port int, host string) (int, string, error) {
	request, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+"/", nil)
	if err != nil {
		return 0, "", err
	}
	request.Host = host
	response, err := client.Do(request)
	if err != nil {
		return 0, "", err
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	return response.StatusCode, string(body), err
}

// proofCheck is one exact request through the vhost, no retries.
func proofCheck(client *http.Client, port int, route proofRoute) error {
	status, body, err := proofGet(client, port, route.host)
	if err != nil {
		return fmt.Errorf("%s: %w", route.RouteID, err)
	}
	if status != http.StatusOK || body != route.body {
		return fmt.Errorf("%s: status=%d body=%q, want 200 %q", route.RouteID, status, body, route.body)
	}
	return nil
}

// proofSweep requests every route once, in parallel with bounded concurrency,
// and returns each request's latency plus every first-attempt failure.
func proofSweep(client *http.Client, port int, routes []proofRoute, concurrency int) ([]time.Duration, []error) {
	latencies := make([]time.Duration, len(routes))
	var mu sync.Mutex
	var failures []error
	var wg sync.WaitGroup
	next := make(chan int)
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				started := time.Now()
				err := proofCheck(client, port, routes[i])
				latencies[i] = time.Since(started)
				if err != nil {
					mu.Lock()
					failures = append(failures, err)
					mu.Unlock()
				}
			}
		}()
	}
	for i := range routes {
		next <- i
	}
	close(next)
	wg.Wait()
	return latencies, failures
}

// proofRandomSample draws requests over routes with a fixed seed so a steady-
// state latency run is the same request mix on every machine.
func proofRandomSample(routes []proofRoute, requests int) []proofRoute {
	rng := rand.New(rand.NewPCG(1000, 1000)) //nolint:gosec // deterministic request mix, not security-sensitive
	sample := make([]proofRoute, 0, requests)
	for range requests {
		sample = append(sample, routes[rng.IntN(len(routes))])
	}
	return sample
}

// proofSpread picks count routes evenly spaced across the set.
func proofSpread(t *testing.T, routes []proofRoute, count int) []proofRoute {
	t.Helper()
	if len(routes) < count {
		t.Fatalf("cannot spread a %d-route sample over %d routes", count, len(routes))
	}
	step := len(routes) / count
	sample := make([]proofRoute, 0, count)
	for i := range count {
		sample = append(sample, routes[i*step])
	}
	return sample
}

func proofPercentile(latencies []time.Duration, percent int) time.Duration {
	if len(latencies) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), latencies...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[(len(sorted)-1)*percent/100]
}

// proofAwaitStatus polls one Host until the vhost answers with the status.
func proofAwaitStatus(t *testing.T, client *http.Client, port int, host string, want int, timeout time.Duration, runner <-chan error) {
	t.Helper()
	var last string
	proofWaitFor(t, runner, timeout, func() bool {
		status, body, err := proofGet(client, port, host)
		if err != nil {
			last = err.Error()
			return false
		}
		last = fmt.Sprintf("status=%d body=%q", status, body)
		return status == want
	}, func() string { return fmt.Sprintf("%s to answer %d (last: %s)", host, want, last) })
}

// proofWait polls condition until it holds, failing if the runner exits or
// the timeout passes first.
func proofWait(t *testing.T, runner <-chan error, timeout time.Duration, condition func() bool, what string) {
	t.Helper()
	proofWaitFor(t, runner, timeout, condition, func() string { return what })
}

// proofWaitFor is proofWait with the description rendered only on failure,
// so it can carry the last state the condition observed.
func proofWaitFor(t *testing.T, runner <-chan error, timeout time.Duration, condition func() bool, describe func() string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		select {
		case err := <-runner:
			t.Fatalf("session group exited while waiting for %s: %v", describe(), err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", timeout, describe())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// proofOverlap is a background request loop over a sample of routes; it
// counts every request and every failure across a rotation.
type proofOverlapFailure struct {
	route string
	at    time.Time
	err   error
}

type proofOverlap struct {
	requests atomic.Int64
	stop     chan struct{}
	wg       sync.WaitGroup

	mu       sync.Mutex
	failures []proofOverlapFailure
}

func startProofOverlap(client *http.Client, port int, routes []proofRoute, workers int) *proofOverlap {
	loop := &proofOverlap{stop: make(chan struct{})}
	for w := range workers {
		loop.wg.Add(1)
		go func(offset int) {
			defer loop.wg.Done()
			for i := offset; ; i++ {
				select {
				case <-loop.stop:
					return
				default:
				}
				route := routes[i%len(routes)]
				err := proofCheck(client, port, route)
				loop.requests.Add(1)
				if err != nil {
					loop.mu.Lock()
					loop.failures = append(loop.failures, proofOverlapFailure{route: route.RouteID, at: time.Now(), err: err})
					loop.mu.Unlock()
				}
				time.Sleep(time.Millisecond)
			}
		}(w)
	}
	return loop
}

func (l *proofOverlap) finish() (requests int64, failures []proofOverlapFailure) {
	close(l.stop)
	l.wg.Wait()
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.requests.Load(), append([]proofOverlapFailure(nil), l.failures...)
}

// proofOverlapVerdict attributes each overlap failure. The pinned FRP client
// admits a work connection only while its proxy is in the running phase, and
// that phase lags the server on both edges of a proxy's life: the server adds
// a new proxy to the load-balancer group inside RegisterProxy and only then
// sends NewProxyResp, and Wrapper.Stop marks a proxy closed in the same
// instant it sends CloseProxy. A request the server dispatches to the proxy
// inside either window is refused by the client and answered 404 by the
// server's reverse proxy. Both windows belong to the FRP fork, so a failure
// at a route's own replacement-registration instant (registering) or inside
// the drain after promotion (draining) is measured; anything else is the
// Connector's rotation and is a hard failure.
type proofOverlapVerdict struct {
	registering, draining, hard int
	firstHard                   error
	maxRegisterOffset           time.Duration
	maxDrainOffset              time.Duration
}

func judgeProofOverlap(failures []proofOverlapFailure, registeredAt map[string]time.Time, promotedAt, withdrawnAt time.Time, settle time.Duration) proofOverlapVerdict {
	var verdict proofOverlapVerdict
	for _, failure := range failures {
		registered, known := registeredAt[failure.route]
		switch {
		case known && !failure.at.Before(registered) && failure.at.Sub(registered) <= settle:
			verdict.registering++
			verdict.maxRegisterOffset = max(verdict.maxRegisterOffset, failure.at.Sub(registered))
		case !failure.at.Before(promotedAt) && failure.at.Before(withdrawnAt.Add(settle)):
			verdict.draining++
			verdict.maxDrainOffset = max(verdict.maxDrainOffset, failure.at.Sub(promotedAt))
		default:
			verdict.hard++
			if verdict.firstHard == nil {
				verdict.firstHard = fmt.Errorf("%s relative to promotion, %s relative to the route's replacement registration: %w",
					failure.at.Sub(promotedAt), failure.at.Sub(registered), failure.err)
			}
		}
	}
	return verdict
}

type proofGoroutines struct {
	Total  int `json:"total"`
	Client int `json:"frp_client"`
	Server int `json:"frp_server"`
	Share  int `json:"share"`
	Other  int `json:"other"`
}

// proofGoroutineSnapshot counts live goroutines by the package that created
// them, so the in-process FRP client, the in-process FRP server, and this
// package's own supervision are reported apart.
func proofGoroutineSnapshot() proofGoroutines {
	// Sized from the live count up front; each undersized attempt is one
	// more stop-the-world pass.
	buf := make([]byte, max(8<<20, runtime.NumGoroutine()*4096))
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, len(buf)*2)
	}
	var snapshot proofGoroutines
	for _, block := range strings.Split(string(buf), "\n\n") {
		if !strings.HasPrefix(block, "goroutine ") {
			continue
		}
		snapshot.Total++
		owner := block
		if i := strings.LastIndex(block, "\ncreated by "); i >= 0 {
			owner = block[i:]
		} else if lines := strings.SplitN(block, "\n", 3); len(lines) > 1 {
			owner = lines[1]
		}
		switch {
		case strings.Contains(owner, "github.com/fatedier/frp/client"):
			snapshot.Client++
		case strings.Contains(owner, "github.com/fatedier/frp/server"):
			snapshot.Server++
		case strings.Contains(owner, "qurl-connector/pkg/share"):
			snapshot.Share++
		default:
			snapshot.Other++
		}
	}
	return snapshot
}

type proofSnapshot struct {
	Goroutines proofGoroutines `json:"goroutines"`
	OpenFDs    int             `json:"open_fds"`
	HeapInuse  uint64          `json:"heap_inuse_bytes"`
	Sys        uint64          `json:"sys_bytes"`
}

func takeProofSnapshot() proofSnapshot {
	// Collect first so HeapInuse is live memory rather than garbage from the
	// previous snapshot's goroutine dump; Sys stays the high-water mark.
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	fds, _ := proofOpenFDs()
	return proofSnapshot{Goroutines: proofGoroutineSnapshot(), OpenFDs: fds, HeapInuse: stats.HeapInuse, Sys: stats.Sys}
}

// proofServerOnlineHTTPProxies asks the FRP server's own API how many HTTP
// proxies its proxy manager currently holds.
func proofServerOnlineHTTPProxies(t *testing.T, client *http.Client, apiPort int) int {
	t.Helper()
	response, err := client.Get("http://127.0.0.1:" + strconv.Itoa(apiPort) + "/api/proxy/http")
	if err != nil {
		t.Fatalf("query FRP server proxies: %v", err)
	}
	var payload struct {
		Proxies []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"proxies"`
	}
	err = json.NewDecoder(response.Body).Decode(&payload)
	_ = response.Body.Close()
	if err != nil {
		t.Fatalf("decode FRP server proxies: %v", err)
	}
	online := 0
	for _, proxy := range payload.Proxies {
		if proxy.Status == "online" {
			online++
		}
	}
	return online
}

type proofReport struct {
	GOOS         string `json:"goos"`
	GOARCH       string `json:"goarch"`
	GoVersion    string `json:"go_version"`
	NumCPU       int    `json:"num_cpu"`
	RaceDetector bool   `json:"race_detector"`
	Routes       int    `json:"routes"`
	Backends     int    `json:"backends"`

	RotationWindowMs   float64 `json:"rotation_window_ms"`
	RotationLeadNeedMs float64 `json:"rotation_lead_need_ms"`

	StartToAllServingMs           float64 `json:"start_to_all_serving_ms"`
	RoutesServingAtFirstPromotion int     `json:"routes_serving_at_first_promotion"`
	SweepMs                       float64 `json:"sweep_ms"`
	SweepP50Ms                    float64 `json:"sweep_p50_ms"`
	SweepP99Ms                    float64 `json:"sweep_p99_ms"`
	SteadyRequests                int     `json:"steady_requests"`
	SteadyP50Ms                   float64 `json:"steady_p50_ms"`
	SteadyP99Ms                   float64 `json:"steady_p99_ms"`
	RotationReregisterMs          float64 `json:"rotation_reregister_ms"`
	RotationPromoteMs             float64 `json:"rotation_promote_ms"`
	DrainWithdrawMs               float64 `json:"drain_withdraw_ms"`
	OverlapCoverage               string  `json:"overlap_coverage"`
	OverlapRequests               int64   `json:"overlap_requests"`
	OverlapFailures               int     `json:"overlap_failures"`
	OverlapFailuresRegistering    int     `json:"overlap_failures_at_route_registration"`
	OverlapRegisterMaxOffsetMs    float64 `json:"overlap_failure_max_ms_after_route_registration"`
	OverlapFailuresDraining       int     `json:"overlap_failures_in_drain_window"`
	OverlapDrainMaxOffsetMs       float64 `json:"overlap_failure_max_ms_after_promotion"`

	Snapshots          map[string]proofSnapshot `json:"snapshots"`
	GoroutinesPerRoute float64                  `json:"goroutines_per_route"`
	FDsMeasured        bool                     `json:"open_fds_measured"`
	FDsPerRouteIdle    float64                  `json:"open_fds_per_route_after_sweep"`
	PeakRSSBytes       uint64                   `json:"peak_rss_bytes"`
	PeakRSSSource      string                   `json:"peak_rss_source"`

	ServerOnlineProxies int `json:"server_online_http_proxies"`
	NewProxyAdmitted    int `json:"new_proxy_admitted"`
	NewProxyRejected    int `json:"new_proxy_rejected"`
}

func proofMillis(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func proofMiB(bytes uint64) float64 { return float64(bytes) / (1 << 20) }

func (r proofReport) summary() string {
	base, registered := r.Snapshots["baseline"], r.Snapshots["registered"]
	afterSweep, afterRotation, afterStop := r.Snapshots["after_sweep"], r.Snapshots["after_rotation"], r.Snapshots["after_stop"]
	fds := "not measured on " + r.GOOS
	if r.FDsMeasured {
		fds = fmt.Sprintf("baseline %d  registered %d  after sweep %d (%.2f/route idle work conns)  after rotation %d  after stop %d",
			base.OpenFDs, registered.OpenFDs, afterSweep.OpenFDs, r.FDsPerRouteIdle, afterRotation.OpenFDs, afterStop.OpenFDs)
	}
	rss := "not measured on " + r.GOOS
	if r.PeakRSSSource != "" {
		rss = fmt.Sprintf("%.1f MiB (%s)", proofMiB(r.PeakRSSBytes), r.PeakRSSSource)
	}
	return fmt.Sprintf(`
scaling proof: %d routes on one Connector admission and one FRP session (%s/%s, %s, %d CPUs, race=%t, %d backends, loopback)
  Run() -> all %d routes serving          %8.0f ms   (%d serving at first promotion)
  vhost sweep, %d routes, %d-way          %8.0f ms   cold p50 %.2f ms  p99 %.2f ms
  steady-state latency, %d requests       warm p50 %.2f ms  p99 %.2f ms
  rotation: Admit -> all re-registered    %8.0f ms   Admit -> promoted %.0f ms   (window %.0f s; production lead need %.0f s)
  drain: promoted -> old proxies gone     %8.0f ms
  overlap requests / failures             %d / %d   (%d at a route's own re-registration instant, max +%.1f ms; %d in the drain window, max +%.1f ms; 0 elsewhere; loop covered %s)
  goroutines  baseline %d  registered %d (%.2f/route: frp client %d, frp server %d, share %d, other %d)  after rotation %d  after stop %d
  open FDs    %s
  peak RSS    %s   Go sys %.1f MiB registered / %.1f MiB after sweep / %.1f MiB after rotation
  FRP server online HTTP proxies          %d
  NewProxy admitted / rejected            %d / %d
`,
		r.Routes, r.GOOS, r.GOARCH, r.GoVersion, r.NumCPU, r.RaceDetector, r.Backends,
		r.Routes, r.StartToAllServingMs, r.RoutesServingAtFirstPromotion,
		r.Routes, proofSweepConcurrency, r.SweepMs, r.SweepP50Ms, r.SweepP99Ms,
		r.SteadyRequests, r.SteadyP50Ms, r.SteadyP99Ms,
		r.RotationReregisterMs, r.RotationPromoteMs, r.RotationWindowMs/1000, r.RotationLeadNeedMs/1000,
		r.DrainWithdrawMs,
		r.OverlapRequests, r.OverlapFailures, r.OverlapFailuresRegistering, r.OverlapRegisterMaxOffsetMs, r.OverlapFailuresDraining, r.OverlapDrainMaxOffsetMs, r.OverlapCoverage,
		base.Goroutines.Total, registered.Goroutines.Total, r.GoroutinesPerRoute,
		registered.Goroutines.Client, registered.Goroutines.Server, registered.Goroutines.Share, registered.Goroutines.Other,
		afterRotation.Goroutines.Total, afterStop.Goroutines.Total,
		fds,
		rss, proofMiB(registered.Sys), proofMiB(afterSweep.Sys), proofMiB(afterRotation.Sys),
		r.ServerOnlineProxies,
		r.NewProxyAdmitted, r.NewProxyRejected)
}

func TestHermeticSessionGroupServes1000Routes(t *testing.T) {
	routeCount := proofDefaultRoutes
	if value := os.Getenv(proofRoutesEnv); value != "" {
		parsed, err := strconv.Atoi(value)
		minimum := proofRouteChurn + proofSampleRoutes + 2
		if err != nil || parsed < minimum || parsed+proofRouteChurn > MaxGroupRoutes {
			t.Fatalf("%s=%q: want an integer in [%d, %d]", proofRoutesEnv, value, minimum, MaxGroupRoutes-proofRouteChurn)
		}
		routeCount = parsed
	}
	const (
		knockResourceID = "q_catalog_resource"
		groupResourceID = "group-resource"
	)

	backends := make([]int, proofBackends)
	for i := range backends {
		prefix := strconv.Itoa(i) + "|"
		echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, prefix+r.Host)
		}))
		t.Cleanup(echo.Close)
		backends[i] = echo.Listener.Addr().(*net.TCPAddr).Port
	}
	routes := make([]proofRoute, 0, routeCount+proofRouteChurn)
	for i := range routeCount + proofRouteChurn {
		routes = append(routes, proofRouteAt(i, backends))
	}
	initial, churnIn := routes[:routeCount], routes[routeCount:]

	port := reserveHermeticPort(t)
	apiPort := reserveHermeticPort(t)
	plugin := newHermeticQRTSPlugin(t)
	proofEnableFRPMetrics()
	serverCfg := hermeticFRPSConfig(port, port, proofSubdomainHost, plugin.server.URL)
	serverCfg.WebServer.Addr, serverCfg.WebServer.Port = "127.0.0.1", apiPort
	frps := startHermeticFRPSFromConfig(t, serverCfg)
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

	// Rotation is time-driven. The first admission's window is 2W, so the
	// production lead formula (30s floor, 50ms per route) is capped to
	// exactly W = openTime/2: the steady-state phases must finish inside the
	// first W, and the replacement then has W to re-register every route
	// before the old admission expires. The second admission is long so
	// nothing rotates again during the rejection phase and teardown.
	window := 12*time.Second + time.Duration(routeCount)*20*time.Millisecond
	resourceHost := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	first := Admission{
		KnockResourceID: knockResourceID, ResourceID: groupResourceID,
		RunID: "1111111111111111", RunAttempt: 1, Token: "token-one",
		ResourceHost: resourceHost, SessionID: 101,
		SessionReceipt: testSessionReceipt(101, "1111111111111111", 1), OpenTime: 2 * window,
	}
	second := Admission{
		KnockResourceID: knockResourceID, ResourceID: groupResourceID,
		RunID: "2222222222222222", RunAttempt: 2, Token: "token-two",
		ResourceHost: resourceHost, SessionID: 102,
		SessionReceipt: testSessionReceipt(102, "2222222222222222", 2), OpenTime: 10 * time.Minute,
	}
	admitter := &hermeticAdmitter{admissions: []Admission{first, second}}
	// insideWindow names the real cause when a slow machine overruns the
	// steady-state budget, instead of letting the rotation fire mid-phase and
	// a later assertion blame SetRoutes for a second admission.
	insideWindow := func(phase string) {
		t.Helper()
		if elapsed := time.Since(admitter.admittedAtIndex(0)); elapsed >= window {
			t.Fatalf("%s reached %s after the first admission, past the %s rotation window (12s + 20ms per route): the machine is too slow for the steady-state budget, not a rotation defect", phase, elapsed, window)
		}
	}
	// budgeted wraps a steady-state wait condition so the budget is checked
	// on every poll: a rotation that fires mid-wait would otherwise surface as
	// the wait's own timeout.
	budgeted := func(phase string, condition func() bool) func() bool {
		return func() bool {
			insideWindow(phase)
			return condition()
		}
	}

	events := &proofEvents{serving: make(map[uint64]int)}
	var runner *SessionGroupRunner
	runner, err = NewSessionGroupRunner(SessionGroupConfig{
		KnockResourceID: knockResourceID, ResourceID: groupResourceID, Routes: localRoutes(initial),
		Admitter: admitter, Sessions: factory,
		MinBackoff: 10 * time.Millisecond, MaxBackoff: 25 * time.Millisecond,
		StopTimeout: 10 * time.Second,
		OnServing: func(admission Admission) {
			// Promotion is reported before the promoted session's routes are
			// reported one by one, so the active session's states at this
			// instant are the proof of what was serving when it took over.
			serving := 0
			for _, state := range runner.RouteStates() {
				if state.Phase == RouteServing {
					serving++
				}
			}
			events.promote(admission.SessionID, serving)
		},
		OnRouteServing:       func(_ string, admission Admission) { events.routeServing(admission.SessionID) },
		OnRouteFailed:        events.routeFailed,
		OnRotationLeadCapped: events.capped,
		OnRetry:              func(err error, _ time.Duration) { events.retry(err) },
	})
	if err != nil {
		t.Fatal(err)
	}

	report := proofReport{
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, GoVersion: runtime.Version(), NumCPU: runtime.NumCPU(),
		RaceDetector: proofRaceDetector, Routes: routeCount, Backends: proofBackends,
		RotationWindowMs: proofMillis(window), Snapshots: map[string]proofSnapshot{},
	}
	_, report.FDsMeasured = proofOpenFDs()
	report.Snapshots["baseline"] = takeProofSnapshot()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runnerResult := make(chan error, 1)
	runStarted := time.Now()
	go func() { runnerResult <- runner.Run(ctx) }()

	// Phase 1: every route registers on one admission and one session.
	proofWait(t, runnerResult, 60*time.Second+time.Duration(routeCount)*50*time.Millisecond,
		func() bool { return events.servingCount(first.SessionID) >= routeCount }, "every route serving on the first session")
	report.StartToAllServingMs = proofMillis(time.Since(runStarted))
	if got := events.servingCount(first.SessionID); got != routeCount {
		t.Fatalf("route serving reports = %d, want exactly one per route (%d)", got, routeCount)
	}
	if got := admitter.admissionCount(); got != 1 {
		t.Fatalf("admissions = %d, want one knock for %d routes", got, routeCount)
	}
	states := runner.RouteStates()
	if len(states) != routeCount {
		t.Fatalf("active session tracks %d routes, want %d", len(states), routeCount)
	}
	for routeID, state := range states {
		if state.Phase != RouteServing {
			t.Fatalf("route %q phase = %s (%v), want serving", routeID, state.Phase, state.Err)
		}
	}
	report.Snapshots["registered"] = takeProofSnapshot()
	report.ServerOnlineProxies = proofServerOnlineHTTPProxies(t, client, apiPort)
	if report.ServerOnlineProxies != routeCount {
		t.Fatalf("FRP server reports %d online HTTP proxies, want %d", report.ServerOnlineProxies, routeCount)
	}
	requireProofRegistrations(t, plugin, routeCount)
	t.Logf("phase 1: %d routes serving on one admission after %.0f ms", routeCount, report.StartToAllServingMs)

	// Phase 2: every route answers through the vhost, first request, in parallel.
	sweepStarted := time.Now()
	latencies, failures := proofSweep(client, port, initial, proofSweepConcurrency)
	report.SweepMs = proofMillis(time.Since(sweepStarted))
	requireNoProofFailures(t, "first request through the vhost", failures)
	report.SweepP50Ms, report.SweepP99Ms = proofMillis(proofPercentile(latencies, 50)), proofMillis(proofPercentile(latencies, 99))
	report.Snapshots["after_sweep"] = takeProofSnapshot()
	t.Logf("phase 2: %d routes answered in %.0f ms (p50 %.2f ms, p99 %.2f ms)", routeCount, report.SweepMs, report.SweepP50Ms, report.SweepP99Ms)

	// Phase 3: steady-state latency over a fixed random request mix, scaled
	// down for small groups so the default run's budget is not spent here.
	latencies, failures = proofSweep(client, port, proofRandomSample(initial, min(proofSteadyRequests, 10*routeCount)), proofSteadyConcurrency)
	requireNoProofFailures(t, "steady-state request", failures)
	report.SteadyRequests = len(latencies)
	report.SteadyP50Ms, report.SteadyP99Ms = proofMillis(proofPercentile(latencies, 50)), proofMillis(proofPercentile(latencies, 99))
	insideWindow("phase 3 (steady-state latency)")

	// Phase 4: ten routes leave and ten join the live session: no new knock,
	// no sibling re-registration.
	churned := append(append([]proofRoute(nil), initial[proofRouteChurn:]...), churnIn...)
	if err := runner.SetRoutes(ctx, localRoutes(churned)); err != nil {
		t.Fatal(err)
	}
	proofWait(t, runnerResult, 15*time.Second,
		budgeted("phase 4 (route churn)", func() bool { return events.servingCount(first.SessionID) >= routeCount+proofRouteChurn }), "added routes serving")
	if got := events.servingCount(first.SessionID); got != routeCount+proofRouteChurn {
		t.Fatalf("route serving reports after SetRoutes = %d, want %d", got, routeCount+proofRouteChurn)
	}
	for _, route := range churnIn {
		if err := proofCheck(client, port, route); err != nil {
			t.Fatalf("added route did not answer: %v", err)
		}
	}
	for _, route := range initial[:proofRouteChurn] {
		insideWindow("phase 4 (route churn)")
		proofAwaitStatus(t, client, port, route.host, http.StatusNotFound, 15*time.Second, runnerResult)
	}
	if got := admitter.admissionCount(); got != 1 {
		t.Fatalf("admissions after SetRoutes = %d, want still one", got)
	}
	requireProofRegistrations(t, plugin, routeCount+proofRouteChurn)
	states = runner.RouteStates()
	if len(states) != routeCount {
		t.Fatalf("active session tracks %d routes after SetRoutes, want %d", len(states), routeCount)
	}
	for _, route := range initial[:proofRouteChurn] {
		if _, present := states[route.RouteID]; present {
			t.Fatalf("removed route %q is still tracked", route.RouteID)
		}
	}
	insideWindow("phase 4 (route churn)")
	t.Logf("phase 4: %d routes out, %d in, still one admission", proofRouteChurn, proofRouteChurn)

	// Phase 5: restarting one route re-registers that proxy alone.
	restarted := churned[0]
	oldName := states[restarted.RouteID].ProxyName
	if err := runner.RestartRoute(ctx, restarted.RouteID); err != nil {
		t.Fatal(err)
	}
	proofWait(t, runnerResult, 15*time.Second,
		budgeted("phase 5 (route restart)", func() bool { return events.servingCount(first.SessionID) >= routeCount+proofRouteChurn+1 }), "restarted route serving again")
	if got := events.servingCount(first.SessionID); got != routeCount+proofRouteChurn+1 {
		t.Fatalf("route serving reports after RestartRoute = %d, want %d", got, routeCount+proofRouteChurn+1)
	}
	newName := runner.RouteStates()[restarted.RouteID].ProxyName
	if newName == oldName || !strings.HasSuffix(newName, "-r1") {
		t.Fatalf("restarted route proxy name = %q (was %q), want a fresh restart generation", newName, oldName)
	}
	if err := proofCheck(client, port, restarted); err != nil {
		t.Fatalf("restarted route did not answer: %v", err)
	}
	counts := requireProofRegistrations(t, plugin, routeCount+proofRouteChurn+1)
	if counts[oldName] != 1 || counts[newName] != 1 {
		t.Fatalf("NewProxy admissions around restart: old %q = %d, new %q = %d, want one each", oldName, counts[oldName], newName, counts[newName])
	}
	insideWindow("phase 5 (route restart)")
	t.Logf("phase 5: route %q restarted as %q; siblings untouched", restarted.RouteID, newName)

	// Phase 6: rotation. The replacement must carry every route before the old
	// session retires, and a request loop across the overlap must see no
	// failure at all.
	// Under the race detector the loop starts only once the old proxies have
	// left the server. The pinned FRP client reads a proxy's phase in
	// Wrapper.InWorkConn after releasing its lock, so a work connection the
	// server dispatches to a proxy at its registration instant is not only
	// refused (the window measured below) but is also reported by the
	// detector as a data race in the fork, which would fail this lane on the
	// fork's behalf. After withdrawal every proxy the loop can reach is
	// already running, so every such read is ordered after its write. The
	// non-race lanes and the opt-in run cover the whole rotation.
	sample := proofSpread(t, churned, proofSampleRoutes)
	var overlap *proofOverlap
	report.OverlapCoverage = "the whole rotation"
	if !proofRaceDetector {
		overlap = startProofOverlap(client, port, sample, proofOverlapWorkers)
	}
	promotionDeadline := time.Until(admitter.admittedAtIndex(0).Add(2*window)) + 15*time.Second
	proofWait(t, runnerResult, promotionDeadline, func() bool { return len(events.promotionList()) >= 2 }, "replacement promoted")
	promotions := events.promotionList()
	if len(promotions) != 2 {
		t.Fatalf("promotions = %d, want exactly the first cycle and one replacement", len(promotions))
	}
	report.RoutesServingAtFirstPromotion = promotions[0].serving
	if promotions[1].sessionID != second.SessionID {
		t.Fatalf("second promotion is session %d, want %d", promotions[1].sessionID, second.SessionID)
	}
	if promotions[1].serving != routeCount {
		t.Fatalf("replacement promoted with %d of %d routes serving", promotions[1].serving, routeCount)
	}
	if failed := events.failureList(); len(failed) != 0 {
		t.Fatalf("routes reported failed across the rotation: %v", failed)
	}
	// The drain starts the instant the replacement is promoted: the old
	// session's proxies are withdrawn from the server, which keeps serving
	// only the replacement's. Time how long the server takes to hold exactly
	// the replacement's proxies again.
	proofWait(t, runnerResult, 15*time.Second,
		func() bool { return proofServerOnlineHTTPProxies(t, client, apiPort) == routeCount }, "old proxies to leave the FRP server")
	withdrawnAt := time.Now()
	if overlap == nil {
		report.OverlapCoverage = "the drain after the old proxies were withdrawn (race detector)"
		overlap = startProofOverlap(client, port, sample, proofOverlapWorkers)
	}
	proofWait(t, runnerResult, 30*time.Second, func() bool {
		for _, admission := range admitter.retiredSnapshot() {
			if admission.SessionID == first.SessionID {
				return true
			}
		}
		return false
	}, "old admission retired")
	requests, overlapFailures := overlap.finish()
	if requests == 0 {
		t.Fatal("overlap loop made no requests")
	}
	promotedAt := promotions[1].at
	report.DrainWithdrawMs = proofMillis(withdrawnAt.Sub(promotedAt))
	if drain := withdrawnAt.Sub(promotedAt); drain > proofDrainCeiling {
		t.Fatalf("old proxies took %s to leave the FRP server after promotion, want under %s", drain, proofDrainCeiling)
	}
	// Attribute every failure to the exact server-side event of its own
	// route: the instant the replacement's proxy for that route was admitted
	// (from the plugin's per-proxy timestamps), or the drain after promotion.
	registeredAt := make(map[string]time.Time, routeCount)
	admittedTimes := plugin.admittedTimes()
	for routeID, state := range runner.RouteStates() {
		if at, ok := admittedTimes[state.ProxyName]; ok {
			registeredAt[routeID] = at
		}
	}
	verdict := judgeProofOverlap(overlapFailures, registeredAt, promotedAt, withdrawnAt, proofDrainSettle)
	if verdict.hard != 0 {
		t.Fatalf("overlap loop: %d of %d requests failed outside any FRP work-connection admission window; first: %v",
			verdict.hard, requests, verdict.firstHard)
	}
	// The excused windows are one dispatch race per proxy edge, so they can
	// cost at most a request or two per sampled route; anything larger is an
	// outage wearing the window's name.
	if verdict.registering+verdict.draining > proofSampleRoutes {
		t.Fatalf("overlap loop: %d failures inside the FRP admission windows across %d sampled routes (%d at registration, %d in the drain); a dispatch race costs at most one per route",
			verdict.registering+verdict.draining, proofSampleRoutes, verdict.registering, verdict.draining)
	}
	report.OverlapRequests, report.OverlapFailures = requests, len(overlapFailures)
	report.OverlapFailuresRegistering, report.OverlapRegisterMaxOffsetMs = verdict.registering, proofMillis(verdict.maxRegisterOffset)
	report.OverlapFailuresDraining, report.OverlapDrainMaxOffsetMs = verdict.draining, proofMillis(verdict.maxDrainOffset)
	rotationAdmitAt := admitter.admittedAtIndex(1)
	lastRegistered, registered := plugin.lastAdmittedAt(second.RunID)
	if registered != routeCount {
		t.Fatalf("replacement session registered %d proxies, want %d", registered, routeCount)
	}
	report.RotationReregisterMs = proofMillis(lastRegistered.Sub(rotationAdmitAt))
	report.RotationPromoteMs = proofMillis(promotions[1].at.Sub(rotationAdmitAt))
	requireProofRegistrations(t, plugin, 2*routeCount+proofRouteChurn+1)
	caps := events.capList()
	if len(caps) == 0 || caps[0].routes != routeCount || caps[0].lead != window {
		t.Fatalf("rotation lead cap reports = %+v, want the first admission capped at %s for %d routes", caps, window, routeCount)
	}
	report.RotationLeadNeedMs = proofMillis(caps[0].need)
	report.Snapshots["after_rotation"] = takeProofSnapshot()
	t.Logf("phase 6: rotation re-registered %d routes in %.0f ms, promoted at %.0f ms, old proxies withdrawn %.0f ms after promotion; %d overlap requests, %d failures (%d at a route's re-registration instant, %d in the drain window)",
		routeCount, report.RotationReregisterMs, report.RotationPromoteMs, report.DrainWithdrawMs, requests, len(overlapFailures), verdict.registering, verdict.draining)

	// Phase 7: one route the server rejects as resource_not_found is
	// withdrawn alone; every sibling keeps answering on the same session.
	gone := churned[proofRouteChurn]
	nextGeneration := runner.RouteStates()[gone.RouteID].Route
	nextGeneration.Generation++
	plugin.rejectProxy(groupProxyName(nextGeneration, second.SessionID), "resource_not_found: resource not found")
	if err := runner.RestartRoute(ctx, gone.RouteID); err != nil {
		t.Fatal(err)
	}
	proofWait(t, runnerResult, 15*time.Second, func() bool { return events.failureOf(gone.RouteID) != nil }, "rejected route reported")
	if err := events.failureOf(gone.RouteID); !errors.Is(err, ErrResourceGone) {
		t.Fatalf("rejected route failure = %v, want ErrResourceGone", err)
	}
	survivors := make([]proofRoute, 0, routeCount-1)
	for _, route := range churned {
		if route.RouteID != gone.RouteID {
			survivors = append(survivors, route)
		}
	}
	_, failures = proofSweep(client, port, survivors, proofSweepConcurrency)
	requireNoProofFailures(t, "sibling request after a rejected route", failures)
	proofAwaitStatus(t, client, port, gone.host, http.StatusNotFound, 15*time.Second, runnerResult)
	states = runner.RouteStates()
	if _, present := states[gone.RouteID]; present || len(states) != routeCount-1 {
		t.Fatalf("active session tracks %d routes after a rejected route (gone present: %t), want %d without it", len(states), present, routeCount-1)
	}
	if got := admitter.admissionCount(); got != 2 {
		t.Fatalf("admissions after a rejected route = %d, want still two", got)
	}
	if failed := events.failureList(); len(failed) != 1 {
		t.Fatalf("route failures = %v, want exactly the rejected route", failed)
	}
	if retries := events.retryList(); len(retries) != 0 {
		t.Fatalf("hermetic run retried %d times: %v", len(retries), retries)
	}
	observations := plugin.snapshot()
	report.NewProxyAdmitted, report.NewProxyRejected = 0, 0
	for _, observation := range observations {
		if observation.rejected {
			report.NewProxyRejected++
		} else {
			report.NewProxyAdmitted++
		}
	}
	if report.NewProxyAdmitted != 2*routeCount+proofRouteChurn+1 || report.NewProxyRejected != 1 {
		t.Fatalf("NewProxy admitted/rejected = %d/%d, want %d/1", report.NewProxyAdmitted, report.NewProxyRejected, 2*routeCount+proofRouteChurn+1)
	}
	t.Logf("phase 7: route %q withdrawn on resource_not_found; %d siblings still answer", gone.RouteID, len(survivors))

	// Teardown: both admissions retire exactly, and the process returns to
	// its baseline goroutine and descriptor counts.
	cancel()
	select {
	case err := <-runnerResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("runner exit = %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("session group runner did not stop")
	}
	retired := admitter.retiredSnapshot()
	if len(retired) != 2 || retired[0].SessionID != first.SessionID || retired[1].SessionID != second.SessionID {
		t.Fatalf("retired admissions = %v, want exactly the two in order", retired)
	}
	transport.CloseIdleConnections()
	baseline := report.Snapshots["baseline"]
	// The FRP server keeps a couple of idle keep-alive connections to the
	// plugin it authorized against, so the settled state sits a few
	// goroutines and descriptors above baseline; a leak would be per route,
	// so tolerances well below the smallest route count still catch one.
	settled := time.Now().Add(15 * time.Second)
	for {
		snapshot := takeProofSnapshot()
		report.Snapshots["after_stop"] = snapshot
		if snapshot.Goroutines.Total <= baseline.Goroutines.Total+24 && snapshot.OpenFDs <= baseline.OpenFDs+16 {
			break
		}
		if time.Now().After(settled) {
			t.Fatalf("after stop: %d goroutines (baseline %d) and %d open FDs (baseline %d) did not settle within 15s: %+v",
				snapshot.Goroutines.Total, baseline.Goroutines.Total, snapshot.OpenFDs, baseline.OpenFDs, snapshot.Goroutines)
		}
		time.Sleep(50 * time.Millisecond)
	}

	registeredSnapshot := report.Snapshots["registered"]
	report.GoroutinesPerRoute = float64(registeredSnapshot.Goroutines.Total-baseline.Goroutines.Total) / float64(routeCount)
	if report.FDsMeasured {
		report.FDsPerRouteIdle = float64(report.Snapshots["after_sweep"].OpenFDs-baseline.OpenFDs) / float64(routeCount)
	}
	if rss, ok := proofPeakRSSBytes(); ok {
		report.PeakRSSBytes, report.PeakRSSSource = rss, "getrusage ru_maxrss, whole test process"
	}
	t.Log(report.summary())
	if path := os.Getenv(proofReportEnv); path != "" {
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
			t.Fatalf("write %s: %v", proofReportEnv, err)
		}
		t.Logf("report written to %s", path)
	}
}

// requireProofRegistrations asserts the plugin admitted exactly distinct
// proxy names, each registered exactly once, and returns the counts.
func requireProofRegistrations(t *testing.T, plugin *hermeticQRTSPlugin, distinct int) map[string]int {
	t.Helper()
	counts := plugin.admittedNewProxies()
	if len(counts) != distinct {
		t.Fatalf("%d distinct proxies admitted, want %d", len(counts), distinct)
	}
	for name, count := range counts {
		if count != 1 {
			t.Fatalf("proxy %q was registered %d times, want exactly once (a duplicate NewProxy means the client re-sent it)", name, count)
		}
	}
	return counts
}

func requireNoProofFailures(t *testing.T, what string, failures []error) {
	t.Helper()
	if len(failures) == 0 {
		return
	}
	shown := failures
	if len(shown) > 5 {
		shown = shown[:5]
	}
	t.Fatalf("%d %s failures; first %d: %v", len(failures), what, len(shown), shown)
}
