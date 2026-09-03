package share

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	frpserver "github.com/fatedier/frp/server"
)

const hermeticOwnerMissing = "owner_missing: connector identity missing"

type hermeticAdmitter struct {
	mu         sync.Mutex
	admissions []Admission
	next       int
	// admittedAt records when each scripted admission was handed out.
	admittedAt []time.Time
	retired    []Admission
}

func (a *hermeticAdmitter) Admit(ctx context.Context, _, _ string) (Admission, error) {
	a.mu.Lock()
	if a.next < len(a.admissions) {
		admission := a.admissions[a.next]
		a.next++
		a.admittedAt = append(a.admittedAt, time.Now())
		a.mu.Unlock()
		return admission, nil
	}
	a.mu.Unlock()
	<-ctx.Done()
	return Admission{}, ctx.Err()
}

// admissionCount is how many scripted admissions have been handed out.
func (a *hermeticAdmitter) admissionCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.next
}

// admittedAtIndex is when the i-th admission was handed out.
func (a *hermeticAdmitter) admittedAtIndex(i int) time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.admittedAt[i]
}

func (a *hermeticAdmitter) Retire(_ context.Context, admission Admission) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.retired = append(a.retired, admission)
	return nil
}

func (a *hermeticAdmitter) retiredSnapshot() []Admission {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Admission(nil), a.retired...)
}

type hermeticNewProxyObservation struct {
	runID     string
	proxyName string
	rejected  bool
	at        time.Time
}

type hermeticQRTSPlugin struct {
	server *httptest.Server

	mu            sync.Mutex
	stale         map[string]bool
	rejectProxies map[string]string
	observations  []hermeticNewProxyObservation
}

type hermeticTCPForwarder struct {
	listener net.Listener

	mu     sync.RWMutex
	target string
}

func newHermeticTCPForwarder(t *testing.T, target string) *hermeticTCPForwarder {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	forwarder := &hermeticTCPForwarder{listener: listener, target: target}
	go forwarder.serve()
	t.Cleanup(func() { _ = listener.Close() })
	return forwarder
}

func (f *hermeticTCPForwarder) addr() string { return f.listener.Addr().String() }

func (f *hermeticTCPForwarder) setTarget(target string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.target = target
}

func (f *hermeticTCPForwarder) serve() {
	for {
		client, err := f.listener.Accept()
		if err != nil {
			return
		}
		f.mu.RLock()
		target := f.target
		f.mu.RUnlock()
		go func() {
			defer client.Close()
			upstream, err := net.DialTimeout("tcp", target, time.Second)
			if err != nil {
				return
			}
			defer upstream.Close()
			done := make(chan struct{}, 2)
			go func() {
				_, _ = io.Copy(upstream, client)
				done <- struct{}{}
			}()
			go func() {
				_, _ = io.Copy(client, upstream)
				done <- struct{}{}
			}()
			<-done
		}()
	}
}

func newHermeticQRTSPlugin(t *testing.T) *hermeticQRTSPlugin {
	t.Helper()
	plugin := &hermeticQRTSPlugin{stale: make(map[string]bool), rejectProxies: make(map[string]string)}
	plugin.server = httptest.NewServer(http.HandlerFunc(plugin.handle))
	t.Cleanup(plugin.server.Close)
	return plugin
}

func (p *hermeticQRTSPlugin) handle(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Op      string `json:"op"`
		Content struct {
			User struct {
				RunID string `json:"run_id"`
			} `json:"user"`
			ProxyName string `json:"proxy_name"`
		} `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "invalid plugin request", http.StatusBadRequest)
		return
	}
	response := map[string]any{"reject": false, "unchange": true}
	if request.Op == "NewProxy" {
		p.mu.Lock()
		reason, rejected := p.rejectProxies[request.Content.ProxyName]
		if !rejected && p.stale[request.Content.User.RunID] {
			reason, rejected = hermeticOwnerMissing, true
		}
		p.observations = append(p.observations, hermeticNewProxyObservation{
			runID: request.Content.User.RunID, proxyName: request.Content.ProxyName, rejected: rejected, at: time.Now(),
		})
		p.mu.Unlock()
		if rejected {
			response = map[string]any{"reject": true, "reject_reason": reason}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (p *hermeticQRTSPlugin) markStale(runID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stale[runID] = true
}

// rejectProxy makes every NewProxy for the exact proxy name fail with the
// given wire text, independent of the Login RunID.
func (p *hermeticQRTSPlugin) rejectProxy(proxyName, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rejectProxies[proxyName] = reason
}

// admittedNewProxies counts admitted NewProxy calls per proxy name.
func (p *hermeticQRTSPlugin) admittedNewProxies() map[string]int {
	p.mu.Lock()
	defer p.mu.Unlock()
	counts := make(map[string]int)
	for _, observation := range p.observations {
		if !observation.rejected {
			counts[observation.proxyName]++
		}
	}
	return counts
}

// admittedTimes reports, per proxy name, when its latest NewProxy was admitted.
func (p *hermeticQRTSPlugin) admittedTimes() map[string]time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	times := make(map[string]time.Time)
	for _, observation := range p.observations {
		if !observation.rejected && observation.at.After(times[observation.proxyName]) {
			times[observation.proxyName] = observation.at
		}
	}
	return times
}

// lastAdmittedAt reports when the latest NewProxy for the RunID was admitted
// and how many were admitted in total for it.
func (p *hermeticQRTSPlugin) lastAdmittedAt(runID string) (time.Time, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var last time.Time
	count := 0
	for _, observation := range p.observations {
		if observation.runID != runID || observation.rejected {
			continue
		}
		count++
		if observation.at.After(last) {
			last = observation.at
		}
	}
	return last, count
}

func (p *hermeticQRTSPlugin) snapshot() []hermeticNewProxyObservation {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]hermeticNewProxyObservation(nil), p.observations...)
}

func reserveHermeticPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func startHermeticFRPS(t *testing.T, bindPort, vhostPort int, subdomainHost, pluginURL string) *frpserver.Service {
	t.Helper()
	return startHermeticFRPSFromConfig(t, hermeticFRPSConfig(bindPort, vhostPort, subdomainHost, pluginURL))
}

// hermeticFRPSConfig is the FRP server shape every hermetic test shares: one
// loopback listener multiplexing control and vhost HTTP, the tunnel-auth
// plugin on NewProxy, and routing by subdomain.
func hermeticFRPSConfig(bindPort, vhostPort int, subdomainHost, pluginURL string) *v1.ServerConfig {
	return &v1.ServerConfig{
		BindAddr: "127.0.0.1", BindPort: bindPort,
		ProxyBindAddr: "127.0.0.1", VhostHTTPPort: vhostPort,
		SubDomainHost: subdomainHost,
		HTTPPlugins: []v1.HTTPPluginOptions{{
			Name: "qrts-sim", Addr: pluginURL, Path: "/", Ops: []string{"NewProxy"},
		}},
	}
}

func startHermeticFRPSFromConfig(t *testing.T, cfg *v1.ServerConfig) *frpserver.Service {
	t.Helper()
	if err := cfg.Complete(); err != nil {
		t.Fatalf("complete FRPS config: %v", err)
	}
	service, err := frpserver.NewService(cfg)
	if err != nil {
		t.Fatalf("start FRPS: %v", err)
	}
	go service.Run(context.Background())
	return service
}

func pollHermeticHTTP(t *testing.T, port int, host, want string, runner <-chan error) {
	t.Helper()
	pollHermeticRoute(t, port, "hermetic."+host, want, runner)
}

// pollHermeticRoute sends vhost requests for one exact Host until the expected
// body traverses the admitted route.
func pollHermeticRoute(t *testing.T, port int, hostHeader, want string, runner <-chan error) {
	t.Helper()
	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		select {
		case err := <-runner:
			t.Fatalf("resource runner exited before traffic was ready: %v", err)
		default:
		}
		request, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = hostHeader
		response, err := client.Do(request)
		if err != nil {
			lastErr = err
		} else {
			body, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr == nil && response.StatusCode == http.StatusOK && string(body) == want {
				return
			}
			if readErr != nil {
				lastErr = fmt.Errorf("status=%d body=%q: read response: %w", response.StatusCode, body, readErr)
			} else {
				lastErr = fmt.Errorf("status=%d body=%q", response.StatusCode, body)
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("traffic did not traverse the hermetic NHP-admitted FRP route: %v", lastErr)
}

func TestHermeticResourceRunnerRecoversFromQRTSSessionLoss(t *testing.T) {
	const (
		knockResourceID = "q_catalog_resource"
		resourceID      = "public-resource"
		echoBody        = "crid-lifecycle-hermetic-echo"
	)
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, echoBody)
	}))
	t.Cleanup(echo.Close)
	echoPort := echo.Listener.Addr().(*net.TCPAddr).Port

	// Each FRPS multiplexes control and vhost HTTP on one listener. A stable
	// loopback forwarder models the NLB address while routing new connections to
	// the replacement server instance after restart.
	firstPort := reserveHermeticPort(t)
	secondPort := reserveHermeticPort(t)
	plugin := newHermeticQRTSPlugin(t)
	firstFRPS := startHermeticFRPS(t, firstPort, firstPort, "example.test", plugin.server.URL)
	t.Cleanup(func() { _ = firstFRPS.Close() })
	forwarder := newHermeticTCPForwarder(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(firstPort)))

	falseValue := false
	common := &v1.ClientCommonConfig{}
	common.Log.Level = "error"
	common.Transport.TLS.Enable = &falseValue
	if err := common.Complete(); err != nil {
		t.Fatal(err)
	}
	factory, err := NewFRPSessionFactory(FRPFactoryConfig{
		Common: common,
		Route: LocalHTTPRoute{
			RouteID: "hermetic", LocalIP: "127.0.0.1", LocalPort: echoPort,
			ResourceID: resourceID, ConnectorRoutingID: "hermetic",
		},
		ClientVersion: "v1.0.0", ReadyPoll: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceHost := forwarder.addr()
	admitter := &hermeticAdmitter{admissions: []Admission{
		{
			KnockResourceID: knockResourceID, ResourceID: resourceID,
			RunID: "1111111111111111", RunAttempt: 1, Token: "token-one",
			ResourceHost: resourceHost, SessionID: 101,
			SessionReceipt: testSessionReceipt(101, "1111111111111111", 1), OpenTime: 5 * time.Minute,
		},
		{
			KnockResourceID: knockResourceID, ResourceID: resourceID,
			RunID: "2222222222222222", RunAttempt: 2, Token: "token-two",
			ResourceHost: resourceHost, SessionID: 102,
			SessionReceipt: testSessionReceipt(102, "2222222222222222", 2), OpenTime: 5 * time.Minute,
		},
	}}
	serving := make(chan Admission, 2)
	runner, err := NewResourceRunner(ResourceConfig{
		KnockResourceID: knockResourceID, ResourceID: resourceID,
		Admitter: admitter, Sessions: factory,
		MinBackoff: 10 * time.Millisecond, MaxBackoff: 25 * time.Millisecond,
		RotationLead: time.Minute, StopTimeout: 5 * time.Second,
		OnServing: func(admission Admission) { serving <- admission },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runnerResult := make(chan error, 1)
	go func() { runnerResult <- runner.Run(ctx) }()

	select {
	case got := <-serving:
		if got.RunID != "1111111111111111" {
			t.Fatalf("first serving RunID = %q", got.RunID)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("first FRP route did not become serving")
	}
	pollHermeticHTTP(t, firstPort, "example.test", echoBody, runnerResult)

	secondFRPS := startHermeticFRPS(t, secondPort, secondPort, "restart.test", plugin.server.URL)
	t.Cleanup(func() { _ = secondFRPS.Close() })
	plugin.markStale("1111111111111111")
	forwarder.setTarget(net.JoinHostPort("127.0.0.1", strconv.Itoa(secondPort)))
	if err := firstFRPS.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-serving:
		if got.RunID != "2222222222222222" {
			t.Fatalf("replacement serving RunID = %q", got.RunID)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("owner_missing did not produce a fresh admitted FRP cycle")
	}
	pollHermeticHTTP(t, secondPort, "restart.test", echoBody, runnerResult)

	cancel()
	select {
	case err := <-runnerResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("runner exit = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("resource runner did not stop")
	}

	retired := admitter.retiredSnapshot()
	if len(retired) != 2 || retired[0].RunID != "1111111111111111" || retired[1].RunID != "2222222222222222" {
		t.Fatalf("exact retired admissions = %#v", retired)
	}
	observations := plugin.snapshot()
	var admittedFirst, rejectedFirst, admittedSecond bool
	for _, observation := range observations {
		switch {
		case observation.runID == "1111111111111111" && !observation.rejected:
			admittedFirst = true
		case observation.runID == "1111111111111111" && observation.rejected:
			rejectedFirst = true
		case observation.runID == "2222222222222222" && !observation.rejected:
			admittedSecond = true
		}
	}
	if !admittedFirst || !rejectedFirst || !admittedSecond {
		t.Fatalf("qRTS observations = %#v", observations)
	}
}
