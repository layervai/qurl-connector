package share

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	frpproxy "github.com/fatedier/frp/client/proxy"
	v1 "github.com/fatedier/frp/pkg/config/v1"

	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

func TestFRPSessionFactoryBuildsOverlapSafeResourceCycles(t *testing.T) {
	common := &v1.ClientCommonConfig{Metadatas: map[string]string{"preserved": "value"}}
	factory, err := NewFRPSessionFactory(FRPFactoryConfig{
		Common: common,
		Route: LocalHTTPRoute{
			RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
			ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
		},
		ClientVersion: "v1.2.3",
	})
	if err != nil {
		t.Fatal(err)
	}
	build := func(sessionID uint64) (*v1.ClientCommonConfig, *v1.HTTPProxyConfig, string) {
		t.Helper()
		admission := Admission{
			KnockResourceID: "q_catalog_key", ResourceID: "public-resource",
			RunID: "run", RunAttempt: 1, Token: "token", ResourceHost: "frp.example:7000",
			SessionID: sessionID, SessionReceipt: testSessionReceipt(sessionID, "run", 1), OpenTime: 2,
		}
		cycleCommon, proxies, names, err := factory.BuildConfig(admission)
		if err != nil {
			t.Fatal(err)
		}
		proxy, ok := proxies[0].(*v1.HTTPProxyConfig)
		if !ok {
			t.Fatalf("proxy type = %T", proxies[0])
		}
		return cycleCommon, proxy, names[0]
	}
	commonA, proxyA, nameA := build(101)
	commonB, proxyB, nameB := build(102)
	if nameA == nameB || proxyA.Name == proxyB.Name {
		t.Fatalf("overlap cycles reused proxy name %q", nameA)
	}
	for label, proxy := range map[string]*v1.HTTPProxyConfig{"a": proxyA, "b": proxyB} {
		if proxy.SubDomain != "routing-resource" || proxy.LoadBalancer.Group != "routing-resource" || proxy.LoadBalancer.GroupKey != "routing-resource" {
			t.Errorf("cycle %s routing changed: %+v", label, proxy)
		}
		if proxy.LocalIP != "127.0.0.1" || proxy.LocalPort != 3000 {
			t.Errorf("cycle %s target changed: %s:%d", label, proxy.LocalIP, proxy.LocalPort)
		}
		if got := proxy.Metadatas[nhpconfig.MetaResourceID]; got != "public-resource" {
			t.Errorf("cycle %s public resource metadata = %q", label, got)
		}
	}
	for label, cycleCommon := range map[string]*v1.ClientCommonConfig{"a": commonA, "b": commonB} {
		if cycleCommon.ServerAddr != "frp.example" || cycleCommon.ServerPort != 7000 {
			t.Errorf("cycle %s admitted server = %s:%d", label, cycleCommon.ServerAddr, cycleCommon.ServerPort)
		}
		if cycleCommon.Metadatas[nhpconfig.MetaQURLKnockToken] != "token" || cycleCommon.Metadatas["preserved"] != "value" {
			t.Errorf("cycle %s Login metadata = %#v", label, cycleCommon.Metadatas)
		}
	}
	if _, ok := common.Metadatas[nhpconfig.MetaQURLKnockToken]; ok {
		t.Fatal("cycle token mutated the caller's common config")
	}
}

func TestFRPSessionFactoryRejectsUnsafeAdmittedHosts(t *testing.T) {
	tlsOn := true
	base := FRPFactoryConfig{
		Common: &v1.ClientCommonConfig{},
		Route: LocalHTTPRoute{
			RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
			ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
		},
	}
	admission := Admission{
		KnockResourceID: "q_catalog_key", ResourceID: "public-resource",
		RunID: "run", RunAttempt: 1, Token: "token", SessionID: 1,
		SessionReceipt: testSessionReceipt(1, "run", 1), OpenTime: time.Minute,
	}
	for _, resourceHost := range []string{"frp.example", "2001:db8::1", ":7000", "frp.example:0", "frp.example:65536"} {
		t.Run(resourceHost, func(t *testing.T) {
			factory, err := NewFRPSessionFactory(base)
			if err != nil {
				t.Fatal(err)
			}
			admission.ResourceHost = resourceHost
			if _, _, _, err := factory.BuildConfig(admission); err == nil {
				t.Fatal("unsafe admitted host was accepted")
			}
		})
	}

	t.Run("IP literal under implicit TLS SNI", func(t *testing.T) {
		cfg := base
		cfg.Common = &v1.ClientCommonConfig{}
		cfg.Common.Transport.TLS.Enable = &tlsOn
		factory, err := NewFRPSessionFactory(cfg)
		if err != nil {
			t.Fatal(err)
		}
		admission.ResourceHost = "127.0.0.1:7000"
		if _, _, _, err := factory.BuildConfig(admission); err == nil {
			t.Fatal("IP literal with TLS and no explicit server name was accepted")
		}
	})

	t.Run("bracketed IPv6 stays dialable", func(t *testing.T) {
		factory, err := NewFRPSessionFactory(base)
		if err != nil {
			t.Fatal(err)
		}
		admission.ResourceHost = "[2001:db8::1]:7000"
		common, _, _, err := factory.BuildConfig(admission)
		if err != nil {
			t.Fatal(err)
		}
		if common.ServerAddr != "[2001:db8::1]" || common.ServerPort != 7000 {
			t.Fatalf("admitted endpoint = %s:%d", common.ServerAddr, common.ServerPort)
		}
	})
}

type statusMap map[string]*frpproxy.WorkingStatus

func (s statusMap) GetProxyStatus(name string) (*frpproxy.WorkingStatus, bool) {
	item, ok := s[name]
	return item, ok
}

func TestServingReadinessRequiresEveryExactProxyRunning(t *testing.T) {
	status := statusMap{
		"cycle-a": {Phase: frpproxy.ProxyPhaseRunning},
		"cycle-b": {Phase: frpproxy.ProxyPhaseStartErr},
		"stale":   {Phase: frpproxy.ProxyPhaseRunning},
	}
	if proxiesRunning(status, []string{"cycle-a", "cycle-b"}) {
		t.Fatal("readiness accepted a configured proxy in start error")
	}
	status["cycle-b"].Phase = frpproxy.ProxyPhaseRunning
	if !proxiesRunning(status, []string{"cycle-a", "cycle-b"}) {
		t.Fatal("readiness rejected the exact configured running set")
	}
	delete(status, "cycle-b")
	if proxiesRunning(status, []string{"cycle-a", "cycle-b"}) {
		t.Fatal("readiness substituted an unrelated running proxy")
	}
}

func TestProxyStartErrorTaxonomy(t *testing.T) {
	tests := []struct {
		name string
		err  string
		want error
	}{
		{name: "stale knock", err: "knock_invalid: knock token expired", want: ErrAdmissionStale},
		{name: "missing owner", err: "owner_missing: connector identity missing", want: ErrAdmissionStale},
		{name: "serving session stale", err: "session_stale: serving session is stale", want: ErrAdmissionStale},
		{name: "gone", err: "resource_not_found: resource not found", want: ErrResourceGone},
		{name: "registration transient", err: "registration_failed: device registration unavailable"},
		{name: "rate transient", err: "rate_limited: retry later"},
		{name: "circuit transient", err: "circuit_open: control plane unavailable"},
		{name: "auth transient", err: "auth_error: validation unavailable"},
		{name: "embedded tag", err: "proxy knock_invalid: knock token expired"},
		{name: "leading whitespace", err: " knock_invalid: knock token expired"},
		{name: "missing exact delimiter", err: "knock_invalid:knock token expired"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status := statusMap{"cycle": {Phase: frpproxy.ProxyPhaseStartErr, Err: test.err}}
			running, err := inspectProxyStatuses(status, []string{"cycle"})
			if running {
				t.Fatal("start error reported running")
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("inspect error = %v, want %v", err, test.want)
			}
			if test.want == nil && err != nil {
				t.Fatalf("transient/malformed tag terminated cycle: %v", err)
			}
		})
	}
}

type blockingFRPService struct{}

func (blockingFRPService) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}
func (blockingFRPService) GracefulClose(time.Duration) {}

type closeDurationFRPService struct {
	duration chan time.Duration
}

func (s *closeDurationFRPService) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}
func (s *closeDurationFRPService) GracefulClose(duration time.Duration) {
	s.duration <- duration
}

func TestFRPSessionRetirementDoesNotBlockReplacementRenewal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	service := &closeDurationFRPService{duration: make(chan time.Duration, 1)}
	session := &frpServingSession{
		svc: service, status: statusMap{}, names: []string{"cycle"}, poll: time.Millisecond,
		ready: make(chan struct{}), done: make(chan struct{}), cancel: cancel,
	}
	go session.run(ctx)
	if err := session.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if duration := <-service.duration; duration != 4*time.Second {
		t.Fatalf("retired FRP cycle grace duration = %v, want 4s", duration)
	}
}

type lockedStatus struct {
	mu   sync.Mutex
	item *frpproxy.WorkingStatus
}

func (s *lockedStatus) GetProxyStatus(string) (*frpproxy.WorkingStatus, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := *s.item
	return &copy, true
}

func (s *lockedStatus) set(phase, err string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.item.Phase = phase
	s.item.Err = err
}

func TestFRPSessionStatusTransitionsDriveExactLifecycle(t *testing.T) {
	start := func(status *lockedStatus) *frpServingSession {
		ctx, cancel := context.WithCancel(context.Background())
		session := &frpServingSession{
			svc: blockingFRPService{}, status: status, names: []string{"cycle"},
			poll: time.Millisecond, ready: make(chan struct{}), done: make(chan struct{}), cancel: cancel,
		}
		go session.run(ctx)
		return session
	}

	t.Run("transient remains same session", func(t *testing.T) {
		status := &lockedStatus{item: &frpproxy.WorkingStatus{Phase: frpproxy.ProxyPhaseStartErr, Err: "rate_limited: retry later"}}
		session := start(status)
		select {
		case <-session.Done():
			t.Fatalf("transient status ended session: %v", session.Err())
		case <-time.After(10 * time.Millisecond):
		}
		status.set(frpproxy.ProxyPhaseRunning, "")
		select {
		case <-session.Ready():
		case <-time.After(time.Second):
			t.Fatal("session did not become ready after same-session retry")
		}
		_ = session.Stop(context.Background())
	})

	t.Run("running session later loses admission", func(t *testing.T) {
		status := &lockedStatus{item: &frpproxy.WorkingStatus{Phase: frpproxy.ProxyPhaseRunning}}
		session := start(status)
		select {
		case <-session.Ready():
		case <-time.After(time.Second):
			t.Fatal("initial running status did not report ready")
		}
		status.set(frpproxy.ProxyPhaseStartErr, "knock_invalid: knock token expired")
		select {
		case <-session.Done():
		case <-time.After(time.Second):
			t.Fatal("later terminal status did not end the serving cycle")
		}
		if !errors.Is(session.Err(), ErrAdmissionStale) {
			t.Fatalf("session error = %v, want stale admission", session.Err())
		}
	})

	t.Run("running session later becomes stale", func(t *testing.T) {
		status := &lockedStatus{item: &frpproxy.WorkingStatus{Phase: frpproxy.ProxyPhaseRunning}}
		session := start(status)
		select {
		case <-session.Ready():
		case <-time.After(time.Second):
			t.Fatal("initial running status did not report ready")
		}
		status.set(frpproxy.ProxyPhaseStartErr, "session_stale: serving session is stale")
		select {
		case <-session.Done():
		case <-time.After(time.Second):
			t.Fatal("later stale-session status did not end the serving cycle")
		}
		if !errors.Is(session.Err(), ErrAdmissionStale) {
			t.Fatalf("session error = %v, want stale admission", session.Err())
		}
	})

	for name, test := range map[string]struct {
		statusErr string
		want      error
	}{
		"stale admission": {statusErr: "owner_missing: connector identity missing", want: ErrAdmissionStale},
		"gone resource":   {statusErr: "resource_not_found: resource not found", want: ErrResourceGone},
	} {
		t.Run(name, func(t *testing.T) {
			status := &lockedStatus{item: &frpproxy.WorkingStatus{Phase: frpproxy.ProxyPhaseStartErr, Err: test.statusErr}}
			session := start(status)
			select {
			case <-session.Done():
			case <-time.After(time.Second):
				t.Fatal("terminal start error did not end FRP cycle")
			}
			if !errors.Is(session.Err(), test.want) {
				t.Fatalf("session error = %v, want %v", session.Err(), test.want)
			}
		})
	}
}
