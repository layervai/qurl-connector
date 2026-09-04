package share

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	frpclient "github.com/fatedier/frp/client"
	frpproxy "github.com/fatedier/frp/client/proxy"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"

	"github.com/fatedier/frp/pkg/policy/security"

	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

// LocalHTTPRoute is the exact local and platform identity of one managed HTTP
// share. Public ResourceID is authorization metadata; ConnectorRoutingID is
// the stable subdomain/load-balancer identity.
type LocalHTTPRoute struct {
	RouteID            string
	LocalIP            string
	LocalPort          int
	ResourceID         string
	ConnectorRoutingID string
}

type FRPFactoryConfig struct {
	Common        *v1.ClientCommonConfig
	Route         LocalHTTPRoute
	ClientVersion string
	ConfigPath    string
	ReadyPoll     time.Duration
}

type FRPSessionFactory struct {
	cfg FRPFactoryConfig
}

func NewFRPSessionFactory(cfg FRPFactoryConfig) (*FRPSessionFactory, error) {
	if cfg.Common == nil {
		return nil, errors.New("build FRP session factory: common config is nil")
	}
	if err := validateLocalHTTPRoute(cfg.Route); err != nil {
		return nil, fmt.Errorf("build FRP session factory: %w", err)
	}
	if cfg.ReadyPoll <= 0 {
		cfg.ReadyPoll = 100 * time.Millisecond
	}
	return &FRPSessionFactory{cfg: cfg}, nil
}

// BuildConfig renders one overlap-safe cycle. Proxy Name changes with the NHP
// SessionID, while group, group key, subdomain, public resource metadata, and
// local target remain stable.
func (f *FRPSessionFactory) BuildConfig(admission Admission) (*v1.ClientCommonConfig, []v1.ProxyConfigurer, []string, error) {
	if err := validateAdmission(admission, admission.KnockResourceID, f.cfg.Route.ResourceID); err != nil {
		return nil, nil, nil, err
	}
	common, err := buildAdmittedCommon(f.cfg.Common, admission, f.cfg.ClientVersion)
	if err != nil {
		return nil, nil, nil, err
	}
	proxyName := nhpconfig.FRPProxyName(f.cfg.Route.RouteID, sessionProxyDiscriminator(admission.SessionID))
	proxy := buildRouteProxy(f.cfg.Route, proxyName)
	return common, []v1.ProxyConfigurer{proxy}, []string{proxyName}, nil
}

func validateLocalHTTPRoute(route LocalHTTPRoute) error {
	if route.RouteID == "" || route.ResourceID == "" || route.ConnectorRoutingID == "" {
		return errors.New("route identities are incomplete")
	}
	if route.LocalIP == "" || route.LocalPort < 1 || route.LocalPort > 65535 {
		return errors.New("local target is invalid")
	}
	return nil
}

// buildAdmittedCommon renders the Login half of one admission: the admitted
// server endpoint, the bearer knock token, and fail-fast login. The caller's
// base config is never mutated.
func buildAdmittedCommon(base *v1.ClientCommonConfig, admission Admission, clientVersion string) (*v1.ClientCommonConfig, error) {
	common := cloneCommon(base)
	host, port, err := parseAdmittedResourceHost(admission.ResourceHost)
	if err != nil {
		return nil, fmt.Errorf("parse admitted FRP host: %w", err)
	}
	if tlsEnabled(common) && common.Transport.TLS.ServerName == "" && ipLiteralHost(host) {
		return nil, errors.New("parse admitted FRP host: IP-literal target requires an explicit TLS server name")
	}
	common.ServerAddr = host
	common.ServerPort = port
	if common.Metadatas == nil {
		common.Metadatas = map[string]string{}
	}
	common.Metadatas[nhpconfig.MetaQURLKnockToken] = admission.Token
	if clientVersion != "" {
		common.Metadatas[nhpconfig.MetaClientVersion] = clientVersion
	}
	failFast := true
	common.LoginFailExit = &failFast
	return common, nil
}

// sessionProxyDiscriminator is the per-admission replica discriminator folded
// into every proxy name so overlapping cycles never collide on the server.
func sessionProxyDiscriminator(sessionID uint64) string {
	return "nhp" + strconv.FormatUint(sessionID, 36)
}

// buildRouteProxy renders one HTTP proxy. Group, group key, subdomain, public
// resource metadata, and the local target are the route's stable identity;
// only the name changes between cycles.
func buildRouteProxy(route LocalHTTPRoute, proxyName string) *v1.HTTPProxyConfig {
	proxy := &v1.HTTPProxyConfig{}
	proxy.Name = proxyName
	proxy.Type = string(v1.ProxyTypeHTTP)
	proxy.LocalIP = route.LocalIP
	proxy.LocalPort = route.LocalPort
	proxy.SubDomain = route.ConnectorRoutingID
	proxy.LoadBalancer.Group = route.ConnectorRoutingID
	proxy.LoadBalancer.GroupKey = route.ConnectorRoutingID
	proxy.Metadatas = map[string]string{nhpconfig.MetaResourceID: route.ResourceID}
	return proxy
}

func (f *FRPSessionFactory) Start(ctx context.Context, admission Admission) (ServingSession, error) {
	if ctx == nil {
		return nil, errors.New("start FRP serving session: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	common, proxies, names, err := f.BuildConfig(admission)
	if err != nil {
		return nil, err
	}
	cfgSource := source.NewConfigSource()
	if err := cfgSource.ReplaceAll(proxies, nil); err != nil {
		return nil, fmt.Errorf("set FRP proxy configs: %w", err)
	}
	session := &frpServingSession{
		ready: make(chan struct{}), done: make(chan struct{}), names: names,
		poll: f.cfg.ReadyPoll,
	}
	svc, err := frpclient.NewService(frpclient.ServiceOptions{
		Common: common, InitialRunID: admission.RunID,
		OnFirstLoginSuccess: func(runID string) error {
			if runID != admission.RunID {
				return errors.New("FRP accepted Login under a different NHP RunID")
			}
			return nil
		},
		ConfigSourceAggregator: source.NewAggregator(cfgSource),
		UnsafeFeatures:         &security.UnsafeFeatures{},
		ConfigFilePath:         f.cfg.ConfigPath,
	})
	if err != nil {
		return nil, err
	}
	session.svc = svc
	session.status = svc.StatusExporter()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// The caller's context bounds Start, but must not become the returned
	// session's lifetime. Replacement attempts intentionally carry the old
	// admission deadline; retaining that context would tear down the new FRP
	// route immediately after a successful promotion.
	runCtx, cancel := context.WithCancel(context.Background())
	session.cancel = cancel
	go session.run(runCtx)
	return session, nil
}

type frpService interface {
	Run(context.Context) error
	GracefulClose(time.Duration)
}

type frpServingSession struct {
	svc    frpService
	status frpclient.StatusExporter
	names  []string
	poll   time.Duration
	ready  chan struct{}
	done   chan struct{}
	cancel context.CancelFunc

	mu        sync.Mutex
	err       error
	stopOnce  sync.Once
	readyOnce sync.Once
}

func (s *frpServingSession) run(ctx context.Context) {
	defer s.cancel()
	go s.watchReady(ctx)
	err := s.svc.Run(ctx)
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
	close(s.done)
}

func (s *frpServingSession) watchReady(ctx context.Context) {
	ticker := time.NewTicker(s.poll)
	defer ticker.Stop()
	for {
		running, terminalErr := inspectProxyStatuses(s.status, s.names)
		if terminalErr != nil {
			s.fail(terminalErr)
			return
		}
		if running {
			s.readyOnce.Do(func() { close(s.ready) })
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *frpServingSession) fail(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
	s.cancel()
}

func (s *frpServingSession) Ready() <-chan struct{} { return s.ready }
func (s *frpServingSession) Done() <-chan struct{}  { return s.done }
func (s *frpServingSession) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}
func (s *frpServingSession) Stop(ctx context.Context) error {
	return s.shutdown(ctx, 0)
}

// Drain preserves requests already assigned to the old proxy while removing
// it from new routing after a replacement becomes serving.
func (s *frpServingSession) Drain(ctx context.Context) error {
	return s.shutdown(ctx, 4*time.Second)
}

func (s *frpServingSession) shutdown(ctx context.Context, grace time.Duration) error {
	s.stopOnce.Do(func() {
		// GracefulClose records the drain interval before it cancels FRP's
		// internal service context. Canceling our parent context first races
		// Service.Run into an immediate close with the default zero interval.
		s.svc.GracefulClose(grace)
		s.cancel()
	})
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		err := s.Err()
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
}

func proxiesRunning(status frpclient.StatusExporter, names []string) bool {
	running, _ := inspectProxyStatuses(status, names)
	return running
}

// ErrAdmissionStale reports a qRTS rejection that requires a fresh
// resource-bound NHP admission rather than FRP's same-session retry.
var ErrAdmissionStale = errors.New("qURL share admission is no longer usable")

// inspectProxyStatuses treats FRP's status exporter as the authoritative
// client-side NewProxy result. Exact qRTS rejection tags that require a new
// NHP session terminate this cycle; resource_not_found is permanent. Other
// start errors remain inside FRP's same-session retry loop.
func inspectProxyStatuses(status frpclient.StatusExporter, names []string) (bool, error) {
	if status == nil || len(names) == 0 {
		return false, nil
	}
	for _, name := range names {
		item, ok := status.GetProxyStatus(name)
		if !ok || item == nil {
			return false, nil
		}
		if item.Phase == frpproxy.ProxyPhaseStartErr {
			switch proxyStartErrorTag(item.Err) {
			case "knock_invalid", "owner_missing", "session_stale":
				return false, fmt.Errorf("%w: %s", ErrAdmissionStale, item.Err)
			case "resource_not_found":
				return false, fmt.Errorf("%w: %s", ErrResourceGone, item.Err)
			}
		}
		if item.Phase != frpproxy.ProxyPhaseRunning {
			return false, nil
		}
	}
	return true, nil
}

func proxyStartErrorTag(value string) string {
	if strings.TrimSpace(value) != value {
		return ""
	}
	tag, detail, ok := strings.Cut(value, ": ")
	if !ok || tag == "" || detail == "" {
		return ""
	}
	for _, ch := range tag {
		if (ch < 'a' || ch > 'z') && ch != '_' {
			return ""
		}
	}
	return tag
}

func cloneCommon(in *v1.ClientCommonConfig) *v1.ClientCommonConfig {
	out := *in
	if in.Metadatas != nil {
		out.Metadatas = make(map[string]string, len(in.Metadatas))
		for key, value := range in.Metadatas {
			out.Metadatas[key] = value
		}
	}
	return &out
}

// parseAdmittedResourceHost accepts only canonical host:port values. A bare
// host, ambiguous unbracketed IPv6 literal, empty host, or invalid port cannot
// fall back to a static FRP endpoint after admission.
func parseAdmittedResourceHost(value string) (string, int, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return "", 0, fmt.Errorf("split host and port: %w", err)
	}
	if strings.TrimSpace(host) == "" {
		return "", 0, errors.New("host is empty")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("port %q is outside 1..65535", portText)
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = "[" + host + "]"
	}
	return host, port, nil
}

func ipLiteralHost(host string) bool {
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	return net.ParseIP(host) != nil
}

// tlsEnabled mirrors the audited FRP connector transport decision for the
// pinned fork. Any future protocol addition must be classified before the FRP
// dependency is advanced.
func tlsEnabled(common *v1.ClientCommonConfig) bool {
	if common == nil {
		return false
	}
	if common.Transport.TLS.Enable != nil && *common.Transport.TLS.Enable {
		return true
	}
	switch common.Transport.Protocol {
	case "wss", "quic":
		return true
	default:
		return false
	}
}
