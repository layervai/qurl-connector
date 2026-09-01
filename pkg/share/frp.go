package share

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
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
// the stable subdomain/load-balancer identity. Its formatting methods redact
// runtime request-header names and values, and JSON/YAML encoding omits them.
type LocalHTTPRoute struct {
	RouteID            string
	LocalIP            string
	LocalPort          int
	ResourceID         string
	ConnectorRoutingID string
	// RequestHeaders contains runtime-only values for requests to the local
	// origin. The map is cloned, sent to frps in NewProxy, retained there for the
	// session, and applied server-side. A non-empty map requires an encrypted FRP
	// transport and the local FRP web/admin server disabled; the latter gate
	// bounds only local disclosure. The overlay is limited to 16 entries and
	// 1,024 aggregate name/value bytes.
	// Empty values are intentionally allowed for marker-header semantics and
	// still count as entries.
	RequestHeaders map[string]string `json:"-" yaml:"-"`
}

// String keeps runtime request-header names and values out of logs,
// assertions, and diagnostics.
func (r LocalHTTPRoute) String() string {
	return fmt.Sprintf(
		"share.LocalHTTPRoute{RouteID:%q, LocalIP:%q, LocalPort:%d, ResourceID:%q, ConnectorRoutingID:%q, RequestHeaders:[REDACTED]}",
		r.RouteID, r.LocalIP, r.LocalPort, r.ResourceID, r.ConnectorRoutingID,
	)
}

// GoString applies the same runtime request-header redaction to %#v formatting.
func (r LocalHTTPRoute) GoString() string { return r.String() }

// The pinned FRP JSON reader caps NewProxy content at 10,240 bytes.
// encoding/json can expand each raw string byte to six wire bytes, so the
// aggregate and entry caps leave roughly 4 KiB for the existing envelope.
const (
	maxRuntimeRequestHeaderCount = 16
	maxRuntimeRequestHeaderBytes = 1024
)

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

// String prevents the factory's private configuration from being expanded by
// fmt and exposing runtime request headers.
func (f FRPSessionFactory) String() string {
	common := "set"
	if f.cfg.Common == nil {
		common = "nil"
	}
	return fmt.Sprintf(
		"share.FRPSessionFactory{Common:%s, Route:%s, ClientVersion:%q, ConfigPath:%q, ReadyPoll:%s}",
		common, f.cfg.Route.String(), f.cfg.ClientVersion, f.cfg.ConfigPath, f.cfg.ReadyPoll,
	)
}

// GoString applies the same private-configuration redaction to %#v formatting.
func (f FRPSessionFactory) GoString() string { return f.String() }

func NewFRPSessionFactory(cfg FRPFactoryConfig) (*FRPSessionFactory, error) {
	if cfg.Common == nil {
		return nil, errors.New("build FRP session factory: common config is nil")
	}
	if cfg.Route.RouteID == "" || cfg.Route.ResourceID == "" || cfg.Route.ConnectorRoutingID == "" {
		return nil, errors.New("build FRP session factory: route identities are incomplete")
	}
	if cfg.Route.LocalIP == "" || cfg.Route.LocalPort < 1 || cfg.Route.LocalPort > 65535 {
		return nil, errors.New("build FRP session factory: local target is invalid")
	}
	cfg.Route.RequestHeaders = cloneRequestHeaders(cfg.Route.RequestHeaders)
	if err := validateRequestHeaders(cfg.Route.RequestHeaders); err != nil {
		return nil, err
	}
	if len(cfg.Route.RequestHeaders) > 0 && !tlsEnabled(cfg.Common) {
		return nil, errors.New("build FRP session factory: runtime request headers require encrypted FRP transport")
	}
	if len(cfg.Route.RequestHeaders) > 0 && cfg.Common.WebServer.Port > 0 {
		return nil, errors.New("build FRP session factory: runtime request headers require FRP web server to be disabled")
	}
	if cfg.ReadyPoll <= 0 {
		cfg.ReadyPoll = 100 * time.Millisecond
	}
	return &FRPSessionFactory{cfg: cfg}, nil
}

// BuildConfig renders one overlap-safe cycle. Proxy Name changes with the NHP
// SessionID, while group, group key, subdomain, public resource metadata, and
// local target remain stable. Returned configs are mutable, but Start is the
// supported execution path; callers must not re-enable FRP web/admin on a
// returned common config when request headers exist.
func (f *FRPSessionFactory) BuildConfig(admission Admission) (*v1.ClientCommonConfig, []v1.ProxyConfigurer, []string, error) {
	if err := validateAdmission(admission, admission.KnockResourceID, f.cfg.Route.ResourceID); err != nil {
		return nil, nil, nil, err
	}
	common := cloneCommon(f.cfg.Common)
	if len(f.cfg.Route.RequestHeaders) > 0 && !tlsEnabled(common) {
		return nil, nil, nil, errors.New("render FRP session config: runtime request headers require encrypted FRP transport")
	}
	// cloneCommon copies the TLS enablement pointee, and WebServer.Port is
	// value-typed, so these checks bind to the exact common config returned for
	// the FRP session.
	if len(f.cfg.Route.RequestHeaders) > 0 && common.WebServer.Port > 0 {
		return nil, nil, nil, errors.New("render FRP session config: runtime request headers require FRP web server to be disabled")
	}
	host, port, err := parseAdmittedResourceHost(admission.ResourceHost)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse admitted FRP host: %w", err)
	}
	if tlsEnabled(common) && common.Transport.TLS.ServerName == "" && ipLiteralHost(host) {
		return nil, nil, nil, errors.New("parse admitted FRP host: IP-literal target requires an explicit TLS server name")
	}
	common.ServerAddr = host
	common.ServerPort = port
	if common.Metadatas == nil {
		common.Metadatas = map[string]string{}
	}
	common.Metadatas[nhpconfig.MetaQURLKnockToken] = admission.Token
	if f.cfg.ClientVersion != "" {
		common.Metadatas[nhpconfig.MetaClientVersion] = f.cfg.ClientVersion
	}
	failFast := true
	common.LoginFailExit = &failFast

	proxyName := nhpconfig.FRPProxyName(f.cfg.Route.RouteID, "nhp"+strconv.FormatUint(admission.SessionID, 36))
	proxy := &v1.HTTPProxyConfig{}
	proxy.Name = proxyName
	proxy.Type = string(v1.ProxyTypeHTTP)
	proxy.LocalIP = f.cfg.Route.LocalIP
	proxy.LocalPort = f.cfg.Route.LocalPort
	proxy.SubDomain = f.cfg.Route.ConnectorRoutingID
	proxy.LoadBalancer.Group = f.cfg.Route.ConnectorRoutingID
	proxy.LoadBalancer.GroupKey = f.cfg.Route.ConnectorRoutingID
	proxy.Metadatas = map[string]string{nhpconfig.MetaResourceID: f.cfg.Route.ResourceID}
	proxy.RequestHeaders.Set = cloneRequestHeaders(f.cfg.Route.RequestHeaders)
	return common, []v1.ProxyConfigurer{proxy}, []string{proxyName}, nil
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
	if in.Transport.TLS.Enable != nil {
		enabled := *in.Transport.TLS.Enable
		out.Transport.TLS.Enable = &enabled
	}
	if in.Metadatas != nil {
		out.Metadatas = make(map[string]string, len(in.Metadatas))
		for key, value := range in.Metadatas {
			out.Metadatas[key] = value
		}
	}
	return &out
}

func cloneRequestHeaders(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for name, value := range in {
		out[name] = value
	}
	return out
}

func validateRequestHeaders(headers map[string]string) error {
	if len(headers) > maxRuntimeRequestHeaderCount {
		return errors.New("build FRP session factory: request headers exceed runtime limits")
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	aggregateBytes := 0
	for _, name := range names {
		if len(name) > maxRuntimeRequestHeaderBytes-aggregateBytes {
			return errors.New("build FRP session factory: request headers exceed runtime limits")
		}
		aggregateBytes += len(name)
		if len(headers[name]) > maxRuntimeRequestHeaderBytes-aggregateBytes {
			return errors.New("build FRP session factory: request headers exceed runtime limits")
		}
		aggregateBytes += len(headers[name])
	}

	seen := make(map[string]struct{}, len(headers))
	for _, name := range names {
		value := headers[name]
		if !validHTTPHeaderName(name) {
			return errors.New("build FRP session factory: request header name is invalid")
		}
		canonicalName := strings.ToLower(name)
		if reservedRequestHeaderName(canonicalName) {
			return errors.New("build FRP session factory: request header name is reserved")
		}
		if _, ok := seen[canonicalName]; ok {
			return errors.New("build FRP session factory: request header names are duplicated")
		}
		seen[canonicalName] = struct{}{}
		if !validHTTPHeaderValue(value) {
			return errors.New("build FRP session factory: request header value is invalid")
		}
	}
	return nil
}

func reservedRequestHeaderName(canonicalName string) bool {
	switch canonicalName {
	case "host",
		"content-length",
		"connection",
		"proxy-connection",
		"keep-alive",
		"proxy-authenticate",
		"proxy-authorization",
		"te",
		"trailer",
		"transfer-encoding",
		"upgrade",
		"forwarded",
		"x-forwarded-for",
		"x-forwarded-host",
		"x-forwarded-proto",
		"x-real-ip",
		"x-forwarded-port":
		return true
	default:
		return false
	}
}

func validHTTPHeaderName(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		switch c := value[i]; {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)):
		default:
			return false
		}
	}
	return true
}

// validHTTPHeaderValue matches Go's HTTP transport rule by rejecting control
// bytes other than horizontal tab.
func validHTTPHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c != '\t' && (c < ' ' || c == 0x7f) {
			return false
		}
	}
	return true
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
