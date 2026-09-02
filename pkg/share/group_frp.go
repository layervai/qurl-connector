package share

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	frpclient "github.com/fatedier/frp/client"
	frpproxy "github.com/fatedier/frp/client/proxy"
	frpconfig "github.com/fatedier/frp/pkg/config"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/policy/security"

	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

// MaxGroupRoutes bounds one session group. Every route is one FRP proxy on
// the group's single control session, so the bound caps the proxy set one
// admission may carry, not the number of admissions.
const MaxGroupRoutes = 2000

// ErrRouteNotServing reports a route that stayed configured but did not reach
// FRP's running phase on a replacement session before the prior admission
// expired. The route remains in the group and inside FRP's same-session
// NewProxy retry; it is not permanently unavailable like ErrResourceGone.
var ErrRouteNotServing = errors.New("qURL share route is not serving")

var errGroupSessionEnded = errors.New("FRP session group has ended")

// GroupRoute is one route of a session group. Generation is the route's
// restart generation: it is folded into the FRP proxy name, so a restarted
// route registers as a fresh proxy (a new NewProxy on the server) on the same
// admission without disturbing its siblings. Generation 0 renders exactly the
// single-route proxy name.
type GroupRoute struct {
	LocalHTTPRoute
	Generation uint64
}

// RoutePhase is the observed serving state of one route on one session.
type RoutePhase string

const (
	// RoutePending means the proxy is configured but has not reached FRP's
	// running phase; Err carries the last transient start error, if any.
	RoutePending RoutePhase = "pending"
	// RouteServing means NewProxy was admitted and the proxy is running.
	RouteServing RoutePhase = "serving"
	// RouteFailed is terminal for this proxy registration: Err wraps
	// ErrResourceGone and the proxy has been withdrawn from the session.
	RouteFailed RoutePhase = "failed"
)

// RouteState is one route's exact registration on one session.
type RouteState struct {
	Route     GroupRoute
	ProxyName string
	Phase     RoutePhase
	Err       error
}

// GroupServingSession is one FRP control session that carries many proxies
// under one Admission. Ready closes once every route that is not permanently
// failed is running (and at least one is); later additions never reopen it,
// so callers that add routes must consult RouteStates. Update replaces the
// proxy set on the live session: unchanged proxies keep serving, removed
// proxies are withdrawn, added or regenerated proxies register.
//
// The server admits NewProxy only while the Login's knock token is inside its
// admission window, so a route may be added to a session only within the
// admission's OpenTime of the knock; SessionGroupRunner enforces this by
// never adding to a session that is already being replaced.
//
// A resource_not_found rejection is that route's failure only (RouteFailed
// with ErrResourceGone) and never ends the session. A knock_invalid,
// owner_missing, or session_stale rejection invalidates the admission every
// proxy shares and therefore ends the whole session with ErrAdmissionStale.
type GroupServingSession interface {
	ServingSession
	Update(context.Context, []GroupRoute) error
	RouteStates() map[string]RouteState
	// Changes is signaled (coalesced) whenever any route state changes or the
	// session ends. Read RouteStates after each signal.
	Changes() <-chan struct{}
}

// SessionGroupFactory starts one FRP session carrying every given route from
// one immutable admission. The same contract as SessionFactory applies to the
// Login half; each proxy stamps its own route's public resource ID.
type SessionGroupFactory interface {
	Start(context.Context, Admission, []GroupRoute) (GroupServingSession, error)
}

// ValidateGroupRoutes checks the bound and the route identity uniqueness one
// session group requires: route ID, public resource ID, and connector routing
// ID must each be unique within the group, and every local target must be
// dialable.
func ValidateGroupRoutes(routes []LocalHTTPRoute) error {
	return validateGroupRouteIdentities(len(routes), func(i int) LocalHTTPRoute { return routes[i] })
}

func validateGroupRouteSet(routes []GroupRoute) error {
	return validateGroupRouteIdentities(len(routes), func(i int) LocalHTTPRoute { return routes[i].LocalHTTPRoute })
}

func validateGroupRouteIdentities(count int, at func(int) LocalHTTPRoute) error {
	if count == 0 {
		return errors.New("session group has no routes")
	}
	if count > MaxGroupRoutes {
		return fmt.Errorf("session group has %d routes; one admission carries at most %d", count, MaxGroupRoutes)
	}
	routeIDs := make(map[string]int, count)
	resourceIDs := make(map[string]int, count)
	routingIDs := make(map[string]int, count)
	for i := range count {
		route := at(i)
		if err := validateLocalHTTPRoute(route); err != nil {
			return fmt.Errorf("routes[%d] (%s): %w", i, route.RouteID, err)
		}
		if first, ok := routeIDs[route.RouteID]; ok {
			return fmt.Errorf("routes[%d]: route ID %q is already used by routes[%d]", i, route.RouteID, first)
		}
		if first, ok := resourceIDs[route.ResourceID]; ok {
			return fmt.Errorf("routes[%d] (%s): resource ID %q is already used by routes[%d]", i, route.RouteID, route.ResourceID, first)
		}
		if first, ok := routingIDs[route.ConnectorRoutingID]; ok {
			return fmt.Errorf("routes[%d] (%s): connector routing ID %q is already used by routes[%d]", i, route.RouteID, route.ConnectorRoutingID, first)
		}
		routeIDs[route.RouteID] = i
		resourceIDs[route.ResourceID] = i
		routingIDs[route.ConnectorRoutingID] = i
	}
	return nil
}

// groupProxyName renders the proxy name for one route generation on one
// admission. Generation 0 is the single-route name; later generations append
// a hyphen-separated restart suffix so a restarted route and any other cycle
// can never collide.
func groupProxyName(route GroupRoute, sessionID uint64) string {
	discriminator := sessionProxyDiscriminator(sessionID)
	if route.Generation > 0 {
		discriminator += "-r" + strconv.FormatUint(route.Generation, 36)
	}
	return nhpconfig.FRPProxyName(route.RouteID, discriminator)
}

// FRPGroupFactoryConfig configures FRPSessionGroupFactory. Routes are not part
// of the factory: SessionGroupRunner owns the route set and passes it to
// Start and Update.
type FRPGroupFactoryConfig struct {
	Common        *v1.ClientCommonConfig
	ClientVersion string
	ConfigPath    string
	ReadyPoll     time.Duration
}

// FRPSessionGroupFactory builds one FRP control session carrying N HTTP
// proxies per admission. Login carries the group's knock token once; each
// proxy carries its own route's public resource ID, subdomain, and
// load-balancer group exactly as the single-route factory renders them.
type FRPSessionGroupFactory struct {
	cfg FRPGroupFactoryConfig
}

func NewFRPSessionGroupFactory(cfg FRPGroupFactoryConfig) (*FRPSessionGroupFactory, error) {
	if cfg.Common == nil {
		return nil, errors.New("build FRP session group factory: common config is nil")
	}
	if cfg.ReadyPoll <= 0 {
		cfg.ReadyPoll = 100 * time.Millisecond
	}
	return &FRPSessionGroupFactory{cfg: cfg}, nil
}

// BuildConfig renders one admission's Login config plus one proxy per route.
// Proxy names change with the NHP SessionID and the route generation; every
// other per-route identity is stable across cycles.
func (f *FRPSessionGroupFactory) BuildConfig(admission Admission, routes []GroupRoute) (*v1.ClientCommonConfig, []v1.ProxyConfigurer, []string, error) {
	if err := validateAdmission(admission, admission.KnockResourceID, admission.ResourceID); err != nil {
		return nil, nil, nil, err
	}
	if err := validateGroupRouteSet(routes); err != nil {
		return nil, nil, nil, err
	}
	common, err := buildAdmittedCommon(f.cfg.Common, admission, f.cfg.ClientVersion)
	if err != nil {
		return nil, nil, nil, err
	}
	proxies, names, err := renderGroupProxies(routes, admission.SessionID)
	if err != nil {
		return nil, nil, nil, err
	}
	return common, proxies, names, nil
}

func renderGroupProxies(routes []GroupRoute, sessionID uint64) ([]v1.ProxyConfigurer, []string, error) {
	proxies := make([]v1.ProxyConfigurer, 0, len(routes))
	names := make([]string, 0, len(routes))
	seen := make(map[string]string, len(routes))
	for _, route := range routes {
		name := groupProxyName(route, sessionID)
		if other, ok := seen[name]; ok {
			return nil, nil, fmt.Errorf("routes %q and %q render the same proxy name %q", other, route.RouteID, name)
		}
		seen[name] = route.RouteID
		proxies = append(proxies, buildRouteProxy(route.LocalHTTPRoute, name))
		names = append(names, name)
	}
	return proxies, names, nil
}

// completeGroupProxies applies exactly the filtering and defaulting FRP's
// service applies to its initial proxy set. UpdateAllConfigurer diffs live
// proxies against the new set with reflect.DeepEqual, so an incomplete config
// would restart every unchanged proxy on each hot update.
func completeGroupProxies(common *v1.ClientCommonConfig, proxies []v1.ProxyConfigurer) []v1.ProxyConfigurer {
	filtered, _ := frpconfig.FilterClientConfigurers(common, proxies, nil)
	return frpconfig.CompleteProxyConfigurers(filtered)
}

func (f *FRPSessionGroupFactory) Start(ctx context.Context, admission Admission, routes []GroupRoute) (GroupServingSession, error) {
	if ctx == nil {
		return nil, errors.New("start FRP session group: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	common, proxies, _, err := f.BuildConfig(admission, routes)
	if err != nil {
		return nil, err
	}
	cfgSource := source.NewConfigSource()
	if err := cfgSource.ReplaceAll(completeGroupProxies(common, proxies), nil); err != nil {
		return nil, fmt.Errorf("set FRP proxy configs: %w", err)
	}
	session := newFRPGroupSession(nil, nil, common, admission.SessionID, f.cfg.ReadyPoll, routes)
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
	// As with the single-route factory, the caller's context bounds Start
	// only; the session owns its serving lifetime until Stop or Drain.
	runCtx, cancel := context.WithCancel(context.Background())
	session.cancel = cancel
	go session.run(runCtx)
	return session, nil
}

// frpGroupService is the live-update surface of the pinned FRP fork's client
// service. UpdateAllConfigurer diffs by proxy name and config and starts or
// stops only what changed.
type frpGroupService interface {
	frpService
	UpdateAllConfigurer([]v1.ProxyConfigurer, []v1.VisitorConfigurer) error
}

type groupRouteEntry struct {
	route GroupRoute
	name  string
	phase RoutePhase
	err   error
}

type frpGroupSession struct {
	svc       frpGroupService
	status    frpclient.StatusExporter
	common    *v1.ClientCommonConfig
	sessionID uint64
	poll      time.Duration
	ready     chan struct{}
	done      chan struct{}
	changes   chan struct{}
	cancel    context.CancelFunc

	// updateMu serializes proxy-set pushes to FRP so the service always
	// receives them in the same order the route table changed.
	updateMu sync.Mutex
	mu       sync.Mutex
	routes   map[string]*groupRouteEntry
	err      error
	stopped  bool

	stopOnce  sync.Once
	readyOnce sync.Once
}

func newFRPGroupSession(svc frpGroupService, status frpclient.StatusExporter, common *v1.ClientCommonConfig,
	sessionID uint64, poll time.Duration, routes []GroupRoute,
) *frpGroupSession {
	session := &frpGroupSession{
		svc: svc, status: status, common: common, sessionID: sessionID, poll: poll,
		ready: make(chan struct{}), done: make(chan struct{}), changes: make(chan struct{}, 1),
		routes: make(map[string]*groupRouteEntry, len(routes)),
	}
	for _, route := range routes {
		session.routes[route.RouteID] = &groupRouteEntry{route: route, name: groupProxyName(route, sessionID), phase: RoutePending}
	}
	return session
}

func (s *frpGroupSession) run(ctx context.Context) {
	defer s.cancel()
	go s.watch(ctx)
	err := s.svc.Run(ctx)
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.stopped = true
	for _, entry := range s.routes {
		if entry.phase == RouteServing {
			entry.phase, entry.err = RoutePending, errGroupSessionEnded
		}
	}
	s.mu.Unlock()
	close(s.done)
	s.notify()
}

func (s *frpGroupSession) watch(ctx context.Context) {
	ticker := time.NewTicker(s.poll)
	defer ticker.Stop()
	for {
		withdrawn, terminalErr := s.observe()
		if terminalErr != nil {
			s.fail(terminalErr)
			return
		}
		if withdrawn {
			s.pushLiveProxies()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// observe folds FRP's per-proxy status into route phases. It reports whether
// a route was newly withdrawn (permanently failed) and any admission-level
// rejection that must end the whole session.
func (s *frpGroupSession) observe() (withdrawn bool, terminalErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status == nil {
		return false, nil
	}
	changed := false
	live, serving := 0, 0
	for routeID, entry := range s.routes {
		if entry.phase == RouteFailed {
			continue
		}
		phase, err, terminal := inspectRouteStatus(s.status, entry.name)
		if terminal != nil {
			return false, fmt.Errorf("route %q: %w", routeID, terminal)
		}
		if phase == RouteFailed {
			withdrawn = true
		} else {
			live++
			if phase == RouteServing {
				serving++
			}
		}
		if entry.phase != phase || errText(entry.err) != errText(err) {
			entry.phase, entry.err = phase, err
			changed = true
		}
	}
	if live > 0 && serving == live {
		s.readyOnce.Do(func() { close(s.ready) })
	}
	if changed {
		s.notify()
	}
	return withdrawn, nil
}

// inspectRouteStatus classifies one proxy's FRP status. Admission-level
// rejection tags come back as terminalErr; resource_not_found is the route's
// own permanent failure (routeErr); every other state stays pending inside
// FRP's same-session retry, with the last transient start error in routeErr.
func inspectRouteStatus(status frpclient.StatusExporter, name string) (phase RoutePhase, routeErr, terminalErr error) {
	item, ok := status.GetProxyStatus(name)
	if !ok || item == nil {
		return RoutePending, nil, nil
	}
	switch item.Phase {
	case frpproxy.ProxyPhaseRunning:
		return RouteServing, nil, nil
	case frpproxy.ProxyPhaseStartErr:
		switch proxyStartErrorTag(item.Err) {
		case "knock_invalid", "owner_missing", "session_stale":
			return RoutePending, nil, fmt.Errorf("%w: %s", ErrAdmissionStale, item.Err)
		case "resource_not_found":
			return RouteFailed, fmt.Errorf("%w: %s", ErrResourceGone, item.Err), nil
		}
		return RoutePending, errors.New(item.Err), nil
	default:
		return RoutePending, nil, nil
	}
}

func sortGroupRoutes(routes []GroupRoute) {
	sort.Slice(routes, func(i, j int) bool { return routes[i].RouteID < routes[j].RouteID })
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Update replaces the session's route set. Entries whose route and proxy name
// are unchanged keep their observed state; everything else registers afresh.
func (s *frpGroupSession) Update(ctx context.Context, routes []GroupRoute) error {
	if ctx == nil {
		return errors.New("update FRP session group: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// An empty set is legal on a live session: a runner withdraws every
	// proxy from a session it is about to retire while the replacement
	// carries the new ones.
	if len(routes) > 0 {
		if err := validateGroupRouteSet(routes); err != nil {
			return err
		}
	}
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return errGroupSessionEnded
	}
	next := make(map[string]*groupRouteEntry, len(routes))
	for _, route := range routes {
		name := groupProxyName(route, s.sessionID)
		if current, ok := s.routes[route.RouteID]; ok && current.name == name && current.route == route {
			next[route.RouteID] = current
			continue
		}
		next[route.RouteID] = &groupRouteEntry{route: route, name: name, phase: RoutePending}
	}
	s.routes = next
	proxies, err := s.liveProxiesLocked()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	s.notify()
	return s.svc.UpdateAllConfigurer(proxies, nil)
}

// pushLiveProxies withdraws permanently failed proxies from FRP so the
// service stops re-sending a NewProxy the server will keep rejecting.
func (s *frpGroupSession) pushLiveProxies() {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	proxies, err := s.liveProxiesLocked()
	s.mu.Unlock()
	if err != nil {
		return
	}
	_ = s.svc.UpdateAllConfigurer(proxies, nil)
}

func (s *frpGroupSession) liveProxiesLocked() ([]v1.ProxyConfigurer, error) {
	live := make([]GroupRoute, 0, len(s.routes))
	for _, entry := range s.routes {
		if entry.phase != RouteFailed {
			live = append(live, entry.route)
		}
	}
	sortGroupRoutes(live)
	proxies, _, err := renderGroupProxies(live, s.sessionID)
	if err != nil {
		return nil, err
	}
	return completeGroupProxies(s.common, proxies), nil
}

func (s *frpGroupSession) RouteStates() map[string]RouteState {
	s.mu.Lock()
	defer s.mu.Unlock()
	states := make(map[string]RouteState, len(s.routes))
	for routeID, entry := range s.routes {
		states[routeID] = RouteState{Route: entry.route, ProxyName: entry.name, Phase: entry.phase, Err: entry.err}
	}
	return states
}

func (s *frpGroupSession) Changes() <-chan struct{} { return s.changes }

func (s *frpGroupSession) notify() {
	select {
	case s.changes <- struct{}{}:
	default:
	}
}

func (s *frpGroupSession) fail(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
	s.cancel()
}

func (s *frpGroupSession) Ready() <-chan struct{} { return s.ready }
func (s *frpGroupSession) Done() <-chan struct{}  { return s.done }
func (s *frpGroupSession) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *frpGroupSession) Stop(ctx context.Context) error {
	return s.shutdown(ctx, 0)
}

// Drain preserves requests already assigned to the old proxies while removing
// them from new routing after a replacement becomes serving.
func (s *frpGroupSession) Drain(ctx context.Context) error {
	return s.shutdown(ctx, 4*time.Second)
}

func (s *frpGroupSession) shutdown(ctx context.Context, grace time.Duration) error {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.stopped = true
		s.mu.Unlock()
		// GracefulClose records the drain interval before it cancels FRP's
		// internal service context; see frpServingSession.shutdown.
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
