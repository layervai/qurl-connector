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
// admission may carry, not the number of admissions. At the bound the
// rotation lead needs 2000 × 50ms = 100s, which fits only when the admission
// OpenTime is at least 200s; a shorter window reports OnRotationLeadCapped on
// every admission and may promote a replacement before every route has
// re-registered.
const MaxGroupRoutes = 2000

// ErrRouteNotServing reports a route that stayed configured but did not reach
// FRP's running phase on a replacement session before the prior admission
// expired. The route remains in the group and inside FRP's same-session
// NewProxy retry; it is not permanently unavailable like ErrResourceGone.
var ErrRouteNotServing = errors.New("qURL share route is not serving")

// maxPushRetryDelay caps the backoff between retries of a failed proxy-set
// push; the first retry waits one poll interval.
const maxPushRetryDelay = 5 * time.Second

// ErrSessionGroupEnded is returned by GroupServingSession.Update once the
// session has stopped. SessionGroupRunner treats it as benign: the desired
// set is authoritative and the next cycle starts from it.
var ErrSessionGroupEnded = errors.New("FRP session group has ended")

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
// so callers that add routes must consult RouteStates. SessionGroupRunner
// itself never reads Ready: it drives entirely off Changes and RouteStates,
// and Ready exists for simple single-shot callers. Update replaces the proxy
// set on the live session: unchanged proxies keep serving, removed proxies
// are withdrawn, added or regenerated proxies register.
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
// can never collide. FRPProxyName caps the discriminator at
// replica.MaxDiscriminatorLen; a session ID wide enough to fill it renders a
// restart generation as a short prefix plus a digest of the full
// discriminator, which stays unique but is no longer readable in server logs.
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
	// The group owns its proxy set; a Login-level start filter would drop
	// routes on the floor as permanently pending.
	if len(cfg.Common.Start) > 0 {
		return nil, errors.New("build FRP session group factory: common config must not set a proxy start filter")
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
// would restart every unchanged proxy on each hot update. A proxy the filter
// would drop is an error rather than a silently pending route.
func completeGroupProxies(common *v1.ClientCommonConfig, proxies []v1.ProxyConfigurer) ([]v1.ProxyConfigurer, error) {
	filtered, _ := frpconfig.FilterClientConfigurers(common, proxies, nil)
	if len(filtered) != len(proxies) {
		kept := make(map[string]struct{}, len(filtered))
		for _, proxy := range filtered {
			kept[proxy.GetBaseConfig().Name] = struct{}{}
		}
		var dropped []string
		for _, proxy := range proxies {
			if _, ok := kept[proxy.GetBaseConfig().Name]; !ok {
				dropped = append(dropped, proxy.GetBaseConfig().Name)
			}
		}
		return nil, fmt.Errorf("FRP client config filters out proxies %q", dropped)
	}
	return frpconfig.CompleteProxyConfigurers(filtered), nil
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
	completed, err := completeGroupProxies(common, proxies)
	if err != nil {
		return nil, err
	}
	cfgSource := source.NewConfigSource()
	if err := cfgSource.ReplaceAll(completed, nil); err != nil {
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
	// version counts route-table changes; pushed is the version FRP has
	// accepted. They differ while a push is owed or has failed, and watch
	// retries every tick until they meet.
	version uint64
	pushed  uint64
	// pushErr is the last failed push while one is still owed; RouteStates
	// surfaces it on every pending route so a stuck push is distinguishable
	// from a proxy FRP simply has not registered yet. pushFailures and
	// nextPushAt back the watch retry off exponentially (from one poll up to
	// maxPushRetryDelay) so a wedged service is not re-pushed 2000 proxies
	// at every tick.
	pushErr      error
	pushFailures int
	nextPushAt   time.Time
	err          error
	stopped      bool

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
			entry.phase, entry.err = RoutePending, ErrSessionGroupEnded
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
		terminalErr := s.observe()
		if terminalErr != nil {
			s.fail(terminalErr)
			return
		}
		if s.pushDue() {
			_ = s.push()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type routeObservation struct {
	routeID string
	name    string
	phase   RoutePhase
	err     error
}

// observe folds FRP's per-proxy status into route phases. A route that
// permanently failed is withdrawn from the proxy set (the table version
// advances so watch pushes the smaller set); an admission-level rejection is
// returned and ends the whole session. The status exporter is queried
// outside the table lock so a 2000-route scan never blocks Update or
// RouteStates; an entry replaced meanwhile is simply skipped this tick.
func (s *frpGroupSession) observe() error {
	if s.status == nil {
		return nil
	}
	s.mu.Lock()
	observations := make([]routeObservation, 0, len(s.routes))
	for routeID, entry := range s.routes {
		if entry.phase != RouteFailed {
			observations = append(observations, routeObservation{routeID: routeID, name: entry.name})
		}
	}
	s.mu.Unlock()
	for i := range observations {
		phase, err, terminal := inspectRouteStatus(s.status, observations[i].name)
		if terminal != nil {
			return fmt.Errorf("route %q: %w", observations[i].routeID, terminal)
		}
		observations[i].phase, observations[i].err = phase, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for _, observed := range observations {
		entry, ok := s.routes[observed.routeID]
		if !ok || entry.name != observed.name || entry.phase == RouteFailed {
			continue
		}
		if observed.phase == RouteFailed {
			s.version++
		}
		if entry.phase != observed.phase || errText(entry.err) != errText(observed.err) {
			entry.phase, entry.err = observed.phase, observed.err
			changed = true
		}
	}
	live, serving := 0, 0
	for _, entry := range s.routes {
		if entry.phase == RouteFailed {
			continue
		}
		live++
		if entry.phase == RouteServing {
			serving++
		}
	}
	if live > 0 && serving == live {
		s.readyOnce.Do(func() { close(s.ready) })
	}
	if changed {
		s.notify()
	}
	return nil
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
// The route table is authoritative from the moment Update returns: if the
// push to FRP fails, the error is returned and the session keeps retrying the
// push on every poll until FRP accepts it, so RouteStates never reports a
// route as serving that FRP has not registered.
//
// On the pinned FRP fork (github.com/layervai/frp, see go.mod), a push before
// the first Login is stored and becomes the Login's proxy set, every re-Login
// after a control loss re-registers the most recently pushed set, and the
// client never re-applies its startup snapshot on its own; hot changes
// therefore survive reconnects.
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
		return ErrSessionGroupEnded
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
	s.version++
	s.mu.Unlock()
	s.notify()
	return s.pushUnderUpdateMu()
}

// pushOwed reports whether FRP has not yet accepted the current table.
func (s *frpGroupSession) pushOwed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.stopped && s.pushed != s.version
}

// pushDue is pushOwed gated by the retry backoff after a failed push.
func (s *frpGroupSession) pushDue() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.stopped && s.pushed != s.version && !time.Now().Before(s.nextPushAt)
}

// push hands the live proxy set to FRP. It withdraws permanently failed
// proxies so the service stops re-sending a NewProxy the server will keep
// rejecting, and it is retried by watch until FRP accepts the current table.
func (s *frpGroupSession) push() error {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	return s.pushUnderUpdateMu()
}

// pushUnderUpdateMu is the push body; the caller holds updateMu (not mu),
// which is what keeps successive pushes in table order. The table is
// snapshotted under mu and rendered after it is released, so a 2000-route
// render never blocks observe or RouteStates; the version snapshot is what
// the retry protocol keys on.
func (s *frpGroupSession) pushUnderUpdateMu() error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return ErrSessionGroupEnded
	}
	version := s.version
	live := s.liveRoutesLocked()
	s.mu.Unlock()
	proxies, err := s.renderLiveProxies(live)
	if err != nil {
		return s.recordPushFailure(fmt.Errorf("render FRP proxy set: %w", err))
	}
	if err := s.svc.UpdateAllConfigurer(proxies, nil); err != nil {
		return s.recordPushFailure(fmt.Errorf("update FRP proxy set: %w", err))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pushed < version {
		s.pushed = version
	}
	s.pushFailures, s.nextPushAt = 0, time.Time{}
	// FRP accepted a set; a still-owed newer version reports its own failure
	// if it has one, so the old failure must not linger on pending routes.
	if s.pushErr != nil {
		s.pushErr = nil
		s.notify()
	}
	return nil
}

func (s *frpGroupSession) recordPushFailure(err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pushErr = err
	s.pushFailures++
	delay := s.poll
	for i := 1; i < s.pushFailures && delay < maxPushRetryDelay; i++ {
		delay *= 2
	}
	if delay > maxPushRetryDelay {
		delay = maxPushRetryDelay
	}
	s.nextPushAt = time.Now().Add(delay)
	s.notify()
	return err
}

func (s *frpGroupSession) liveRoutesLocked() []GroupRoute {
	live := make([]GroupRoute, 0, len(s.routes))
	for _, entry := range s.routes {
		if entry.phase != RouteFailed {
			live = append(live, entry.route)
		}
	}
	sortGroupRoutes(live)
	return live
}

func (s *frpGroupSession) renderLiveProxies(live []GroupRoute) ([]v1.ProxyConfigurer, error) {
	proxies, _, err := renderGroupProxies(live, s.sessionID)
	if err != nil {
		return nil, err
	}
	return completeGroupProxies(s.common, proxies)
}

// ServingRouteIDs returns only the routes in FRP's running phase; the runner
// prefers it over RouteStates for the promotion gate during rotation.
func (s *frpGroupSession) ServingRouteIDs() map[string]struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	serving := make(map[string]struct{})
	for routeID, entry := range s.routes {
		if entry.phase == RouteServing {
			serving[routeID] = struct{}{}
		}
	}
	return serving
}

// RouteStates reports every route's registration. While a push to FRP is
// owed and the last attempt failed, pending routes without a more specific
// start error carry that push error.
func (s *frpGroupSession) RouteStates() map[string]RouteState {
	s.mu.Lock()
	defer s.mu.Unlock()
	var pushErr error
	if s.pushed != s.version {
		pushErr = s.pushErr
	}
	states := make(map[string]RouteState, len(s.routes))
	for routeID, entry := range s.routes {
		state := RouteState{Route: entry.route, ProxyName: entry.name, Phase: entry.phase, Err: entry.err}
		if state.Phase == RoutePending && state.Err == nil {
			state.Err = pushErr
		}
		states[routeID] = state
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
