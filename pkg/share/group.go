package share

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ErrGroupEmpty ends Run once every route has been withdrawn as permanently
// unavailable (ErrResourceGone). There is nothing left to admit, so the
// runner retires its admission and returns instead of knocking for an empty
// proxy set; start a new group once routes exist again.
var ErrGroupEmpty = errors.New("qURL share session group has no routes left")

// SessionGroupConfig configures one SessionGroupRunner.
//
// KnockResourceID and ResourceID identify the single NHP admission the whole
// group shares: every Connector route is protected by the same knock resource,
// so one knock legitimately authorizes every proxy, and the durable
// session-operation journal records one operation per admission (the group),
// never one per route. ResourceID is the protected resource identity bound to
// that admission; each route's own public ResourceID travels in its proxy's
// FRP metadata.
type SessionGroupConfig struct {
	KnockResourceID string
	ResourceID      string
	Routes          []LocalHTTPRoute
	Admitter        Admitter
	Sessions        SessionGroupFactory

	MinBackoff time.Duration
	MaxBackoff time.Duration
	// RotationLead is a floor on the replacement lead; see groupRotationLead
	// for how the lead grows with the route count.
	RotationLead time.Duration
	StopTimeout  time.Duration

	// OnServing reports each promoted admission: the first cycle once any
	// route serves, and each replacement once it is promoted.
	OnServing func(Admission)
	// OnRouteServing reports a route reaching FRP's running phase on the
	// active session, once per proxy registration: again after every
	// promotion (with the new Admission) and after every RestartRoute.
	OnRouteServing func(routeID string, admission Admission)
	// OnRouteFailed reports ErrResourceGone when a route is withdrawn from
	// the group permanently, and ErrRouteNotServing when a route that the
	// retiring session served did not come up on its replacement before the
	// old admission expired (the route stays in the group and keeps retrying).
	// A whole-session loss is not reported per route; the group re-admits and
	// OnRouteServing fires again for every route.
	OnRouteFailed func(routeID string, err error)
	// OnRetry has the same contract as ResourceConfig.OnRetry.
	OnRetry func(error, time.Duration)
	// OnRotationLeadCapped reports, once per route count per admission,
	// that the admission window is too short for the lead the route count
	// needs: the replacement gets only lead (half the window) instead of
	// need, so a rotation may promote before every route re-registers.
	OnRotationLeadCapped func(routes int, need, lead time.Duration)
}

// SessionGroupRunner serves many routes on one NHP admission and one FRP
// control session. Compared with one ResourceRunner per route, a group costs
// one knock, one Login, and one heartbeat stream for the whole set; only the
// per-proxy NewProxy authorizations scale with the route count.
//
// Renewal is make-before-break exactly as in ResourceRunner: the replacement
// admission and session are built while the old one keeps serving, and the
// old session is drained only after every route the old session was serving
// is running on the replacement (or, if some never come up, at the old
// admission's expiry, keeping the routes that did and reporting the rest).
//
// The server admits a NewProxy only while the Login's knock token is inside
// its admission window, so routes can join a session only within OpenTime of
// its knock. SetRoutes therefore adds routes to the active session while it
// is current, and only withdraws from a session that is already being
// replaced; additions during a rotation land on the replacement.
type SessionGroupRunner struct {
	cfg SessionGroupConfig

	// applyMu serializes pushes of the desired set to live sessions so every
	// session observes route changes in the order they were made.
	applyMu sync.Mutex

	// wake nudges Run after a desired-set change so the rotation timer is
	// recomputed from the new route count.
	wake chan struct{}

	mu      sync.Mutex
	desired map[string]LocalHTTPRoute
	// divergent records that a caller's apply failed before the live
	// sessions saw the desired set; Run re-applies under its own context.
	divergent bool
	// restarts holds each route's generation for the runner's lifetime,
	// including routes that have left the group: a route that comes back
	// must register under a fresh proxy name, never the one a lingering
	// server-side registration may still hold. One small entry per distinct
	// route ID ever in the group is the bound.
	restarts map[string]uint64
	active   *groupCycle
	pending  *groupCycle
	rotating bool
	running  bool
	// reported maps route ID to the proxy name last reported serving on the
	// active cycle, so a promotion or restart re-reports while flaps do not.
	reported map[string]string
}

type groupCycle struct {
	admission Admission
	session   GroupServingSession
	expiresAt time.Time
	// capReported is the route count for which the lead cap was last
	// reported on this cycle; it is touched only by the Run goroutine.
	capReported int
}

func NewSessionGroupRunner(cfg SessionGroupConfig) (*SessionGroupRunner, error) {
	if cfg.KnockResourceID == "" {
		return nil, errors.New("build session group: knock resource ID is empty")
	}
	if cfg.ResourceID == "" {
		return nil, errors.New("build session group: protected resource ID is empty")
	}
	if cfg.Admitter == nil {
		return nil, errors.New("build session group: admitter is nil")
	}
	if cfg.Sessions == nil {
		return nil, errors.New("build session group: session factory is nil")
	}
	if err := ValidateGroupRoutes(cfg.Routes); err != nil {
		return nil, fmt.Errorf("build session group: %w", err)
	}
	if cfg.MinBackoff < 0 || cfg.MaxBackoff < 0 || cfg.RotationLead < 0 || cfg.StopTimeout < 0 {
		return nil, errors.New("build session group: durations cannot be negative")
	}
	if cfg.MinBackoff == 0 {
		cfg.MinBackoff = time.Second
	}
	if cfg.MaxBackoff == 0 {
		cfg.MaxBackoff = 30 * time.Second
	}
	if cfg.MaxBackoff < cfg.MinBackoff {
		return nil, errors.New("build session group: max backoff is below min backoff")
	}
	if cfg.StopTimeout == 0 {
		cfg.StopTimeout = 5 * time.Second
	}
	runner := &SessionGroupRunner{
		cfg:      cfg,
		desired:  make(map[string]LocalHTTPRoute, len(cfg.Routes)),
		restarts: make(map[string]uint64),
		reported: make(map[string]string),
		wake:     make(chan struct{}, 1),
	}
	for _, route := range cfg.Routes {
		runner.desired[route.RouteID] = route
	}
	runner.cfg.Routes = nil
	return runner, nil
}

// Rotation-lead scaling; variables so tests can shrink the time scale.
var (
	groupLeadFloor    = 30 * time.Second
	groupLeadPerRoute = 50 * time.Millisecond
)

// groupRotationLead is how long before the admission expires the replacement
// cycle starts. Registering N proxies on a fresh session is sequential on the
// server: every NewProxy is one authorization round trip plus registration,
// a few milliseconds each, after Login itself. The needed lead therefore
// grows at 50ms per route (50s for 1000 routes) above a 30s floor that covers
// the knock and Login; the configured lead is a floor, never a ceiling. The
// result is clamped to [1s, openTime/2] (or exactly openTime/2 when that is
// below 1s) so the old session still serves for at least half its lifetime.
// need is returned unclamped so a caller can see when the cap binds.
func groupRotationLead(openTime, configured time.Duration, routes int) (lead, need time.Duration) {
	need = max(configured, groupLeadFloor, time.Duration(routes)*groupLeadPerRoute)
	upper := openTime / 2
	lower := min(time.Second, upper)
	return min(max(need, lower), upper), need
}

// rotateAt is computed from the current route count every time Run arms
// its timer, so a group that grows inside an admission window rotates with
// the lead the larger set needs rather than the lead it was admitted with.
func (r *SessionGroupRunner) rotateAt(cycle *groupCycle) time.Time {
	routes := r.desiredCount()
	lead, need := groupRotationLead(cycle.admission.OpenTime, r.cfg.RotationLead, routes)
	if lead < need && cycle.capReported != routes && r.cfg.OnRotationLeadCapped != nil {
		cycle.capReported = routes
		r.cfg.OnRotationLeadCapped(routes, need, lead)
	}
	return cycle.expiresAt.Add(-lead)
}

// Run serves until ctx ends. Admission and connection failures retry forever
// with bounded jitter. Run returns early only when the group's protected
// resource is permanently gone (ErrResourceGone from admission), when every
// route has been withdrawn as permanently unavailable (ErrGroupEmpty), or
// when an exact retirement fails.
func (r *SessionGroupRunner) Run(ctx context.Context) (retErr error) {
	if ctx == nil {
		return errors.New("run session group: context is nil")
	}
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return errors.New("run session group: already running")
	}
	r.running = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.running = false
		r.mu.Unlock()
	}()

	var drains cycleDrainSet
	backoff := r.cfg.MinBackoff
	defer drains.stopAndWait(r.cfg.StopTimeout)
	defer func() { retErr = errors.Join(retErr, r.stopCycle(r.takeActive())) }()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		active := r.currentActive()
		if active == nil {
			cycle, err := r.startReadyCycle(ctx, nil)
			if err != nil {
				if errors.Is(err, ErrResourceGone) || errors.Is(err, ErrGroupEmpty) {
					return err
				}
				if retryErr := retryAfter(ctx, r.cfg.OnRetry, err, jitter(backoff)); retryErr != nil {
					return retryErr
				}
				backoff = nextBackoff(backoff, r.cfg.MaxBackoff)
				continue
			}
			backoff = r.cfg.MinBackoff
			r.promote(ctx, cycle)
			if r.desiredCount() == 0 {
				return ErrGroupEmpty
			}
			active = cycle
		}

		rotate := time.NewTimer(time.Until(r.rotateAt(active)))
		select {
		case <-ctx.Done():
			stopTimer(rotate)
			return ctx.Err()
		case <-r.wake:
			stopTimer(rotate)
			r.healDivergence(ctx)
		case <-active.session.Done():
			stopTimer(rotate)
			sessionErr := active.session.Err()
			r.takeActive()
			retireErr := r.stopCycle(active)
			if errors.Is(sessionErr, ErrResourceGone) || retireErr != nil {
				return errors.Join(sessionErr, retireErr)
			}
		case <-active.session.Changes():
			stopTimer(rotate)
			r.healDivergence(ctx)
			r.reportActive(ctx)
			if r.desiredCount() == 0 {
				return ErrGroupEmpty
			}
		case <-rotate.C:
			r.setRotating(true)
			replacement, err := r.startReadyCycle(ctx, active)
			if err != nil {
				if errors.Is(err, ErrResourceGone) || errors.Is(err, ErrGroupEmpty) {
					return err
				}
				// Keep the old serving session while a replacement is still
				// possible; the attempt is already bounded by the old
				// authorization deadline, and the group stays in rotation so
				// no route is added to the expiring session.
				if time.Now().Before(active.expiresAt) {
					continue
				}
				r.takeActive()
				r.setRotating(false)
				if retireErr := r.stopCycle(active); retireErr != nil {
					return errors.Join(err, retireErr)
				}
				continue
			}
			r.promote(ctx, replacement)
			drains.start(active.session, r.cfg.StopTimeout, func() { _ = r.retireAdmission(active.admission) })
			if r.desiredCount() == 0 {
				return ErrGroupEmpty
			}
		}
	}
}

// SetRoutes replaces the group's desired route set. Additions and removals
// apply to the live session immediately (no new admission); a replacement
// that is still being built receives the new set as well, and the rotation
// timer is re-armed for the new route count. A route that was removed and
// later re-added, or whose local target changed, registers under a fresh
// proxy name so the server sees a new NewProxy rather than the stale one; a
// route's public resource ID and connector routing ID are immutable
// identities and may not change in place (remove the route and add it
// again). A session that ends
// while the set is being applied is not an error: the desired set is
// authoritative and the next cycle starts from it, and if applying fails for
// any other reason (a canceled caller context, for instance) the error is
// returned and Run re-applies the desired set under its own context. An
// empty set is not expressible here: a group always has at least one route,
// and a group whose routes have all gone ends Run with ErrGroupEmpty.
func (r *SessionGroupRunner) SetRoutes(ctx context.Context, routes []LocalHTTPRoute) error {
	if ctx == nil {
		return errors.New("set session group routes: context is nil")
	}
	if err := ValidateGroupRoutes(routes); err != nil {
		return fmt.Errorf("set session group routes: %w", err)
	}
	r.mu.Lock()
	next := make(map[string]LocalHTTPRoute, len(routes))
	for _, route := range routes {
		next[route.RouteID] = route
		current, exists := r.desired[route.RouteID]
		if !exists || current == route {
			continue
		}
		if current.ResourceID != route.ResourceID || current.ConnectorRoutingID != route.ConnectorRoutingID {
			r.mu.Unlock()
			return fmt.Errorf("set session group routes: route %q changes its resource identity in place (resource %q to %q, routing %q to %q); remove the route and add it again",
				route.RouteID, current.ResourceID, route.ResourceID, current.ConnectorRoutingID, route.ConnectorRoutingID)
		}
	}
	for routeID, current := range r.desired {
		route, keep := next[routeID]
		if !keep || current != route {
			// Removed, or its local target changed: the next registration of
			// this route ID must not reuse a name the server still holds.
			r.restarts[routeID]++
		}
	}
	r.desired = next
	r.mu.Unlock()
	return r.applyAndWake(ctx)
}

// RestartRoute withdraws one route's proxy and registers it again under a new
// proxy name on the same admission, so the server sees a fresh NewProxy for
// that route alone. Siblings and the admission are untouched. While the group
// is rotating, the active session keeps its current registration (a rotating
// session never registers anything) and the restart lands on the replacement
// at promotion, at most one rotation lead later.
func (r *SessionGroupRunner) RestartRoute(ctx context.Context, routeID string) error {
	if ctx == nil {
		return errors.New("restart session group route: context is nil")
	}
	r.mu.Lock()
	if _, ok := r.desired[routeID]; !ok {
		r.mu.Unlock()
		return fmt.Errorf("restart session group route: %q is not in the group", routeID)
	}
	r.restarts[routeID]++
	r.mu.Unlock()
	return r.applyAndWake(ctx)
}

// applyAndWake pushes the desired set from a caller, records a failure for
// Run to heal, and wakes Run so the rotation timer follows the route count.
func (r *SessionGroupRunner) applyAndWake(ctx context.Context) error {
	err := r.apply(ctx)
	if err != nil {
		r.mu.Lock()
		r.divergent = true
		r.mu.Unlock()
	}
	r.signalWake()
	return err
}

// healDivergence re-applies the desired set under Run's context after a
// caller's apply failed, so desired state converges on the next wake or
// change signal instead of at the next rotation.
func (r *SessionGroupRunner) healDivergence(ctx context.Context) {
	r.mu.Lock()
	divergent := r.divergent
	r.divergent = false
	r.mu.Unlock()
	if !divergent {
		return
	}
	if err := r.apply(ctx); err != nil {
		r.mu.Lock()
		r.divergent = true
		r.mu.Unlock()
	}
}

func (r *SessionGroupRunner) signalWake() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// RouteStates reports every route's registration on the active session, or
// an empty map while no session is serving.
func (r *SessionGroupRunner) RouteStates() map[string]RouteState {
	active := r.currentActive()
	if active == nil {
		return map[string]RouteState{}
	}
	return active.session.RouteStates()
}

// apply pushes the desired set to the live sessions. A session that is being
// replaced only ever loses routes: adding to it could hit the server's
// NewProxy knock-expiry gate and end the whole session with a stale-admission
// rejection while its replacement is still registering.
func (r *SessionGroupRunner) apply(ctx context.Context) error {
	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	r.mu.Lock()
	desired := r.desiredRoutesLocked()
	active, pending, rotating := r.active, r.pending, r.rotating
	r.mu.Unlock()

	var errs []error
	if pending != nil && pending != active && !sessionEnded(pending.session) {
		if err := pending.session.Update(ctx, desired); err != nil && !errors.Is(err, ErrSessionGroupEnded) {
			errs = append(errs, fmt.Errorf("replacement session: %w", err))
		}
	}
	if active != nil && !sessionEnded(active.session) {
		routes := desired
		if rotating {
			routes = retainRoutes(active.session.RouteStates(), desired)
		}
		// A session that is retiring underneath the update is benign: the
		// desired set is authoritative for every later cycle.
		if err := active.session.Update(ctx, routes); err != nil && !errors.Is(err, ErrSessionGroupEnded) {
			errs = append(errs, fmt.Errorf("active session: %w", err))
		}
	}
	return errors.Join(errs...)
}

func sessionEnded(session ServingSession) bool {
	select {
	case <-session.Done():
		return true
	default:
		return false
	}
}

// retainRoutes keeps only routes the session already carries, with the exact
// generation it carries, so a rotating session sees removals but no
// registrations.
func retainRoutes(states map[string]RouteState, desired []GroupRoute) []GroupRoute {
	retained := make([]GroupRoute, 0, len(desired))
	for _, route := range desired {
		if state, ok := states[route.RouteID]; ok && state.Phase != RouteFailed {
			retained = append(retained, state.Route)
		}
	}
	sortGroupRoutes(retained)
	return retained
}

func (r *SessionGroupRunner) desiredRoutes() []GroupRoute {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.desiredRoutesLocked()
}

func (r *SessionGroupRunner) desiredCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.desired)
}

func (r *SessionGroupRunner) desiredRoutesLocked() []GroupRoute {
	routes := make([]GroupRoute, 0, len(r.desired))
	for routeID, route := range r.desired {
		routes = append(routes, GroupRoute{LocalHTTPRoute: route, Generation: r.restarts[routeID]})
	}
	sortGroupRoutes(routes)
	return routes
}

func (r *SessionGroupRunner) startReadyCycle(ctx context.Context, old *groupCycle) (*groupCycle, error) {
	backoff := r.cfg.MinBackoff
	for {
		cycle, err := r.startCycleAttempt(ctx, old)
		if err == nil || old == nil {
			return cycle, err
		}
		if errors.Is(err, ErrResourceGone) || errors.Is(err, ErrGroupEmpty) {
			return nil, err
		}
		remaining := time.Until(old.expiresAt)
		if remaining <= 0 {
			return nil, err
		}
		wait := jitter(backoff)
		if wait > remaining {
			wait = remaining
		}
		if retryErr := retryAfter(ctx, r.cfg.OnRetry, err, wait); retryErr != nil {
			return nil, retryErr
		}
		backoff = nextBackoff(backoff, r.cfg.MaxBackoff)
	}
}

func (r *SessionGroupRunner) startCycleAttempt(ctx context.Context, old *groupCycle) (*groupCycle, error) {
	attemptCtx := ctx
	cancelAttempt := func() {}
	if old != nil {
		attemptCtx, cancelAttempt = context.WithDeadline(ctx, old.expiresAt)
	}
	defer cancelAttempt()

	// Never spend a knock on an empty proxy set.
	if r.desiredCount() == 0 {
		return nil, ErrGroupEmpty
	}
	started := time.Now()
	admission, err := r.cfg.Admitter.Admit(attemptCtx, r.cfg.KnockResourceID, r.cfg.ResourceID)
	if err != nil {
		return nil, err
	}
	if err := validateAdmission(admission, r.cfg.KnockResourceID, r.cfg.ResourceID); err != nil {
		return nil, errors.Join(err, r.retireAdmission(admission))
	}
	routes := r.desiredRoutes()
	expiresAt := started.Add(admission.OpenTime)
	session, err := r.cfg.Sessions.Start(attemptCtx, admission, routes)
	if err != nil {
		return nil, errors.Join(err, r.retireAdmission(admission))
	}
	cycle := &groupCycle{admission: admission, session: session, expiresAt: expiresAt, capReported: -1}
	r.setPending(cycle)
	// Route changes that raced with Start land on the new session now; a
	// session that already ended is caught below.
	_ = r.apply(ctx)

	readyDeadline := expiresAt
	if old != nil && old.expiresAt.Before(readyDeadline) {
		readyDeadline = old.expiresAt
	}
	readyCtx, cancel := context.WithDeadline(attemptCtx, readyDeadline)
	defer cancel()
	for {
		if sessionEnded(session) {
			return nil, r.failCycle(cycle, nil)
		}
		states := session.RouteStates()
		r.withdrawGone(ctx, states)
		if r.desiredCount() == 0 {
			return nil, r.failCycle(cycle, ErrGroupEmpty)
		}
		if r.cycleServing(states, old) {
			return cycle, nil
		}
		select {
		case <-readyCtx.Done():
			states = session.RouteStates()
			r.withdrawGone(ctx, states)
			if r.desiredCount() == 0 {
				return nil, r.failCycle(cycle, ErrGroupEmpty)
			}
			if old != nil && anyRouteServing(states) {
				// The old admission is expiring: promote what came up and
				// report what the old session served that did not.
				r.reportNotServing(old, states)
				return cycle, nil
			}
			return nil, r.failCycle(cycle, readyCtx.Err())
		case <-session.Done():
			return nil, r.failCycle(cycle, nil)
		case <-session.Changes():
		}
	}
}

// cycleServing decides whether a new cycle may be promoted. The first cycle
// serves as soon as any route runs. A replacement must first carry every
// route the old session is still serving, so promotion never regresses a
// route that was up. An old session that serves nothing, including one that
// died mid-rotation, has nothing to regress, so the gate deliberately relaxes
// to "any route serving" rather than waiting for the old admission to expire.
func (r *SessionGroupRunner) cycleServing(states map[string]RouteState, old *groupCycle) bool {
	needed := r.routesServedBy(old)
	if len(needed) == 0 {
		return anyRouteServing(states)
	}
	for routeID := range needed {
		if state, ok := states[routeID]; !ok || state.Phase != RouteServing {
			return false
		}
	}
	return true
}

// servingRouteLister is an optional GroupServingSession refinement that
// returns only the serving route IDs, sparing the promotion gate a full
// RouteStates copy on every change signal during a large rotation.
type servingRouteLister interface {
	ServingRouteIDs() map[string]struct{}
}

func (r *SessionGroupRunner) routesServedBy(cycle *groupCycle) map[string]struct{} {
	if cycle == nil {
		return nil
	}
	var serving map[string]struct{}
	if lister, ok := cycle.session.(servingRouteLister); ok {
		serving = lister.ServingRouteIDs()
	} else {
		states := cycle.session.RouteStates()
		serving = make(map[string]struct{}, len(states))
		for routeID, state := range states {
			if state.Phase == RouteServing {
				serving[routeID] = struct{}{}
			}
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for routeID := range serving {
		if _, desired := r.desired[routeID]; !desired {
			delete(serving, routeID)
		}
	}
	return serving
}

func anyRouteServing(states map[string]RouteState) bool {
	for _, state := range states {
		if state.Phase == RouteServing {
			return true
		}
	}
	return false
}

func (r *SessionGroupRunner) reportNotServing(old *groupCycle, states map[string]RouteState) {
	if r.cfg.OnRouteFailed == nil {
		return
	}
	needed := r.routesServedBy(old)
	missing := make([]string, 0, len(needed))
	for routeID := range needed {
		if state, ok := states[routeID]; !ok || state.Phase != RouteServing {
			missing = append(missing, routeID)
		}
	}
	sort.Strings(missing)
	for _, routeID := range missing {
		err := fmt.Errorf("%w on the replacement session before the prior admission expired", ErrRouteNotServing)
		if last := states[routeID].Err; last != nil {
			err = fmt.Errorf("%w: %w", err, last)
		}
		r.cfg.OnRouteFailed(routeID, err)
	}
}

// withdrawGone drops permanently unavailable routes from the desired set,
// withdraws them from every live session, and reports them. Siblings are
// never touched.
func (r *SessionGroupRunner) withdrawGone(ctx context.Context, states map[string]RouteState) {
	type goneRoute struct {
		routeID string
		err     error
	}
	var gone []goneRoute
	r.mu.Lock()
	for routeID, state := range states {
		if state.Phase != RouteFailed || !errors.Is(state.Err, ErrResourceGone) {
			continue
		}
		if _, desired := r.desired[routeID]; !desired {
			continue
		}
		delete(r.desired, routeID)
		r.restarts[routeID]++
		gone = append(gone, goneRoute{routeID: routeID, err: state.Err})
	}
	r.mu.Unlock()
	if len(gone) == 0 {
		return
	}
	sort.Slice(gone, func(i, j int) bool { return gone[i].routeID < gone[j].routeID })
	_ = r.apply(ctx)
	if r.cfg.OnRouteFailed != nil {
		for _, route := range gone {
			r.cfg.OnRouteFailed(route.routeID, route.err)
		}
	}
}

// promote makes cycle the active session and reports it.
func (r *SessionGroupRunner) promote(ctx context.Context, cycle *groupCycle) {
	r.mu.Lock()
	r.active = cycle
	if r.pending == cycle {
		r.pending = nil
	}
	r.rotating = false
	r.reported = make(map[string]string)
	r.mu.Unlock()
	if r.cfg.OnServing != nil {
		r.cfg.OnServing(cycle.admission)
	}
	r.reportActive(ctx)
}

// reportActive folds the active session's route states into callbacks.
func (r *SessionGroupRunner) reportActive(ctx context.Context) {
	active := r.currentActive()
	if active == nil {
		return
	}
	states := active.session.RouteStates()
	r.withdrawGone(ctx, states)
	var serving []string
	r.mu.Lock()
	for routeID, state := range states {
		if state.Phase == RouteServing && r.reported[routeID] != state.ProxyName {
			r.reported[routeID] = state.ProxyName
			serving = append(serving, routeID)
		}
	}
	r.mu.Unlock()
	if r.cfg.OnRouteServing == nil {
		return
	}
	sort.Strings(serving)
	for _, routeID := range serving {
		r.cfg.OnRouteServing(routeID, active.admission)
	}
}

func (r *SessionGroupRunner) failCycle(cycle *groupCycle, cause error) error {
	r.clearPending(cycle)
	err := cause
	if err == nil {
		err = cycle.session.Err()
	}
	stopServingSession(cycle.session, r.cfg.StopTimeout)
	err = errors.Join(err, r.retireAdmission(cycle.admission))
	if err == nil {
		err = errors.New("FRP session ended before serving")
	}
	return err
}

func (r *SessionGroupRunner) stopCycle(cycle *groupCycle) error {
	if cycle == nil {
		return nil
	}
	stopServingSession(cycle.session, r.cfg.StopTimeout)
	return r.retireAdmission(cycle.admission)
}

func (r *SessionGroupRunner) retireAdmission(admission Admission) error {
	return retireAdmission(r.cfg.Admitter, admission, r.cfg.StopTimeout)
}

func (r *SessionGroupRunner) currentActive() *groupCycle {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active
}

func (r *SessionGroupRunner) takeActive() *groupCycle {
	r.mu.Lock()
	defer r.mu.Unlock()
	active := r.active
	r.active = nil
	return active
}

func (r *SessionGroupRunner) setPending(cycle *groupCycle) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending = cycle
}

func (r *SessionGroupRunner) clearPending(cycle *groupCycle) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == cycle {
		r.pending = nil
	}
}

// setRotating is serialized with apply so an in-flight apply that read
// rotating == false completes before the flag flips: no addition can land on
// a session after it has entered rotation.
func (r *SessionGroupRunner) setRotating(rotating bool) {
	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rotating = rotating
}
