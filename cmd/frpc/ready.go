package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// Foreground readiness announcement.
//
// Customer report: "after start proxy success the terminal looks
// frozen/unresponsive — nothing tells you the connector is now running in the
// foreground and that's expected." That is exactly what `run` did: FRP's last
// `[route] start proxy success` INFO line was the final byte written, and a
// healthy, serving Connector is indistinguishable from a hung one.
//
// So once every configured route's proxy has actually reached FRP's running
// phase, print a short block naming the live routes and saying, in words, that
// staying attached is the point and how to stop.
//
// Readiness comes from pkg/share's OnRouteServing callback, per route, after
// that route's exact proxy reaches FRP's running phase on the session group's
// active session. It is not timer-based and does not scrape logs, so the block
// names only registered routes: with several routes it waits for the last one
// to come up, and a route the platform has permanently revoked (OnRouteFailed
// with ErrResourceGone) is dropped from the wait rather than listed as live.
//
// The wait is bounded. FRP keeps a proxy the server rejected for any reason
// other than resource_not_found in a pending retry indefinitely, so a route
// stuck on such a rejection would otherwise hold the block back forever while
// its siblings serve — the frozen-terminal symptom again, on a Connector that
// is genuinely running. readyFallbackWait after the group first serves, the
// block prints the live routes, names the outstanding ones as still
// registering, and then narrates each of those as it comes up or is retired.
//
// What this deliberately does NOT print is a public URL. Managed Connector
// routes have no client-derivable public host — the qURL control plane discloses it only
// after the qURL is resolved and the NHP grant is open (see routePublicLabel in
// list.go). Printing a locally-assembled hostname here would invent a customer-
// facing address the client is not entitled to compute.

// readyRoute is one line of the ready block: what the customer calls the route
// and where it points locally.
type readyRoute struct {
	routeID string
	target  string
}

// readyFallbackWait bounds how long the block waits for the last route once
// the group's first session serves. Registering a full set on a fresh session
// is sequential and costs milliseconds per route, so anything still pending
// this long after the first route came up is stuck in FRP's retry, not queued
// behind its siblings. A variable so tests can shrink it.
var readyFallbackWait = 30 * time.Second

// readyAnnouncer prints the foreground block once per process: the first
// time every route still configured is serving, or, failing that, once the
// bounded wait after the first serving route elapses.
//
// Once, not once per supervised cycle: the block explains a startup surprise,
// and a reconnect an hour later re-teaching the operator about Ctrl+C is noise.
// The lifecycle engine's per-cycle FRP logs already narrate reconnects.
//
// "Still configured" because a route whose resource the platform has revoked
// is retired in place while its siblings keep serving. The block waits only
// for routes that can still come up and names only the routes that did, so
// it never reports a configured-but-dead route as live.
type readyAnnouncer struct {
	out io.Writer

	// interactive gates the Ctrl+C sentence. Under systemd, launchd, or a
	// piped `docker run` there is no terminal to press it in, and the output
	// is a log rather than something a human is watching — so those get the
	// same facts without the instruction.
	interactive bool

	mu sync.Mutex
	// routes is every configured route in config order; serving and retired
	// are keyed by route ID and together decide when nothing is outstanding.
	routes  []readyRoute
	index   map[string]readyRoute
	serving map[string]struct{}
	retired map[string]struct{}
	// announced latches the single print, including across cycles.
	announced bool
	// waiting is the set the fallback block named as still registering; each
	// gets one follow-up line when it serves or is retired.
	waiting map[string]struct{}
	// fallback is the bounded wait, armed once by the first sessionPromoted.
	// stopped ends it for good: a callback that had already fired when stop
	// ran must not arm a successor.
	fallback     *time.Timer
	fallbackWait time.Duration
	stopped      bool
	// live, when set, answers which routes serve on the active session right
	// now. The fallback consults it instead of the accumulated serving set:
	// a session can end and a replacement be under construction when the
	// wait elapses, with no promotion in between to clear the set.
	live func() []string
}

func newReadyAnnouncer(routes []readyRoute, out io.Writer, interactive bool) *readyAnnouncer {
	a := &readyAnnouncer{
		out: out, interactive: interactive,
		routes:  append([]readyRoute(nil), routes...),
		index:   make(map[string]readyRoute, len(routes)),
		serving: make(map[string]struct{}, len(routes)),
		retired: make(map[string]struct{}),
		waiting: make(map[string]struct{}),
	}
	for _, route := range routes {
		a.index[route.routeID] = route
	}
	return a
}

// sessionPromoted records that the group promoted a session (OnServing).
//
// Whatever served on the previous session is forgotten. The group re-reports
// every route serving on the new session immediately afterwards, and a
// whole-session loss is deliberately not reported per route, so without this
// a reconnect inside the bounded wait would carry routes from the dead
// session into the block as live. The first promotion also arms the bounded
// wait; later ones leave it alone.
func (a *readyAnnouncer) sessionPromoted(wait time.Duration) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	clear(a.serving)
	if a.announced || a.stopped || a.fallback != nil {
		return
	}
	a.fallbackWait = wait
	a.fallback = time.AfterFunc(wait, a.announceOutstanding)
}

// setLiveProbe installs the runtime's answer to "which routes serve on the
// active session now", used by the bounded wait when it fires.
func (a *readyAnnouncer) setLiveProbe(live func() []string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.live = live
}

// retiredRoutes lists the routes retired so far, in config order.
func (a *readyAnnouncer) retiredRoutes() []string {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var ids []string
	for _, route := range a.routes {
		if _, gone := a.retired[route.routeID]; gone {
			ids = append(ids, route.routeID)
		}
	}
	return ids
}

// stop ends the bounded wait for good. The block is not printed by stop.
func (a *readyAnnouncer) stop() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stopped = true
	if a.fallback != nil {
		a.fallback.Stop()
	}
}

// routeServing records that routeID reached FRP's running phase and prints
// the block if it was the last route outstanding. A route that is not
// configured is ignored, and so is a repeat: a later cycle re-registering
// the same route changes nothing the block has to say.
func (a *readyAnnouncer) routeServing(routeID string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.index[routeID]; !ok {
		return
	}
	if _, gone := a.retired[routeID]; gone {
		return
	}
	a.serving[routeID] = struct{}{}
	if a.announced {
		a.narrateLocked(routeID, true)
		return
	}
	a.announceIfCompleteLocked()
}

// routeRetired drops a permanently unavailable route from the set the block
// waits for and reports whether this call retired it: false for a route
// that is not configured or was retired already. If every remaining route
// is already serving, the block prints now, without the retired route.
func (a *readyAnnouncer) routeRetired(routeID string) bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.index[routeID]; !ok {
		return false
	}
	if _, gone := a.retired[routeID]; gone {
		return false
	}
	a.retired[routeID] = struct{}{}
	delete(a.serving, routeID)
	if a.announced {
		a.narrateLocked(routeID, false)
		return true
	}
	a.announceIfCompleteLocked()
	return true
}

// narrateLocked prints one follow-up line for a route the fallback block
// named as still registering. Every other transition after the block is
// the lifecycle engine's per-cycle story, told by FRP's own logs.
func (a *readyAnnouncer) narrateLocked(routeID string, live bool) {
	if _, ok := a.waiting[routeID]; !ok {
		return
	}
	delete(a.waiting, routeID)
	if live {
		fmt.Fprintf(a.out, "  %s✓ %s is now live%s  →  %s\n", colorGreen, routeID, colorReset, a.index[routeID].target)
		return
	}
	fmt.Fprintf(a.out, "  %s✗ %s retired%s — its resource is permanently unavailable\n", colorYellow, routeID, colorReset)
}

// partitionLocked splits the configured routes, in config order, into the
// ones serving and the ones still outstanding (neither serving nor retired).
func (a *readyAnnouncer) partitionLocked() (live, outstanding []readyRoute) {
	for _, route := range a.routes {
		if _, ok := a.serving[route.routeID]; ok {
			live = append(live, route)
			continue
		}
		if _, gone := a.retired[route.routeID]; !gone {
			outstanding = append(outstanding, route)
		}
	}
	return live, outstanding
}

// announceIfCompleteLocked writes the block at most once, when at least one
// route serves and none is outstanding.
func (a *readyAnnouncer) announceIfCompleteLocked() {
	if a.announced {
		return
	}
	live, outstanding := a.partitionLocked()
	if len(live) == 0 || len(outstanding) > 0 {
		return
	}
	a.printLocked(live, nil)
}

// announceOutstanding is the fallback: the bounded wait elapsed, so print
// what serves and name what does not. Nothing live means the group lost its
// session again after promoting; wait another round rather than announce a
// Connector that serves nothing.
func (a *readyAnnouncer) announceOutstanding() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.announced || a.stopped {
		return
	}
	if a.live != nil {
		// Rebuild the serving set from the runtime's view so a session that
		// ended since the last promotion cannot lend its routes to the block.
		// Lock order: this holds a.mu and the probe takes the runner's lock;
		// every runner callback into this announcer runs with no runner lock
		// held (SessionGroupConfig documents that), so the order never
		// reverses.
		clear(a.serving)
		for _, routeID := range a.live() {
			if _, ok := a.index[routeID]; !ok {
				continue
			}
			if _, gone := a.retired[routeID]; gone {
				continue
			}
			a.serving[routeID] = struct{}{}
		}
	}
	live, outstanding := a.partitionLocked()
	if len(live) == 0 {
		a.fallback = time.AfterFunc(a.fallbackWait, a.announceOutstanding)
		return
	}
	a.printLocked(live, outstanding)
}

func (a *readyAnnouncer) printLocked(live, outstanding []readyRoute) {
	a.announced = true
	if a.fallback != nil {
		a.fallback.Stop()
	}
	for _, route := range outstanding {
		a.waiting[route.routeID] = struct{}{}
	}
	fmt.Fprint(a.out, a.render(live, outstanding))
}

// render builds the block as a string so its exact shape is testable without
// capturing os.Stdout. live is what the block lists; outstanding, when the
// bounded wait forced the print, is named as still registering.
func (a *readyAnnouncer) render(live, outstanding []readyRoute) string {
	var b strings.Builder
	if len(outstanding) == 0 {
		fmt.Fprintf(&b, "\n  %s✓ Connector is running%s — %d route(s) live\n\n",
			colorGreen, colorReset, len(live))
	} else {
		fmt.Fprintf(&b, "\n  %s✓ Connector is running%s — %d of %d route(s) live\n\n",
			colorGreen, colorReset, len(live), len(live)+len(outstanding))
	}

	width := 0
	for _, r := range live {
		// Rune count, not byte length: a non-ASCII route ID would blow the
		// column alignment if measured in bytes.
		if n := len([]rune(r.routeID)); n > width {
			width = n
		}
	}
	for _, r := range live {
		// Pad outside the color so the escape wraps the ID alone rather than
		// a run of colored trailing spaces.
		fmt.Fprintf(&b, "    %s%s%s%s  →  %s\n",
			colorCyan, r.routeID, colorReset, strings.Repeat(" ", width-len([]rune(r.routeID))), r.target)
	}

	if len(outstanding) > 0 {
		ids := make([]string, 0, len(outstanding))
		for _, r := range outstanding {
			ids = append(ids, r.routeID)
		}
		fmt.Fprintf(&b, "\n  %sStill registering:%s %s — FRP keeps retrying; a line prints here when each comes up or is retired.\n",
			colorYellow, colorReset, strings.Join(ids, ", "))
	}

	b.WriteString("\n")
	if a.interactive {
		fmt.Fprintf(&b, "  Serving in the foreground — that's expected. Press %sCtrl+C%s to stop.\n\n",
			colorBold, colorReset)
	} else {
		b.WriteString("  Serving in the foreground until this process is stopped.\n\n")
	}
	return b.String()
}
