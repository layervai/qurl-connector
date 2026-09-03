package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
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

// readyAnnouncer prints the foreground block once per process, the first
// time every route still configured is serving.
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
	index   map[string]struct{}
	serving map[string]struct{}
	retired map[string]struct{}
	// announced latches the single print, including across cycles.
	announced bool
}

func newReadyAnnouncer(routes []readyRoute, out io.Writer, interactive bool) *readyAnnouncer {
	a := &readyAnnouncer{
		out: out, interactive: interactive,
		routes:  append([]readyRoute(nil), routes...),
		index:   make(map[string]struct{}, len(routes)),
		serving: make(map[string]struct{}, len(routes)),
		retired: make(map[string]struct{}),
	}
	for _, route := range routes {
		a.index[route.routeID] = struct{}{}
	}
	return a
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
	a.announceIfCompleteLocked()
}

// routeRetired drops a permanently unavailable route from the set the block
// waits for. If every remaining route is already serving, the block prints
// now, without the retired route.
func (a *readyAnnouncer) routeRetired(routeID string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.index[routeID]; !ok {
		return
	}
	a.retired[routeID] = struct{}{}
	delete(a.serving, routeID)
	a.announceIfCompleteLocked()
}

// announceIfCompleteLocked writes the block at most once, when at least one
// route serves and none is outstanding (neither serving nor retired).
func (a *readyAnnouncer) announceIfCompleteLocked() {
	if a.announced {
		return
	}
	live := make([]readyRoute, 0, len(a.routes))
	for _, route := range a.routes {
		if _, ok := a.serving[route.routeID]; ok {
			live = append(live, route)
			continue
		}
		if _, gone := a.retired[route.routeID]; !gone {
			return
		}
	}
	if len(live) == 0 {
		return
	}
	a.announced = true
	fmt.Fprint(a.out, a.render(live))
}

// render builds the block for the live routes as a string so its exact shape
// is testable without capturing os.Stdout.
func (a *readyAnnouncer) render(live []readyRoute) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n  %s✓ Connector is running%s — %d route(s) live\n\n",
		colorGreen, colorReset, len(live))

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

	b.WriteString("\n")
	if a.interactive {
		fmt.Fprintf(&b, "  Serving in the foreground — that's expected. Press %sCtrl+C%s to stop.\n\n",
			colorBold, colorReset)
	} else {
		b.WriteString("  Serving in the foreground until this process is stopped.\n\n")
	}
	return b.String()
}
