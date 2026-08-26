package main

import (
	"fmt"
	"io"
	"strings"
	"sync/atomic"
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
// Readiness comes from pkg/share's OnServing callback, after the exact
// configured proxy reaches FRP's running phase. It is not timer-based and does
// not scrape logs, so the block appears only for a registered route.
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

// readyAnnouncer prints the foreground block once per process.
//
// Once, not once per supervised cycle: the block explains a startup surprise,
// and a reconnect an hour later re-teaching the operator about Ctrl+C is noise.
// The lifecycle engine's per-cycle FRP logs already narrate reconnects.
type readyAnnouncer struct {
	routes []readyRoute
	out    io.Writer

	// interactive gates the Ctrl+C sentence. Under systemd, launchd, or a
	// piped `docker run` there is no terminal to press it in, and the output
	// is a log rather than something a human is watching — so those get the
	// same facts without the instruction.
	interactive bool

	// announced latches the first print, including across cycles.
	announced atomic.Bool
}

// announce writes the block, at most once for the life of the announcer.
func (a *readyAnnouncer) announce() {
	if a == nil || !a.announced.CompareAndSwap(false, true) {
		return
	}
	fmt.Fprint(a.out, a.render())
}

// render builds the block as a string so its exact shape is testable without
// capturing os.Stdout.
func (a *readyAnnouncer) render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n  %s✓ Connector is running%s — %d route(s) live\n\n",
		colorGreen, colorReset, len(a.routes))

	width := 0
	for _, r := range a.routes {
		// Rune count, not byte length: a non-ASCII route ID would blow the
		// column alignment if measured in bytes.
		if n := len([]rune(r.routeID)); n > width {
			width = n
		}
	}
	for _, r := range a.routes {
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
