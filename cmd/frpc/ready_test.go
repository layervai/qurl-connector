package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func readyTestRoutes(ids ...string) []readyRoute {
	routes := make([]readyRoute, 0, len(ids))
	for i, id := range ids {
		routes = append(routes, readyRoute{routeID: id, target: fmt.Sprintf("127.0.0.1:%d", 3000+i)})
	}
	return routes
}

// readyBlockRoutes returns the route IDs a rendered block names, in order.
func readyBlockRoutes(block string) []string {
	var ids []string
	for _, line := range strings.Split(stripANSI(block), "\n") {
		if before, _, ok := strings.Cut(line, "→"); ok {
			ids = append(ids, strings.TrimSpace(before))
		}
	}
	return ids
}

func TestReadyAnnouncerWaitsForEveryRouteThenPrintsOnce(t *testing.T) {
	var out bytes.Buffer
	announcer := newReadyAnnouncer(readyTestRoutes("a", "b"), &out, true)

	announcer.routeServing("a")
	if out.Len() != 0 {
		t.Fatalf("ready block printed with route b still outstanding:\n%s", out.String())
	}
	for range 3 {
		announcer.routeServing("b")
	}
	// A later cycle re-reporting a route must not re-teach Ctrl+C.
	announcer.routeServing("a")

	if n := strings.Count(out.String(), "Connector is running"); n != 1 {
		t.Fatalf("ready block printed %d times, want exactly 1:\n%s", n, out.String())
	}
	if !strings.Contains(out.String(), "2 route(s) live") {
		t.Errorf("ready block should count both serving routes; got:\n%s", out.String())
	}
	if got := readyBlockRoutes(out.String()); strings.Join(got, ",") != "a,b" {
		t.Errorf("ready block routes = %v, want [a b]", got)
	}
}

func TestReadyAnnouncerDropsRetiredRouteAndNamesOnlyServingRoutes(t *testing.T) {
	var out bytes.Buffer
	announcer := newReadyAnnouncer(readyTestRoutes("a", "b", "c"), &out, false)

	announcer.routeServing("a")
	announcer.routeServing("b")
	if out.Len() != 0 {
		t.Fatalf("ready block printed with route c still outstanding:\n%s", out.String())
	}
	// The platform revoked c: the block must not wait for it, and must not
	// list it as live.
	announcer.routeRetired("c")

	if !strings.Contains(out.String(), "2 route(s) live") {
		t.Errorf("ready block should count only the serving routes; got:\n%s", out.String())
	}
	if got := readyBlockRoutes(out.String()); strings.Join(got, ",") != "a,b" {
		t.Errorf("ready block routes = %v, want [a b]", got)
	}
	// A retired route that later reports serving is stale news from a session
	// that no longer carries it.
	announcer.routeServing("c")
	if n := strings.Count(out.String(), "Connector is running"); n != 1 {
		t.Fatalf("ready block printed %d times, want exactly 1", n)
	}
}

func TestReadyAnnouncerPrintsNothingWhenEveryRouteIsRetired(t *testing.T) {
	var out bytes.Buffer
	announcer := newReadyAnnouncer(readyTestRoutes("a", "b"), &out, false)
	announcer.routeRetired("a")
	announcer.routeRetired("b")
	if out.Len() != 0 {
		t.Fatalf("ready block printed with no route live:\n%s", out.String())
	}
}

func TestReadyAnnouncerIgnoresRoutesItWasNotConfiguredWith(t *testing.T) {
	var out bytes.Buffer
	announcer := newReadyAnnouncer(readyTestRoutes("a"), &out, false)
	announcer.routeServing("stranger")
	announcer.routeRetired("stranger")
	if out.Len() != 0 {
		t.Fatalf("ready block printed for an unconfigured route:\n%s", out.String())
	}
	announcer.routeServing("a")
	if got := readyBlockRoutes(out.String()); strings.Join(got, ",") != "a" {
		t.Errorf("ready block routes = %v, want [a]", got)
	}
}

func TestReadyBlockOmitsCtrlCWhenNotInteractive(t *testing.T) {
	// Under systemd/launchd or a piped `docker run` the output is a log, and
	// there is no terminal to press Ctrl+C in — but the facts still belong in
	// the journal.
	announcer := newReadyAnnouncer(nil, &bytes.Buffer{}, false)

	got := announcer.render([]readyRoute{{routeID: "myapp", target: "127.0.0.1:8080"}})
	if strings.Contains(got, "Ctrl+C") {
		t.Errorf("non-interactive ready block should not tell the operator to press Ctrl+C; got:\n%s", got)
	}
	for _, want := range []string{"Connector is running", "1 route(s) live", "myapp", "foreground"} {
		if !strings.Contains(got, want) {
			t.Errorf("non-interactive ready block missing %q; got:\n%s", want, got)
		}
	}
}

func TestReadyBlockAlignsRouteIDColumn(t *testing.T) {
	announcer := newReadyAnnouncer(nil, &bytes.Buffer{}, false)

	var arrowColumns []int
	block := announcer.render([]readyRoute{
		{routeID: "a", target: "127.0.0.1:1"},
		{routeID: "much-longer-id", target: "127.0.0.1:2"},
	})
	for _, line := range strings.Split(stripANSI(block), "\n") {
		if idx := strings.Index(line, "→"); idx >= 0 {
			arrowColumns = append(arrowColumns, len([]rune(line[:idx])))
		}
	}
	if len(arrowColumns) != 2 {
		t.Fatalf("found %d route lines, want 2", len(arrowColumns))
	}
	if arrowColumns[0] != arrowColumns[1] {
		t.Errorf("route targets not aligned: arrow columns %v", arrowColumns)
	}
}

// stripANSI removes the color escapes so a column-alignment assertion measures
// what the operator sees rather than the bytes written.
//
// It strips the ansi* constants rather than the color* variables so the result
// does not depend on whether the gate happens to be open: the variables are
// empty when stdout is not a terminal, which would quietly turn this into a
// no-op and leave the alignment assertion measuring escaped bytes the moment
// someone runs the block with color on.
func stripANSI(s string) string {
	for _, code := range []string{ansiReset, ansiGreen, ansiYellow, ansiCyan, ansiBold} {
		s = strings.ReplaceAll(s, code, "")
	}
	return s
}
