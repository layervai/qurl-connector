package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

func readyTestRoutes(ids ...string) []readyRoute {
	routes := make([]readyRoute, 0, len(ids))
	for i, id := range ids {
		routes = append(routes, readyRoute{routeID: id, target: fmt.Sprintf("127.0.0.1:%d", 3000+i)})
	}
	return routes
}

// readyBlockRoutes returns the route IDs a rendered block lists as live, in
// order. Follow-up "is now live" lines are not block rows.
func readyBlockRoutes(block string) []string {
	var ids []string
	for _, line := range strings.Split(stripANSI(block), "\n") {
		if !strings.HasPrefix(line, "    ") {
			continue
		}
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

func TestReadyAnnouncerFallsBackAfterBoundedWaitAndNarratesTheRest(t *testing.T) {
	out := &lockedBuffer{}
	announcer := newReadyAnnouncer(readyTestRoutes("a", "b", "c", "d"), out, false)
	t.Cleanup(announcer.stop)

	announcer.sessionPromoted(10 * time.Millisecond)
	announcer.routeServing("a")
	announcer.routeServing("b")
	waitFor(t, 2*time.Second, func() bool { return strings.Contains(out.String(), "Connector is running") }, "the fallback block")

	block := out.String()
	if !strings.Contains(block, "2 of 4 route(s) live") {
		t.Errorf("fallback block should say how many of the configured routes are live; got:\n%s", block)
	}
	if got := readyBlockRoutes(block); strings.Join(got, ",") != "a,b" {
		t.Errorf("fallback block rows = %v, want only the live routes [a b]", got)
	}
	if !strings.Contains(block, "Still registering:") || !strings.Contains(block, "c, d") {
		t.Errorf("fallback block should name the outstanding routes as still registering; got:\n%s", block)
	}

	// The outstanding routes are narrated as they resolve, once each.
	announcer.routeServing("c")
	announcer.routeServing("c")
	announcer.routeRetired("d")
	got := out.String()
	if n := strings.Count(got, "c is now live"); n != 1 {
		t.Errorf("route c narrated %d times, want 1:\n%s", n, got)
	}
	if !strings.Contains(got, "127.0.0.1:3002") {
		t.Errorf("route c's follow-up should carry its local target:\n%s", got)
	}
	if !strings.Contains(got, "d retired") {
		t.Errorf("route d's retirement should be narrated:\n%s", got)
	}
	if n := strings.Count(got, "Connector is running"); n != 1 {
		t.Errorf("block printed %d times, want exactly 1", n)
	}
	// A route the block already listed as live is not news.
	announcer.routeServing("a")
	if strings.Contains(out.String(), "a is now live") {
		t.Error("a route the block listed as live was narrated again")
	}
}

func TestReadyAnnouncerFallbackDoesNotFireOnceComplete(t *testing.T) {
	out := &lockedBuffer{}
	announcer := newReadyAnnouncer(readyTestRoutes("a", "b"), out, false)
	t.Cleanup(announcer.stop)

	announcer.sessionPromoted(10 * time.Millisecond)
	announcer.routeServing("a")
	announcer.routeServing("b")
	time.Sleep(40 * time.Millisecond)

	got := out.String()
	if n := strings.Count(got, "Connector is running"); n != 1 {
		t.Fatalf("block printed %d times, want exactly 1:\n%s", n, got)
	}
	if strings.Contains(got, " of ") || strings.Contains(got, "Still registering") {
		t.Errorf("a complete block must not carry the fallback wording:\n%s", got)
	}
}

func TestReadyAnnouncerFallbackWaitsForSomethingLive(t *testing.T) {
	out := &lockedBuffer{}
	announcer := newReadyAnnouncer(readyTestRoutes("a", "b"), out, false)
	t.Cleanup(announcer.stop)

	// The group promoted but every route flapped back to pending before the
	// wait elapsed: announcing a running Connector with nothing live would
	// be a lie, so the wait rolls over.
	announcer.sessionPromoted(5 * time.Millisecond)
	time.Sleep(25 * time.Millisecond)
	if out.String() != "" {
		t.Fatalf("fallback block printed with nothing live:\n%s", out.String())
	}
	announcer.routeServing("a")
	waitFor(t, 2*time.Second, func() bool { return strings.Contains(out.String(), "1 of 2 route(s) live") }, "the rolled-over fallback block")
}

func TestReadyAnnouncerForgetsRoutesServedByALostSession(t *testing.T) {
	out := &lockedBuffer{}
	announcer := newReadyAnnouncer(readyTestRoutes("a", "b", "c", "d"), out, false)
	t.Cleanup(announcer.stop)

	// Session 1 served a, b, c with d pending; it was lost, and the group
	// promoted session 2 on which only a and b have registered so far.
	announcer.sessionPromoted(time.Hour)
	for _, id := range []string{"a", "b", "c"} {
		announcer.routeServing(id)
	}
	announcer.sessionPromoted(time.Hour)
	announcer.routeServing("a")
	announcer.routeServing("b")
	// A late promotion must not re-arm a shorter wait either; the first one
	// owns the timer. (Both waits are an hour here; the block prints below
	// only because the set completes.)
	if out.String() != "" {
		t.Fatalf("block printed with c and d not serving on the active session:\n%s", out.String())
	}

	// d never comes up and c comes back: the block must list exactly the
	// routes serving on the active session.
	announcer.routeRetired("d")
	announcer.routeServing("c")
	if !strings.Contains(out.String(), "3 route(s) live") {
		t.Fatalf("block should count the routes serving on the active session; got:\n%s", out.String())
	}
	if got := readyBlockRoutes(out.String()); strings.Join(got, ",") != "a,b,c" {
		t.Errorf("block routes = %v, want [a b c]", got)
	}
}

func TestReadyAnnouncerFallbackListsOnlyTheActiveSessionsRoutes(t *testing.T) {
	out := &lockedBuffer{}
	announcer := newReadyAnnouncer(readyTestRoutes("a", "b", "c", "d"), out, false)
	t.Cleanup(announcer.stop)

	// d never registers, so the block is still waiting when session 1 is
	// lost and replaced; c served on session 1 but has not re-registered.
	announcer.sessionPromoted(time.Hour)
	announcer.routeServing("a")
	announcer.routeServing("b")
	announcer.routeServing("c")
	announcer.sessionPromoted(time.Hour)
	announcer.routeServing("a")
	announcer.routeServing("b")
	// Force the bounded wait now rather than in an hour.
	announcer.announceOutstanding()

	block := out.String()
	if !strings.Contains(block, "2 of 4 route(s) live") {
		t.Errorf("fallback block counted a route from the lost session as live; got:\n%s", block)
	}
	if got := readyBlockRoutes(block); strings.Join(got, ",") != "a,b" {
		t.Errorf("fallback block rows = %v, want [a b]", got)
	}
	if !strings.Contains(block, "Still registering:") || !strings.Contains(block, "c, d") {
		t.Errorf("fallback block should name c and d as still registering; got:\n%s", block)
	}
}

func TestReadyAnnouncerFallbackAsksTheRuntimeWhatIsLive(t *testing.T) {
	out := &lockedBuffer{}
	announcer := newReadyAnnouncer(readyTestRoutes("a", "b", "c", "d"), out, false)
	t.Cleanup(announcer.stop)

	// a, b, c served, then the session ended and its replacement is still
	// being built: nothing is live and no promotion has cleared the set.
	announcer.sessionPromoted(time.Hour)
	for _, id := range []string{"a", "b", "c"} {
		announcer.routeServing(id)
	}
	live := []string{}
	announcer.setLiveProbe(func() []string { return live })
	announcer.announceOutstanding()
	if out.String() != "" {
		t.Fatalf("fallback block printed routes from an ended session:\n%s", out.String())
	}

	// The replacement has a alone so far, plus a stranger the block must
	// ignore; d was retired meanwhile.
	live = []string{"a", "stranger"}
	announcer.routeRetired("d")
	announcer.announceOutstanding()
	block := out.String()
	if !strings.Contains(block, "1 of 3 route(s) live") {
		t.Errorf("fallback block should count what the runtime reports live; got:\n%s", block)
	}
	if got := readyBlockRoutes(block); strings.Join(got, ",") != "a" {
		t.Errorf("fallback block rows = %v, want [a]", got)
	}
	if !strings.Contains(block, "Still registering: b, c ") || strings.Contains(block, "b, c, d") {
		t.Errorf("fallback block should name b and c as still registering and not the retired d; got:\n%s", block)
	}
	if got := announcer.retiredRoutes(); strings.Join(got, ",") != "d" {
		t.Errorf("retiredRoutes = %v, want [d]", got)
	}
}

func TestReadyAnnouncerStopEndsTheFallbackForGood(t *testing.T) {
	out := &lockedBuffer{}
	announcer := newReadyAnnouncer(readyTestRoutes("a", "b"), out, false)

	// Nothing live when the wait elapses, so the callback would re-arm;
	// stop must win against that, whatever the interleaving.
	announcer.sessionPromoted(5 * time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	announcer.stop()
	announcer.routeServing("a")
	time.Sleep(30 * time.Millisecond)
	if out.String() != "" {
		t.Fatalf("a stopped announcer printed:\n%s", out.String())
	}
	announcer.sessionPromoted(time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	if out.String() != "" {
		t.Fatalf("a stopped announcer re-armed its wait:\n%s", out.String())
	}
}

func TestReadyBlockOmitsCtrlCWhenNotInteractive(t *testing.T) {
	// Under systemd/launchd or a piped `docker run` the output is a log, and
	// there is no terminal to press Ctrl+C in — but the facts still belong in
	// the journal.
	announcer := newReadyAnnouncer(nil, &bytes.Buffer{}, false)

	got := announcer.render([]readyRoute{{routeID: "myapp", target: "127.0.0.1:8080"}}, nil)
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
	}, nil)
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
