package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestReadyAnnouncerAnnouncesOncePerProcess(t *testing.T) {
	var out bytes.Buffer
	announcer := &readyAnnouncer{
		routes: []readyRoute{{routeID: "myapp", target: "127.0.0.1:8080"}},
		out:    &out, interactive: true,
	}
	for range 3 {
		announcer.announce()
	}
	if n := strings.Count(out.String(), "Connector is running"); n != 1 {
		t.Fatalf("ready block printed %d times, want exactly 1", n)
	}
}

func TestReadyBlockOmitsCtrlCWhenNotInteractive(t *testing.T) {
	// Under systemd/launchd or a piped `docker run` the output is a log, and
	// there is no terminal to press Ctrl+C in — but the facts still belong in
	// the journal.
	announcer := &readyAnnouncer{
		routes: []readyRoute{{routeID: "myapp", target: "127.0.0.1:8080"}},
		out:    &bytes.Buffer{},
	}

	got := announcer.render()
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
	announcer := &readyAnnouncer{
		routes: []readyRoute{
			{routeID: "a", target: "127.0.0.1:1"},
			{routeID: "much-longer-id", target: "127.0.0.1:2"},
		},
		out: &bytes.Buffer{},
	}

	var arrowColumns []int
	for _, line := range strings.Split(stripANSI(announcer.render()), "\n") {
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
