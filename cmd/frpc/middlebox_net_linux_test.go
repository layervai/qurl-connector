//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
)

// This file is the adverse-middlebox network emulation the TestMiddlebox*
// tests knock through. It builds, per test, three throwaway network
// namespaces joined by veth pairs:
//
//	client ns (qmbc-*)          middlebox ns (qmbm-*)           server ns (qmbs-*)
//	c0 10.90.1.2/24  ────────  mc 10.90.1.1/24 ┐
//	default via 10.90.1.1                      │ ip_forward=1
//	                            ms 10.90.2.1/24 ┘ nft masquerade  ──────── s0 10.90.2.2/24
//
// The middlebox namespace source-NATs everything it forwards toward the
// server (nftables masquerade pinned to a port range so a NAT rebind is
// provable, not probabilistic), can drop its conntrack state mid-session to
// emulate a NAT that lost its binding, and carries the tc-netem qdiscs for
// loss/delay/reorder/duplication. The server namespace deliberately has no
// route back to 10.90.1.0/24: a cell reached through this middlebox can only
// ever answer the NAT address, exactly like a real NAT'd deployment.
//
// Everything here needs CAP_NET_ADMIN + CAP_SYS_ADMIN (in practice: root).
// Construction probes for that by attempting the first `ip netns add` and
// skips the test cleanly when it fails, so `make test` on an unprivileged
// machine is unaffected. CI runs these tests via the dedicated "Middlebox
// emulation" lane in .github/workflows/ci.yml, which executes only
// `-test.run '^TestMiddlebox'` under sudo and fails if any of them skipped.
const (
	middleboxClientIP     = "10.90.1.2"
	middleboxNATClientIP  = "10.90.1.1"
	middleboxNATServerIP  = "10.90.2.1"
	middleboxServerIP     = "10.90.2.2"
	middleboxClientveth   = "c0"
	middleboxNATClientDev = "mc"
	middleboxNATServerDev = "ms"
	middleboxServerveth   = "s0"

	// Masquerade port ranges. Phase A is the boot NAT binding pool; rebindNAT
	// atomically swaps the middlebox to the disjoint phase B pool and flushes
	// conntrack, so "the NAT rebound" is assertable as strict range
	// membership on the server-observed source port — never a guess about
	// which ephemeral port the kernel preserved.
	middleboxNATPortFloorA = 41000
	middleboxNATPortCeilA  = 41099
	middleboxNATPortFloorB = 41100
	middleboxNATPortCeilB  = 41199
)

// middleboxNetSequence disambiguates namespace names when one test process
// builds several emulations (each test builds its own).
var middleboxNetSequence atomic.Int32

type middleboxNet struct {
	t        *testing.T
	clientNS string
	natNS    string
	serverNS string
}

// requireMiddleboxTools skips when a binary the test's emulation needs is not
// on PATH. Base tooling (ip, nft, sysctl) is checked by newMiddleboxNet;
// tests pass the extras they use: "conntrack" (NAT rebind) or "tc" (netem).
func requireMiddleboxTools(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("middlebox emulation needs %q on PATH: %v", tool, err)
		}
	}
}

// newMiddleboxNet stands up the three-namespace emulation above, with the
// phase-A masquerade active, or skips the test when the host cannot build it.
func newMiddleboxNet(t *testing.T) *middleboxNet {
	t.Helper()
	requireMiddleboxTools(t, "ip", "nft", "sysctl")
	suffix := fmt.Sprintf("%d-%d", os.Getpid(), middleboxNetSequence.Add(1))
	m := &middleboxNet{
		t:        t,
		clientNS: "qmbc-" + suffix,
		natNS:    "qmbm-" + suffix,
		serverNS: "qmbs-" + suffix,
	}

	// The first namespace add doubles as the privilege/kernel-support probe:
	// on EPERM (unprivileged), a seccomp-restricted container, or a kernel
	// without netns support this fails, and that is a skip, not a failure.
	if output, err := exec.Command("ip", "netns", "add", m.clientNS).CombinedOutput(); err != nil {
		t.Skipf("middlebox emulation needs CAP_NET_ADMIN+CAP_SYS_ADMIN (root) to build network namespaces: ip netns add: %v: %s", err, output)
	}
	m.deleteNamespaceOnCleanup(m.clientNS)
	// The probe passed, so the remaining setup runs with privileges; any
	// failure from here on is a real harness failure, not a missing capability.
	m.mustExec("ip", "netns", "add", m.natNS)
	m.deleteNamespaceOnCleanup(m.natNS)
	m.mustExec("ip", "netns", "add", m.serverNS)
	m.deleteNamespaceOnCleanup(m.serverNS)

	m.mustExec("ip", "link", "add", middleboxClientveth, "netns", m.clientNS,
		"type", "veth", "peer", "name", middleboxNATClientDev, "netns", m.natNS)
	m.mustExec("ip", "link", "add", middleboxServerveth, "netns", m.serverNS,
		"type", "veth", "peer", "name", middleboxNATServerDev, "netns", m.natNS)

	m.mustExec("ip", "-n", m.clientNS, "addr", "add", middleboxClientIP+"/24", "dev", middleboxClientveth)
	m.mustExec("ip", "-n", m.clientNS, "link", "set", middleboxClientveth, "up")
	m.mustExec("ip", "-n", m.clientNS, "link", "set", "lo", "up")
	m.mustExec("ip", "-n", m.clientNS, "route", "add", "default", "via", middleboxNATClientIP)

	m.mustExec("ip", "-n", m.natNS, "addr", "add", middleboxNATClientIP+"/24", "dev", middleboxNATClientDev)
	m.mustExec("ip", "-n", m.natNS, "addr", "add", middleboxNATServerIP+"/24", "dev", middleboxNATServerDev)
	m.mustExec("ip", "-n", m.natNS, "link", "set", middleboxNATClientDev, "up")
	m.mustExec("ip", "-n", m.natNS, "link", "set", middleboxNATServerDev, "up")
	m.mustExec("ip", "-n", m.natNS, "link", "set", "lo", "up")

	m.mustExec("ip", "-n", m.serverNS, "addr", "add", middleboxServerIP+"/24", "dev", middleboxServerveth)
	m.mustExec("ip", "-n", m.serverNS, "link", "set", middleboxServerveth, "up")
	m.mustExec("ip", "-n", m.serverNS, "link", "set", "lo", "up")

	m.mustExec("ip", "netns", "exec", m.natNS, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	m.mustExec("ip", "netns", "exec", m.natNS, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0")

	// nft only accepts a port-mapped masquerade after a transport-protocol
	// match; every flow this middlebox forwards is the knocker's UDP.
	m.mustLoadNATRuleset(fmt.Sprintf(`table ip qmb {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname %q meta l4proto udp masquerade to :%d-%d
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
	}
}
`, middleboxNATServerDev, middleboxNATPortFloorA, middleboxNATPortCeilA))
	return m
}

func (m *middleboxNet) deleteNamespaceOnCleanup(namespace string) {
	m.t.Cleanup(func() {
		// Best-effort: sockets bound inside are already closed by later-registered
		// (earlier-run) cleanups, and the namespace dies with its last reference.
		_ = exec.Command("ip", "netns", "del", namespace).Run()
	})
}

func (m *middleboxNet) mustExec(args ...string) string {
	m.t.Helper()
	output, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		m.t.Fatalf("middlebox setup: %s: %v: %s", strings.Join(args, " "), err, output)
	}
	return string(output)
}

// mustLoadNATRuleset feeds one atomic script to nft inside the middlebox
// namespace, so rule swaps never leave a half-configured NAT visible to
// in-flight packets.
func (m *middleboxNet) mustLoadNATRuleset(script string) {
	m.t.Helper()
	if err := m.loadNATRuleset(script); err != nil {
		m.t.Fatal(err)
	}
}

func (m *middleboxNet) loadNATRuleset(script string) error {
	cmd := exec.Command("ip", "netns", "exec", m.natNS, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("middlebox nft script %q: %w: %s", script, err, output)
	}
	return nil
}

// rebindNAT emulates a NAT middlebox that lost its binding state mid-session
// (idle timeout, state-table pressure, or a reboot): the masquerade pool is
// swapped to the disjoint phase-B port range and every conntrack entry is
// flushed. In-flight replies to old bindings are now undeliverable, and the
// next outbound datagram allocates a fresh, provably different public source.
// The error form exists so a test-cell serve goroutine can trigger the rebind
// at an exact wire moment (between reading a request and answering it) —
// t.Fatal is not legal off the test goroutine.
func (m *middleboxNet) rebindNAT() {
	m.t.Helper()
	if err := m.rebindNATErr(); err != nil {
		m.t.Fatal(err)
	}
}

func (m *middleboxNet) rebindNATErr() error {
	if err := m.loadNATRuleset(fmt.Sprintf(
		"flush chain ip qmb postrouting\nadd rule ip qmb postrouting oifname %q meta l4proto udp masquerade to :%d-%d\n",
		middleboxNATServerDev, middleboxNATPortFloorB, middleboxNATPortCeilB)); err != nil {
		return err
	}
	// conntrack -F prints its summary line on stderr with exit status 0; only
	// a real failure surfaces here.
	if output, err := exec.Command("ip", "netns", "exec", m.natNS, "conntrack", "-F").CombinedOutput(); err != nil {
		return fmt.Errorf("flush middlebox conntrack: %w: %s", err, output)
	}
	return nil
}

// applyNetem installs one netem spec on both middlebox interfaces, shaping
// the two directions independently (egress toward the server on ms, egress
// toward the client on mc). A kernel without sch_netem is a skip — the
// dedicated CI lane modprobes it and separately fails if these tests skip —
// while any other tc failure is a harness bug.
func (m *middleboxNet) applyNetem(spec ...string) {
	m.t.Helper()
	for _, device := range []string{middleboxNATServerDev, middleboxNATClientDev} {
		args := append([]string{"ip", "netns", "exec", m.natNS,
			"tc", "qdisc", "replace", "dev", device, "root", "netem"}, spec...)
		output, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err == nil {
			continue
		}
		rendered := strings.ToLower(string(output))
		if strings.Contains(rendered, "unknown") || strings.Contains(rendered, "no such file") {
			m.t.Skipf("middlebox emulation needs the sch_netem qdisc (modprobe sch_netem): %v: %s", err, output)
		}
		m.t.Fatalf("middlebox netem setup: %s: %v: %s", strings.Join(args, " "), err, output)
	}
}

// dropEveryOtherKnockDatagram makes the middlebox eat the 1st, 3rd, 5th, …
// client→server datagram addressed to the cell port — deterministic 50% loss
// on the request path (numgen inc is a per-rule packet counter, evaluated in
// the forward hook before source NAT). Replies are untouched, so the exact
// loss pattern, and therefore the exact SDK retry schedule, is pinned.
func (m *middleboxNet) dropEveryOtherKnockDatagram(cellPort int) {
	m.t.Helper()
	m.mustExec("ip", "netns", "exec", m.natNS,
		"nft", "add", "rule", "ip", "qmb", "forward",
		"iifname", middleboxNATClientDev, "udp", "dport", strconv.Itoa(cellPort),
		"numgen", "inc", "mod", "2", "==", "0", "drop")
}

func (m *middleboxNet) namespacePath(namespace string) string {
	return "/run/netns/" + namespace
}

// listenCellUDP binds the test cell's real UDP socket on the server-side veth
// address inside the server namespace. The caller owns the socket; wrapping
// it in newReassignmentTestUDPServerOn hands ownership to that rig's cleanup.
func (m *middleboxNet) listenCellUDP() *net.UDPConn {
	m.t.Helper()
	var conn *net.UDPConn
	err := inNetworkNamespace(m.namespacePath(m.serverNS), func() error {
		c, listenErr := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(middleboxServerIP)})
		conn = c
		return listenErr
	})
	if err != nil {
		m.t.Fatalf("listen cell UDP inside %s: %v", m.serverNS, err)
	}
	return conn
}

// clientDialer returns the knocker-side transport: every SDK dial, whichever
// fake-public resolved address it targets, produces a connected UDP socket
// created inside the client namespace and aimed at the real in-namespace cell
// address — so each exchange attempt crosses the middlebox exactly like a
// NAT'd production client, while per-address dial counts stay observable.
func (m *middleboxNet) clientDialer(cellAddress string) *middleboxDialer {
	return &middleboxDialer{
		nsPath: m.namespacePath(m.clientNS),
		target: cellAddress,
		dials:  make(map[string]int),
	}
}

type middleboxDialer struct {
	nsPath string
	target string

	mu    sync.Mutex
	dials map[string]int
}

func (d *middleboxDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.dials[host]++
	d.mu.Unlock()
	var conn net.Conn
	err = inNetworkNamespace(d.nsPath, func() error {
		c, dialErr := (&net.Dialer{}).DialContext(ctx, network, d.target)
		conn = c
		return dialErr
	})
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (d *middleboxDialer) count(host string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials[host]
}

func (d *middleboxDialer) total() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	sum := 0
	for _, n := range d.dials {
		sum += n
	}
	return sum
}

// inNetworkNamespace runs fn with the calling OS thread switched into the
// network namespace at nsPath, so sockets fn creates are born inside it (a
// socket keeps its namespace for life; later reads/writes need no pinning).
// If the original namespace cannot be restored the thread is deliberately
// left locked, so the runtime retires it with the goroutine instead of ever
// scheduling unrelated goroutines onto a thread stuck inside the emulation.
func inNetworkNamespace(nsPath string, fn func() error) (err error) {
	runtime.LockOSThread()
	original, openErr := os.Open("/proc/thread-self/ns/net")
	if openErr != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("open current network namespace: %w", openErr)
	}
	defer func() { _ = original.Close() }()
	handle, openErr := os.Open(nsPath)
	if openErr != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("open network namespace %s: %w", nsPath, openErr)
	}
	defer func() { _ = handle.Close() }()
	if setErr := unix.Setns(int(handle.Fd()), unix.CLONE_NEWNET); setErr != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("enter network namespace %s: %w", nsPath, setErr)
	}
	defer func() {
		if restoreErr := unix.Setns(int(original.Fd()), unix.CLONE_NEWNET); restoreErr != nil {
			err = errors.Join(err, fmt.Errorf("restore original network namespace: %w", restoreErr))
			return
		}
		runtime.UnlockOSThread()
	}()
	return fn()
}
