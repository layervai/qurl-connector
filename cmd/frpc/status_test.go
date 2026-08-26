package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"

	"github.com/layervai/qurl-connector/pkg/agentstate"
	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

// withCapturedStdout runs fn with os.Stdout redirected to a captured
// buffer. Like the package-level config/status globals in the tests
// below, this is not parallel-safe.
func withCapturedStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	t.Cleanup(func() {
		os.Stdout = orig
		_ = w.Close()
		_ = r.Close()
	})
	runErr := fn()
	_ = w.Close()
	buf, _ := io.ReadAll(r)
	return string(buf), runErr
}

func TestRunStatusJSONReportsAdminAuthUnavailable(t *testing.T) {
	dir := t.TempDir()
	isolateConnectorStateForTest(t, dir)
	cfgPath := filepath.Join(dir, "qurl-proxy.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
server:
  addr: boundary.example.com
  port: 7000
  protocol: tcp
admin:
  enabled: true
  addr: 127.0.0.1
  port: 7400
routes:
  - id: web
    type: http
    local_ip: 127.0.0.1
    local_port: 8080
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	prevCfgFile := cfgFile
	prevStatusJSON := statusJSON
	cfgFile = cfgPath
	statusJSON = true
	t.Cleanup(func() {
		cfgFile = prevCfgFile
		statusJSON = prevStatusJSON
	})
	setCachedMachineIDForTest(t, unknownMachineID)

	out, err := withCapturedStdout(t, func() error {
		return runStatus(nil, nil)
	})
	if err != nil {
		t.Fatalf("runStatus returned error: %v", err)
	}

	var got statusOutput
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("status JSON did not parse: %v\noutput:\n%s", err, out)
	}
	if !got.AdminAuthUnavailable {
		t.Fatalf("AdminAuthUnavailable = false, want true; output:\n%s", out)
	}
	if got.Running {
		t.Fatalf("Running = true, want false when admin auth password is unavailable")
	}
}

func TestRunStatusJSONHydratesCachedResourceIDReadOnly(t *testing.T) {
	dir := realPrivateConnectorTestDir(t)
	stateDir := filepath.Join(dir, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(agentstate.EnvStateDirPrimary, stateDir)
	seedConnectorIdentityCacheForTest(t, stateDir, "web", testPublicResourceID)
	cfgPath := filepath.Join(dir, "qurl-proxy.yaml")
	raw := []byte("routes:\n  - id: web\n    type: http\n    local_ip: 127.0.0.1\n    local_port: 8080\n")
	if err := os.WriteFile(cfgPath, raw, 0o400); err != nil {
		t.Fatal(err)
	}

	previousCfgFile, previousJSON := cfgFile, statusJSON
	cfgFile, statusJSON = cfgPath, true
	t.Cleanup(func() { cfgFile, statusJSON = previousCfgFile, previousJSON })
	out, err := withCapturedStdout(t, func() error { return runStatus(nil, nil) })
	if err != nil {
		t.Fatal(err)
	}
	var got statusOutput
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("status JSON did not parse: %v\n%s", err, out)
	}
	if len(got.Routes) != 1 || got.Routes[0].ResourceID != testPublicResourceID {
		t.Fatalf("status routes = %#v, want cached resource_id", got.Routes)
	}
	after, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(raw) {
		t.Fatalf("status mutated YAML: got %q want %q", after, raw)
	}
}

func TestRunStatusJSONMatchesSaltedProxyWithoutYAMLDiscriminator(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/status" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"http":[{"name":"web-daemon-salt","status":"running","remote_addr":"edge.example.com:443"}]}`)
	}))
	t.Cleanup(admin.Close)
	host, portText, err := net.SplitHostPort(admin.Listener.Addr().String())
	if err != nil {
		t.Fatalf("admin addr parse: %v", err)
	}

	dir := t.TempDir()
	isolateConnectorStateForTest(t, dir)
	cfgPath := filepath.Join(dir, "qurl-proxy.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
server:
  addr: boundary.example.com
  port: 7000
  protocol: tcp
admin:
  enabled: true
  addr: `+host+`
  port: `+portText+`
  password: secret
routes:
  - id: web
    type: http
    local_ip: 127.0.0.1
    local_port: 8080
    resource_id: `+testPublicResourceID+`
    connector_routing_id: c-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	prevCfgFile := cfgFile
	prevStatusJSON := statusJSON
	cfgFile = cfgPath
	statusJSON = true
	t.Cleanup(func() {
		cfgFile = prevCfgFile
		statusJSON = prevStatusJSON
	})

	out, err := withCapturedStdout(t, func() error {
		return runStatus(nil, nil)
	})
	if err != nil {
		t.Fatalf("runStatus returned error: %v", err)
	}

	var got statusOutput
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("status JSON did not parse: %v\noutput:\n%s", err, out)
	}
	if !got.Running {
		t.Fatalf("Running = false, want true; output:\n%s", out)
	}
	if len(got.Routes) != 1 {
		t.Fatalf("got %d routes, want 1; output:\n%s", len(got.Routes), out)
	}
	route := got.Routes[0]
	if route.ID != "web" {
		t.Fatalf("route ID = %q, want web", route.ID)
	}
	if route.Status != "running" {
		t.Errorf("route Status = %q, want running", route.Status)
	}
	if route.RemoteAddr != "edge.example.com:443" {
		t.Errorf("route RemoteAddr = %q, want edge.example.com:443", route.RemoteAddr)
	}
}

// TestBuildRouteStatuses_PrecedenceOrder pins the per-route status
// resolution precedence that pollers + the human-readable renderer
// both depend on. The four branches in buildRouteStatuses must
// resolve in this order:
//
//  1. Live proxy entry present → use FRP's own Status (and Err if set).
//  2. adminDisabled → "admin disabled" (operator opted out of probe).
//  3. !running && !adminDisabled → "connector offline" (daemon down).
//  4. fall-through default → "not running" (initial value; never
//     observed in practice because (3) catches all probe failures
//     not covered by (2)).
//
// A regression that swaps (2) and (3) would show "connector offline" on
// every route when admin is gated off — misleading because the FRP
// daemon may well be running, we just can't introspect it. Pinning
// the order here catches that without needing an httptest.Server.
func TestBuildRouteStatuses_PrecedenceOrder(t *testing.T) {
	cfg := &nhpconfig.Config{
		Routes: []nhpconfig.Route{
			{ID: "live", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 80},
			{ID: "live-with-err", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 81},
			{ID: "no-live-entry", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 82},
		},
	}
	proxyMap := map[string][]adminProxyStatus{
		"http": {
			{Name: "live", Status: "running", RemoteAddr: "example.com:443"},
			{Name: "live-with-err", Status: "running", Err: "upstream unreachable"},
		},
	}

	cases := []struct {
		name          string
		running       bool
		adminDisabled bool
		wantStatuses  map[string]string
	}{
		{
			// Running daemon + admin enabled: a route absent from FRP's
			// proxy map is the "registration pending" window — keep the
			// initial "not running" value rather than falsely claiming
			// the daemon is offline.
			name:          "running daemon + no live entry → keeps initial not running",
			running:       true,
			adminDisabled: false,
			wantStatuses: map[string]string{
				"live":          "running",
				"live-with-err": "error: upstream unreachable",
				"no-live-entry": "not running",
			},
		},
		{
			name:          "no entry + adminDisabled → admin disabled",
			running:       false,
			adminDisabled: true,
			wantStatuses: map[string]string{
				"live":          "running",
				"live-with-err": "error: upstream unreachable",
				"no-live-entry": "admin disabled",
			},
		},
		{
			name:          "no entry + !running + !adminDisabled → connector offline",
			running:       false,
			adminDisabled: false,
			wantStatuses: map[string]string{
				"live":          "running",
				"live-with-err": "error: upstream unreachable",
				"no-live-entry": "connector offline",
			},
		},
		{
			name:          "live entry still wins even when adminDisabled is also set (impossible state but defensive)",
			running:       false,
			adminDisabled: true,
			wantStatuses: map[string]string{
				"live":          "running",
				"live-with-err": "error: upstream unreachable",
				"no-live-entry": "admin disabled",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildRouteStatuses(cfg, proxyMap, tc.running, tc.adminDisabled)
			if len(got) != len(cfg.Routes) {
				t.Fatalf("got %d routes, want %d", len(got), len(cfg.Routes))
			}
			for _, rs := range got {
				want, ok := tc.wantStatuses[rs.ID]
				if !ok {
					t.Errorf("unexpected route %q in output", rs.ID)
					continue
				}
				if rs.Status != want {
					t.Errorf("route %q Status = %q, want %q", rs.ID, rs.Status, want)
				}
			}
		})
	}
}

// TestBuildRouteStatuses_NilCfgReturnsNil pins the load/discover-
// error case: when cfg is nil (discovery error OR cfg failed Load),
// buildRouteStatuses returns nil rather than an empty slice. The
// caller-side renderer distinguishes nil-cfg ("No routes configured"
// hint) from empty-routes (legitimate "no routes after merge"), and
// a regression to returning [] would muddle the two cases in the
// JSON output.
func TestBuildRouteStatuses_NilCfgReturnsNil(t *testing.T) {
	got := buildRouteStatuses(nil, nil, false, false)
	if got != nil {
		t.Errorf("buildRouteStatuses(nil cfg) = %v, want nil (load-failed/discover-failed paths depend on this signal)", got)
	}
}

// TestBuildRouteStatuses_LivePropagatesRemoteAddr pins that the
// RemoteAddr from the live proxy entry round-trips into the
// routeStatus output. Pollers read RemoteAddr to display "where is
// this route registered" — a regression that dropped it would
// silently break the status table.
func TestBuildRouteStatuses_LivePropagatesRemoteAddr(t *testing.T) {
	cfg := &nhpconfig.Config{
		Routes: []nhpconfig.Route{
			{ID: "web", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 80},
		},
	}
	proxyMap := map[string][]adminProxyStatus{
		"http": {
			{Name: "web", Status: "running", RemoteAddr: "tucker.example.com:443"},
		},
	}
	got := buildRouteStatuses(cfg, proxyMap, true, false)
	if len(got) != 1 {
		t.Fatalf("got %d routes, want 1", len(got))
	}
	if got[0].RemoteAddr != "tucker.example.com:443" {
		t.Errorf("RemoteAddr = %q, want %q", got[0].RemoteAddr, "tucker.example.com:443")
	}
}

func TestBuildRouteStatuses_MatchesSaltedRuntimeProxyName(t *testing.T) {
	cfg := &nhpconfig.Config{
		Server: nhpconfig.ServerConfig{
			ReplicaDiscriminator: "replica-a",
		},
		Routes: []nhpconfig.Route{
			{ID: "web", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080, ResourceID: "r_abc123"},
		},
	}
	proxyMap := map[string][]adminProxyStatus{
		"http": {
			{Name: "web-replica-a", Status: "running", RemoteAddr: "edge.example.com:443"},
		},
	}
	got := buildRouteStatuses(cfg, proxyMap, true, false)
	if len(got) != 1 {
		t.Fatalf("got %d routes, want 1", len(got))
	}
	if got[0].ID != "web" {
		t.Fatalf("ID = %q, want web", got[0].ID)
	}
	if got[0].Status != "running" {
		t.Errorf("Status = %q, want running", got[0].Status)
	}
	if got[0].RemoteAddr != "edge.example.com:443" {
		t.Errorf("RemoteAddr = %q, want edge.example.com:443", got[0].RemoteAddr)
	}
	if got[0].ResourceID != "r_abc123" {
		t.Errorf("ResourceID = %q, want r_abc123", got[0].ResourceID)
	}
}

func TestBuildRouteStatuses_FallsBackToRawProxyName(t *testing.T) {
	cfg := &nhpconfig.Config{
		Server: nhpconfig.ServerConfig{
			ReplicaDiscriminator: "replica-a",
		},
		Routes: []nhpconfig.Route{
			{ID: "web", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080},
		},
	}
	proxyMap := map[string][]adminProxyStatus{
		"http": {
			{Name: "web", Status: "running", RemoteAddr: "legacy.example.com:443"},
		},
	}
	got := buildRouteStatuses(cfg, proxyMap, true, false)
	if len(got) != 1 {
		t.Fatalf("got %d routes, want 1", len(got))
	}
	if got[0].Status != "running" {
		t.Errorf("Status = %q, want running", got[0].Status)
	}
	if got[0].RemoteAddr != "legacy.example.com:443" {
		t.Errorf("RemoteAddr = %q, want legacy.example.com:443", got[0].RemoteAddr)
	}
}

func TestBuildRouteStatuses_FallsBackToSaltedPrefixForRandomDiscriminator(t *testing.T) {
	cfg := &nhpconfig.Config{
		Server: nhpconfig.ServerConfig{
			ReplicaDiscriminator: "fresh-status-random",
		},
		Routes: []nhpconfig.Route{
			{ID: "web", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080},
		},
	}
	proxyMap := map[string][]adminProxyStatus{
		"http": {
			{Name: "web-daemon-random", Status: "running", RemoteAddr: "random.example.com:443"},
		},
	}
	got := buildRouteStatuses(cfg, proxyMap, true, false)
	if len(got) != 1 {
		t.Fatalf("got %d routes, want 1", len(got))
	}
	if got[0].Status != "running" {
		t.Errorf("Status = %q, want running", got[0].Status)
	}
	if got[0].RemoteAddr != "random.example.com:443" {
		t.Errorf("RemoteAddr = %q, want random.example.com:443", got[0].RemoteAddr)
	}
}

func TestBuildRouteStatuses_PrefixFallbackSkipsLongerRouteID(t *testing.T) {
	cfg := &nhpconfig.Config{
		Server: nhpconfig.ServerConfig{
			ReplicaDiscriminator: "fresh-status-random",
		},
		Routes: []nhpconfig.Route{
			{ID: "web", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080},
			{ID: "web-api", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8081},
		},
	}
	proxyMap := map[string][]adminProxyStatus{
		"http": {
			{Name: "web-api-daemon-random", Status: "running", RemoteAddr: "api.example.com:443"},
		},
	}
	got := buildRouteStatuses(cfg, proxyMap, true, false)
	if len(got) != 2 {
		t.Fatalf("got %d routes, want 2", len(got))
	}
	byID := map[string]routeStatus{}
	for _, rs := range got {
		byID[rs.ID] = rs
	}
	if byID["web"].Status != "not running" {
		t.Errorf("web Status = %q, want not running (must not steal web-api salted proxy)", byID["web"].Status)
	}
	if byID["web-api"].Status != "running" {
		t.Errorf("web-api Status = %q, want running", byID["web-api"].Status)
	}
	if byID["web-api"].RemoteAddr != "api.example.com:443" {
		t.Errorf("web-api RemoteAddr = %q, want api.example.com:443", byID["web-api"].RemoteAddr)
	}
}

func TestBuildRouteStatuses_PrefixFallbackSkipsRawLongerRouteID(t *testing.T) {
	cfg := &nhpconfig.Config{
		Server: nhpconfig.ServerConfig{
			ReplicaDiscriminator: "fresh-status-random",
		},
		Routes: []nhpconfig.Route{
			{ID: "web", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080},
			{ID: "web-api", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8081},
		},
	}
	proxyMap := map[string][]adminProxyStatus{
		"http": {
			{Name: "web-api", Status: "running", RemoteAddr: "api.example.com:443"},
		},
	}
	got := buildRouteStatuses(cfg, proxyMap, true, false)
	if len(got) != 2 {
		t.Fatalf("got %d routes, want 2", len(got))
	}
	byID := map[string]routeStatus{}
	for _, rs := range got {
		byID[rs.ID] = rs
	}
	if byID["web"].Status != "not running" {
		t.Errorf("web Status = %q, want not running (must not steal web-api raw proxy)", byID["web"].Status)
	}
	if byID["web-api"].Status != "running" {
		t.Errorf("web-api Status = %q, want running", byID["web-api"].Status)
	}
	if byID["web-api"].RemoteAddr != "api.example.com:443" {
		t.Errorf("web-api RemoteAddr = %q, want api.example.com:443", byID["web-api"].RemoteAddr)
	}
}

func TestBuildRouteStatuses_UsesEnvIDFallbackForSingleRoute(t *testing.T) {
	t.Setenv(envConnectorID, "env-supplied")
	cfg := &nhpconfig.Config{
		Routes: []nhpconfig.Route{
			{Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080},
		},
	}
	proxyMap := map[string][]adminProxyStatus{
		"http": {
			{Name: "env-supplied", Status: "running", RemoteAddr: "edge.example.com:443"},
		},
	}
	got := buildRouteStatuses(cfg, proxyMap, true, false)
	if len(got) != 1 {
		t.Fatalf("got %d routes, want 1", len(got))
	}
	if got[0].ID != "env-supplied" {
		t.Fatalf("ID = %q, want env-supplied", got[0].ID)
	}
	if got[0].Status != "running" {
		t.Errorf("Status = %q, want running", got[0].Status)
	}
	if got[0].RemoteAddr != "edge.example.com:443" {
		t.Errorf("RemoteAddr = %q, want edge.example.com:443", got[0].RemoteAddr)
	}
}

func TestTruncatePreservesUTF8(t *testing.T) {
	got := truncate("héllo世界", 6)
	if got != "hél..." {
		t.Fatalf("truncate returned %q, want hél...", got)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("truncate returned invalid UTF-8: %q", got)
	}
}

func TestTruncateSmallMaxUsesEllipsis(t *testing.T) {
	tests := []struct {
		max  int
		want string
	}{
		{max: 3, want: "..."},
		{max: 2, want: ".."},
		{max: 1, want: "."},
		{max: 0, want: ""},
		{max: -1, want: ""},
	}

	for _, tc := range tests {
		if got := truncate("abcdef", tc.max); got != tc.want {
			t.Fatalf("truncate max=%d returned %q, want %q", tc.max, got, tc.want)
		}
	}
}
