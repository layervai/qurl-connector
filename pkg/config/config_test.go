package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testRoutingA        = "c-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testRoutingB        = "c-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbq"
	testRoutingC        = "c-ccccccccccccccccccccccccccccccccccccccccccccccccccca"
	testRoutingZ        = "c-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzq"
	testPublicResourceA = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2vPoafaVb5Lue-bfcCuoL-_CnVBKf8YvV94G8ozebA6RHEQUPsnguSt1yx2mTzDSogBmb9WYEVBDgX7vc2NKTg"
	testPublicResourceB = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcOtuxu2qhc3gt1E7BiEU0CLqEDlXDwzZq0JnESgMAwERX6y_XXF5Cn5SKITWIZQmUhCZ0pHHlVn7SmFUTAnTGQ"
)

// writeConfig writes YAML content to a temporary file and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "qurl-proxy.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}
	return p
}

func TestLoadAcceptsAndDropsRetiredGeneratedFields(t *testing.T) {
	t.Setenv(EnvAuditFile, "")
	path := writeConfig(t, `
server:
  addr: frp.example
  public_domain: qurl.site
  port: 7000
  protocol: websocket
nhp:
  enabled: true
  machine_id: machine-1
qurl:
  api_url: https://api.example/v1
  token: token-1
admin:
  enabled: false
  addr: 127.0.0.1
  port: 7400
audit:
  enabled: false
  file_path: /tmp/connector-audit.log
  mirror_slog: false
routes:
  - id: web
    type: http
    local_port: 8080
  - id: api
    type: http
    local_ip: 127.0.0.2
    local_port: 8443
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Addr != "frp.example" || cfg.Server.Port != 7000 || cfg.Server.Protocol != "websocket" ||
		!cfg.NHP.Enabled || cfg.NHP.MachineID != "machine-1" || cfg.QURL.APIURL != "https://api.example/v1" ||
		cfg.QURL.Token != "token-1" || cfg.Audit.FilePath != "/tmp/connector-audit.log" || len(cfg.Routes) != 2 ||
		cfg.Routes[1].ID != "api" || cfg.Routes[1].Type != RouteTypeHTTP || cfg.Routes[1].LocalIP != "127.0.0.2" || cfg.Routes[1].LocalPort != 8443 {
		t.Fatalf("retired-field strip changed sibling config: %#v", cfg)
	}
	savedPath := filepath.Join(t.TempDir(), "saved.yaml")
	if err := Save(cfg, savedPath); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "public_domain:") || strings.Contains(string(raw), "admin:") {
		t.Fatalf("Save retained retired generated fields:\n%s", raw)
	}
}

func TestStripRetiredGeneratedFieldsPreservesCleanBytes(t *testing.T) {
	const input = "\n# keep operator line numbers\nroutes:\n  - id: web\n    type: http\n    local_port: 8080\n"
	got, err := stripRetiredGeneratedFields(input)
	if err != nil {
		t.Fatal(err)
	}
	if got != input {
		t.Fatalf("clean config changed:\n%s", got)
	}
}

func TestLoadRejectsOtherRetiredFRPFields(t *testing.T) {
	tests := []struct {
		name  string
		field string
		yaml  string
	}{
		{"server token", "token", "server:\n  token: old\n"},
		{"subdomain", "subdomain", "routes:\n  - id: web\n    type: http\n    local_port: 8080\n    subdomain: old\n"},
		{"custom domains", "custom_domains", "routes:\n  - id: web\n    type: http\n    local_port: 8080\n    custom_domains: [old.example]\n"},
		{"remote port", "remote_port", "routes:\n  - id: web\n    type: http\n    local_port: 8080\n    remote_port: 7001\n"},
		{"host rewrite", "host_rewrite", "routes:\n  - id: web\n    type: http\n    local_port: 8080\n    host_rewrite: old.example\n"},
		{"headers", "headers", "routes:\n  - id: web\n    type: http\n    local_port: 8080\n    headers: {X-Test: value}\n"},
		{"load balancer group", "load_balancer_group", "routes:\n  - id: web\n    type: http\n    local_port: 8080\n    load_balancer_group: old\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tt.yaml))
			if err == nil || !strings.Contains(err.Error(), "field "+tt.field+" not found") {
				t.Fatalf("Load error = %v, want strict rejection of %s", err, tt.field)
			}
		})
	}
}

func TestLoad_StaticServerAddrRequiresPort(t *testing.T) {
	yaml := `
server:
  addr: example.com
routes:
  - id: web
    type: http
    local_port: 80
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected error for static server.addr without server.port")
	}
	if !strings.Contains(err.Error(), "server.addr and server.port must be set together") {
		t.Fatalf("error = %q, want addr/port pairing diagnostic", err.Error())
	}
}

func TestLoad_DefaultLocalIP(t *testing.T) {
	yaml := `
routes:
  - id: web
    type: http
    local_port: 80
`
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Routes[0].LocalIP != "127.0.0.1" {
		t.Errorf("default local_ip = %q, want 127.0.0.1", cfg.Routes[0].LocalIP)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_StaticServerPortRequiresAddr(t *testing.T) {
	yaml := `
server:
  port: 7000
routes:
  - id: web
    type: http
    local_port: 80
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected error for static server.port without server.addr")
	}
	if !strings.Contains(err.Error(), "server.addr and server.port must be set together") {
		t.Fatalf("error = %q, want addr/port pairing diagnostic", err.Error())
	}
}

func TestLoad_EmptyServerTargetPreservesNHPAckDialTarget(t *testing.T) {
	yaml := `
routes:
  - id: web
    type: http
    local_port: 80
`
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Routes) != 1 {
		t.Errorf("expected 1 route, got %d", len(cfg.Routes))
	}
	if cfg.Server.Addr != "" {
		t.Errorf("server.addr = %q, want empty so NHP ACK supplies the dial target", cfg.Server.Addr)
	}
	if cfg.Server.Port != 0 {
		t.Errorf("server.port = %d, want empty so NHP ACK supplies the dial target", cfg.Server.Port)
	}
}

func TestLoad_MissingRouteID(t *testing.T) {
	yaml := `
server:
  addr: example.com
  port: 7000
routes:
  - id: web
    type: http
    local_port: 80
  - type: http
    local_port: 81
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for missing route id")
	}
}

func TestLoad_AllowsSingleRouteIDFromEnvFallback(t *testing.T) {
	yaml := `
server:
  addr: example.com
  port: 7000
routes:
  - type: http
    local_port: 80
`
	if _, err := Load(writeConfig(t, yaml)); err != nil {
		t.Fatalf("single unpinned route without id should load so QURL_CONNECTOR_ID can supply it at runtime: %v", err)
	}
}

func TestLoadAppliesEgressLocalIPEnvOverride(t *testing.T) {
	t.Setenv("QURL_CONNECTOR_EGRESS_LOCAL_IP", " 192.0.2.10 ")
	cfg, err := Load(writeConfig(t, `
routes:
  - id: web
    type: http
    local_port: 80
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Server.EgressLocalIP; got != "192.0.2.10" {
		t.Fatalf("server.egress_local_ip = %q, want env override", got)
	}
}

func TestLoad_AllowsPinnedRouteIDOutsideSlugRegex(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "explicit id",
			yaml: fmt.Sprintf(`
server:
  addr: example.com
  port: 7000
routes:
  - id: "My App"
    type: http
    local_port: 80
    resource_id: %s
    connector_routing_id: c-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
`, testPublicResourceA),
			want: "My App",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(writeConfig(t, tc.yaml))
			if err != nil {
				t.Fatalf("Load pinned route with non-slug id: %v", err)
			}
			if got := cfg.Routes[0].ID; got != tc.want {
				t.Fatalf("Route.ID = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLoad_DuplicateRouteIDs(t *testing.T) {
	yaml := `
server:
  addr: example.com
  port: 7000
routes:
  - id: web
    type: http
    local_port: 80
  - id: web
    type: http
    local_port: 81
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for duplicate route ids")
	}
}

func TestLoad_DuplicatePinnedRouteIDs(t *testing.T) {
	yaml := `
server:
  addr: example.com
  port: 7000
routes:
  - id: "My App"
    type: http
    local_port: 80
    resource_id: r_first000000
  - id: "My App"
    type: http
    local_port: 81
    resource_id: r_second00000
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for duplicate pinned route ids")
	}
	if !strings.Contains(err.Error(), `duplicate route id "My App"`) {
		t.Fatalf("error = %q, want duplicate pinned route id", err.Error())
	}
}

func TestLoad_InvalidPortRanges(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "server port too high",
			yaml: `
server:
  addr: example.com
  port: 65536
routes:
  - id: web
    type: http
    local_port: 80
`,
		},
		{
			name: "server port negative",
			yaml: `
server:
  addr: example.com
  port: -1
routes:
  - id: web
    type: http
    local_port: 80
`,
		},
		{
			name: "local port 0",
			yaml: `
server:
  addr: example.com
  port: 7000
routes:
  - id: web
    type: http
    local_port: 0
`,
		},
		{
			name: "local port too high",
			yaml: `
server:
  addr: example.com
  port: 7000
routes:
  - id: web
    type: http
    local_port: 65536
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tt.yaml))
			if err == nil {
				t.Fatalf("expected validation error for %s", tt.name)
			}
		})
	}
}

func TestLoad_HTTPRoute(t *testing.T) {
	yaml := `
server:
  addr: example.com
  port: 7000
routes:
  - id: web
    type: http
    local_port: 80
`
	_, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoad_UnsupportedRouteType(t *testing.T) {
	yaml := `
server:
  addr: example.com
  port: 7000
routes:
  - id: web
    type: frp_udp
    local_port: 80
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for unsupported route type")
	}
}

func TestLoad_RejectsInternalFRPRouteType(t *testing.T) {
	tests := []struct {
		name string
		typ  string
		want string
	}{
		{name: "http", typ: "frp_http", want: `unsupported route type "frp_http"; use type: http`},
		{name: "tcp", typ: "frp_tcp", want: `unsupported route type "frp_tcp"; use type: http`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := fmt.Sprintf(`
server:
  addr: example.com
  port: 7000
routes:
  - id: web
    type: %s
    local_port: 80
`, tt.typ)
			_, err := Load(writeConfig(t, yaml))
			if err == nil {
				t.Fatal("expected validation error for internal route type")
			}
			if got := err.Error(); !strings.Contains(got, tt.want) {
				t.Fatalf("error = %q, want substring %q", got, tt.want)
			}
		})
	}
}

func TestResolveEnvVars_Basic(t *testing.T) {
	t.Setenv("QURL_TEST_HOST", "myhost.example.com")
	result := resolveEnvVars("${QURL_TEST_HOST}")
	if result != "myhost.example.com" {
		t.Errorf("got %q, want %q", result, "myhost.example.com")
	}
}

func TestResolveEnvVars_WithDefault(t *testing.T) {
	// Ensure the var is not set.
	t.Setenv("QURL_TEST_UNSET_99", "")
	_ = os.Unsetenv("QURL_TEST_UNSET_99")

	result := resolveEnvVars("${QURL_TEST_UNSET_99:-fallback}")
	if result != "fallback" {
		t.Errorf("got %q, want %q", result, "fallback")
	}
}

func TestResolveEnvVars_MissingNoDefault(t *testing.T) {
	_ = os.Unsetenv("QURL_TEST_MISSING_42")
	result := resolveEnvVars("${QURL_TEST_MISSING_42}")
	if result != "" {
		t.Errorf("got %q, want empty string", result)
	}
}

func TestResolveEnvVars_SetOverridesDefault(t *testing.T) {
	t.Setenv("QURL_TEST_OVERRIDE", "real")
	result := resolveEnvVars("${QURL_TEST_OVERRIDE:-fallback}")
	if result != "real" {
		t.Errorf("got %q, want %q", result, "real")
	}
}

func TestResolveEnvVars_InYAML(t *testing.T) {
	t.Setenv("QURL_TEST_ADDR", "remote.host")

	yaml := `
server:
  addr: ${QURL_TEST_ADDR}
  port: 7000
routes:
  - id: web
    type: http
    local_port: 80
`
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Addr != "remote.host" {
		t.Errorf("server.addr = %q, want %q", cfg.Server.Addr, "remote.host")
	}
}

func TestLoad_DefaultProtocol(t *testing.T) {
	yaml := `
server:
  addr: example.com
  port: 7000
routes:
  - id: web
    type: http
    local_port: 80
`
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Protocol != "tcp" {
		t.Errorf("default protocol = %q, want %q", cfg.Server.Protocol, "tcp")
	}
}

func TestLoad_ExplicitProtocol(t *testing.T) {
	yaml := `
server:
  addr: example.com
  port: 7000
  protocol: kcp
routes:
  - id: web
    type: http
    local_port: 80
`
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Protocol != "kcp" {
		t.Errorf("protocol = %q, want %q (explicit value should not be overwritten)", cfg.Server.Protocol, "kcp")
	}
}

func TestLoad_TransportDefaults(t *testing.T) {
	yaml := `
server:
  addr: example.com
  port: 7000
routes:
  - id: web
    type: http
    local_port: 80
`
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Keepalive != 60 {
		t.Errorf("default keepalive = %d, want 60", cfg.Server.Keepalive)
	}
	if cfg.Server.DialTimeout != 10 {
		t.Errorf("default dial_timeout = %d, want 10", cfg.Server.DialTimeout)
	}
	if cfg.Server.LoginFailExit == nil {
		t.Fatal("default login_fail_exit should not be nil")
	}
	if *cfg.Server.LoginFailExit != false {
		t.Errorf("default login_fail_exit = %v, want false", *cfg.Server.LoginFailExit)
	}
}

func TestLoad_TransportCustom(t *testing.T) {
	yaml := `
server:
  addr: example.com
  port: 7000
  keepalive: 30
  dial_timeout: 5
  login_fail_exit: true
routes:
  - id: web
    type: http
    local_port: 80
`
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Keepalive != 30 {
		t.Errorf("keepalive = %d, want 30", cfg.Server.Keepalive)
	}
	if cfg.Server.DialTimeout != 5 {
		t.Errorf("dial_timeout = %d, want 5", cfg.Server.DialTimeout)
	}
	if cfg.Server.LoginFailExit == nil {
		t.Fatal("login_fail_exit should not be nil")
	}
	if *cfg.Server.LoginFailExit != true {
		t.Errorf("login_fail_exit = %v, want true", *cfg.Server.LoginFailExit)
	}
}

// TestNewDefaulted verifies that NewDefaulted seeds the same defaults
// Load applies, so the fresh-config path in `qurl-connector add` writes a
// fully-populated YAML rather than a sparse one. The contract is the
// callable surface used from cmd/frpc/add.go; if a future refactor
// changes Save's behavior to no longer rely on populated fields, the
// fresh-config UX still benefits from having them written.
func TestNewDefaulted(t *testing.T) {
	cfg := NewDefaulted()
	if cfg == nil {
		t.Fatal("NewDefaulted returned nil")
	}
	if cfg.Server.Addr != "" {
		t.Errorf("Server.Addr = %q, want empty so NHP ACK supplies the dial target", cfg.Server.Addr)
	}
	if cfg.Server.Port != 0 {
		t.Errorf("Server.Port = %d, want 0 so NHP ACK supplies the port", cfg.Server.Port)
	}
	if cfg.Server.Protocol != "tcp" {
		t.Errorf("Server.Protocol = %q, want %q", cfg.Server.Protocol, "tcp")
	}
	if cfg.Server.Keepalive != 60 {
		t.Errorf("Server.Keepalive = %d, want 60", cfg.Server.Keepalive)
	}
	if cfg.Server.DialTimeout != 10 {
		t.Errorf("Server.DialTimeout = %d, want 10", cfg.Server.DialTimeout)
	}
	if cfg.Server.LoginFailExit == nil || *cfg.Server.LoginFailExit != false {
		t.Errorf("Server.LoginFailExit = %v, want pointer-to-false", cfg.Server.LoginFailExit)
	}
}

func TestConfig_RoutingAndPublicIdentityStaySeparate(t *testing.T) {
	cfg := &Config{Routes: []Route{{
		ID: "managed", ResourceID: testPublicResourceA, ConnectorRoutingID: testRoutingA,
	}}}
	if got := cfg.PrimaryResourceID(); got != testPublicResourceA {
		t.Fatalf("PrimaryResourceID = %q, want public identity", got)
	}
	cfg.SetKnockResourceID(testPublicResourceA, "qurl-tunnel-server")
	if got := cfg.KnockResourceID(cfg.PrimaryResourceID()); got != "qurl-tunnel-server" {
		t.Fatalf("KnockResourceID(public identity) = %q", got)
	}
}

func TestLoad_PinnedResourcePendingRoutingHydration(t *testing.T) {
	yaml := fmt.Sprintf(`
routes:
  - id: pinned
    type: http
    local_port: 8080
    resource_id: %s
`, testPublicResourceA)
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("Load must allow API-backed routing hydration: %v", err)
	}
	if cfg.Routes[0].ResourceID != testPublicResourceA || cfg.Routes[0].ConnectorRoutingID != "" {
		t.Fatalf("Load altered incomplete managed identity: %+v", cfg.Routes[0])
	}
}

func TestConfigKnockResourceIDAccessors(t *testing.T) {
	var nilCfg *Config
	nilCfg.SetKnockResourceID("r_nil", "qurl-tunnel-server-a")
	if got := nilCfg.KnockResourceID("r_nil"); got != "" {
		t.Fatalf("nil Config KnockResourceID = %q, want empty", got)
	}

	cfg := &Config{}
	cfg.SetKnockResourceID("", "qurl-tunnel-server-a")
	cfg.SetKnockResourceID("r_empty", "")
	if len(cfg.Runtime.KnockResourceIDs) != 0 {
		t.Fatalf("empty inputs must not initialize/write KnockResourceIDs, got %#v", cfg.Runtime.KnockResourceIDs)
	}

	cfg.SetKnockResourceID("r_alpha", "qurl-tunnel-server-a")
	if got := cfg.KnockResourceID("r_alpha"); got != "qurl-tunnel-server-a" {
		t.Fatalf("KnockResourceID(r_alpha) = %q, want qurl-tunnel-server-a", got)
	}
	if got := cfg.KnockResourceID("r_missing"); got != "" {
		t.Fatalf("KnockResourceID(r_missing) = %q, want empty", got)
	}
}

func TestConfigFirstDifferentKnockResourceIDDeterministic(t *testing.T) {
	cfg := &Config{}
	cfg.SetKnockResourceID("r_zulu", "qurl-tunnel-server-c")
	cfg.SetKnockResourceID("r_alpha", "qurl-tunnel-server-a")
	cfg.SetKnockResourceID("r_same", "qurl-tunnel-server-b")

	resourceID, knockResourceID, ok := cfg.FirstDifferentKnockResourceID("r_new", "qurl-tunnel-server-b")
	if !ok {
		t.Fatal("expected a cross-resource knock_resource_id conflict")
	}
	if resourceID != "r_alpha" || knockResourceID != "qurl-tunnel-server-a" {
		t.Fatalf("FirstDifferentKnockResourceID returned (%q,%q), want sorted first conflict (r_alpha,qurl-tunnel-server-a)", resourceID, knockResourceID)
	}

	sameOnly := &Config{}
	sameOnly.SetKnockResourceID("r_same", "qurl-tunnel-server-b")
	if _, _, ok := sameOnly.FirstDifferentKnockResourceID("r_same", "qurl-tunnel-server-b"); ok {
		t.Fatal("same resource_id must not conflict with itself")
	}
	if _, _, ok := cfg.FirstDifferentKnockResourceID("r_new", "qurl-tunnel-server-a"); !ok {
		t.Fatal("different existing resource with a different knock_resource_id should conflict")
	}
}

func TestLoad_AuditDefaultsApplied(t *testing.T) {
	yaml := `
server:
  addr: example.com
  port: 7000
routes:
  - id: web
    type: http
    local_port: 80
`
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Audit.Enabled == nil || !*cfg.Audit.Enabled {
		t.Errorf("Audit.Enabled must default true")
	}
	if cfg.Audit.MirrorSlog == nil || !*cfg.Audit.MirrorSlog {
		t.Errorf("Audit.MirrorSlog must default true")
	}
	if cfg.Audit.FilePath != DefaultAuditFilePath {
		t.Errorf("Audit.FilePath = %q, want %q", cfg.Audit.FilePath, DefaultAuditFilePath)
	}
}

func TestLoad_AuditYAMLOverridesDefaults(t *testing.T) {
	yaml := `
server:
  addr: example.com
  port: 7000
audit:
  enabled: false
  file_path: /tmp/custom-audit.log
  mirror_slog: false
  max_size_mb: 50
  max_age_days: 30
  max_backups: 7
  compress: false
  buffer_size: 1024
routes:
  - id: web
    type: http
    local_port: 80
`
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Audit.Enabled == nil || *cfg.Audit.Enabled {
		t.Errorf("Audit.Enabled = %v, want false", cfg.Audit.Enabled)
	}
	if cfg.Audit.FilePath != "/tmp/custom-audit.log" {
		t.Errorf("Audit.FilePath = %q, want /tmp/custom-audit.log", cfg.Audit.FilePath)
	}
	if cfg.Audit.MirrorSlog == nil || *cfg.Audit.MirrorSlog {
		t.Errorf("Audit.MirrorSlog = %v, want false", cfg.Audit.MirrorSlog)
	}
	if cfg.Audit.MaxSizeMB != 50 {
		t.Errorf("Audit.MaxSizeMB = %d, want 50", cfg.Audit.MaxSizeMB)
	}
	if cfg.Audit.MaxAgeDays != 30 {
		t.Errorf("Audit.MaxAgeDays = %d, want 30", cfg.Audit.MaxAgeDays)
	}
	if cfg.Audit.MaxBackups != 7 {
		t.Errorf("Audit.MaxBackups = %d, want 7", cfg.Audit.MaxBackups)
	}
	if cfg.Audit.Compress == nil || *cfg.Audit.Compress {
		t.Errorf("Audit.Compress = %v, want false", cfg.Audit.Compress)
	}
	if cfg.Audit.BufferSize != 1024 {
		t.Errorf("Audit.BufferSize = %d, want 1024", cfg.Audit.BufferSize)
	}
}

func TestLoad_AuditFileEnvOverridesYAML(t *testing.T) {
	t.Setenv(EnvAuditFile, "/var/log/env-override.log")
	yaml := `
server:
  addr: example.com
  port: 7000
audit:
  file_path: /var/log/yaml-set.log
routes:
  - id: web
    type: http
    local_port: 80
`
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Audit.FilePath != "/var/log/env-override.log" {
		t.Errorf("Audit.FilePath = %q, want env override /var/log/env-override.log", cfg.Audit.FilePath)
	}
}

// `qurl-connector add` used to generate `nhp: enabled: false`, so the first
// `run` after the documented add command did nothing useful until the file was
// hand-edited. The native UDP path is the product, not an opt-in.
func TestNewDefaulted_EnablesNativeNHP(t *testing.T) {
	if !NewDefaulted().NHP.Enabled {
		t.Fatal("a newly generated config must enable native NHP")
	}
}

// The fence: applyDefaults must NOT flip it, or every existing config that
// turned NHP off on purpose would silently have it re-enabled on load. Enabled
// is a plain bool, so applyDefaults cannot tell "absent" from "explicitly
// false" -- which is exactly why the default belongs in NewDefaulted only.
func TestApplyDefaults_LeavesExplicitlyDisabledNHPAlone(t *testing.T) {
	cfg := &Config{}
	cfg.NHP.Enabled = false
	applyDefaults(cfg)
	if cfg.NHP.Enabled {
		t.Fatal("applyDefaults must not re-enable NHP on an existing config")
	}
}
