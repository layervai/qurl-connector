package config

import (
	"fmt"
	"io"
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

// captureStderr runs fn with os.Stderr redirected to a pipe and returns
// whatever fn wrote there. Used to assert the loud-warning contract on
// QURL_ADMIN_ENABLED, which is part of the security gate's UX.
//
// Safe against fn panicking: w.Close() runs in a deferred guard so the
// reader goroutine doesn't block forever. The panic re-raises after
// the read completes so the test still fails with a useful trace.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w

	done := make(chan string, 1)
	go func() {
		buf, _ := io.ReadAll(r)
		done <- string(buf)
	}()

	var panicked any
	func() {
		defer func() {
			panicked = recover()
			_ = w.Close()
			os.Stderr = orig
		}()
		fn()
	}()
	out := <-done
	if panicked != nil {
		panic(panicked)
	}
	return out
}

// writeConfig is a test helper that writes YAML content to a temp file and
// returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "qurl-proxy.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}
	return p
}

func TestLoad_ValidConfig(t *testing.T) {
	yaml := `
server:
  addr: frps.example.com
  port: 7000
  token: secret
  protocol: tcp
nhp:
  enabled: true
  machine_id: abc123
qurl:
  api_url: https://api.example.com
  token: qurl-token
routes:
  - id: web
    type: http
    local_port: 8080
    host_rewrite: localhost
    headers:
      X-Custom: value
  - id: ssh
    type: tcp
    local_port: 22
    remote_port: 6022
`
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server.Addr != "frps.example.com" {
		t.Errorf("server.addr = %q, want %q", cfg.Server.Addr, "frps.example.com")
	}
	if cfg.Server.Port != 7000 {
		t.Errorf("server.port = %d, want 7000", cfg.Server.Port)
	}
	if cfg.Server.Token != "secret" {
		t.Errorf("server.token = %q, want %q", cfg.Server.Token, "secret")
	}
	if cfg.NHP.Enabled != true {
		t.Error("nhp.enabled should be true")
	}
	if len(cfg.Routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(cfg.Routes))
	}

	// Check defaults were applied.
	if cfg.Routes[0].LocalIP != "127.0.0.1" {
		t.Errorf("routes[0].local_ip = %q, want 127.0.0.1", cfg.Routes[0].LocalIP)
	}
	if cfg.Routes[1].LocalIP != "127.0.0.1" {
		t.Errorf("routes[1].local_ip = %q, want 127.0.0.1", cfg.Routes[1].LocalIP)
	}
}

func TestLoad_AdminDefaultsDisabled(t *testing.T) {
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
	if cfg.Admin.Enabled {
		t.Error("Admin.Enabled must default to false — opt-in is the whole point of the gate")
	}
	if cfg.Admin.Addr != DefaultAdminAddr {
		t.Errorf("Admin.Addr default = %q, want %q", cfg.Admin.Addr, DefaultAdminAddr)
	}
	if cfg.Admin.Port != DefaultAdminPort {
		t.Errorf("Admin.Port default = %d, want %d", cfg.Admin.Port, DefaultAdminPort)
	}
}

func TestLoad_AdminEnabledViaYAML(t *testing.T) {
	yaml := `
server:
  addr: example.com
  port: 7000
admin:
  enabled: true
routes:
  - id: web
    type: http
    local_port: 80
`
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Admin.Enabled {
		t.Fatal("Admin.Enabled = false, want true (set via YAML)")
	}
}

func TestLoad_AdminEnabledViaEnvOverride(t *testing.T) {
	yaml := `
server:
  addr: example.com
  port: 7000
routes:
  - id: web
    type: http
    local_port: 80
`
	t.Setenv("QURL_ADMIN_ENABLED", "true")
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Admin.Enabled {
		t.Fatal("QURL_ADMIN_ENABLED=true must flip a YAML-omitted block to true")
	}
	// An env-only operator must still get the loopback defaults so
	// the resulting admin surface binds correctly. A future change
	// that reordered defaults vs. env-resolution would otherwise
	// silently leave Addr=="" and break the listener.
	if cfg.Admin.Addr != DefaultAdminAddr {
		t.Errorf("Admin.Addr = %q, want default %q (env-only opt-in must inherit Addr default)", cfg.Admin.Addr, DefaultAdminAddr)
	}
	if cfg.Admin.Port != DefaultAdminPort {
		t.Errorf("Admin.Port = %d, want default %d (env-only opt-in must inherit Port default)", cfg.Admin.Port, DefaultAdminPort)
	}
}

func TestLoad_AdminEnvUnrecognizedFallsThroughToYAML(t *testing.T) {
	// QURL_ADMIN_ENABLED is the documented runtime kill switch for a
	// security surface. An unrecognized value must NOT silently flip
	// the surface; it must fall through to whatever the YAML said,
	// AND warn loudly to stderr so operators see the typo.
	yaml := `
server:
  addr: example.com
  port: 7000
admin:
  enabled: true
routes:
  - id: web
    type: http
    local_port: 80
`
	cfgPath := writeConfig(t, yaml)
	t.Setenv("QURL_ADMIN_ENABLED", "enable") // common typo: "enable" vs "enabled"/"true"

	var cfg *Config
	stderr := captureStderr(t, func() {
		var loadErr error
		cfg, loadErr = Load(cfgPath)
		if loadErr != nil {
			t.Fatalf("unexpected error: %v", loadErr)
		}
	})
	if !cfg.Admin.Enabled {
		t.Fatal("unrecognized QURL_ADMIN_ENABLED must fall through to YAML (admin.enabled=true here), not silently flip to false")
	}
	if !strings.Contains(stderr, "QURL_ADMIN_ENABLED=") || !strings.Contains(stderr, "not recognized") {
		t.Errorf("expected stderr warning about unrecognized env value, got: %q", stderr)
	}
}

// TestLoad_AdminEnvAcceptedValues covers the full set of accepted
// truthy/falsy spellings the env parser recognizes (including
// mixed-case and whitespace). Pins the contract so a future tweak to
// the switch can't silently drop a value users rely on for the
// runtime kill switch.
func TestLoad_AdminEnvAcceptedValues(t *testing.T) {
	yaml := `
server:
  addr: example.com
  port: 7000
admin:
  enabled: false
routes:
  - id: web
    type: http
    local_port: 80
`
	cfgPath := writeConfig(t, yaml)

	truthy := []string{"1", "true", "yes", "on", "TRUE", "True", " true ", "YES", "On"}
	falsy := []string{"0", "false", "no", "off", "FALSE", "False", " false ", "NO", "Off"}

	for _, v := range truthy {
		t.Run("truthy_"+v, func(t *testing.T) {
			t.Setenv("QURL_ADMIN_ENABLED", v)
			cfg, err := Load(cfgPath)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !cfg.Admin.Enabled {
				t.Errorf("QURL_ADMIN_ENABLED=%q must enable", v)
			}
		})
	}
	// Re-anchor YAML to admin.enabled=true so the falsy cases can
	// observe the env actually flipping it off.
	yamlOn := strings.Replace(yaml, "enabled: false", "enabled: true", 1)
	cfgPathOn := writeConfig(t, yamlOn)
	for _, v := range falsy {
		t.Run("falsy_"+v, func(t *testing.T) {
			t.Setenv("QURL_ADMIN_ENABLED", v)
			cfg, err := Load(cfgPathOn)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.Admin.Enabled {
				t.Errorf("QURL_ADMIN_ENABLED=%q must disable", v)
			}
		})
	}
}

// TestLoad_AdminYAMLAddrPortPreserved pins that an operator-set
// admin.addr / admin.port survives applyDefaults — without this, a
// future change to default-ordering could silently clobber a custom
// port (e.g., port 7401) back to 7400 and the operator-reported
// admin URL would diverge from the actual listener.
func TestLoad_AdminYAMLAddrPortPreserved(t *testing.T) {
	yaml := `
server:
  addr: example.com
  port: 7000
admin:
  enabled: true
  addr: 127.0.0.2
  port: 7401
routes:
  - id: web
    type: http
    local_port: 80
`
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Admin.Addr != "127.0.0.2" {
		t.Errorf("Admin.Addr = %q, want %q (YAML-set value must not be defaulted)", cfg.Admin.Addr, "127.0.0.2")
	}
	if cfg.Admin.Port != 7401 {
		t.Errorf("Admin.Port = %d, want 7401 (YAML-set value must not be defaulted)", cfg.Admin.Port)
	}
}

// TestLoad_AdminNonLoopbackRequiresAllowRemote pins the two-step
// opt-in gate. A single edit of admin.addr from a loopback default to
// 0.0.0.0 (or any RFC1918 / public IP) must NOT silently bind the FRP
// admin API off-host — Validate has to reject until admin.allow_remote
// is explicitly true. This is the "no off-host reachability without
// two deliberate YAML changes" contract.
func TestLoad_AdminNonLoopbackRequiresAllowRemote(t *testing.T) {
	base := `
server:
  addr: example.com
  port: 7000
admin:
  enabled: true
  addr: 0.0.0.0%s
routes:
  - id: web
    type: http
    local_port: 80
`
	t.Run("rejected without allow_remote", func(t *testing.T) {
		_, err := Load(writeConfig(t, fmt.Sprintf(base, "")))
		if err == nil {
			t.Fatal("expected validation error for non-loopback admin.addr without allow_remote")
		}
		if !strings.Contains(err.Error(), "allow_remote") {
			t.Errorf("error must mention allow_remote; got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "non-loopback") {
			t.Errorf("error must mention non-loopback; got %q", err.Error())
		}
	})
	t.Run("accepted with allow_remote true AND password", func(t *testing.T) {
		// New in cr-flagged hardening: allow_remote=true now ALSO
		// requires an explicit admin.password (the machineID
		// fallback is partly-inferable and indefensible for
		// off-host exposure). Test both fields set together.
		cfg, err := Load(writeConfig(t, fmt.Sprintf(base, "\n  allow_remote: true\n  password: strong-random-secret-32-chars-xxx")))
		if err != nil {
			t.Fatalf("unexpected error with allow_remote=true + password: %v", err)
		}
		if !cfg.Admin.AllowRemote {
			t.Errorf("Admin.AllowRemote = false, want true (set via YAML)")
		}
		if cfg.Admin.Password != "strong-random-secret-32-chars-xxx" {
			t.Errorf("Admin.Password = %q, want %q", cfg.Admin.Password, "strong-random-secret-32-chars-xxx")
		}
	})
	t.Run("rejected with allow_remote true but empty password", func(t *testing.T) {
		_, err := Load(writeConfig(t, fmt.Sprintf(base, "\n  allow_remote: true")))
		if err == nil {
			t.Fatal("expected validation error for allow_remote=true without admin.password (machineID-fallback indefensible for off-host)")
		}
		if !strings.Contains(err.Error(), "admin.password") {
			t.Errorf("error must mention admin.password; got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "machineID") && !strings.Contains(err.Error(), "off-host") {
			t.Errorf("error should explain the off-host machineID hazard; got %q", err.Error())
		}
	})
	t.Run("loopback ignores allow_remote", func(t *testing.T) {
		yaml := `
server:
  addr: example.com
  port: 7000
admin:
  enabled: true
  addr: 127.0.0.1
routes:
  - id: web
    type: http
    local_port: 80
`
		if _, err := Load(writeConfig(t, yaml)); err != nil {
			t.Fatalf("loopback admin must not require allow_remote: %v", err)
		}
	})
	t.Run("explicit allow_remote requires password even on loopback", func(t *testing.T) {
		yaml := `
server:
  addr: example.com
  port: 7000
admin:
  enabled: true
  addr: 127.0.0.1
  allow_remote: true
routes:
  - id: web
    type: http
    local_port: 80
`
		_, err := Load(writeConfig(t, yaml))
		if err == nil || !strings.Contains(err.Error(), "admin.password") {
			t.Fatalf("explicit allow_remote without password error = %v", err)
		}
	})
	t.Run("disabled ignores non-loopback", func(t *testing.T) {
		yaml := `
server:
  addr: example.com
  port: 7000
admin:
  enabled: false
  addr: 0.0.0.0
routes:
  - id: web
    type: http
    local_port: 80
`
		if _, err := Load(writeConfig(t, yaml)); err != nil {
			t.Fatalf("disabled admin must skip the allow_remote check: %v", err)
		}
	})
}

// TestAdminBindLooksRoutable pins the defense-in-depth helper that
// Validate uses to decide whether to require admin.allow_remote. The helper
// runs at config-load time but the warning emission happens only at
// bind time (in run.go) — separating the two so `status --json`
// pollers don't spam stderr on every invocation.
func TestAdminBindLooksRoutable(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
		want bool
	}{
		{"nil config", nil, false},
		{"disabled never routable", &Config{Admin: AdminConfig{Enabled: false, Addr: "0.0.0.0"}}, false},
		{"IPv4 loopback", &Config{Admin: AdminConfig{Enabled: true, Addr: "127.0.0.1"}}, false},
		{"IPv4 loopback /8", &Config{Admin: AdminConfig{Enabled: true, Addr: "127.0.0.5"}}, false},
		{"IPv6 loopback", &Config{Admin: AdminConfig{Enabled: true, Addr: "::1"}}, false},
		{"localhost literal", &Config{Admin: AdminConfig{Enabled: true, Addr: "localhost"}}, false},
		{"localhost mixed case", &Config{Admin: AdminConfig{Enabled: true, Addr: "Localhost"}}, false},
		{"localhost upper case", &Config{Admin: AdminConfig{Enabled: true, Addr: "LOCALHOST"}}, false},
		{"empty address fails closed", &Config{Admin: AdminConfig{Enabled: true}}, true},
		{"whitespace address fails closed", &Config{Admin: AdminConfig{Enabled: true, Addr: "  "}}, true},
		{"IPv4 any", &Config{Admin: AdminConfig{Enabled: true, Addr: "0.0.0.0"}}, true},
		{"IPv6 any", &Config{Admin: AdminConfig{Enabled: true, Addr: "::"}}, true},
		{"IPv4 RFC1918", &Config{Admin: AdminConfig{Enabled: true, Addr: "192.168.1.1"}}, true},
		{"IPv4 public", &Config{Admin: AdminConfig{Enabled: true, Addr: "8.8.8.8"}}, true},
		{"IPv6 public", &Config{Admin: AdminConfig{Enabled: true, Addr: "2001:db8::1"}}, true},
		// Non-"localhost" hostnames are now treated as routable so
		// allow_remote is required. Tightened in cr round 7: the
		// previous bypass-by-default contradicted the PR's
		// "no off-host exposure without two opt-ins" framing.
		// `host.docker.internal` resolves to a routable address on
		// Docker for Mac/Windows; a public hostname resolves to a
		// public IP. Either way, the operator chose a hostname
		// deliberately and needs to acknowledge the off-host intent.
		{"docker hostname now requires allow_remote", &Config{Admin: AdminConfig{Enabled: true, Addr: "host.docker.internal"}}, true},
		{"public hostname now requires allow_remote", &Config{Admin: AdminConfig{Enabled: true, Addr: "tunnel.example.com"}}, true},
		{"internal hostname now requires allow_remote", &Config{Admin: AdminConfig{Enabled: true, Addr: "internal-svc"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := AdminBindLooksRoutable(tc.cfg); got != tc.want {
				t.Errorf("AdminBindLooksRoutable(%+v) = %v, want %v", tc.cfg, got, tc.want)
			}
		})
	}
}

// TestLoad_AdminPortRange rejects out-of-range admin.port at parse
// time. Without this, an operator setting `port: 99999` would only
// learn at `run` time via an opaque FRP-side bind failure — too far
// from where the typo lives.
func TestLoad_AdminPortRange(t *testing.T) {
	// Port=0 is intentionally NOT here — it's the "use default" sentinel
	// that applyDefaults rewrites to DefaultAdminPort before Validate runs,
	// and the defaults path is covered by TestLoad_AdminDefaultsDisabled
	// / TestLoad_AdminEnabledViaEnvOverride.
	cases := []struct {
		name string
		port int
	}{
		{"too high", 99999},
		{"negative", -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			yaml := fmt.Sprintf(`
server:
  addr: example.com
  port: 7000
admin:
  enabled: true
  port: %d
routes:
  - id: web
    type: http
    local_port: 80
`, tc.port)
			_, err := Load(writeConfig(t, yaml))
			if err == nil {
				t.Fatalf("expected validation error for admin.port=%d", tc.port)
			}
			if !strings.Contains(err.Error(), "admin.port") {
				t.Errorf("error must mention admin.port; got %q", err.Error())
			}
		})
	}
}

// TestLoad_AdminPortIgnoredWhenDisabled: a stale out-of-range Port
// set in YAML while Enabled=false must NOT fail validation — the
// listener never binds, so the value is harmless. This lets operators
// flip the gate off without first scrubbing the rest of the block.
func TestLoad_AdminPortIgnoredWhenDisabled(t *testing.T) {
	yaml := `
server:
  addr: example.com
  port: 7000
admin:
  enabled: false
  port: 99999
routes:
  - id: web
    type: http
    local_port: 80
`
	if _, err := Load(writeConfig(t, yaml)); err != nil {
		t.Fatalf("unexpected error for disabled admin with stale port: %v", err)
	}
}

// TestLoad_AdminEnvEnablesValidationOfStaleYAML pins the dual of
// TestLoad_AdminPortIgnoredWhenDisabled: a stale out-of-range port
// stays inert as long as YAML+env both say `enabled=false`, but
// an operator who later sets `QURL_ADMIN_ENABLED=true` to opt in
// MUST fail validation (the stale port becomes live the moment the
// listener would bind, so a 99999 value is genuinely broken).
//
// The behavior is correct (env-enable should validate), but
// previously untested — surfacing it here so a future change to
// applyEnvOverrides ordering can't silently let an invalid post-
// env-flip config through.
func TestLoad_AdminEnvEnablesValidationOfStaleYAML(t *testing.T) {
	yaml := `
server:
  addr: example.com
  port: 7000
admin:
  enabled: false
  port: 99999
routes:
  - id: web
    type: http
    local_port: 80
`
	t.Setenv("QURL_ADMIN_ENABLED", "true")
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected Validate to reject admin.port=99999 once env-enable activated the block, got nil")
	}
	if !strings.Contains(err.Error(), "admin.port") {
		t.Errorf("error didn't name admin.port; got %q (operator needs to see which field is invalid)", err.Error())
	}
}

// TestLocalAdminURL pins the unspecified-address substitution for
// from-localhost callers (add reload, status probe). 0.0.0.0 → 127.0.0.1
// and :: → ::1 are the load-bearing cases — on Linux the kernel
// routes outbound dials to 0.0.0.0 as 127.0.0.1, but Windows and
// macOS don't, so an operator who set admin.addr: 0.0.0.0 +
// allow_remote: true on a non-Linux host would otherwise see `add`
// and `status` silently fail despite the off-host bind working.
//
// Non-wildcard addresses pass through unchanged (the regular AdminURL
// path).
func TestLocalAdminURL(t *testing.T) {
	cases := []struct {
		name string
		addr string
		port int
		want string
	}{
		{"unspecified IPv4 → loopback", "0.0.0.0", 7400, "http://127.0.0.1:7400"},
		{"unspecified IPv6 → loopback", "::", 7400, "http://[::1]:7400"},
		{"loopback IPv4 unchanged", "127.0.0.1", 7400, "http://127.0.0.1:7400"},
		{"loopback IPv6 unchanged", "::1", 7400, "http://[::1]:7400"},
		{"hostname unchanged", "localhost", 7400, "http://localhost:7400"},
		{"non-loopback IPv4 unchanged", "192.168.1.100", 7400, "http://192.168.1.100:7400"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := LocalAdminURL(tc.addr, tc.port)
			if got != tc.want {
				t.Errorf("LocalAdminURL(%q, %d) = %q, want %q", tc.addr, tc.port, got, tc.want)
			}
		})
	}
}

// TestAdminURL pins the URL-construction contract that admin-API
// callers (run banner, add reload, status probe, status display)
// share via pkg/config. The load-bearing case is the IPv6 bracket:
// an operator setting `admin.addr: "::1"` MUST produce
// `http://[::1]:7400` (not the invalid `http://::1:7400`), or the
// admin probe silently fails to connect. A regression that drops
// net.JoinHostPort surfaces here as a literal string mismatch on
// the IPv6 case.
func TestAdminURL(t *testing.T) {
	cases := []struct {
		name string
		addr string
		port int
		want string
	}{
		{"loopback IPv4 default port", "127.0.0.1", 7400, "http://127.0.0.1:7400"},
		{"loopback IPv6 brackets", "::1", 7400, "http://[::1]:7400"},
		{"hostname passes through", "localhost", 8080, "http://localhost:8080"},
		{"non-loopback IPv4 opt-in", "0.0.0.0", 7400, "http://0.0.0.0:7400"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AdminURL(tc.addr, tc.port)
			if got != tc.want {
				t.Errorf("AdminURL(%q, %d) = %q, want %q", tc.addr, tc.port, got, tc.want)
			}
		})
	}
}

// TestNewDefaulted_EnvDoesNotPersist pins the runtime-vs-install-time
// boundary: QURL_ADMIN_ENABLED set at the moment `add` runs must NOT
// get baked into the YAML that's written to disk. The env is a runtime
// override; the saved YAML records only the operator's literal intent.
// Without this split, an operator who set the env once would see the
// gate stuck on across reboots even after unsetting it.
func TestNewDefaulted_EnvDoesNotPersist(t *testing.T) {
	t.Setenv("QURL_ADMIN_ENABLED", "true")
	cfg := NewDefaulted()
	if cfg.Admin.Enabled {
		t.Fatal("NewDefaulted must NOT apply QURL_ADMIN_ENABLED — env is a runtime override, not an install-time default")
	}
}

func TestLoad_AdminEnvOverridesYAML(t *testing.T) {
	// Operator opting out at runtime via env even though the YAML
	// shipped with admin.enabled=true — the env wins. Matters for
	// quickly killing the surface on a running install without
	// rewriting the config file.
	yaml := `
admin:
  enabled: true
routes:
  - id: web
    type: http
    local_port: 80
`
	t.Setenv("QURL_ADMIN_ENABLED", "false")
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Admin.Enabled {
		t.Fatal("QURL_ADMIN_ENABLED=false must override YAML admin.enabled=true")
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
	if cfg.Server.PublicDomain != "qurl.site" {
		t.Errorf("server.public_domain = %q, want default %q", cfg.Server.PublicDomain, "qurl.site")
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

func TestLoad_TCPWithoutRemotePort(t *testing.T) {
	yaml := `
server:
  addr: example.com
  port: 7000
routes:
  - id: ssh
    type: tcp
    local_port: 22
`
	// remote_port is optional (server-assigned), so this should pass
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Routes[0].RemotePort != 0 {
		t.Errorf("expected remote_port 0, got %d", cfg.Routes[0].RemotePort)
	}
}

func TestLoad_HTTPWithoutSubdomainOrDomains(t *testing.T) {
	yaml := `
server:
  addr: example.com
  port: 7000
routes:
  - id: web
    type: http
    local_port: 80
`
	// subdomain/custom_domains are optional (may be auto-generated), so this should pass
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Routes[0].Subdomain != "" {
		t.Errorf("expected empty subdomain, got %q", cfg.Routes[0].Subdomain)
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
		{name: "tcp", typ: "frp_tcp", want: `unsupported route type "frp_tcp"; use type: tcp`},
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
	t.Setenv("QURL_TEST_TOKEN", "s3cret")

	yaml := `
server:
  addr: ${QURL_TEST_ADDR}
  port: 7000
  token: ${QURL_TEST_TOKEN}
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
	if cfg.Server.Token != "s3cret" {
		t.Errorf("server.token = %q, want %q", cfg.Server.Token, "s3cret")
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
	if cfg.Server.PublicDomain != "qurl.site" {
		t.Errorf("Server.PublicDomain = %q, want %q", cfg.Server.PublicDomain, "qurl.site")
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

func TestLoad_CustomDomainsValid(t *testing.T) {
	yaml := `
server:
  addr: example.com
  port: 7000
routes:
  - id: web
    type: http
    local_port: 80
    custom_domains:
      - app.example.com
      - www.example.com
`
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Routes[0].CustomDomains) != 2 {
		t.Errorf("expected 2 custom domains, got %d", len(cfg.Routes[0].CustomDomains))
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

func TestLoad_SubdomainRoutingIDDisagreement(t *testing.T) {
	yaml := fmt.Sprintf(`
server:
  addr: example.com
  port: 7000
routes:
  - id: dashboard
    type: http
    local_port: 8080
    subdomain: kevin-laptop-demo
    resource_id: %s
    connector_routing_id: c-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
`, testPublicResourceA)
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error when subdomain != resource_id")
	}
	if !strings.Contains(err.Error(), "connector_routing_id") {
		t.Errorf("error must mention connector_routing_id; got %q", err.Error())
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

func TestLoad_SubdomainRoutingIDMatch(t *testing.T) {
	yaml := fmt.Sprintf(`
server:
  addr: example.com
  port: 7000
routes:
  - id: dashboard
    type: http
    local_port: 8080
    subdomain: c-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    resource_id: %s
    connector_routing_id: c-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
`, testPublicResourceA)
	if _, err := Load(writeConfig(t, yaml)); err != nil {
		t.Fatalf("expected no error when subdomain == connector_routing_id; got %v", err)
	}
}

func TestLoad_TemplatedSubdomainCannotOverrideRoutingID(t *testing.T) {
	cases := []struct {
		name      string
		subdomain string
	}{
		{"spaced template", "{{ .MachineID }}"},
		{"bare template", "{{.MachineID}}"},
		{"templated with literal prefix", "admin-{{ .MachineID }}"},
		{"templated with literal suffix", "{{.MachineID}}.admin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			yaml := fmt.Sprintf(`
server:
  addr: example.com
  port: 7000
routes:
  - id: admin
    type: http
    local_port: 9090
    subdomain: %q
    resource_id: %s
    connector_routing_id: c-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
`, tc.subdomain, testPublicResourceA)
			if _, err := Load(writeConfig(t, yaml)); err == nil {
				t.Fatalf("template %q must not override producer routing identity", tc.subdomain)
			}
		})
	}
}

// TestLoad_UnrecognizedTemplatesRejected: subdomain values that
// expandMachineID does NOT rewrite at runtime are treated as
// literals and validated against resource_id. Pre-fix, any `{{`
// substring or any `.MachineID` substring opted out of the equality
// check — masking mismatches behind opaque FRP-side errors. The
// sentinel-based detector keeps the validator and renderer in lock
// step: if expandMachineID wouldn't touch the value, it's a literal.
func TestLoad_UnrecognizedTemplatesRejected(t *testing.T) {
	cases := []struct {
		name      string
		subdomain string
	}{
		{"double spaces inside braces", "{{  .MachineID  }}"},
		{"asymmetric spacing", "{{.MachineID }}"},
		{".MachineID substring without braces", "foo.MachineIDbar"},
		{".MachineID literal no braces", ".MachineID"},
		{"unrelated template", "{{ INVALID }}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			yaml := fmt.Sprintf(`
server:
  addr: example.com
  port: 7000
routes:
  - id: admin
    type: http
    local_port: 9090
    subdomain: %q
    resource_id: %s
    connector_routing_id: c-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
`, tc.subdomain, testPublicResourceA)
			_, err := Load(writeConfig(t, yaml))
			if err == nil {
				t.Fatalf("expected validation error for unrecognized template %q", tc.subdomain)
			}
			if !strings.Contains(err.Error(), "connector_routing_id") {
				t.Errorf("error must mention connector_routing_id; got %q", err.Error())
			}
		})
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
