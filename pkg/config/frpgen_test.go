package config

import (
	"strings"
	"testing"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	frpvalidation "github.com/fatedier/frp/pkg/config/v1/validation"
)

func TestGenerateFRPClientConfig_Basic(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Addr:     "frps.example.com",
			Port:     7000,
			Token:    "secret",
			Protocol: "kcp",
		},
		Routes: []Route{
			{
				ID:          "web",
				Type:        RouteTypeHTTP,
				LocalIP:     "127.0.0.1",
				LocalPort:   8080,
				Subdomain:   "myapp",
				HostRewrite: "localhost",
				Headers: map[string]string{
					"X-Real-IP": "pass",
				},
			},
			{
				ID:         "ssh",
				Type:       RouteTypeTCP,
				LocalIP:    "127.0.0.1",
				LocalPort:  22,
				RemotePort: 6022,
			},
		},
	}

	common, proxies, visitors, err := GenerateFRPClientConfig(cfg, "machine-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify common config.
	if common.ServerAddr != "frps.example.com" {
		t.Errorf("ServerAddr = %q, want %q", common.ServerAddr, "frps.example.com")
	}
	if common.ServerPort != 7000 {
		t.Errorf("ServerPort = %d, want 7000", common.ServerPort)
	}
	if common.Auth.Token != "secret" {
		t.Errorf("Auth.Token = %q, want %q", common.Auth.Token, "secret")
	}
	if common.Transport.Protocol != "kcp" {
		t.Errorf("Transport.Protocol = %q, want %q", common.Transport.Protocol, "kcp")
	}

	// Verify proxies.
	if len(proxies) != 2 {
		t.Fatalf("expected 2 proxies, got %d", len(proxies))
	}
	if visitors != nil {
		t.Errorf("expected nil visitors, got %v", visitors)
	}

	// HTTP proxy.
	httpProxy, ok := proxies[0].(*v1.HTTPProxyConfig)
	if !ok {
		t.Fatalf("proxies[0] type = %T, want *v1.HTTPProxyConfig", proxies[0])
	}
	if httpProxy.Name != "web" {
		t.Errorf("http proxy Name = %q, want %q", httpProxy.Name, "web")
	}
	if httpProxy.Type != "http" {
		t.Errorf("http proxy Type = %q, want %q", httpProxy.Type, "http")
	}
	if httpProxy.LocalIP != "127.0.0.1" {
		t.Errorf("http proxy LocalIP = %q, want %q", httpProxy.LocalIP, "127.0.0.1")
	}
	if httpProxy.LocalPort != 8080 {
		t.Errorf("http proxy LocalPort = %d, want 8080", httpProxy.LocalPort)
	}
	if httpProxy.SubDomain != "myapp" {
		t.Errorf("http proxy SubDomain = %q, want %q", httpProxy.SubDomain, "myapp")
	}
	if httpProxy.HostHeaderRewrite != "localhost" {
		t.Errorf("http proxy HostHeaderRewrite = %q, want %q", httpProxy.HostHeaderRewrite, "localhost")
	}
	if httpProxy.RequestHeaders.Set["X-Real-IP"] != "pass" {
		t.Errorf("http proxy header X-Real-IP = %q, want %q", httpProxy.RequestHeaders.Set["X-Real-IP"], "pass")
	}

	// TCP proxy.
	tcpProxy, ok := proxies[1].(*v1.TCPProxyConfig)
	if !ok {
		t.Fatalf("proxies[1] type = %T, want *v1.TCPProxyConfig", proxies[1])
	}
	if tcpProxy.Name != "ssh" {
		t.Errorf("tcp proxy Name = %q, want %q", tcpProxy.Name, "ssh")
	}
	if tcpProxy.Type != "tcp" {
		t.Errorf("tcp proxy Type = %q, want %q", tcpProxy.Type, "tcp")
	}
	if tcpProxy.RemotePort != 6022 {
		t.Errorf("tcp proxy RemotePort = %d, want 6022", tcpProxy.RemotePort)
	}
}

func TestGenerateFRPClientConfig_PinnedLegacyIDAcceptedAsFRPProxyName(t *testing.T) {
	cfg := &Config{
		Routes: []Route{{
			ID:                 "My App",
			Type:               RouteTypeHTTP,
			LocalIP:            "127.0.0.1",
			LocalPort:          8080,
			ResourceID:         testPublicResourceA,
			ConnectorRoutingID: testRoutingA,
		}},
	}

	_, proxies, _, err := GenerateFRPClientConfig(cfg, "machine-1")
	if err != nil {
		t.Fatalf("GenerateFRPClientConfig: %v", err)
	}
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}

	base := proxies[0].GetBaseConfig()
	if base.Name != "My App" {
		t.Fatalf("proxy Name = %q, want pinned legacy id verbatim", base.Name)
	}
	proxies[0].Complete()
	if err := frpvalidation.ValidateProxyConfigurerForClient(proxies[0]); err != nil {
		t.Fatalf("FRP client validation rejected pinned legacy proxy name %q: %v", base.Name, err)
	}
}

// TestGenerateFRPClientConfig_NeverSetsWebServer pins the contract
// that GenerateFRPClientConfig MUST leave `common.WebServer` at its
// zero value regardless of cfg.Admin. The admin-gate decision lives
// in run.go (the only call site that conditionally populates
// WebServer.* based on cfg.Admin.Enabled). If GenerateFRPClientConfig
// were ever to start touching WebServer, run.go's gate would no
// longer be load-bearing and an operator's `admin.enabled: false`
// could be silently bypassed.
//
// Three inputs covered: Admin unset (zero value), Admin disabled
// explicitly, Admin enabled with full addr/port. WebServer.Port == 0
// in all three is the load-bearing invariant; LayerV FRP
// v0.70.0-layerv.5 `client/service.go:214` gates the HTTP admin listener on
// `options.Common.WebServer.Port > 0`, so leaving the field at zero
// is what actually prevents the bind.
func TestGenerateFRPClientConfig_NeverSetsWebServer(t *testing.T) {
	baseCfg := func() *Config {
		return &Config{
			Server: ServerConfig{Addr: "frps.example.com", Port: 7000},
			Routes: []Route{{
				ID:        "web",
				Type:      RouteTypeHTTP,
				LocalIP:   "127.0.0.1",
				LocalPort: 8080,
				Subdomain: "myapp",
			}},
		}
	}

	cases := []struct {
		name  string
		admin AdminConfig
	}{
		{"admin unset (zero value)", AdminConfig{}},
		{"admin explicitly disabled", AdminConfig{Enabled: false, Addr: DefaultAdminAddr, Port: DefaultAdminPort}},
		{"admin enabled (gating lives in run.go, NOT this layer)", AdminConfig{Enabled: true, Addr: DefaultAdminAddr, Port: DefaultAdminPort}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseCfg()
			cfg.Admin = tc.admin

			common, _, _, err := GenerateFRPClientConfig(cfg, "machine-1")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if common.WebServer.Port != 0 {
				t.Errorf("WebServer.Port = %d, want 0 (GenerateFRPClientConfig MUST NOT touch WebServer — the admin gate lives in run.go)", common.WebServer.Port)
			}
			if common.WebServer.Addr != "" {
				t.Errorf("WebServer.Addr = %q, want \"\" (GenerateFRPClientConfig MUST NOT touch WebServer)", common.WebServer.Addr)
			}
			if common.WebServer.User != "" {
				t.Errorf("WebServer.User = %q, want \"\"", common.WebServer.User)
			}
			if common.WebServer.Password != "" {
				t.Errorf("WebServer.Password = %q, want \"\"", common.WebServer.Password)
			}
		})
	}
}

func TestGenerateFRPClientConfig_MachineIDTemplate(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Addr: "example.com",
			Port: 7000,
		},
		Routes: []Route{
			{
				ID:        "admin",
				Type:      RouteTypeHTTP,
				LocalIP:   "127.0.0.1",
				LocalPort: 9090,
				Subdomain: "admin-{{ .MachineID }}",
			},
		},
	}

	_, proxies, _, err := GenerateFRPClientConfig(cfg, "abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	httpProxy := proxies[0].(*v1.HTTPProxyConfig)
	if httpProxy.SubDomain != "admin-abc123" {
		t.Errorf("SubDomain = %q, want %q", httpProxy.SubDomain, "admin-abc123")
	}
}

func TestGenerateFRPClientConfig_MachineIDTemplateNoSpaces(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Addr: "example.com",
			Port: 7000,
		},
		Routes: []Route{
			{
				ID:        "admin",
				Type:      RouteTypeHTTP,
				LocalIP:   "127.0.0.1",
				LocalPort: 9090,
				Subdomain: "admin-{{.MachineID}}",
			},
		},
	}

	_, proxies, _, err := GenerateFRPClientConfig(cfg, "xyz789")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	httpProxy := proxies[0].(*v1.HTTPProxyConfig)
	if httpProxy.SubDomain != "admin-xyz789" {
		t.Errorf("SubDomain = %q, want %q", httpProxy.SubDomain, "admin-xyz789")
	}
}

func TestGenerateFRPClientConfig_NoToken(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Addr: "example.com",
			Port: 7000,
		},
		Routes: []Route{
			{
				ID:        "web",
				Type:      RouteTypeHTTP,
				LocalIP:   "127.0.0.1",
				LocalPort: 80,
				Subdomain: "app",
			},
		},
	}

	common, _, _, err := GenerateFRPClientConfig(cfg, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if common.Auth.Token != "" {
		t.Errorf("Auth.Token = %q, want empty", common.Auth.Token)
	}
}

func TestGenerateFRPClientConfig_NoProtocol(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Addr: "example.com",
			Port: 7000,
		},
		Routes: []Route{
			{
				ID:        "web",
				Type:      RouteTypeHTTP,
				LocalIP:   "127.0.0.1",
				LocalPort: 80,
				Subdomain: "app",
			},
		},
	}

	common, _, _, err := GenerateFRPClientConfig(cfg, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if common.Transport.Protocol != "" {
		t.Errorf("Transport.Protocol = %q, want empty (applyDefaults sets tcp before this runs in production)", common.Transport.Protocol)
	}
}

// TestGenerateFRPClientConfig_BothTokensSet_QURLNotInAuth_ServerInAuth
// pins the dual-token wire shape after the api-key meta was retired:
// (1) the qURL API key (cfg.QURL.Token) MUST NOT be written to
// common.Auth.Token, and (2) when Server.Token is also set, that
// explicit legacy escape hatch wins for Auth.Token. The server's
// tunnel-auth mode fail-closes on a non-empty FRPS_AUTH_TOKEN and runs
// the FRP server with the default empty `auth.token`; any non-empty
// common.Auth.Token derived from QURL.Token would produce a different
// md5(token+timestamp) than the server's empty-token-derived value and
// FRP would reject Login with "token in login doesn't match token from
// configuration" before the plugin ever runs. Server.Token is the
// caller's deliberate signal to use FRP's built-in shared-token
// verifier (deployments without the qURL authorization plugin), and is
// the only path that legitimately writes Auth.Token. Also pins the
// post-rip-out property that the qURL key never reaches the FRP Login
// wire under any Metas key — qURL tunnel server no longer
// reads `qurl_api_key` (PR #131), so the client must not write it.
func TestGenerateFRPClientConfig_BothTokensSet_QURLNotInAuth_ServerInAuth(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Addr:  "example.com",
			Port:  7000,
			Token: "shared-secret",
		},
		QURL: QURLConfig{
			Token: "lv_live_user_key",
		},
		Routes: []Route{
			{
				ID:        "web",
				Type:      RouteTypeHTTP,
				LocalIP:   "127.0.0.1",
				LocalPort: 80,
				Subdomain: "app",
			},
		},
	}

	common, _, _, err := GenerateFRPClientConfig(cfg, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Server.Token is the explicit legacy escape hatch — it wins for
	// Auth.Token. The qURL key must never land in Auth.Token because
	// that would trigger FRP's shared-token mismatch under tunnel-auth.
	if common.Auth.Token != "shared-secret" {
		t.Errorf("Auth.Token = %q, want %q (Server.Token is the explicit shared-FRP-token opt-in; QURL.Token must never reach Auth.Token)", common.Auth.Token, "shared-secret")
	}
	if common.Auth.Token == "lv_live_user_key" {
		t.Errorf("Auth.Token = %q — QURL.Token must NEVER be written to Auth.Token (would trigger FRP shared-token mismatch under tunnel-auth, blocking every Login before the plugin runs)", common.Auth.Token)
	}
	// Post-rip-out wire contract: cfg.QURL.Token must NEVER appear in
	// any common.Metadatas value. qURL tunnel server PR #131
	// removed the api-key read from tunnel-auth — the client write is
	// dead and must stay dead.
	for k, v := range common.Metadatas {
		if v == "lv_live_user_key" {
			t.Errorf("Metadatas[%q] = %q — QURL.Token must NEVER reach FRP Login Metas (qurl_api_key meta was retired in qURL tunnel server PR #131)", k, v)
		}
	}
}

// TestGenerateFRPClientConfig_QURLTokenAloneLeavesAuthTokenEmpty pins
// the canonical tunnel-auth case: only QURL.Token configured, no
// Server.Token. Auth.Token must stay empty so FRP's default
// md5("" + timestamp) matches the server's empty-token-derived value.
// (The "no metadata-key write" half of the wire contract is pinned
// by TestGenerateFRPClientConfig_NoQURLAPIKeyMetaUnderAnyConfig, which
// table-drives this same config shape.)
func TestGenerateFRPClientConfig_QURLTokenAloneLeavesAuthTokenEmpty(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Addr: "example.com", Port: 7000},
		QURL:   QURLConfig{Token: "lv_live_user_key"},
		Routes: []Route{{ID: "web", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 80, Subdomain: "app"}},
	}

	common, _, _, err := GenerateFRPClientConfig(cfg, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if common.Auth.Token != "" {
		t.Errorf("Auth.Token = %q, want empty (canonical tunnel-auth: QURL.Token must NOT reach Auth.Token)", common.Auth.Token)
	}
}

// TestGenerateFRPClientConfig_NoQURLAPIKeyMetaUnderAnyConfig pins the
// post-rip-out wire contract: across every meaningful combination of
// QURL.Token and Server.Token, the generator MUST NOT populate the
// retired `qurl_api_key` Login.Metas key. Defends against a future
// refactor that resurrects the meta write (qURL tunnel server
// PR #131 removed the read; reintroducing the write is silently
// inert today but would leak a credential across the wire to a server
// that discards it).
func TestGenerateFRPClientConfig_NoQURLAPIKeyMetaUnderAnyConfig(t *testing.T) {
	// Literal-key check is intentional: the constant MetaQURLAPIKey
	// is gone; this test pins the WIRE KEY, which must remain absent
	// regardless of whether the Go symbol exists.
	const retiredAPIKeyMeta = "qurl_api_key"

	cases := []struct {
		name string
		cfg  *Config
	}{
		{
			name: "no tokens",
			cfg: &Config{
				Server: ServerConfig{Addr: "example.com", Port: 7000},
				Routes: []Route{{ID: "web", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 80, Subdomain: "app"}},
			},
		},
		{
			name: "QURL.Token only (canonical tunnel-auth)",
			cfg: &Config{
				Server: ServerConfig{Addr: "example.com", Port: 7000},
				QURL:   QURLConfig{Token: "lv_live_user_key"},
				Routes: []Route{{ID: "web", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 80, Subdomain: "app"}},
			},
		},
		{
			name: "Server.Token only (legacy shared-FRP-token)",
			cfg: &Config{
				Server: ServerConfig{Addr: "example.com", Port: 7000, Token: "shared-secret"},
				Routes: []Route{{ID: "web", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 80, Subdomain: "app"}},
			},
		},
		{
			name: "both tokens",
			cfg: &Config{
				Server: ServerConfig{Addr: "example.com", Port: 7000, Token: "shared-secret"},
				QURL:   QURLConfig{Token: "lv_live_user_key"},
				Routes: []Route{{ID: "web", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 80, Subdomain: "app"}},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			common, _, _, err := GenerateFRPClientConfig(tc.cfg, "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got, ok := common.Metadatas[retiredAPIKeyMeta]; ok {
				t.Errorf("Metadatas[%q] = %q, want absent (qurl_api_key was retired in qURL tunnel server PR #131; the client must not write the dead meta); full Metadatas = %v",
					retiredAPIKeyMeta, got, common.Metadatas)
			}
		})
	}
}

// TestGenerateFRPClientConfig_NoTokensLeavesAuthTokenEmpty pins the
// no-auth configuration: when neither QURL.Token nor Server.Token is
// set, Auth.Token must stay empty so FRP's default md5("" + timestamp)
// matches the server. (The "no metadata-key write" half is pinned by
// TestGenerateFRPClientConfig_NoQURLAPIKeyMetaUnderAnyConfig, which
// table-drives this same config shape.)
func TestGenerateFRPClientConfig_NoTokensLeavesAuthTokenEmpty(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Addr: "example.com", Port: 7000},
		Routes: []Route{{ID: "web", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 80, Subdomain: "app"}},
	}
	common, _, _, err := GenerateFRPClientConfig(cfg, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if common.Auth.Token != "" {
		t.Errorf("Auth.Token = %q, want empty (no tokens configured)", common.Auth.Token)
	}
}

// TestGenerateFRPClientConfig_AuthMethodDefaultsToToken pins an
// implicit upstream contract: after run.go was simplified to drop
// `common.Auth.Method = "token"`, we now rely on FRP's
// `common.Complete()` to default Auth.Method to "token" (FRP
// v0.70.0-layerv.5 pkg/config/v1/client.go:207). If a future FRP bump
// changes that default, the production handshake would fall back
// to a different auth method and silently fail at server-side
// validation. This test calls Complete() and asserts the default
// so the dependency upgrade fails loudly here, not at runtime.
func TestGenerateFRPClientConfig_AuthMethodDefaultsToToken(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Addr: "example.com", Port: 7000, Token: "shared-secret"},
		Routes: []Route{{ID: "web", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 80, Subdomain: "app"}},
	}
	common, _, _, err := GenerateFRPClientConfig(cfg, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := common.Complete(); err != nil {
		t.Fatalf("common.Complete() failed: %v", err)
	}
	if got := common.Auth.Method; got != v1.AuthMethodToken {
		t.Errorf("Auth.Method after Complete() = %q, want %q "+
			"(FRP upstream default — if this fails after a frp bump, "+
			"audit run.go to see if Auth.Method needs to be set explicitly again)",
			got, v1.AuthMethodToken)
	}
}

func TestGenerateFRPClientConfig_ServerTokenFallback(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Addr:  "example.com",
			Port:  7000,
			Token: "shared-secret",
		},
		Routes: []Route{
			{
				ID:        "web",
				Type:      RouteTypeHTTP,
				LocalIP:   "127.0.0.1",
				LocalPort: 80,
				Subdomain: "app",
			},
		},
	}

	common, _, _, err := GenerateFRPClientConfig(cfg, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if common.Auth.Token != "shared-secret" {
		t.Errorf("Auth.Token = %q, want %q (should fall back to server token)", common.Auth.Token, "shared-secret")
	}
}

func TestGenerateFRPClientConfig_CustomDomains(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Addr: "example.com",
			Port: 7000,
		},
		Routes: []Route{
			{
				ID:            "web",
				Type:          RouteTypeHTTP,
				LocalIP:       "127.0.0.1",
				LocalPort:     80,
				CustomDomains: []string{"app.example.com", "www.example.com"},
			},
		},
	}

	_, proxies, _, err := GenerateFRPClientConfig(cfg, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	httpProxy := proxies[0].(*v1.HTTPProxyConfig)
	if len(httpProxy.CustomDomains) != 2 {
		t.Fatalf("expected 2 custom domains, got %d", len(httpProxy.CustomDomains))
	}
	if httpProxy.CustomDomains[0] != "app.example.com" {
		t.Errorf("CustomDomains[0] = %q, want %q", httpProxy.CustomDomains[0], "app.example.com")
	}
}

func TestGenerateFRPClientConfig_TransportDefaults(t *testing.T) {
	f := false
	cfg := &Config{
		Server: ServerConfig{
			Addr:          "example.com",
			Port:          7000,
			Keepalive:     60,
			DialTimeout:   10,
			LoginFailExit: &f,
		},
		Routes: []Route{
			{
				ID:        "web",
				Type:      RouteTypeHTTP,
				LocalIP:   "127.0.0.1",
				LocalPort: 80,
				Subdomain: "app",
			},
		},
	}

	common, _, _, err := GenerateFRPClientConfig(cfg, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if common.LoginFailExit == nil || *common.LoginFailExit != false {
		t.Errorf("LoginFailExit = %v, want false", common.LoginFailExit)
	}
	if common.Transport.DialServerKeepAlive != 60 {
		t.Errorf("DialServerKeepAlive = %d, want 60", common.Transport.DialServerKeepAlive)
	}
	if common.Transport.DialServerTimeout != 10 {
		t.Errorf("DialServerTimeout = %d, want 10", common.Transport.DialServerTimeout)
	}
}

func TestGenerateFRPClientConfig_CustomTransport(t *testing.T) {
	tr := true
	cfg := &Config{
		Server: ServerConfig{
			Addr:          "example.com",
			Port:          7000,
			Keepalive:     120,
			DialTimeout:   5,
			LoginFailExit: &tr,
		},
		Routes: []Route{
			{
				ID:        "web",
				Type:      RouteTypeHTTP,
				LocalIP:   "127.0.0.1",
				LocalPort: 80,
				Subdomain: "app",
			},
		},
	}

	common, _, _, err := GenerateFRPClientConfig(cfg, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if common.LoginFailExit == nil || *common.LoginFailExit != true {
		t.Errorf("LoginFailExit = %v, want true", common.LoginFailExit)
	}
	if common.Transport.DialServerKeepAlive != 120 {
		t.Errorf("DialServerKeepAlive = %d, want 120", common.Transport.DialServerKeepAlive)
	}
	if common.Transport.DialServerTimeout != 5 {
		t.Errorf("DialServerTimeout = %d, want 5", common.Transport.DialServerTimeout)
	}
}

func TestGenerateFRPClientConfig_UnsupportedType(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Addr: "example.com",
			Port: 7000,
		},
		Routes: []Route{
			{
				ID:        "bad",
				Type:      RouteType("frp_udp"),
				LocalIP:   "127.0.0.1",
				LocalPort: 80,
			},
		},
	}

	_, _, _, err := GenerateFRPClientConfig(cfg, "")
	if err == nil {
		t.Fatal("expected error for unsupported route type")
	}
}

func TestGenerateFRPClientConfig_RejectsEmptyRouteID(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Addr: "frps.example.com", Port: 7000},
		Routes: []Route{{
			Type:      RouteTypeHTTP,
			LocalIP:   "127.0.0.1",
			LocalPort: 8080,
		}},
	}
	_, _, _, err := GenerateFRPClientConfig(cfg, "")
	if err == nil {
		t.Fatal("GenerateFRPClientConfig returned nil error, want empty route id error")
	}
	if !strings.Contains(err.Error(), "route id is required before FRP generation") {
		t.Fatalf("error = %v, want route id guard", err)
	}
}

func TestBuildHTTPProxy_UsesRoutingIDAndRetainsPublicMetadata(t *testing.T) {
	r := Route{
		ID: "dashboard", Type: RouteTypeHTTP,
		LocalIP: "127.0.0.1", LocalPort: 8080,
		ResourceID: testPublicResourceA, ConnectorRoutingID: testRoutingA,
	}
	pc := buildHTTPProxy(r, "machine-xyz", "")
	if pc.SubDomain != testRoutingA {
		t.Errorf("SubDomain = %q, want connector routing identity", pc.SubDomain)
	}
	if got := pc.Metadatas[MetaResourceID]; got != testPublicResourceA {
		t.Errorf("Metadatas[%q] = %q, want public resource identity", MetaResourceID, got)
	}
}

func TestGenerateFRPClientConfig_RejectsManagedCustomDomains(t *testing.T) {
	cfg := &Config{Routes: []Route{{
		ID: "managed", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080,
		ResourceID: testPublicResourceA, ConnectorRoutingID: testRoutingA,
		CustomDomains: []string{"victim.example.com"},
	}}}

	_, _, _, err := GenerateFRPClientConfig(cfg, "machine-xyz")
	if err == nil || !strings.Contains(err.Error(), "cannot set custom_domains") {
		t.Fatalf("GenerateFRPClientConfig error = %v, want managed custom_domains rejection", err)
	}
}

func TestBuildHTTPProxy_DoesNotEmitManagedCustomDomains(t *testing.T) {
	r := Route{
		ID: "managed", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080,
		ResourceID: testPublicResourceA, ConnectorRoutingID: testRoutingA,
		CustomDomains: []string{"victim.example.com"},
	}

	pc := buildHTTPProxy(r, "machine-xyz", "")
	if len(pc.CustomDomains) != 0 {
		t.Fatalf("managed CustomDomains = %v, want none", pc.CustomDomains)
	}
}

// TestBuildHTTPProxy_ExplicitSubDomainPreserved fences the override
// path: an operator-set subdomain that matches connector_routing_id keeps the
// literal value, and Metas[resource_id] still carries the public identity.
func TestBuildHTTPProxy_ExplicitSubDomainPreserved(t *testing.T) {
	r := Route{
		ID:                 "dashboard",
		Type:               RouteTypeHTTP,
		LocalIP:            "127.0.0.1",
		LocalPort:          8080,
		Subdomain:          testRoutingA,
		ResourceID:         testPublicResourceA,
		ConnectorRoutingID: testRoutingA,
	}
	pc := buildHTTPProxy(r, "machine-xyz", "")
	if pc.SubDomain != testRoutingA {
		t.Errorf("SubDomain = %q, want %q", pc.SubDomain, testRoutingA)
	}
	if got := pc.Metadatas[MetaResourceID]; got != testPublicResourceA {
		t.Errorf("Metadatas[%q] = %q, want public resource identity", MetaResourceID, got)
	}
}

// Managed routing is authoritative even if a stale template remains on the
// in-memory route. routeToProxy rejects this conflict; the private builder also
// refuses to render the template over producer routing metadata.
func TestBuildHTTPProxy_RoutingIDOverridesManagedTemplate(t *testing.T) {
	r := Route{
		ID:                 "admin",
		Type:               RouteTypeHTTP,
		LocalIP:            "127.0.0.1",
		LocalPort:          9090,
		Subdomain:          "admin-{{ .MachineID }}",
		ResourceID:         testPublicResourceA,
		ConnectorRoutingID: testRoutingA,
	}
	pc := buildHTTPProxy(r, "abc123", "")
	if pc.SubDomain != testRoutingA {
		t.Errorf("SubDomain = %q, want exact routing ID", pc.SubDomain)
	}
	if got := pc.Metadatas[MetaResourceID]; got != testPublicResourceA {
		t.Errorf("Metadatas[%q] = %q, want public resource identity (not the templated subdomain)", MetaResourceID, got)
	}
}

// Managed routing remains authoritative even when a stale template expands to
// empty. routeToProxy rejects the mismatch before this private builder in
// production; the builder still cannot regress to a client-derived fallback.
func TestBuildHTTPProxy_TemplatedSubdomain_EmptyMachineID_NoCollapse(t *testing.T) {
	r := Route{
		ID:                 "admin",
		Type:               RouteTypeHTTP,
		LocalIP:            "127.0.0.1",
		LocalPort:          9090,
		Subdomain:          "{{ .MachineID }}",
		ResourceID:         testPublicResourceA,
		ConnectorRoutingID: testRoutingA,
	}
	pc := buildHTTPProxy(r, "", "")
	if pc.SubDomain != testRoutingA {
		t.Errorf("SubDomain = %q, want exact routing ID", pc.SubDomain)
	}
	if got := pc.Metadatas[MetaResourceID]; got != testPublicResourceA {
		t.Errorf("Metadatas[%q] = %q, want public resource identity", MetaResourceID, got)
	}
}

// TestBuildHTTPProxy_NoResourceID_NoMetasKey: routes without a
// resource_id (legacy / non-qURL FRP usage) MUST NOT emit an empty
// Metas[resource_id] — that would route the tunnel-server lookup
// through `resource_not_found` instead of the proxy-name/subdomain
// fallback paths. The empty-string-vs-absent distinction is the
// load-bearing invariant the test pins.
func TestBuildHTTPProxy_NoResourceID_NoMetasKey(t *testing.T) {
	r := Route{
		ID:        "legacy",
		Type:      RouteTypeHTTP,
		LocalIP:   "127.0.0.1",
		LocalPort: 8080,
		Subdomain: "legacy-app",
	}
	pc := buildHTTPProxy(r, "", "")
	if pc.SubDomain != "legacy-app" {
		t.Errorf("SubDomain = %q, want %q", pc.SubDomain, "legacy-app")
	}
	if _, ok := pc.Metadatas[MetaResourceID]; ok {
		t.Errorf("Metadatas[%q] should be absent when ResourceID is empty (got map=%v)", MetaResourceID, pc.Metadatas)
	}
}

// TestBuildHTTPProxy_LoadBalancerGroupWired pins the multi-replica
// fan-out wire: when Route.LoadBalancerGroup is set, FRP's
// LoadBalancer.Group + LoadBalancer.GroupKey both populate so FRPS
// can register the proxy under the group's routing key and the
// group's per-key auth.
func TestBuildHTTPProxy_LoadBalancerGroupWired(t *testing.T) {
	r := Route{
		ID:                 "tucker",
		Type:               RouteTypeHTTP,
		LocalIP:            "127.0.0.1",
		LocalPort:          8080,
		ResourceID:         testPublicResourceA,
		ConnectorRoutingID: testRoutingA,
		LoadBalancerGroup:  testRoutingA,
	}
	pc := buildHTTPProxy(r, "", "")
	if pc.LoadBalancer.Group != testRoutingA {
		t.Errorf("LoadBalancer.Group = %q, want routing identity", pc.LoadBalancer.Group)
	}
	if pc.LoadBalancer.GroupKey != testRoutingA {
		t.Errorf("LoadBalancer.GroupKey = %q, want routing identity", pc.LoadBalancer.GroupKey)
	}
}

func TestBuildHTTPProxy_ManagedGroupUsesAuthoritativeRoutingID(t *testing.T) {
	r := Route{
		ID:                 "tucker",
		Type:               RouteTypeHTTP,
		LocalIP:            "127.0.0.1",
		LocalPort:          8080,
		ResourceID:         testPublicResourceA,
		ConnectorRoutingID: testRoutingA,
	}
	pc := buildHTTPProxy(r, "", "")
	if pc.LoadBalancer.Group != testRoutingA {
		t.Errorf("LoadBalancer.Group = %q, want routing identity", pc.LoadBalancer.Group)
	}
	if pc.LoadBalancer.GroupKey != testRoutingA {
		t.Errorf("LoadBalancer.GroupKey = %q, want routing identity", pc.LoadBalancer.GroupKey)
	}
}

// TestBuildTCPProxy_LoadBalancerGroupWired pins the TCP-side wire
// (mirrors the HTTP one — same FRPS group-registration semantics).
func TestBuildTCPProxy_LoadBalancerGroupWired(t *testing.T) {
	r := Route{
		ID:                "ssh",
		Type:              RouteTypeTCP,
		LocalIP:           "127.0.0.1",
		LocalPort:         22,
		RemotePort:        6022,
		LoadBalancerGroup: "r_tcp1234567",
	}
	pc := buildTCPProxy(r, "")
	if pc.LoadBalancer.Group != "r_tcp1234567" {
		t.Errorf("TCP LoadBalancer.Group = %q, want r_tcp1234567", pc.LoadBalancer.Group)
	}
	if pc.LoadBalancer.GroupKey != "r_tcp1234567" {
		t.Errorf("TCP LoadBalancer.GroupKey = %q, want r_tcp1234567", pc.LoadBalancer.GroupKey)
	}
}

func TestGenerateFRPClientConfig_ManagedTCPFailsClosed(t *testing.T) {
	cfg := &Config{Routes: []Route{{
		ID: "ssh", Type: RouteTypeTCP, LocalIP: "127.0.0.1", LocalPort: 22, RemotePort: 6022,
		ResourceID: testPublicResourceA, ConnectorRoutingID: testRoutingA,
	}}}
	_, _, _, err := GenerateFRPClientConfig(cfg, "")
	if err == nil || !strings.Contains(err.Error(), "requires route type \"http\"") {
		t.Fatalf("GenerateFRPClientConfig error = %v, want managed HTTP-only rejection", err)
	}
}

func TestGenerateFRPClientConfig_ManagedRouteMissingRoutingFailsClosed(t *testing.T) {
	cfg := &Config{Routes: []Route{{
		ID: "managed", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080,
		ResourceID: testPublicResourceA,
	}}}
	_, _, _, err := GenerateFRPClientConfig(cfg, "")
	if err == nil || !strings.Contains(err.Error(), "requires its exact server-issued routing identity") {
		t.Fatalf("error = %v, want final routing-identity guard", err)
	}
}

func TestGenerateFRPClientConfig_ManagedRouteRejectsTransportHostileResourceID(t *testing.T) {
	cfg := &Config{Routes: []Route{{
		ID: "managed", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080,
		ResourceID: testPublicResourceA + "\x00", ConnectorRoutingID: testRoutingA,
	}}}
	_, _, _, err := GenerateFRPClientConfig(cfg, "")
	if err == nil || !strings.Contains(err.Error(), "resource_id must not contain control characters") {
		t.Fatalf("error = %v, want managed resource-id control-character rejection", err)
	}
}

func TestGenerateFRPClientConfig_AllowsDistinctManagedRoutingIDs(t *testing.T) {
	cfg := &Config{Routes: []Route{
		{ID: "alpha", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080, ResourceID: testPublicResourceA, ConnectorRoutingID: testRoutingA},
		{ID: "bravo", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 9000, ResourceID: testPublicResourceB, ConnectorRoutingID: testRoutingB},
	}}
	_, proxies, _, err := GenerateFRPClientConfig(cfg, "")
	if err != nil {
		t.Fatalf("GenerateFRPClientConfig: %v", err)
	}
	if len(proxies) != 2 {
		t.Fatalf("proxies = %d, want 2", len(proxies))
	}
	for i, want := range []struct {
		resourceID string
		routingID  string
	}{{testPublicResourceA, testRoutingA}, {testPublicResourceB, testRoutingB}} {
		proxy, ok := proxies[i].(*v1.HTTPProxyConfig)
		if !ok {
			t.Fatalf("proxies[%d] = %T, want *v1.HTTPProxyConfig", i, proxies[i])
		}
		if proxy.SubDomain != want.routingID || proxy.LoadBalancer.Group != want.routingID || proxy.LoadBalancer.GroupKey != want.routingID {
			t.Errorf("proxies[%d] routing = subdomain %q group %q group_key %q, want %q", i, proxy.SubDomain, proxy.LoadBalancer.Group, proxy.LoadBalancer.GroupKey, want.routingID)
		}
		if got := proxy.Metadatas[MetaResourceID]; got != want.resourceID {
			t.Errorf("proxies[%d] resource_id metadata = %q, want %q", i, got, want.resourceID)
		}
	}
}

// TestFRPProxyName fences the salt-render contract.
//   - Empty discriminator → raw route ID for direct config-generation callers.
//   - Non-empty discriminator → `<route-id>-<discriminator>` (deterministic).
//
// Renaming FRPProxyName or changing the join character requires
// coordinated FRP server / qurl-router updates (proxy name is the FRPS NewProxy
// registration key; SubDomain comes from connector_routing_id, not the salted
// name, so vhost routing is unaffected).
func TestFRPProxyName(t *testing.T) {
	cases := []struct {
		name, routeID, discriminator, want string
	}{
		{"empty discriminator returns raw id", "fileviewer-sandbox", "", "fileviewer-sandbox"},
		{"non-empty discriminator appends with hyphen", "fileviewer-sandbox", "abc123def456", "fileviewer-sandbox-abc123def456"},
		{"discriminator normalized at wire boundary", "fileviewer-sandbox", "REPLICA_1!", "fileviewer-sandbox-replica1"},
		{"resource_id-shaped route", "r_abc12345678", "ecsuuidshort", "r_abc12345678-ecsuuidshort"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FRPProxyName(tc.routeID, tc.discriminator); got != tc.want {
				t.Errorf("FRPProxyName(%q, %q) = %q, want %q", tc.routeID, tc.discriminator, got, tc.want)
			}
		})
	}
}

// TestBuildHTTPProxy_DistinctSaltsDistinctNames_SameGroup is the
// core HA invariant: two replicas of the same route slug, with
// different discriminators, MUST produce distinct FRP proxy Names so
// the FRPS NewProxy registration succeeds, AND the same
// LoadBalancer.Group so FRPS round-robins between them.
func TestBuildHTTPProxy_DistinctSaltsDistinctNames_SameGroup(t *testing.T) {
	r := Route{
		ID:                 "fileviewer-sandbox",
		Type:               RouteTypeHTTP,
		LocalIP:            "127.0.0.1",
		LocalPort:          9808,
		ResourceID:         testPublicResourceA,
		ConnectorRoutingID: testRoutingA,
		LoadBalancerGroup:  testRoutingA,
	}
	a := buildHTTPProxy(r, "", "ecsuuid-aa00")
	b := buildHTTPProxy(r, "", "ecsuuid-bb11")

	// Names diverge.
	if a.Name == b.Name {
		t.Errorf("proxy names identical (%q) — would trigger FRP ErrProxyRepeated on the second NewProxy", a.Name)
	}
	if a.Name != "fileviewer-sandbox-ecsuuid-aa00" {
		t.Errorf("a.Name = %q, want %q", a.Name, "fileviewer-sandbox-ecsuuid-aa00")
	}
	if b.Name != "fileviewer-sandbox-ecsuuid-bb11" {
		t.Errorf("b.Name = %q, want %q", b.Name, "fileviewer-sandbox-ecsuuid-bb11")
	}

	// Routing surfaces stay on ConnectorRoutingID; public metadata stays on
	// ResourceID. Neither depends on the salted proxy name.
	if a.LoadBalancer.Group != b.LoadBalancer.Group {
		t.Errorf("LoadBalancer.Group diverged: a=%q b=%q (must be equal for FRPS group fanout)", a.LoadBalancer.Group, b.LoadBalancer.Group)
	}
	if a.LoadBalancer.Group != testRoutingA {
		t.Errorf("LoadBalancer.Group = %q, want connector routing identity", a.LoadBalancer.Group)
	}
	if a.LoadBalancer.GroupKey != b.LoadBalancer.GroupKey {
		t.Errorf("LoadBalancer.GroupKey diverged: a=%q b=%q", a.LoadBalancer.GroupKey, b.LoadBalancer.GroupKey)
	}
	if a.SubDomain != b.SubDomain {
		t.Errorf("SubDomain diverged: a=%q b=%q (must be equal — keyed on connector_routing_id, not salted name)", a.SubDomain, b.SubDomain)
	}
	if a.SubDomain != testRoutingA {
		t.Errorf("SubDomain = %q, want connector routing identity", a.SubDomain)
	}
	if a.Metadatas[MetaResourceID] != b.Metadatas[MetaResourceID] {
		t.Errorf("Metadatas[resource_id] diverged: a=%q b=%q", a.Metadatas[MetaResourceID], b.Metadatas[MetaResourceID])
	}
	if a.Metadatas[MetaResourceID] != testPublicResourceA {
		t.Errorf("Metadatas[resource_id] = %q, want public resource identity", a.Metadatas[MetaResourceID])
	}
}

// TestBuildHTTPProxy_SameSaltStableName: rendering twice with the same
// discriminator produces the same name. Important because the FRP
// managed session's per-cycle re-render must not flap the registration.
func TestBuildHTTPProxy_SameSaltStableName(t *testing.T) {
	r := Route{
		ID:        "fileviewer-sandbox",
		Type:      RouteTypeHTTP,
		LocalIP:   "127.0.0.1",
		LocalPort: 9808,
	}
	a := buildHTTPProxy(r, "", "samesalt")
	b := buildHTTPProxy(r, "", "samesalt")
	if a.Name != b.Name {
		t.Errorf("same-salt render produced different names: %q vs %q", a.Name, b.Name)
	}
}

// TestGenerateFRPClientConfig_HonorsServerReplicaDiscriminator pins
// the wire-up: the YAML knob (cfg.Server.ReplicaDiscriminator) MUST
// flow into the proxy name. Without this, the resolver-set salt in
// run.go has no path to the FRP wire.
func TestGenerateFRPClientConfig_HonorsServerReplicaDiscriminator(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Addr:                 "frps.example.com",
			Port:                 7000,
			ReplicaDiscriminator: "salt12345",
		},
		Routes: []Route{
			{
				ID:        "fileviewer-sandbox",
				Type:      RouteTypeHTTP,
				LocalIP:   "127.0.0.1",
				LocalPort: 9808,
			},
			{
				ID:         "echo",
				Type:       RouteTypeTCP,
				LocalIP:    "127.0.0.1",
				LocalPort:  22,
				RemotePort: 6022,
			},
		},
	}
	_, proxies, _, err := GenerateFRPClientConfig(cfg, "machine-1")
	if err != nil {
		t.Fatalf("GenerateFRPClientConfig: %v", err)
	}
	if len(proxies) != 2 {
		t.Fatalf("got %d proxies, want 2", len(proxies))
	}
	if got := proxies[0].(*v1.HTTPProxyConfig).Name; got != "fileviewer-sandbox-salt12345" {
		t.Errorf("http proxy Name = %q, want %q", got, "fileviewer-sandbox-salt12345")
	}
	if got := proxies[1].(*v1.TCPProxyConfig).Name; got != "echo-salt12345" {
		t.Errorf("tcp proxy Name = %q, want %q", got, "echo-salt12345")
	}
}

// TestGenerateFRPClientConfig_SaltedNamesValidateUnderFRPClient is
// the silent-revert guard for a future FRP bump introducing proxy-
// name length / charset validation. Runs the salted name through
// FRP's client-side validator (the same one that runs against
// production wire), so a CI break here means FRP has tightened the
// name contract and the salt format needs revisiting.
func TestGenerateFRPClientConfig_SaltedNamesValidateUnderFRPClient(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Addr: "frps.example.com",
			Port: 7000,
			// 16-char discriminator — the resolver's MaxDiscriminatorLen.
			ReplicaDiscriminator: "abcdef0123456789",
		},
		Routes: []Route{
			{
				// 14-char route id (a typical fileviewer slug) + 16-char
				// discriminator + 1-char hyphen = 31 chars. LayerV FRP
				// v0.70.0-layerv.5
				// has no name-length validation, but this is the upper
				// bound the salt format produces.
				ID:                 "fileviewer-sbx",
				Type:               RouteTypeHTTP,
				LocalIP:            "127.0.0.1",
				LocalPort:          9808,
				ResourceID:         testPublicResourceA,
				ConnectorRoutingID: testRoutingA,
			},
		},
	}
	_, proxies, _, err := GenerateFRPClientConfig(cfg, "")
	if err != nil {
		t.Fatalf("GenerateFRPClientConfig: %v", err)
	}
	proxies[0].Complete()
	if err := frpvalidation.ValidateProxyConfigurerForClient(proxies[0]); err != nil {
		t.Fatalf("FRP client rejected salted name %q: %v", proxies[0].GetBaseConfig().Name, err)
	}
}
