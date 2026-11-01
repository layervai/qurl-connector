package config

import (
	"strings"
	"testing"
)

// TestValidateSlug_AcceptsMergedQurlServiceShape pins the client-side
// regex to the qURL control-plane CreateResourceRequest.slug
// pattern as merged in PR #729. Drift between client and server would
// either bounce valid slugs at the wrong layer (looks invalid here
// when server accepts) or accept invalid slugs only to round-trip a
// 400 (looks valid here when server rejects).
func TestValidateSlug_AcceptsMergedQurlServiceShape(t *testing.T) {
	valid := []string{
		"abc",                               // 3-char minimum, all letters
		"prod-dashboard",                    // canonical example from the install docs
		"tucker-test",                       // common smoke-test name
		"a-b",                               // shortest valid with hyphen
		"a1b",                               // mixed alphanumeric
		"a" + strings.Repeat("b", 62) + "c", // 64-char max
		"prod--dashboard",                   // consecutive hyphens (server merged with wide regex)
	}
	for _, s := range valid {
		if err := ValidateSlug(s); err != nil {
			t.Errorf("ValidateSlug(%q) = %v, want nil", s, err)
		}
	}
}

func TestValidateSlug_Rejects(t *testing.T) {
	invalid := map[string]string{
		"empty":           "",
		"too short":       "ab",
		"too long":        "a" + strings.Repeat("b", 63) + "c", // 65 chars
		"leading digit":   "1abc",
		"leading hyphen":  "-abc",
		"trailing hyphen": "abc-",
		"underscore":      "ab_c",
		"uppercase":       "Abc",
		"space":           "ab c",
		"unicode":         "abç",
		"dot":             "ab.c",
		"plus":            "ab+c",
	}
	for name, in := range invalid {
		t.Run(name, func(t *testing.T) {
			if err := ValidateSlug(in); err == nil {
				t.Errorf("ValidateSlug(%q) = nil, want error", in)
			}
		})
	}
}

func TestValidateConnectorRoutingID_ExactNoNormalization(t *testing.T) {
	valid := "c-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, accepted := range []string{
		valid,
		"c-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbq",
	} {
		if err := ValidateConnectorRoutingID(accepted); err != nil {
			t.Fatalf("valid canonical producer identity %q rejected: %v", accepted, err)
		}
	}
	for name, value := range map[string]string{
		"leading whitespace":  " " + valid,
		"trailing whitespace": valid + " ",
		"uppercase":           "c-Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"too short":           valid[:len(valid)-1],
		"bad prefix":          "r-" + valid[2:],
		"invalid base32":      "c-1" + valid[3:],
		"nonzero tail bits":   "c-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",
		"padded":              valid + "=",
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateConnectorRoutingID(value); err == nil {
				t.Fatalf("ValidateConnectorRoutingID(%q) = nil, want exact-shape error", value)
			}
		})
	}
}

func TestValidate_RejectsTransportHostilePublicResourceID(t *testing.T) {
	for name, resourceID := range map[string]string{
		"leading whitespace":  " " + testPublicResourceA,
		"trailing whitespace": testPublicResourceA + " ",
		"embedded control":    testPublicResourceA + "\x00",
		"invalid UTF-8":       testPublicResourceA + string([]byte{0xff}),
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &Config{Routes: []Route{{
				ID: "managed", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080,
				CRID: resourceID, ConnectorRoutingID: testRoutingA,
			}}}
			if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "crid") {
				t.Fatalf("Validate error = %v, want exact public resource-id rejection", err)
			}
		})
	}
}

func TestValidateRejectsTransportHostileKnockResourceID(t *testing.T) {
	cfg := &Config{Routes: []Route{{
		ID: "managed", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080,
		CRID: testPublicResourceA, ConnectorRoutingID: testRoutingA, KnockResourceID: " cell-resource",
	}}}
	if err := validateStartupInput(cfg); err == nil || !strings.Contains(err.Error(), "knock_resource_id must not contain leading or trailing whitespace") {
		t.Fatalf("validateStartupInput error = %v, want local knock-resource rejection", err)
	}
}

func TestValidateRejectsNonCanonicalEgressLocalIPWhitespace(t *testing.T) {
	for name, value := range map[string]string{
		"leading":  " 192.0.2.10",
		"trailing": "192.0.2.10 ",
		"only":     " ",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &Config{
				Server: ServerConfig{EgressLocalIP: value},
				Routes: []Route{{ID: "web", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080}},
			}
			if err := validateStartupInput(cfg); err == nil || !strings.Contains(err.Error(), "must not contain leading or trailing whitespace") {
				t.Fatalf("validateStartupInput egress_local_ip %q error = %v", value, err)
			}
		})
	}
}

func TestValidateRejectsUnusableEgressLocalIPScopes(t *testing.T) {
	for name, value := range map[string]string{
		"unspecified IPv4": "0.0.0.0",
		"unspecified IPv6": "::",
		"loopback IPv4":    "127.0.0.1",
		"loopback IPv6":    "::1",
		"link-local IPv4":  "169.254.10.20",
		"link-local IPv6":  "fe80::1",
		"multicast IPv4":   "224.0.0.1",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &Config{
				Server: ServerConfig{EgressLocalIP: value},
				Routes: []Route{{ID: "web", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080}},
			}
			if err := validateStartupInput(cfg); err == nil || !strings.Contains(err.Error(), "non-loopback, non-link-local unicast") {
				t.Fatalf("validateStartupInput egress_local_ip %q error = %v", value, err)
			}
		})
	}

	for _, value := range []string{"192.0.2.10", "10.0.0.10", "2001:db8::10"} {
		cfg := &Config{
			Server: ServerConfig{EgressLocalIP: value},
			Routes: []Route{{ID: "web", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080}},
		}
		if err := validateStartupInput(cfg); err != nil {
			t.Errorf("validateStartupInput rejected usable egress_local_ip %q: %v", value, err)
		}
	}
}

// TestValidateAcceptsSupportedServerProtocols pins the exact FRP transport
// set (plus empty, which applyDefaults resolves to tcp on the Load path) and
// the tcp-family values that remain combinable with egress_local_ip.
func TestValidateAcceptsSupportedServerProtocols(t *testing.T) {
	for _, value := range []string{"", "tcp", "kcp", "quic", "websocket", "wss"} {
		cfg := &Config{
			Server: ServerConfig{Protocol: value},
			Routes: []Route{{ID: "web", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080}},
		}
		if err := validateStartupInput(cfg); err != nil {
			t.Errorf("validateStartupInput rejected supported protocol %q: %v", value, err)
		}
	}

	for _, value := range []string{"", "tcp", "websocket", "wss"} {
		cfg := &Config{
			Server: ServerConfig{Protocol: value, EgressLocalIP: "192.0.2.10"},
			Routes: []Route{{ID: "web", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080}},
		}
		if err := validateStartupInput(cfg); err != nil {
			t.Errorf("validateStartupInput rejected protocol %q with egress_local_ip: %v", value, err)
		}
	}
}

func TestValidateRejectsUnsupportedServerProtocol(t *testing.T) {
	for name, value := range map[string]string{
		"udp":                 "udp",
		"uppercase":           "TCP",
		"mixed case":          "Tcp",
		"leading whitespace":  " tcp",
		"trailing whitespace": "tcp ",
		"garbage":             "carrier-pigeon",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &Config{
				Server: ServerConfig{Protocol: value},
				Routes: []Route{{ID: "web", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080}},
			}
			err := validateStartupInput(cfg)
			if err == nil || !strings.Contains(err.Error(), "not a supported FRP transport") {
				t.Fatalf("validateStartupInput protocol %q error = %v", value, err)
			}
			if !strings.Contains(err.Error(), "tcp, kcp, quic, websocket, wss") {
				t.Errorf("error %q should name the exact allowed transports", err.Error())
			}
		})
	}

	// Whitespace-padded "kcp " must hit the unsupported-value rejection even
	// with egress_local_ip set — nothing may trim it past either gate.
	cfg := &Config{
		Server: ServerConfig{Protocol: "kcp ", EgressLocalIP: "192.0.2.10"},
		Routes: []Route{{ID: "web", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080}},
	}
	if err := validateStartupInput(cfg); err == nil || !strings.Contains(err.Error(), "not a supported FRP transport") {
		t.Fatalf(`validateStartupInput protocol "kcp " with egress_local_ip error = %v`, err)
	}
}

// TestValidateRejectsEgressLocalIPWithKCPOrQUIC fails closed on the split-
// egress hazard: FRP applies Transport.ConnectServerLocalIP only to tcp
// dials, so kcp/quic would leave from the OS-default source IP while the
// knock left from the pinned one, and the session would die at the source-
// scoped default-DROP boundary.
func TestValidateRejectsEgressLocalIPWithKCPOrQUIC(t *testing.T) {
	for _, value := range []string{"kcp", "quic"} {
		t.Run(value, func(t *testing.T) {
			cfg := &Config{
				Server: ServerConfig{Protocol: value, EgressLocalIP: "192.0.2.10"},
				Routes: []Route{{ID: "web", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080}},
			}
			err := validateStartupInput(cfg)
			if err == nil {
				t.Fatalf("expected error for protocol %q with egress_local_ip, got nil", value)
			}
			if !strings.Contains(err.Error(), "egress_local_ip") || !strings.Contains(err.Error(), "different source IPs") {
				t.Errorf("error %q should explain the egress_local_ip source-IP split for %s", err.Error(), value)
			}
		})
	}
}

// TestValidate_AcceptsRouteID covers the validation hook in Validate:
// a route with a well-formed id must pass.
func TestValidate_AcceptsRouteID(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Addr: "proxy.example.com", Port: 7000},
		Routes: []Route{{
			Type:      RouteTypeHTTP,
			LocalIP:   "127.0.0.1",
			LocalPort: 8080,
			ID:        "tucker-test",
		}},
	}
	if err := Validate(cfg); err != nil {
		t.Errorf("Validate rejected a valid id route: %v", err)
	}
}

// TestValidate_RejectsInvalidRouteID pins the boundary check: a route
// with a malformed id must surface a clear error referring to the bad
// value.
func TestValidate_RejectsInvalidRouteID(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Addr: "proxy.example.com", Port: 7000},
		Routes: []Route{{
			Type:      RouteTypeHTTP,
			LocalIP:   "127.0.0.1",
			LocalPort: 8080,
			ID:        "BAD_SLUG",
		}},
	}
	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected error for invalid id, got nil")
	}
	if !strings.Contains(err.Error(), "routes[0]") || !strings.Contains(err.Error(), "BAD_SLUG") {
		t.Errorf("error %q should identify the route index and bad id", err.Error())
	}
}

func TestValidate_BootstrapInputAllowsPinnedResourcePendingHydration(t *testing.T) {
	cfg := &Config{Routes: []Route{{
		ID: "pinned", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080,
		CRID: testPublicResourceA,
	}}}
	if err := validateStartupInput(cfg); err != nil {
		t.Fatalf("startup-input validation blocked pinned hydration: %v", err)
	}
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "connector_routing_id") {
		t.Fatalf("final validation error = %v, want missing connector_routing_id", err)
	}
}

func TestValidate_AllowsCompleteManagedIdentity(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Addr: "proxy.example.com", Port: 7000},
		Routes: []Route{{
			ID:                 "tucker",
			Type:               RouteTypeHTTP,
			LocalIP:            "127.0.0.1",
			LocalPort:          8080,
			CRID:               testPublicResourceA,
			ConnectorRoutingID: testRoutingA,
		}},
	}
	if err := Validate(cfg); err != nil {
		t.Errorf("Validate rejected a slug-less but crid-pinned route: %v", err)
	}
}

func TestValidate_AllowsDistinctManagedIdentityPairs(t *testing.T) {
	cfg := &Config{Routes: []Route{
		{ID: "alpha", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080, CRID: testPublicResourceA, ConnectorRoutingID: testRoutingA},
		{ID: "bravo", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 9000, CRID: testPublicResourceB, ConnectorRoutingID: testRoutingB},
	}}
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate rejected distinct managed identities: %v", err)
	}
}

func TestValidate_RejectsDuplicateManagedResourceID(t *testing.T) {
	cfg := &Config{Routes: []Route{
		{ID: "alpha", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080, CRID: testPublicResourceA, ConnectorRoutingID: testRoutingA},
		{ID: "bravo", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 9000, CRID: testPublicResourceA, ConnectorRoutingID: testRoutingA},
	}}
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "duplicate crid") {
		t.Fatalf("Validate error = %v, want duplicate public resource rejection", err)
	}
}

func TestValidate_RejectsRoutingIDBoundToDifferentResources(t *testing.T) {
	cfg := &Config{Routes: []Route{
		{ID: "alpha", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080, CRID: testPublicResourceA, ConnectorRoutingID: testRoutingA},
		{ID: "bravo", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 9000, CRID: testPublicResourceB, ConnectorRoutingID: testRoutingA},
	}}
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "already bound to crid") {
		t.Fatalf("Validate error = %v, want routing/public identity collision rejection", err)
	}
}

func TestValidate_BootstrapInputRejectsDuplicatePinnedResourceID(t *testing.T) {
	cfg := &Config{Routes: []Route{
		{ID: "alpha", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080, CRID: testPublicResourceA},
		{ID: "bravo", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 9000, CRID: testPublicResourceA},
	}}
	err := validateStartupInput(cfg)
	if err == nil || !strings.Contains(err.Error(), "duplicate crid") {
		t.Fatalf("startup-input error = %v, want duplicate pinned resource rejection", err)
	}
}

func TestValidate_BootstrapInputAllowsDistinctPendingRoutes(t *testing.T) {
	cfg := &Config{Routes: []Route{
		{ID: "alpha", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080},
		{ID: "bravo", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 9000},
	}}
	if err := validateStartupInput(cfg); err != nil {
		t.Fatalf("startup-input rejected distinct unresolved routes: %v", err)
	}
}
