package config

import (
	"encoding/base32"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// slugPattern mirrors the qURL control plane's CreateResourceRequest.slug
// regex (the merged shape from PR #729). Kept in lockstep on purpose:
// validating client-side with a wider regex would let invalid slugs reach
// the server only to bounce as 400; validating tighter would silently
// reject slugs the server would have accepted. Length bounds (3-64) are
// inlined in the regex via the `{1,62}` middle run.
//
// Consecutive hyphens are intentional — the middle character class
// `[a-z0-9-]` does NOT enforce single-hyphen separators (so e.g.
// `prod--dashboard` validates). This mirrors the control plane exactly;
// future tightening must happen on both sides in lockstep or
// otherwise-valid slugs will fail at one boundary.
var slugPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}[a-z0-9]$`)

var connectorRoutingIDEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// ValidateSlug reports whether s is an acceptable Connector resource slug
// per the qURL control-plane contract. Empty input is rejected — callers that
// want to allow empty (e.g. an optional YAML field) must short-circuit
// before calling.
func ValidateSlug(s string) error {
	if !slugPattern.MatchString(s) {
		return fmt.Errorf("slug %q does not match required format (3-64 chars, lowercase a-z0-9 + hyphens, must start with a letter and end alphanumeric)", s)
	}
	return nil
}

// ValidateConnectorRoutingID reports whether s is the exact canonical routing
// label shape returned by the qURL control plane. Decoding validates the producer's
// lowercase, unpadded RFC 4648 base32 wire format; exact re-encoding rejects
// non-zero trailing bits. This validates an opaque value and never derives it
// from resource_id. Producer source of truth:
// the qURL control plane's ConnectorRoutingIDPrefix,
// ConnectorRoutingIDLength, and DeriveConnectorRoutingID.
func ValidateConnectorRoutingID(s string) error {
	// A 32-byte producer digest is 52 characters in unpadded base32; the c-
	// namespace prefix makes the complete label exactly 54 bytes.
	if len(s) != 54 || !strings.HasPrefix(s, "c-") {
		return fmt.Errorf("connector_routing_id %q must be c- plus 52 canonical lowercase unpadded base32 characters", s)
	}
	payload := s[2:]
	decoded, err := connectorRoutingIDEncoding.DecodeString(payload)
	if err != nil || connectorRoutingIDEncoding.EncodeToString(decoded) != payload {
		return fmt.Errorf("connector_routing_id %q must be c- plus the canonical lowercase unpadded base32 encoding of 32 bytes", s)
	}
	return nil
}

// validateExactOpaqueIdentifier rejects transport-hostile spellings without
// inventing semantics for a producer-owned identifier. Resource IDs are public
// keys, but canonical key parsing remains owned by qurl-go; this package only
// guarantees that the exact value is non-empty, valid UTF-8, unpadded by
// surrounding whitespace, and free of control characters before it enters FRP
// metadata or config comparisons.
func validateExactOpaqueIdentifier(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must not contain leading or trailing whitespace", field)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s must contain valid UTF-8", field)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s must not contain control characters", field)
		}
	}
	return nil
}

// Validate checks a fully resolved cfg for structural correctness and returns
// a combined error listing every violation found. Managed routes must already
// carry their server-issued ConnectorRoutingID. Load uses the less-strict
// startup-input phase so a pinned ResourceID can still be hydrated from
// the qURL control plane before this final validation boundary.
func Validate(cfg *Config) error {
	return validate(cfg, true)
}

// validateStartupInput accepts the one intentionally incomplete managed
// shape needed by startup: ResourceID is pinned but ConnectorRoutingID has not
// yet been hydrated. FRP generation independently fails closed if startup
// cannot complete that pair.
func validateStartupInput(cfg *Config) error {
	return validate(cfg, false)
}

func validate(cfg *Config, requireManagedRouting bool) error {
	var errs []error

	// Server validation (only when server section is configured)
	serverAddrSet := strings.TrimSpace(cfg.Server.Addr) != ""
	serverPortSet := cfg.Server.Port != 0
	if serverAddrSet != serverPortSet {
		errs = append(errs, fmt.Errorf("server.addr and server.port must be set together for static FRP boundary config, or both omitted so the NHP ACK supplies the dial target"))
	}
	if strings.TrimSpace(cfg.Server.Token) != "" && !serverAddrSet {
		errs = append(errs, fmt.Errorf("server.token requires server.addr/server.port for static FRP boundary config; omit server.token when the NHP ACK supplies the dial target"))
	}
	if cfg.Server.Port != 0 && (cfg.Server.Port < 1 || cfg.Server.Port > 65535) {
		errs = append(errs, fmt.Errorf("server.port must be 1-65535, got %d", cfg.Server.Port))
	}
	if raw, value := cfg.Server.EgressLocalIP, strings.TrimSpace(cfg.Server.EgressLocalIP); raw != value {
		errs = append(errs, fmt.Errorf("server.egress_local_ip must not contain leading or trailing whitespace, got %q", raw))
	} else if value != "" {
		ip := net.ParseIP(value)
		if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			errs = append(errs, fmt.Errorf("server.egress_local_ip must be a non-loopback, non-link-local unicast IPv4 or IPv6 address, got %q", cfg.Server.EgressLocalIP))
		}
	}
	// Server.Protocol is handed to FRP verbatim (frpgen.go), so an
	// unsupported value would otherwise surface only at runtime, deep inside
	// FRP, with an FRP-shaped error. The allowed set mirrors the vendored FRP
	// v1 validator's SupportedTransportProtocols (pkg/config/v1/validation),
	// kept in sync by the dependency contract test. Exact lowercase spellings
	// only — FRP matches case-sensitively,
	// so "TCP" or a whitespace-padded value must fail here rather than be
	// silently trimmed. Empty means "FRP default"; applyDefaults resolves it
	// to "tcp" on the Load path.
	switch cfg.Server.Protocol {
	case "", "tcp", "websocket", "wss":
	case "kcp", "quic":
		// FRP applies Transport.ConnectServerLocalIP only to tcp dials
		// (websocket/wss rewrite to tcp before dialing; kcp and quic dial
		// with no local address). With egress_local_ip set, the NHP knock
		// would leave from the pinned source IP while the FRP session left
		// from the OS-default one, and the session would be dropped at the
		// source-scoped default-DROP boundary — the exact split the field
		// exists to prevent. Fail closed instead of producing a tunnel
		// that can never come up.
		if cfg.Server.EgressLocalIP != "" {
			errs = append(errs, fmt.Errorf("server.egress_local_ip cannot be combined with server.protocol %q: FRP does not apply a local source address to kcp/quic dials, so the NHP knock and the FRP session would leave from different source IPs and the session would be dropped at the source-scoped boundary; use protocol tcp, websocket, or wss with egress_local_ip", cfg.Server.Protocol))
		}
	default:
		errs = append(errs, fmt.Errorf("server.protocol %q is not a supported FRP transport; use one of tcp, kcp, quic, websocket, wss (exact lowercase), or omit it for the tcp default", cfg.Server.Protocol))
	}

	// Admin validation (only when opted in — a stale Port or Addr set
	// in YAML while Enabled=false is harmless since the listener won't
	// bind).
	if cfg.Admin.Enabled {
		if cfg.Admin.Port < 1 || cfg.Admin.Port > 65535 {
			errs = append(errs, fmt.Errorf("admin.port=%d invalid (must be 1-65535); check qurl-proxy.yaml or unset QURL_ADMIN_ENABLED if you didn't mean to enable the admin API", cfg.Admin.Port))
		}
		// Two-step opt-in for off-host reachability. AdminBindLooksRoutable
		// catches IP literals outside the loopback range (127.0.0.0/8,
		// ::1) AND treats every non-"localhost" hostname as routable
		// (we don't issue DNS at Load time, so an operator deviating
		// from the IP-literal default must accept the off-host gate).
		// Without this gate, a single edit of admin.addr — to
		// 0.0.0.0, to a public hostname, or to host.docker.internal —
		// would silently expose the admin API. The "localhost" carve-
		// out remains because it's structurally ambiguous-but-always-
		// local in every reasonable resolver.
		if AdminBindLooksRoutable(cfg) && !cfg.Admin.AllowRemote {
			errs = append(errs, fmt.Errorf("admin.addr=%q is non-loopback but admin.allow_remote is not set; either revert to a loopback address (any 127.0.0.0/8 IPv4, ::1, or localhost) or add `admin.allow_remote: true` to confirm you want the local status/reload API reachable off-host", cfg.Admin.Addr))
		}

		// The explicit AllowRemote capability REQUIRES a Password even
		// when the current Addr is loopback. The flag authorizes a later
		// off-host address change; keying the credential gate to the
		// current bind would let that one edit silently expose the
		// machineID fallback. That fallback is host-stable and partly
		// inferable — fine only while AllowRemote remains false and any
		// caller is already on the host.
		//
		// Doesn't gate AllowRemote=false (loopback): the machineID
		// fallback stays available on the established loopback path
		// when the runtime can resolve a real machine ID. A loopback
		// bind with no Password either uses machineID-as-password or
		// fails closed at daemon startup if the runtime only has the
		// sentinel "unknown". Any AllowRemote=true configuration with
		// no Password fails Validate before binding.
		if cfg.Admin.AllowRemote && cfg.Admin.Password == "" {
			errs = append(errs, fmt.Errorf("admin.allow_remote=true requires an explicit admin.password even when admin.addr is currently loopback; the flag authorizes off-host exposure, where the host-stable, partly inferable machineID fallback is indefensible. Set admin.password to a strong random secret (e.g. `openssl rand -hex 32`) or revert admin.allow_remote to false"))
		}
	}

	// Route validation
	seenRouteIDs := make(map[string]bool, len(cfg.Routes))
	for i, r := range cfg.Routes {
		prefix := fmt.Sprintf("routes[%d]", i)

		if r.ID == "" {
			if r.ResourceID != "" {
				errs = append(errs, fmt.Errorf("%s: id is required even when resource_id is pinned (id is also used as the local FRP proxy-name base)", prefix))
			} else if len(cfg.Routes) != 1 {
				errs = append(errs, fmt.Errorf("%s: id is required", prefix))
			}
		} else {
			checkDuplicateRouteID := true
			if r.ResourceID == "" {
				if err := ValidateSlug(r.ID); err != nil {
					errs = append(errs, routeIDFormatError(prefix, r, err))
					// Prefer fixing the API-slug shape before reporting
					// duplicates among malformed ids; once the operator
					// fixes the format, duplicate detection runs normally.
					checkDuplicateRouteID = false
				}
			}
			if checkDuplicateRouteID {
				// Deliberately byte-exact: unpinned/API-slug ids are already
				// lowercase via ValidateSlug above, while pinned legacy routes
				// may preserve FRP proxy-name bases that differ only by case.
				// FRP also indexes rendered proxy names by exact string.
				if seenRouteIDs[r.ID] {
					errs = append(errs, fmt.Errorf("%s: duplicate route id %q (check id and migrated legacy name/slug fields)", prefix, r.ID))
				} else {
					seenRouteIDs[r.ID] = true
				}
			}
		}

		switch r.Type {
		case RouteTypeHTTP:
			if r.ResourceID != "" && r.ConnectorRoutingID != "" && r.Subdomain != "" && r.Subdomain != r.ConnectorRoutingID {
				errs = append(errs, fmt.Errorf("%s (%s): subdomain %q must be absent or exactly match connector_routing_id %q", prefix, r.ID, r.Subdomain, r.ConnectorRoutingID))
			}
		case RouteTypeTCP:
			if r.ResourceID != "" || r.ConnectorRoutingID != "" {
				errs = append(errs, fmt.Errorf("%s (%s): managed qURL Connector routes require type: http; the protected Connector server path does not accept TCP proxies", prefix, r.ID))
			}
			// remote_port for low-level ResourceID-free custom FRP routes is
			// validated at run time (it may be server-assigned).
		default:
			if replacement := internalRouteTypeReplacement(r.Type); replacement != "" {
				errs = append(errs, fmt.Errorf("%s (%s): unsupported route type %q; use type: %s", prefix, r.ID, r.Type, replacement))
			} else {
				errs = append(errs, fmt.Errorf("%s (%s): unsupported route type %q", prefix, r.ID, r.Type))
			}
		}

		if r.LocalPort < 1 || r.LocalPort > 65535 {
			errs = append(errs, fmt.Errorf("%s (%s): local_port must be 1-65535, got %d", prefix, r.ID, r.LocalPort))
		}
		if requireManagedRouting && r.ResourceID != "" && r.ConnectorRoutingID == "" {
			errs = append(errs, fmt.Errorf("%s (%s): managed resource_id requires the paired server-issued connector_routing_id", prefix, r.ID))
		}
		if r.ResourceID != "" {
			if err := validateExactOpaqueIdentifier("resource_id", r.ResourceID); err != nil {
				errs = append(errs, fmt.Errorf("%s (%s): %w", prefix, r.ID, err))
			}
			if len(r.CustomDomains) > 0 {
				errs = append(errs, fmt.Errorf("%s (%s): managed qURL Connector routes cannot set custom_domains; the protected server authorizes only the exact producer-issued connector_routing_id", prefix, r.ID))
			}
		}
		if r.ConnectorRoutingID != "" {
			if r.ResourceID == "" {
				errs = append(errs, fmt.Errorf("%s (%s): connector_routing_id requires the paired public resource_id", prefix, r.ID))
			}
			if err := ValidateConnectorRoutingID(r.ConnectorRoutingID); err != nil {
				errs = append(errs, fmt.Errorf("%s (%s): %w", prefix, r.ID, err))
			}
		}
		if r.ResourceID != "" && r.ConnectorRoutingID != "" && r.LoadBalancerGroup != "" && r.LoadBalancerGroup != r.ConnectorRoutingID {
			errs = append(errs, fmt.Errorf("%s (%s): load_balancer_group %q must be absent or exactly match connector_routing_id %q", prefix, r.ID, r.LoadBalancerGroup, r.ConnectorRoutingID))
		}
	}
	if err := ValidateManagedRouteIdentities(cfg.Routes); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// ValidateManagedRouteIdentities enforces a one-to-one mapping between local
// managed routes, public resource identities, and producer routing labels.
// Multiple different routing labels on one Connector session are supported;
// aliasing either side is not. Duplicate public IDs would point one protected
// resource at multiple local targets, while a routing-label collision would
// put distinct resources into one FRP vhost/group and fan requests across them.
//
// This is exported because run and add must check producer-returned identities
// before persisting the local graph. Callers may pass incomplete startup routes:
// empty identity fields are ignored here and validated by
// their phase-specific boundary.
func ValidateManagedRouteIdentities(routes []Route) error {
	type seenIdentity struct {
		index      int
		routeID    string
		resourceID string
	}
	resources := make(map[string]seenIdentity, len(routes))
	routing := make(map[string]seenIdentity, len(routes))
	var errs []error
	for i, route := range routes {
		if route.ResourceID != "" {
			if first, duplicate := resources[route.ResourceID]; duplicate {
				errs = append(errs, fmt.Errorf("routes[%d] (%s): duplicate resource_id %q is already used by routes[%d] (%s); one managed resource may target only one local route per Connector config", i, route.ID, route.ResourceID, first.index, first.routeID))
			} else {
				resources[route.ResourceID] = seenIdentity{index: i, routeID: route.ID, resourceID: route.ResourceID}
			}
		}
		if route.ConnectorRoutingID == "" || route.ResourceID == "" {
			continue
		}
		if first, duplicate := routing[route.ConnectorRoutingID]; duplicate {
			if first.resourceID != route.ResourceID {
				errs = append(errs, fmt.Errorf("routes[%d] (%s): connector_routing_id %q is already bound to resource_id %q by routes[%d] (%s), not %q; refusing a producer collision or cross-wired identity", i, route.ID, route.ConnectorRoutingID, first.resourceID, first.index, first.routeID, route.ResourceID))
			}
		} else {
			routing[route.ConnectorRoutingID] = seenIdentity{index: i, routeID: route.ID, resourceID: route.ResourceID}
		}
	}
	return errors.Join(errs...)
}

func routeIDFormatError(prefix string, r Route, err error) error {
	return fmt.Errorf("%s (%s): %w", prefix, r.ID, err)
}

func internalRouteTypeReplacement(t RouteType) string {
	switch t {
	case "frp_http":
		return string(RouteTypeHTTP)
	case "frp_tcp":
		return string(RouteTypeTCP)
	default:
		return ""
	}
}
