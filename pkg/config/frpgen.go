package config

import (
	"fmt"
	"strings"

	v1 "github.com/fatedier/frp/pkg/config/v1"

	"github.com/layervai/qurl-connector/pkg/replica"
)

// MetaQURLKnockToken is the FRP Login.Metas key qurl-connector
// populates with the AC-issued knock token harvested from
// `ackMsg.ACTokens[resource_id]` after a successful NHP knock. Cross-repo
// wire contract — must match qURL tunnel server's
// tunnelauth.MetaQURLKnockToken constant. The server passes the value
// to nhp-server's `POST /nhp/internal/token/validate` to verify that
// the inbound FRP login is preceded by a valid, recent knock from the
// same `RunID`.
//
// gosec G101 fires on the literal "qurl_knock_token" — gosec classifies
// the substring as a credential pattern. This is the wire-contract
// field NAME, not a credential value baked into source. Renaming on
// either side without coordinating the other locks every knock-required
// client out with a `knock_invalid` Login reject. The key is pinned in
// contracts/qrts_knock_token_login_wire_contract.json and bound to this
// constant by pkg/share's TestQRTSKnockTokenLoginContract.
const MetaQURLKnockToken = "qurl_knock_token" //nolint:gosec // G101: this is the Login.Metas key NAME (wire contract), not a credential value

// MetaClientVersion is the FRP Login.Metas key qurl-connector uses to report
// its build version to qURL tunnel server. The server's
// min-client-version kill switch reads this value at Login; keep it in sync
// with qURL tunnel server/internal/tunnelauth.MetaClientVersion.
const MetaClientVersion = "client_version"

// GenerateFRPClientConfig converts a qURL Config into the FRP v1 types that
// can be passed directly to client.NewService(). The machineID is injected
// into any subdomain template containing {{ .MachineID }}.
func GenerateFRPClientConfig(cfg *Config, machineID string) (*v1.ClientCommonConfig, []v1.ProxyConfigurer, []v1.VisitorConfigurer, error) {
	if err := ValidateManagedRouteIdentities(cfg.Routes); err != nil {
		return nil, nil, nil, fmt.Errorf("managed route identity graph is invalid: %w", err)
	}
	common := &v1.ClientCommonConfig{
		ServerAddr: cfg.Server.Addr,
		ServerPort: cfg.Server.Port,
	}

	// FRP auth wiring: under tunnel-auth mode the server's frps.toml has
	// no `auth` block and the server-side `startTunnelAuth` resolver
	// fail-closes on a non-empty FRPS_AUTH_TOKEN. That means BOTH sides
	// run with the FRP default `auth.token = ""`; any non-empty
	// `common.Auth.Token` the client sends produces a different
	// `md5(token+timestamp)` than the server computes (which uses the
	// empty token), and FRP rejects Login with "token in login doesn't
	// match token from configuration" BEFORE the plugin sees the
	// request. So the qURL API key (cfg.QURL.Token) MUST NOT be stamped
	// into `common.Auth.Token` — it is consumed only by the qURL resource
	// client and is never written to the FRP Login wire. Identity reaches the
	// tunnel-server through
	// the AC-issued knock token in `MetaQURLKnockToken`, which is
	// populated per-cycle by the managed session after a successful NHP
	// knock. FRP Metas ship verbatim regardless of `auth.method`.
	//
	// `common.Auth.Token` is only set from `cfg.Server.Token`, which is
	// the explicit YAML escape hatch for the legacy shared-FRP-token
	// deployment (no qURL authorization plugin in the loop).
	if cfg.Server.Token != "" {
		common.Auth.Token = cfg.Server.Token
	}

	if cfg.Server.Protocol != "" {
		common.Transport.Protocol = cfg.Server.Protocol
	}

	// Reconnection resilience: prevent exit on login failure, tune keepalive.
	// loginFailExit=false ensures FRP retries indefinitely on server restart
	// (ASG replacement takes ~30s, client reconnects automatically).
	common.LoginFailExit = cfg.Server.LoginFailExit
	common.Transport.DialServerKeepAlive = int64(cfg.Server.Keepalive)
	common.Transport.DialServerTimeout = int64(cfg.Server.DialTimeout)

	// FRP v0.68+ has built-in exponential backoff on reconnect when
	// loginFailExit=false. No additional retry cap needed — the backoff
	// is bounded internally and prevents thundering herd on server restart.

	proxies := make([]v1.ProxyConfigurer, 0, len(cfg.Routes))
	for _, route := range cfg.Routes {
		pc, err := routeToProxy(route, machineID, cfg.Server.ReplicaDiscriminator)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("generating proxy for route %q: %w", route.ID, err)
		}
		proxies = append(proxies, pc)
	}

	// No visitors are generated from the qURL config at this time.
	return common, proxies, nil, nil
}

// routeToProxy converts a single Route into the appropriate FRP ProxyConfigurer.
func routeToProxy(r Route, machineID, replicaDiscriminator string) (v1.ProxyConfigurer, error) {
	if r.ID == "" {
		return nil, fmt.Errorf("route id is required before FRP generation")
	}
	if r.ResourceID != "" {
		if err := validateExactOpaqueIdentifier("resource_id", r.ResourceID); err != nil {
			return nil, fmt.Errorf("managed resource identity is invalid: %w", err)
		}
		if r.Type != RouteTypeHTTP {
			return nil, fmt.Errorf("managed qURL Connector resource %q requires route type %q; the protected Connector server path does not accept %q proxies", r.ResourceID, RouteTypeHTTP, r.Type)
		}
		if len(r.CustomDomains) > 0 {
			return nil, fmt.Errorf("managed qURL Connector resource %q cannot set custom_domains; the protected server authorizes only the exact producer-issued connector_routing_id", r.ResourceID)
		}
		if err := ValidateConnectorRoutingID(r.ConnectorRoutingID); err != nil {
			return nil, fmt.Errorf("managed resource %q requires its exact server-issued routing identity before FRP generation: %w", r.ResourceID, err)
		}
		if r.Subdomain != "" && r.Subdomain != r.ConnectorRoutingID {
			return nil, fmt.Errorf("subdomain %q must be absent or exactly match connector_routing_id %q", r.Subdomain, r.ConnectorRoutingID)
		}
		if r.LoadBalancerGroup != "" && r.LoadBalancerGroup != r.ConnectorRoutingID {
			return nil, fmt.Errorf("load_balancer_group %q must be absent or exactly match connector_routing_id %q", r.LoadBalancerGroup, r.ConnectorRoutingID)
		}
	} else if r.ConnectorRoutingID != "" {
		return nil, fmt.Errorf("connector_routing_id requires the paired public resource_id")
	}
	switch r.Type {
	case RouteTypeHTTP:
		return buildHTTPProxy(r, machineID, replicaDiscriminator), nil
	case RouteTypeTCP:
		return buildTCPProxy(r, replicaDiscriminator), nil
	default:
		return nil, fmt.Errorf("unsupported route type %q", r.Type)
	}
}

// FRPProxyName renders the FRP proxy name for a route by joining
// the route's stable ID with the normalized per-replica discriminator.
// Empty discriminator returns the raw route ID. The runtime resolver
// normally supplies a discriminator at boot, including single-replica
// deploys, so this empty branch primarily preserves direct
// config-generation callers and older upgrade windows.
//
// Wire contract (read-on-FRP-bump): the name must be unique per
// `(server_instance, group)` tuple but NOT globally unique across
// the FRP server — two routes with the same Name on DIFFERENT
// LoadBalancerGroups would route correctly. The salt covers the
// only collision shape we hit in practice (same group, same
// route.ID, different replica). See buildHTTPProxy's header
// comment for the group/auth rationale.
func FRPProxyName(routeID, replicaDiscriminator string) string {
	replicaDiscriminator = replica.Normalize(replicaDiscriminator)
	if replicaDiscriminator == "" {
		return routeID
	}
	return routeID + "-" + replicaDiscriminator
}

// MetaResourceID is the FRP Login.Metas key qurl-connector
// populates per-proxy with the qURL resource_id. Cross-repo wire
// contract: must match qURL tunnel server's
// `tunnelauth.metaResourceID` ("resource_id"). Renaming on either side
// without updating the other strands every managed route with
// `resource_not_found`; qRTS requires this metadata and never substitutes
// SubDomain because that carries the independent routing identity.
//
// gosec G101 fires on the literal "resource_id" because it looks like
// a credential field name; this is the wire-contract field NAME, not a
// credential. Same rationale as MetaQURLKnockToken above.
const MetaResourceID = "resource_id" //nolint:gosec // G101: this is the per-proxy Metas key NAME (wire contract), not a credential value

// buildHTTPProxy creates an FRP HTTPProxyConfig from a Route.
//
// Managed routes intentionally split the FRP surfaces: SubDomain and
// load-balancer Group/GroupKey use ConnectorRoutingID; only Metas[resource_id]
// carries the independent public resource identity. NHP-selected runtime
// placement is independent of either field.
func buildHTTPProxy(r Route, machineID, replicaDiscriminator string) *v1.HTTPProxyConfig {
	pc := &v1.HTTPProxyConfig{}
	// Empty-id single-route env fallback is resolved before FRP generation;
	// see cmd/frpc's resolveConnectorIdentities.
	//
	// Multi-replica HA: the salt applied here makes two replicas of the
	// SAME slug present DIFFERENT proxy Names to FRPS so the
	// LoadBalancerGroup fanout below isn't rejected for ErrProxyRepeated.
	// Runtime boot resolves a discriminator by default, so even a single
	// live connector usually presents `<route.ID>-<discriminator>`; an
	// empty discriminator keeps raw r.ID only for direct callers and
	// compatibility paths that intentionally skip runtime resolution.
	pc.Name = FRPProxyName(r.ID, replicaDiscriminator)
	pc.Type = string(v1.ProxyTypeHTTP)
	pc.LocalIP = r.LocalIP
	pc.LocalPort = r.LocalPort

	subdomain := r.ConnectorRoutingID
	if r.ResourceID == "" {
		subdomain = expandMachineID(r.Subdomain, machineID)
	}
	pc.SubDomain = subdomain
	// qRTS authorizes managed routes by the exact producer SubDomain and public
	// metadata; it does not authorize FRP custom_domains. routeToProxy rejects
	// that shape before this private builder, and this guard prevents a future
	// direct builder caller from emitting an unauthenticated managed alias.
	if r.ResourceID == "" {
		pc.CustomDomains = r.CustomDomains
	}

	if r.ResourceID != "" {
		if pc.Metadatas == nil {
			pc.Metadatas = map[string]string{}
		}
		pc.Metadatas[MetaResourceID] = r.ResourceID
	}

	// Multi-replica fan-out: when LoadBalancerGroup is set, FRPS
	// registers all replicas with the same Group under one routing key
	// and balances per-NEW-request across them (long-lived sessions
	// pin to the replica that accepted them; replica drop mid-session
	// breaks that session).
	// FRPS accepts a one-member Group; setting it on the first replica keeps the
	// registration identity stable when more replicas join later.
	//
	// Group + GroupKey both carry the opaque ConnectorRoutingID. FRP uses
	// GroupKey only to require replicas joining one Group to present the same
	// value; ConnectorRoutingID is not a secret and must not be treated as a
	// credential. Tenant authorization remains the tunnel-auth contract:
	// Login.Metas[qurl_knock_token] plus per-proxy Metas[resource_id].
	//
	// LOAD-BEARING ASSUMPTION (reread on FRPS upgrade — see issue #196):
	// in LayerV FRP v0.70.0-layerv.5 GroupKey is treated as a shared secret
	// only among replicas of the same Group — it does not protect
	// cross-tenant joining, the tunnel-auth Metas does. If a future
	// FRPS version makes GroupKey security-critical (e.g. per-Group
	// rate-limiting keyed on it, or cross-tenant Group-join
	// authorization), this approach would be insufficient because the routing
	// identity is intentionally non-secret. Revisit then.
	group := r.LoadBalancerGroup
	if r.ResourceID != "" {
		group = r.ConnectorRoutingID
	}
	if group != "" {
		pc.LoadBalancer.Group = group
		pc.LoadBalancer.GroupKey = group
	}

	if r.HostRewrite != "" {
		pc.HostHeaderRewrite = r.HostRewrite
	}

	if len(r.Headers) > 0 {
		pc.RequestHeaders = v1.HeaderOperations{
			Set: r.Headers,
		}
	}

	return pc
}

// buildTCPProxy creates an FRP TCPProxyConfig from a Route.
func buildTCPProxy(r Route, replicaDiscriminator string) *v1.TCPProxyConfig {
	pc := &v1.TCPProxyConfig{}
	// Empty-id single-route env fallback is resolved before FRP generation;
	// see cmd/frpc's resolveConnectorIdentities.
	//
	// TCP routes get the same salt treatment as HTTP: FRP's group
	// machinery (server/group/tcp.go) mirrors the HTTP path's
	// ErrProxyRepeated check, so a multi-replica TCP route with the
	// same r.ID would collide identically without the salt.
	pc.Name = FRPProxyName(r.ID, replicaDiscriminator)
	pc.Type = string(v1.ProxyTypeTCP)
	pc.LocalIP = r.LocalIP
	pc.LocalPort = r.LocalPort
	pc.RemotePort = r.RemotePort
	// Managed Connector resources are rejected before this builder because the
	// protected server path is HTTP-vhost-only. The explicit group below belongs
	// solely to the low-level ResourceID-free custom FRP escape hatch.
	if r.LoadBalancerGroup != "" {
		pc.LoadBalancer.Group = r.LoadBalancerGroup
		pc.LoadBalancer.GroupKey = r.LoadBalancerGroup
	}
	return pc
}

// expandMachineID replaces {{ .MachineID }} (with flexible whitespace) in s
// with the provided machineID value.
func expandMachineID(s, machineID string) string {
	// Handle both "{{.MachineID}}" and "{{ .MachineID }}" style templates.
	s = strings.ReplaceAll(s, "{{ .MachineID }}", machineID)
	s = strings.ReplaceAll(s, "{{.MachineID}}", machineID)
	return s
}
