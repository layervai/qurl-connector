// Package config provides YAML-based configuration for the qURL Connector.
// It loads a high-level YAML config and can generate the internal FRP runtime
// config used by the qURL Connector.
package config

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level qURL proxy configuration.
type Config struct {
	Server  ServerConfig  `yaml:"server"`
	NHP     NHPConfig     `yaml:"nhp"`
	QURL    QURLConfig    `yaml:"qurl"`
	Admin   AdminConfig   `yaml:"admin,omitempty"`
	Audit   AuditConfig   `yaml:"audit,omitempty"`
	Routes  []Route       `yaml:"routes"`
	Runtime RuntimeConfig `yaml:"-"`
}

// AuditConfig configures the audit-log sink (file + slog mirror) and
// rotation policy. Defaults are production-safe — leaving the block
// out of qurl-proxy.yaml entirely produces a working audit pipeline
// against the default file path with the standard rotation knobs.
// See pkg/audit's LoggerConfig / RotationConfig for the underlying contract.
type AuditConfig struct {
	// Enabled defaults to true. Set false to disable audit emission
	// entirely (the NopLogger is wired into the call sites).
	Enabled *bool `yaml:"enabled,omitempty"`

	// FilePath is the active audit-log file. Defaults to
	// DefaultAuditFilePath. The QURL_AUDIT_FILE env var overrides the
	// YAML (applied in applyEnvOverrides) so a Docker operator can
	// redirect the sink without rewriting the YAML.
	FilePath string `yaml:"file_path,omitempty"`

	// MirrorSlog defaults to true — every audit entry is mirrored
	// through slog.Default() at INFO level so central log shippers
	// (journald, CloudWatch, GCP Logging) see the same stream as the
	// file. Set false to disable when the file is the sole sink (eg
	// bind-mounted to an out-of-process shipper).
	MirrorSlog *bool `yaml:"mirror_slog,omitempty"`

	// BufferSize is the in-process entry channel buffer. Zero falls
	// through to pkg/audit's default (4096). Operators should rarely
	// need to tune this — the channel is sized for the burst rate of
	// a saturated control-plane path, not the steady-state rate.
	BufferSize int `yaml:"buffer_size,omitempty"`

	// MaxSizeMB is the active-file size threshold (in MB) above which
	// lumberjack rotates. Zero falls through to audit.DefaultMaxSizeMB
	// (100). See pkg/audit/rotation.go for the rationale.
	MaxSizeMB int `yaml:"max_size_mb,omitempty"`

	// MaxAgeDays evicts rotated backups older than this many days.
	// Zero falls through to audit.DefaultMaxAgeDays (90 — matches
	// SOC 2 / PCI DSS minimum hot-tier retention).
	MaxAgeDays int `yaml:"max_age_days,omitempty"`

	// MaxBackups caps the number of rotated backups retained. Zero
	// falls through to audit.DefaultMaxBackups (14 — ~1.4 GB on disk
	// at the default MaxSizeMB).
	MaxBackups int `yaml:"max_backups,omitempty"`

	// Compress gzips rotated backups when true. Defaults to true
	// (audit.DefaultCompress) — JSONL compresses 5-10× and lumberjack
	// runs gzip in a background goroutine so steady-state latency is
	// unaffected. Set false to opt out.
	Compress *bool `yaml:"compress,omitempty"`
}

// DefaultAuditFilePath is the developer command's audit-log path when
// AuditConfig.FilePath and QURL_AUDIT_FILE are both unset.
const DefaultAuditFilePath = "/var/log/layerv/qurl-connector/audit.log"

// EnvAuditFile is the env var that overrides AuditConfig.FilePath at
// Load time. Pure runtime override (not persisted to YAML by Save) so
// an operator redirecting the sink can roll back to the YAML
// default by unsetting the env var. See applyEnvOverrides.
const EnvAuditFile = "QURL_AUDIT_FILE"

// RuntimeConfig holds startup-derived process state that must never be
// serialized back into qurl-proxy.yaml. Customer-facing config stays on public
// LayerV endpoints; NHP resource metadata tells the agent what to knock, and
// the ACK supplies the FRP dial target.
type RuntimeConfig struct {
	// KnockResourceIDs maps qURL resource_id -> NHP knock resource_id.
	// Only SetKnockResourceID mutates it. Populated once during device-owned
	// resource hydration before the managed session starts; not safe for concurrent writes.
	KnockResourceIDs map[string]string
}

// AdminConfig gates FRP's built-in HTTP admin API (status + live reload).
// Default is OFF: the Docker install has no in-container caller for it,
// and shipping it always-on leaves an authenticated-but-machine-id-keyed
// surface that defeats the "every reachable path goes through NHP"
// posture. Operators must opt in explicitly.
//
// Addr/Port have non-zero defaults applied in applyDefaults so an
// operator who opts in only needs to set Enabled.
//
// AllowRemote is a SECOND opt-in required when Addr is non-loopback
// (`0.0.0.0`, a RFC1918 IP, a public IP, etc). Without it, Validate
// rejects the config — a single misedited Addr can't silently expose
// the admin API to any peer that can route to the host. The whole
// point of the gate is "no off-host reachability without two
// deliberate YAML changes."
//
// Password is the FRP admin API basic-auth password. When unset, the
// admin listener may use getMachineID() as a loopback-only fallback,
// but only if the runtime can resolve a real protected machine ID.
// Minimal containers often cannot, and the daemon fails closed rather
// than accepting the sentinel "unknown" password. AllowRemote=true
// (off-host exposure) REQUIRES an explicit Password — Validate
// rejects the config otherwise. The machineID fallback is host-stable
// and partly inferable; allowing it on an off-host listener would
// mean a remote attacker who can guess the machineID gets admin
// access. Requiring an explicit password forces operators opting into
// off-host to provide real credentials. #190 tracks dropping admin
// API entirely in favor of stdio-pipe IPC, which obsoletes this
// entire surface; until then this gate closes the obvious hole.
type AdminConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Addr        string `yaml:"addr,omitempty"`
	Port        int    `yaml:"port,omitempty"`
	AllowRemote bool   `yaml:"allow_remote,omitempty"`
	// Password IS a secret by design — gosec G117 flags any exported
	// struct field whose name matches a secret pattern, but this
	// field exists exactly to carry the FRP admin basic-auth
	// credential from YAML into run.go (where it's set on
	// common.WebServer.Password). The YAML file holding it is
	// expected to be 0600 by the surrounding install story; the
	// struct doesn't get serialized to any log/wire path. Renaming
	// to obscure intent would hurt readability; a custom redact-on-
	// print type is a future hardening (issue #190 obsoletes the
	// surface entirely). Per-line suppression with rationale per
	// repo policy on lint dodges.
	Password string `yaml:"password,omitempty"` //nolint:gosec // G117 - field name "Password" matches secret pattern by design; see comment above
}

// ServerConfig holds connection details for the FRP server.
type ServerConfig struct {
	Addr         string `yaml:"addr,omitempty"`
	Port         int    `yaml:"port,omitempty"`
	Token        string `yaml:"token,omitempty"`
	Protocol     string `yaml:"protocol,omitempty"`      // tcp, kcp, quic, websocket, wss
	PublicDomain string `yaml:"public_domain,omitempty"` // vhost domain for public URLs (e.g., qurl.site)

	// EgressLocalIP binds both the native NHP UDP socket and FRP's TCP/
	// websocket connection to one local source address. Multi-homed hosts must
	// set this explicitly so AC admission and the following Connector session
	// cannot leave through different interfaces. Only Protocol tcp, websocket,
	// wss, or empty may be combined with it — FRP never applies a local source
	// address to kcp/quic dials, so Validate rejects those combinations
	// instead of letting the session leave from the wrong IP and die at the
	// source-scoped boundary.
	EgressLocalIP string `yaml:"egress_local_ip,omitempty"`

	// Transport tuning for reconnection resilience.
	Keepalive     int   `yaml:"keepalive,omitempty"`       // TCP keepalive probe interval in seconds (default: 60)
	DialTimeout   int   `yaml:"dial_timeout,omitempty"`    // Server connection timeout in seconds (default: 10)
	LoginFailExit *bool `yaml:"login_fail_exit,omitempty"` // Exit on initial login failure (default: false)

	// ReplicaDiscriminator is the explicit per-process salt appended
	// to FRP proxy names (`<route.ID>-<discriminator>`) so multiple
	// replicas sharing a LoadBalancerGroup can register without
	// colliding on FRP's per-server-instance name uniqueness check
	// (server/control.go:484 emits `proxy [<name>] already exists`;
	// server/proxy/proxy.go:529 emits `proxy name [<name>] is
	// already in use`). The canonical resolution chain lives in
	// pkg/replica.Resolver — the YAML field here is the explicit
	// escape hatch for operators who want to set the salt from
	// outside the resolver (deterministic tests, bare-metal deploys
	// with a fixed-replica taxonomy). When set non-empty, run.go
	// bypasses the resolver chain. Empty (the headless default) →
	// resolver chain picks the salt at boot.
	//
	// The runtime path normally resolves a salt even for single-replica
	// deploys. If both this field AND the resolver return empty (today
	// only possible if a future CONFIG_REQUIRE_STABLE_DISCRIMINATOR
	// hard-fail mode is wired AND the operator declines all sources),
	// frpgen.go emits the raw route.ID as the proxy name for direct
	// config-generation compatibility.
	ReplicaDiscriminator string `yaml:"replica_discriminator,omitempty"`
}

// NHPConfig holds Network Hiding Protocol settings.
type NHPConfig struct {
	Enabled   bool   `yaml:"enabled"`
	MachineID string `yaml:"machine_id,omitempty"`
}

// QURLConfig holds qURL service integration settings.
type QURLConfig struct {
	APIURL string `yaml:"api_url,omitempty"`
	Token  string `yaml:"token,omitempty"`
}

// Route describes a single proxy route.
//
// Managed routes consume three separately carried producer values: ResourceID
// is the public qURL identity, ConnectorRoutingID is the FRP/HRW routing label,
// and Runtime.KnockResourceIDs holds the NHP admission target keyed by the
// public identity. Subdomain and LoadBalancerGroup are optional compatibility
// inputs only; when present on a managed route they must equal the opaque
// ConnectorRoutingID exactly.
type Route struct {
	// ID is the customer-facing route identifier. For Connector resources,
	// the registered-device qurl-go client sends this value verbatim as the
	// qURL resource slug when ResourceID is empty. The JSON tag intentionally omits
	// `omitempty` so list --json pollers always see a stable id key,
	// including the single-route env-fallback shape before resolution.
	ID            string            `yaml:"id,omitempty" json:"id"`
	Type          RouteType         `yaml:"type" json:"type"`
	LocalIP       string            `yaml:"local_ip,omitempty" json:"local_ip,omitempty"`
	LocalPort     int               `yaml:"local_port" json:"local_port"`
	RemotePort    int               `yaml:"remote_port,omitempty" json:"remote_port,omitempty"`
	Subdomain     string            `yaml:"subdomain,omitempty" json:"subdomain,omitempty"`
	CustomDomains []string          `yaml:"custom_domains,omitempty" json:"custom_domains,omitempty"`
	HostRewrite   string            `yaml:"host_rewrite,omitempty" json:"host_rewrite,omitempty"`
	Headers       map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	ResourceID    string            `yaml:"resource_id,omitempty" json:"resource_id,omitempty"`
	// ConnectorRoutingID is returned by the qURL control plane and used verbatim for
	// FRP SubDomain and load-balancer grouping. NHP placement comes from the
	// authenticated ACK instead. This value must never
	// be client-derived from or normalized against ResourceID; the control plane owns
	// the producer-side calculation.
	ConnectorRoutingID string `yaml:"connector_routing_id,omitempty" json:"connector_routing_id,omitempty"`
	TargetURL          string `yaml:"target_url,omitempty" json:"target_url,omitempty"`

	// LoadBalancerGroup wires FRP's HTTP/TCP loadBalancer.group +
	// groupKey so multiple sidecar replicas with the same slug register
	// under one routing key — FRPS load-balances requests across the
	// live replicas. Managed routes use ConnectorRoutingID as the one
	// authoritative value; this field may be omitted or must match it exactly.
	// Unmanaged/custom FRP routes retain the explicit field as before.
	LoadBalancerGroup string `yaml:"load_balancer_group,omitempty" json:"load_balancer_group,omitempty"`
}

// PrimaryResourceID returns the first managed route's public resource identity.
// It is used for resource-indexed NHP metadata, never for routing.
func (c *Config) PrimaryResourceID() string {
	if r := c.primaryRoutingRoute(); r != nil {
		return r.ResourceID
	}
	return ""
}

// primaryRoutingRoute returns the first route carrying a non-empty
// ConnectorRoutingID — the single route whose identity HRWKey and
// PrimaryResourceID both report, keeping that selection rule in one place. A
// nil receiver or a config with no routing-bearing route returns nil, so both
// callers treat "nil config" and "no primary route" uniformly.
func (c *Config) primaryRoutingRoute() *Route {
	if c == nil {
		return nil
	}
	for i := range c.Routes {
		if c.Routes[i].ConnectorRoutingID != "" {
			return &c.Routes[i]
		}
	}
	return nil
}

// SetKnockResourceID records the logical NHP resource_id that should be knocked
// before dialing FRP for a qURL Connector resource. The key is the qURL resource_id
// (the public P-256 identity), not the slug or connector_routing_id.
func (c *Config) SetKnockResourceID(resourceID, knockResourceID string) {
	if c == nil || resourceID == "" || knockResourceID == "" {
		return
	}
	if c.Runtime.KnockResourceIDs == nil {
		c.Runtime.KnockResourceIDs = map[string]string{}
	}
	c.Runtime.KnockResourceIDs[resourceID] = knockResourceID
}

// KnockResourceID returns the logical NHP resource_id recorded for a qURL
// resource_id during device-owned resource hydration.
func (c *Config) KnockResourceID(resourceID string) string {
	if c == nil || resourceID == "" || c.Runtime.KnockResourceIDs == nil {
		return ""
	}
	return c.Runtime.KnockResourceIDs[resourceID]
}

// FirstDifferentKnockResourceID returns the first existing resource mapped to a
// non-empty NHP knock resource different from knockResourceID. Bootstrap uses it
// before SetKnockResourceID so a single connector cannot mix control resources.
// It sorts the current keys for deterministic conflict ordering; the cost is
// bounded by len(KnockResourceIDs) and is paid only before managed sessions start.
func (c *Config) FirstDifferentKnockResourceID(resourceID, knockResourceID string) (existingResourceID, existingKnockResourceID string, ok bool) {
	if c == nil || resourceID == "" || knockResourceID == "" || len(c.Runtime.KnockResourceIDs) == 0 {
		return "", "", false
	}
	existingResourceIDs := make([]string, 0, len(c.Runtime.KnockResourceIDs))
	for existingResourceID := range c.Runtime.KnockResourceIDs {
		if existingResourceID != resourceID {
			existingResourceIDs = append(existingResourceIDs, existingResourceID)
		}
	}
	sort.Strings(existingResourceIDs)
	for _, existingResourceID := range existingResourceIDs {
		existingKnockResourceID := c.Runtime.KnockResourceIDs[existingResourceID]
		if existingKnockResourceID != "" && existingKnockResourceID != knockResourceID {
			return existingResourceID, existingKnockResourceID, true
		}
	}
	return "", "", false
}

// RouteType identifies the proxy protocol for a route.
type RouteType string

const (
	// RouteTypeHTTP proxies HTTP traffic.
	RouteTypeHTTP RouteType = "http"
	// RouteTypeTCP proxies raw TCP traffic.
	RouteTypeTCP RouteType = "tcp"
)

// envVarPattern matches ${VAR} and ${VAR:-default} patterns.
var envVarPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}`)

// resolveEnvVars replaces ${VAR} and ${VAR:-default} patterns in s with
// corresponding environment variable values. If a variable is unset and no
// default is provided, the placeholder is replaced with an empty string.
func resolveEnvVars(s string) string {
	return envVarPattern.ReplaceAllStringFunc(s, func(match string) string {
		parts := envVarPattern.FindStringSubmatch(match)
		if parts == nil {
			return match
		}
		name := parts[1]
		defaultVal := parts[2]

		if val, ok := os.LookupEnv(name); ok {
			return val
		}
		return defaultVal
	})
}

// Load reads a YAML configuration file from path, resolves environment
// variable placeholders, validates the result, and applies defaults.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}
	return decodeConfig(data, path)
}

func decodeConfig(data []byte, path string) (*Config, error) {
	resolved := resolveEnvVars(string(data))

	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(resolved))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	applyDefaults(&cfg)
	// Env overrides are deliberately applied only on Load (runtime),
	// NOT in NewDefaulted (which add.go uses to seed fresh YAML).
	// Otherwise the env decision would silently get baked into the
	// saved YAML and outlive its runtime intent — see add.go's
	// fresh-config path.
	applyEnvOverrides(&cfg)

	if err := validateStartupInput(&cfg); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return &cfg, nil
}

// NewDefaulted returns an empty Config with the same defaults that
// Load applies to a parsed YAML file. Use this on the fresh-config
// path (when no YAML exists yet) so that the eventual Save writes a
// fully-populated file rather than a sparse one missing Protocol /
// PublicDomain / Keepalive / etc. — a sparse file is functionally
// fine because Load re-applies defaults, but a user opening it for
// the first time would otherwise see a config that looks half-set.
func NewDefaulted() *Config {
	cfg := &Config{}
	applyDefaults(cfg)
	// Native NHP on for a NEWLY generated config. `qurl-connector add` used to
	// write `nhp: enabled: false`, so the very first `run` after the documented
	// add command did nothing useful until the file was hand-edited -- the native
	// UDP path is the product, not an opt-in.
	//
	// Deliberately set HERE and not in applyDefaults: Enabled is a plain bool, so
	// applyDefaults cannot tell "absent" from "explicitly false", and flipping it
	// there would silently re-enable NHP for every existing config that had
	// turned it off on purpose. NewDefaulted is only reached when creating a new
	// config, so this changes generation without touching parsing.
	cfg.NHP.Enabled = true
	return cfg
}

// applyDefaults fills in zero-value fields with sensible defaults.
func applyDefaults(cfg *Config) {
	if cfg.Server.Protocol == "" {
		cfg.Server.Protocol = "tcp"
	}
	if cfg.Server.PublicDomain == "" {
		cfg.Server.PublicDomain = "qurl.site"
	}
	// TCP keepalive: 60s detects dead servers much faster than FRP's 7200s (2hr) default.
	if cfg.Server.Keepalive == 0 {
		cfg.Server.Keepalive = 60
	}
	if cfg.Server.DialTimeout == 0 {
		cfg.Server.DialTimeout = 10
	}
	// LoginFailExit=false lets FRP retry indefinitely instead of exiting on first failure.
	if cfg.Server.LoginFailExit == nil {
		f := false
		cfg.Server.LoginFailExit = &f
	}
	for i := range cfg.Routes {
		if cfg.Routes[i].LocalIP == "" {
			cfg.Routes[i].LocalIP = "127.0.0.1"
		}
	}

	// Admin defaults: addr/port get sensible values so an operator opting
	// in only needs to set Enabled. Enabled stays at its zero value
	// (false) — the whole point of this gate is that opt-in is explicit.
	// QURL_ADMIN_ENABLED=true overrides the YAML to flip it on (Docker
	// operators may not want to rebuild a config just for this).
	//
	// Seeding Addr/Port even when Enabled=false is INTENTIONAL: a
	// later QURL_ADMIN_ENABLED=true env override (applyEnvOverrides
	// runs after this) should produce a working config without
	// requiring the operator to also set admin.addr/admin.port in
	// the YAML. Gating these defaults on Enabled would force the env-
	// override path to re-seed, doubling the surface for skew.
	// TestLoad_AdminPortIgnoredWhenDisabled pins the "values exist
	// but inert until Enabled flips" contract.
	if cfg.Admin.Addr == "" {
		cfg.Admin.Addr = DefaultAdminAddr
	}
	if cfg.Admin.Port == 0 {
		cfg.Admin.Port = DefaultAdminPort
	}

	// Audit defaults: Enabled=true, MirrorSlog=true, FilePath →
	// DefaultAuditFilePath.
	if cfg.Audit.Enabled == nil {
		t := true
		cfg.Audit.Enabled = &t
	}
	if cfg.Audit.MirrorSlog == nil {
		t := true
		cfg.Audit.MirrorSlog = &t
	}
	if cfg.Audit.FilePath == "" {
		cfg.Audit.FilePath = DefaultAuditFilePath
	}
}

// applyEnvOverrides applies environment-variable overrides to cfg.
// Split from applyDefaults so the fresh-YAML path in add.go (which
// goes through NewDefaulted) doesn't bake env-time decisions into
// the saved YAML — env stays a pure runtime override.
func applyEnvOverrides(cfg *Config) {
	if value := strings.TrimSpace(os.Getenv("QURL_CONNECTOR_EGRESS_LOCAL_IP")); value != "" {
		cfg.Server.EgressLocalIP = value
	}
	if v, ok := os.LookupEnv("QURL_ADMIN_ENABLED"); ok {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes", "on":
			cfg.Admin.Enabled = true
		case "0", "false", "no", "off":
			cfg.Admin.Enabled = false
		case "":
			// Empty string is the "exported-but-unset" shape common
			// in CI shells (e.g. `export QURL_ADMIN_ENABLED` with
			// no value). Treating it as a typo would spam stderr
			// on every CLI invocation in those environments. Fall
			// through to the YAML silently — the operator didn't
			// actually intend to set the override.
		default:
			// Unrecognized value — fall through to the YAML value
			// would silently leave the surface in its previous state.
			// Since this env var is the documented runtime kill switch
			// for a security surface, a typo on the way to kill it
			// must not be silent. Warn loudly to stderr.
			fmt.Fprintf(os.Stderr, "warning: QURL_ADMIN_ENABLED=%q not recognized (use true/false/1/0/yes/no/on/off); falling back to YAML admin.enabled=%v\n", v, cfg.Admin.Enabled)
		}
	}

	// Audit file path override. Trimmed so a heredoc-pasted value with
	// trailing whitespace doesn't bypass the YAML path. Empty (or
	// whitespace-only) falls through to whatever Audit.FilePath
	// already holds — same convention as the QURL_API_URL and
	// QURL_API_KEY_FILE handlers.
	if v := strings.TrimSpace(os.Getenv(EnvAuditFile)); v != "" {
		cfg.Audit.FilePath = v
	}

}

// AdminBindLooksRoutable reports whether cfg.Admin.Addr would bind to
// a non-loopback address that's reachable from off-host. The result
// is the defense-in-depth check the warning sites in cmd/frpc rely on
// — they emit a stderr warning only when the listener is about to
// bind (i.e., from `run`), not on every config Load. Without this
// split, a scripted poller running `status --json` on a 5-second
// interval would spam stderr forever for a single misconfigured
// `admin.addr`.
//
// Recognized loopback forms:
//   - IP literal whose `net.IP.IsLoopback()` is true (`127.0.0.1`,
//     `::1`, the whole `127.0.0.0/8` block).
//   - The literal string "localhost" (case-insensitive) — common in
//     operator configs even though it requires DNS to actually
//     resolve. We don't issue a lookup here (no network I/O in
//     config land) but the literal is unambiguous enough to treat
//     as loopback.
//
// All other hostnames (`host.docker.internal`, public DNS names,
// internal-only DNS names) return TRUE — treated as routable so
// Validate requires `allow_remote`. The operator has deviated from
// the IP-literal default, which is itself a deliberate change worth
// gating. The previous behavior (hostnames bypass the check) was a
// gap that contradicted the PR framing "no off-host reachability
// without two deliberate YAML changes" — a hostname resolving to a
// public IP at runtime would pass Validate but expose the surface
// off-host. Tightening here closes that gap; the carve-out for
// "localhost" remains because it's structurally ambiguous-but-
// always-local in every reasonable resolver config.
func AdminBindLooksRoutable(cfg *Config) bool {
	if cfg == nil || !cfg.Admin.Enabled {
		return false
	}
	if strings.EqualFold(cfg.Admin.Addr, "localhost") {
		return false
	}
	ip := net.ParseIP(cfg.Admin.Addr)
	if ip == nil {
		// Non-IP hostname — treat as routable. The operator made a
		// deliberate departure from the IP-literal default; the
		// allow_remote gate exists exactly to require a second
		// deliberate opt-in for that class of choice.
		return true
	}
	return !ip.IsLoopback()
}

// DefaultAdminAddr is the loopback bind for FRP's admin API when an
// operator opts in. Hardcoded loopback is deliberate — the admin API
// has no remote-management use case in the Docker install, and a
// future YAML change that flipped this to 0.0.0.0 would silently
// expose the surface to any container peer.
const DefaultAdminAddr = "127.0.0.1"

// DefaultAdminPort is the TCP port FRP's admin API binds when enabled.
const DefaultAdminPort = 7400

// AdminURL builds the FRP admin API base URL for (addr, port). Lives
// next to DefaultAdminAddr/DefaultAdminPort so the URL-construction
// contract (scheme=http, brackets-IPv6-via-net.JoinHostPort) is in
// the same package as the bind defaults. The 4 callers in cmd/frpc
// (run banner, add reload, status probe, status display) share this
// one source of truth.
//
// net.JoinHostPort is the load-bearing detail: an operator setting
// `admin.addr: "::1"` would otherwise produce the invalid URL
// `http://::1:7400/...` and a silent connection failure.
func AdminURL(addr string, port int) string {
	return "http://" + net.JoinHostPort(addr, strconv.Itoa(port))
}

// LocalAdminURL is the AdminURL variant for callers reaching the FRP
// admin API FROM the same host (the `add` reload path and the
// `status` probe — both run alongside the daemon). Substitutes a
// loopback address for the unspecified bind addresses (`0.0.0.0`,
// `::`) so the outbound dial works on every OS, then defers to
// AdminURL for the URL construction.
//
// Cross-platform correctness: Linux's kernel routing treats
// `0.0.0.0` as `127.0.0.1` on outbound dials, but Windows and macOS
// do not. An operator who set `admin.addr: 0.0.0.0` + `allow_remote:
// true` on Windows would otherwise see `add` and `status` silently
// fail to reach the local listener — the daemon IS reachable
// off-host (which is what they opted into), they just can't dial it
// from the same machine via the wildcard address.
//
// `0.0.0.0` → `127.0.0.1`, `::` → `::1`. Loopback (`127.0.0.0/8`,
// `::1`), `localhost`, and non-wildcard addresses pass through
// unchanged.
func LocalAdminURL(addr string, port int) string {
	switch addr {
	case "0.0.0.0":
		addr = "127.0.0.1"
	case "::":
		addr = "::1"
	}
	return AdminURL(addr, port)
}
