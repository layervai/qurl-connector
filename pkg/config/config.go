// Package config provides YAML-based configuration for the qURL Connector.
// It loads a high-level YAML config and can generate the internal FRP runtime
// config used by the qURL Connector.
package config

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level qURL proxy configuration.
type Config struct {
	Server  ServerConfig  `yaml:"server"`
	NHP     NHPConfig     `yaml:"nhp"`
	QURL    QURLConfig    `yaml:"qurl"`
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

// ServerConfig holds connection details for the FRP server.
type ServerConfig struct {
	Addr     string `yaml:"addr,omitempty"`
	Port     int    `yaml:"port,omitempty"`
	Protocol string `yaml:"protocol,omitempty"` // tcp, kcp, quic, websocket, wss

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
// public identity.
type Route struct {
	// ID is the customer-facing route identifier. For Connector resources,
	// the registered-device qurl-go client sends this value verbatim as the
	// qURL resource slug when ResourceID is empty. The JSON tag intentionally omits
	// `omitempty` so list --json pollers always see a stable id key,
	// including the single-route env-fallback shape before resolution.
	ID         string    `yaml:"id,omitempty" json:"id"`
	Type       RouteType `yaml:"type" json:"type"`
	LocalIP    string    `yaml:"local_ip,omitempty" json:"local_ip,omitempty"`
	LocalPort  int       `yaml:"local_port" json:"local_port"`
	ResourceID string    `yaml:"resource_id,omitempty" json:"resource_id,omitempty"`
	// ConnectorRoutingID is returned by the qURL control plane and used verbatim for
	// FRP SubDomain and load-balancer grouping. NHP placement comes from the
	// authenticated ACK instead. This value must never
	// be client-derived from or normalized against ResourceID; the control plane owns
	// the producer-side calculation.
	ConnectorRoutingID string `yaml:"connector_routing_id,omitempty" json:"connector_routing_id,omitempty"`
	TargetURL          string `yaml:"target_url,omitempty" json:"target_url,omitempty"`
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
// fully-populated file rather than a sparse one missing protocol and
// transport defaults. A sparse file is functionally
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

	// Audit file path override. Trimmed so a heredoc-pasted value with
	// trailing whitespace doesn't bypass the YAML path. Empty (or
	// whitespace-only) falls through to whatever Audit.FilePath
	// already holds — same convention as the QURL_API_URL and
	// QURL_API_KEY_FILE handlers.
	if v := strings.TrimSpace(os.Getenv(EnvAuditFile)); v != "" {
		cfg.Audit.FilePath = v
	}

}
