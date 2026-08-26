package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

var statusJSON bool

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show qURL Connector status",
	RunE:  runStatus,
}

func init() {
	statusCmd.Flags().BoolVar(&statusJSON, "json", false, "output status in JSON format")
}

// adminProxyStatus represents a single proxy status from the FRP admin API.
type adminProxyStatus struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Status     string `json:"status"`
	Err        string `json:"err"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
}

// statusOutput is the structured output for --json mode.
//
// AdminDisabled distinguishes "daemon not running" from "admin API
// gated off, cannot determine" — a JSON consumer (CI script, MDM-style
// poller) needs both signals to decide between "restart the daemon"
// and "the operator chose not to expose the probe surface here." The
// human-readable path renders these as different lines already; this
// is the JSON-shaped parity.
//
// Meaningfulness caveat: AdminDisabled is only authoritative when
// the YAML config (`qurl-proxy.yaml`) loaded successfully. For
// configs that failed Load (validation error) or for the
// discover-error case (missing $HOME / permissions), the field is
// `false` by construction even though no admin-gate decision was
// actually made. JSON consumers MUST NOT read absent-or-false-
// AdminDisabled as proof of opt-in; the config-loaded state has
// to be established from elsewhere (e.g., correlate with the
// Routes shape).
type statusOutput struct {
	Running       bool `json:"running"`
	AdminDisabled bool `json:"admin_disabled"`
	// AdminAuthFailed signals that the daemon WAS reachable on the
	// admin port but rejected our basic-auth credentials (401).
	// Distinct from `Running=false` (probe never connected) and
	// `AdminDisabled=true` (we chose not to probe). A common cause:
	// operator rotated admin.password in YAML without restarting the
	// daemon, or vice-versa. JSON consumers should branch on this to
	// surface a "credential drift" hint instead of a misleading
	// "connector offline."
	AdminAuthFailed bool `json:"admin_auth_failed,omitempty"`
	// AdminAuthUnavailable means the config enabled the admin API
	// without an explicit password, but this runtime could not resolve
	// a real machine ID for the legacy loopback-only fallback. The
	// daemon would fail closed on the same config, so status skips the
	// probe rather than sending the known sentinel password.
	AdminAuthUnavailable bool                          `json:"admin_auth_unavailable,omitempty"`
	Proxies              map[string][]adminProxyStatus `json:"proxies,omitempty"`
	Routes               []routeStatus                 `json:"routes,omitempty"`
}

type routeStatus struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Target     string `json:"target"`
	ResourceID string `json:"resource_id,omitempty"`
	Status     string `json:"status"`
	RemoteAddr string `json:"remote_addr,omitempty"`
}

// runStatus renders the tunnel-status view (human-readable banner or
// --json). The control flow resolves to one of three states:
//
//  1. cfg-disabled (cfg != nil && !cfg.Admin.Enabled): skip the
//     probe entirely, render the on-disk routes view with "admin
//     API disabled" status.
//  2. cfg-enabled (cfg != nil && cfg.Admin.Enabled): probe the
//     configured cfg.Admin.{Addr,Port}; merge live FRP proxy state
//     into the per-route output.
//  3. load-error / discover-error (loadErr || discoverErr): skip the
//     probe (probing the default port could misreport against a
//     stale daemon whose config Validate just rejected) and surface
//     the real cause with a Hint pointing at the actual fix.
//
// The switch on `shouldProbe` below encodes which states actually
// hit the admin API; the human-readable renderer below picks the
// right branch from `running`, `adminDisabled`, `loadErr`, and
// `discoverErr` independently.
func runStatus(cmd *cobra.Command, _ []string) error {
	// Load config first — both to show configured routes AND to learn
	// whether the admin API is opted in. Without the opt-in there's
	// no live state to query, so we render an on-disk-only view rather
	// than misreporting the daemon as "not running."
	//
	// loadErr AND discoverErr are both captured (not swallowed) so the
	// non-JSON renderer can surface the real cause:
	//   - discoverErr fires when `nhpconfig.Discover` can't locate any
	//     config file (permissions error, missing $HOME, etc.).
	//   - loadErr fires when Discover succeeded but parse/validate
	//     rejected the file (e.g., admin.addr non-loopback without
	//     allow_remote — the gate this PR introduced).
	// Without these, an operator hitting either failure would see
	// "Service: not running" from status and only learn the real cause
	// on the next `run`. The JSON path keeps swallowing for backward
	// compat with poller shape.
	cfgPath, discoverErr := nhpconfig.Discover(cfgFile)
	var (
		cfg     *nhpconfig.Config
		loadErr error
	)
	if discoverErr == nil {
		cfg, loadErr = nhpconfig.Load(cfgPath)
		if loadErr == nil {
			if err := hydrateConnectorResourceIDsReadOnlyContext(commandContext(cmd), cfg); err != nil {
				return fmt.Errorf("loading Connector identity state: %w", err)
			}
		}
	}

	var proxyMap map[string][]adminProxyStatus
	running := false
	adminDisabled := cfg != nil && !cfg.Admin.Enabled
	adminAuthFailed := false
	adminAuthUnavailable := false
	var adminAuthErr error

	// Pick what to probe:
	//   - cfg loaded and admin opted in → use cfg.Admin.*
	// The cfg-present-but-admin-disabled case skips the probe (the
	// adminDisabled branch below renders that explicitly). The
	// loadErr / discoverErr cases also skip — Validate just rejected
	// the config (or Discover couldn't find it), so probing the
	// default port would either misreport "running" against a stale
	// daemon or thrash on an unreachable bind.
	var probeAddr string
	var probePort int
	shouldProbe := false
	switch {
	case loadErr != nil || discoverErr != nil:
		// Config failed to load/discover; the surfaced error above is
		// the real cause. Skip the probe rather than misreport.
	case cfg != nil && cfg.Admin.Enabled:
		probeAddr, probePort = cfg.Admin.Addr, cfg.Admin.Port
		shouldProbe = true
	}
	if shouldProbe {
		// adminAuthPassword reads cfg.Admin.Password if set, else
		// computes getMachineID() lazily. The first call to
		// getMachineID does platform-specific work (file reads,
		// system calls); subsequent calls are sync.Once-cached, so
		// the lazy-eval here saves a one-time cost on the admin-
		// disabled, load-error, and discover-error branches via the
		// shouldProbe=false guard above.
		password, passErr := adminAuthPassword(&cfg.Admin)
		if passErr != nil {
			adminAuthUnavailable = true
			adminAuthErr = passErr
		} else {
			// LocalAdminURL substitutes loopback for unspecified bind
			// addresses (0.0.0.0 → 127.0.0.1, :: → ::1) so the probe
			// works from the same host on every OS. The display below
			// keeps AdminURL so operators see the actual bind they
			// configured.
			statusURL := nhpconfig.LocalAdminURL(probeAddr, probePort) + "/api/status"
			req, err := http.NewRequest("GET", statusURL, nil)
			if err != nil {
				return fmt.Errorf("creating request: %w", err)
			}
			req.SetBasicAuth("admin", password)

			httpClient := &http.Client{Timeout: 3 * time.Second}
			resp, doErr := httpClient.Do(req)
			if doErr == nil {
				switch resp.StatusCode {
				case http.StatusOK:
					running = true
					body, readErr := io.ReadAll(resp.Body)
					if readErr == nil {
						_ = json.Unmarshal(body, &proxyMap)
					}
				case http.StatusUnauthorized:
					// Daemon IS running and we reached the listener, but
					// our credential didn't match — operator likely
					// regenerated admin.password without restarting the
					// daemon, or vice versa. Surfaced as a distinct
					// status branch below so the operator sees the real
					// cause rather than chasing "connector offline."
					adminAuthFailed = true
				}
				// Close inline rather than defer so the connection releases
				// to the http transport pool as soon as the block exits,
				// not at runStatus return.
				_ = resp.Body.Close()
			}
		}
	}

	// Build route status by merging config with live proxy status. status
	// runs as a separate process, so the in-memory discriminator resolved
	// by `qurl-connector run` is not present in freshly loaded YAML. The
	// merge below therefore treats the FRP admin API as authoritative:
	// exact salted/raw names win first, then an ambiguity-guarded
	// `routeID-` prefix fallback covers env divergence and random-fallback
	// salts that status cannot reproduce cross-process.
	routes := buildRouteStatuses(cfg, proxyMap, running, adminDisabled)

	if statusJSON {
		out := statusOutput{
			Running:              running,
			AdminDisabled:        adminDisabled,
			AdminAuthFailed:      adminAuthFailed,
			AdminAuthUnavailable: adminAuthUnavailable,
			Proxies:              proxyMap,
			Routes:               routes,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	// Human-readable output
	fmt.Printf("\n%sqURL Connector Status%s\n", colorBold, colorReset)
	// Surface a config-load failure BEFORE the running/disabled
	// branches so the operator sees the real cause when admin.addr
	// fails Validate (e.g., non-loopback bind without allow_remote)
	// instead of a misleading "not running."
	if discoverErr != nil {
		fmt.Printf("  %sConfig:   could not discover config file: %v%s\n", colorYellow, discoverErr, colorReset)
		fmt.Printf("  Hint:     Check QURL_CONFIG_DIR / $HOME permissions; skipping probe until the config loads.\n")
	} else if loadErr != nil {
		fmt.Printf("  %sConfig:   could not load %s: %v%s\n", colorYellow, cfgPath, loadErr, colorReset)
		fmt.Printf("  Hint:     Fix the config error above; skipping probe until the config loads.\n")
	}
	if running {
		fmt.Printf("  Service:  %srunning%s\n", colorGreen, colorReset)
		// probeAddr/probePort were copied from cfg.Admin at the
		// switch above. Reading from probe* rather than cfg keeps
		// the print consistent with what we actually dialed.
		fmt.Printf("  Admin:    %s\n", nhpconfig.AdminURL(probeAddr, probePort))
	} else if adminAuthFailed {
		fmt.Printf("  Service:  %sauth failed%s (daemon reachable at %s but rejected admin.password)\n",
			colorYellow, colorReset, nhpconfig.AdminURL(probeAddr, probePort))
		fmt.Printf("  Hint:     admin.password in YAML doesn't match what the daemon started with. Restart the daemon to pick up the current YAML, OR roll back admin.password to the value the running daemon expects.\n")
	} else if adminAuthUnavailable {
		fmt.Printf("  Service:  %sunknown%s (admin API enabled but auth password is unavailable)\n", colorYellow, colorReset)
		fmt.Printf("  Hint:     %v.\n", adminAuthErr)
	} else if adminDisabled {
		fmt.Printf("  Service:  %sunknown%s (admin API disabled in %s — cannot query live state)\n", colorYellow, colorReset, cfgPath)
		fmt.Printf("  Hint:     Set %sadmin: {enabled: true}%s in qurl-proxy.yaml or %sQURL_ADMIN_ENABLED=true%s to opt in\n", colorCyan, colorReset, colorCyan, colorReset)
	} else {
		fmt.Printf("  Service:  %snot running%s\n", colorYellow, colorReset)
		if cfg != nil && len(cfg.Routes) > 0 {
			fmt.Printf("  Hint:     Run %squrl-connector run%s to start Connector routes\n", colorCyan, colorReset)
		}
	}

	if len(routes) > 0 {
		fmt.Printf("\n  %-20s %-8s %-22s %-12s %s\n",
			"ID", "TYPE", "TARGET", "STATUS", "REMOTE")
		fmt.Printf("  %s\n", strings.Repeat("-", 80))
		for _, r := range routes {
			statusColor := colorYellow
			if r.Status == "running" {
				statusColor = colorGreen
			}
			remote := r.RemoteAddr
			if remote == "" {
				remote = "-"
			}
			fmt.Printf("  %-20s %-8s %-22s %s%-12s%s %s\n",
				truncate(r.ID, 20),
				r.Type,
				truncate(r.Target, 22),
				statusColor, truncate(r.Status, 12), colorReset,
				remote,
			)
		}
	} else if cfg == nil || len(cfg.Routes) == 0 {
		fmt.Printf("\n  No routes configured. Run %squrl-connector add%s to register services.\n", colorCyan, colorReset)
	}
	fmt.Println()

	return nil
}

// buildRouteStatuses merges the YAML route config with live FRP admin
// API proxy state and resolves each route's user-facing status string.
//
// Extracted from runStatus so the JSON shape (the load-bearing surface
// for poller consumers) and the per-route status precedence
// (live proxy > admin disabled > connector offline > not running) can be
// unit-tested without standing up an httptest.Server or building the
// full FRP SDK.
//
// Precedence rationale:
//   - Live proxy entry wins: the daemon is the ground truth when we
//     can talk to it.
//   - adminDisabled: the operator chose not to expose the probe
//     surface. The route IS likely running (FRP doesn't need admin
//     to forward traffic) — we just can't introspect.
//   - !running: probe failed and admin isn't disabled, so the daemon
//     is genuinely down.
//   - "not running" (the initial value): daemon IS up and admin IS
//     enabled, but FRP hasn't reported this route in its proxy map
//     yet — the legitimate "daemon up, route registration pending"
//     window during startup. Operators see this transiently if they
//     `status` between daemon start and proxy registration.
//
// Returns nil when cfg is nil (load/discover failure path) —
// caller-side rendering handles the "no routes to show" case.
func buildRouteStatuses(cfg *nhpconfig.Config, proxyMap map[string][]adminProxyStatus, running, adminDisabled bool) []routeStatus {
	if cfg == nil {
		return nil
	}
	proxyLookup := buildProxyLookup(proxyMap)
	routes := make([]routeStatus, 0, len(cfg.Routes))
	fallbackID := routeIDEnvFallback()
	routeIDs := configuredRouteIDs(cfg, fallbackID)
	for _, r := range cfg.Routes {
		id := routeIDWithFallback(cfg, r, fallbackID)
		rs := routeStatus{
			ID:         id,
			Type:       string(r.Type),
			Target:     fmt.Sprintf("%s:%d", r.LocalIP, r.LocalPort),
			ResourceID: r.ResourceID,
			Status:     "not running",
		}
		if ps, ok := lookupRouteProxy(proxyLookup, id, cfg.Server.ReplicaDiscriminator, routeIDs); ok {
			rs.Status = ps.Status
			rs.RemoteAddr = ps.RemoteAddr
			if ps.Err != "" {
				rs.Status = "error: " + ps.Err
			}
		} else if adminDisabled {
			rs.Status = "admin disabled"
		} else if !running {
			rs.Status = "connector offline"
		}
		routes = append(routes, rs)
	}
	return routes
}

func configuredRouteIDs(cfg *nhpconfig.Config, fallbackID string) map[string]struct{} {
	ids := make(map[string]struct{}, len(cfg.Routes))
	for _, r := range cfg.Routes {
		id := routeIDWithFallback(cfg, r, fallbackID)
		if id != "" {
			ids[id] = struct{}{}
		}
	}
	return ids
}

func lookupRouteProxy(proxyLookup map[string]adminProxyStatus, routeID, replicaDiscriminator string, routeIDs map[string]struct{}) (adminProxyStatus, bool) {
	if replicaDiscriminator != "" {
		if ps, ok := proxyLookup[nhpconfig.FRPProxyName(routeID, replicaDiscriminator)]; ok {
			return ps, true
		}
	}
	if ps, ok := proxyLookup[routeID]; ok {
		return ps, true
	}
	return lookupRouteProxyByPrefix(proxyLookup, routeID, routeIDs)
}

func lookupRouteProxyByPrefix(proxyLookup map[string]adminProxyStatus, routeID string, routeIDs map[string]struct{}) (adminProxyStatus, bool) {
	// Common default status display path for salted runtime names when
	// YAML does not pin server.replica_discriminator. The local FRP admin
	// API should reflect the current daemon's configured routes; guard
	// against the common configured-sibling shape (`web` vs `web-api`)
	// and refuse multiple candidates rather than attributing an ambiguous
	// proxy to the wrong route. A single stale admin entry from a
	// de-configured route that shares this prefix can still be attributed
	// here; that is display-only and bounded to stale local admin data.
	prefix := routeID + "-"
	var match adminProxyStatus
	found := false
	for name, ps := range proxyLookup {
		if !strings.HasPrefix(name, prefix) || belongsToLongerRouteID(name, routeID, routeIDs) {
			continue
		}
		if found {
			return adminProxyStatus{}, false
		}
		match = ps
		found = true
	}
	return match, found
}

func belongsToLongerRouteID(proxyName, routeID string, routeIDs map[string]struct{}) bool {
	for otherID := range routeIDs {
		if otherID == routeID || len(otherID) <= len(routeID) {
			continue
		}
		if proxyName == otherID || strings.HasPrefix(proxyName, otherID+"-") {
			return true
		}
	}
	return false
}

// buildProxyLookup flattens the FRP admin API proxy map into a name-keyed lookup.
func buildProxyLookup(proxyMap map[string][]adminProxyStatus) map[string]adminProxyStatus {
	lookup := make(map[string]adminProxyStatus)
	for _, proxies := range proxyMap {
		for _, p := range proxies {
			lookup[p.Name] = p
		}
	}
	return lookup
}

func truncate(s string, max int) string {
	if max <= 0 {
		return ""
	}
	runeCount := utf8.RuneCountInString(s)
	if runeCount <= max {
		return s
	}
	runes := []rune(s)
	if max <= 3 {
		return strings.Repeat(".", max)
	}
	return string(runes[:max-3]) + "..."
}
