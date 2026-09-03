package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/denisbrodbeck/machineid"
	frpconfig "github.com/fatedier/frp/pkg/config"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/config/v1/validation"
	"github.com/fatedier/frp/pkg/policy/security"
	qurl "github.com/layervai/qurl-go/qurl"
	"github.com/spf13/cobra"

	"github.com/layervai/qurl-connector/internal/pinnedfs"
	"github.com/layervai/qurl-connector/pkg/agentstate"
	"github.com/layervai/qurl-connector/pkg/audit"
	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
	"github.com/layervai/qurl-connector/pkg/hubpin"
	"github.com/layervai/qurl-connector/pkg/proofprovenance"
	"github.com/layervai/qurl-connector/pkg/replica"
	"github.com/layervai/qurl-connector/pkg/share"
	"github.com/layervai/qurl-connector/pkg/version"
)

const (
	unknownMachineID = "unknown"

	envConnectorID        = "QURL_CONNECTOR_ID"
	envHubHost            = "QURL_CONNECTOR_HUB_HOST"
	envHubPort            = "QURL_CONNECTOR_HUB_PORT"
	envHubServerPublicKey = "QURL_CONNECTOR_HUB_SERVER_PUBLIC_KEY_B64"
	envRefreshMode        = "LAYERV_AGENT_REGISTRATION_REFRESH_MODE"
	envNativeOwnerID      = "QURL_CONNECTOR_NATIVE_OWNER_ID"

	defaultHubHost = "hub.nhp.layerv.ai"
	defaultHubPort = 443
)

// defaultHubServerPublicKeyB64 remains blank in source. The developer command
// therefore requires the all-or-none custom Hub override instead of trusting
// DNS without a pinned server identity.
var defaultHubServerPublicKeyB64 string
var connectorConfigLockWaitTimeout = 30 * time.Second
var acquireConnectorConfigTransaction = nhpconfig.AcquireFileTransactionContext
var beforeConnectorImmutableConfigFallback = func() {}
var makefileTimestampVersionRe = regexp.MustCompile(`^([vV]?)(\d+\.\d+\.\d+)\.\d+$`)

var (
	logLevel         string
	strictConfigMode bool
	cachedMachineID  string
	machineIDOnce    sync.Once
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start the qURL Connector",
	RunE:  runCmdFunc,
}

func init() {
	runCmd.Flags().StringVar(&logLevel, "log-level", "info", "log level: trace, debug, info, warn, error")
	runCmd.Flags().BoolVar(&strictConfigMode, "strict-config", true, "strict config parsing mode, unknown fields cause errors")
}

type connectorRuntime struct {
	Binding *qurl.AgentRuntimeBinding
	Store   connectorStateContinuity
	Hub     qurl.HubBootstrap
	UDPOpts []qurl.AgentRuntimeUDPOption
	AgentID string
	shared  *share.NativeRuntime
}

type connectorResourceResolveFunc func(
	context.Context,
	*qurl.AgentRuntimeBinding,
	*qurl.NativeConnectorResourceRequest,
	...qurl.AgentRuntimeUDPOption,
) (*qurl.ConnectorResourceResolution, error)

type connectorConfigAccess struct {
	config      *nhpconfig.Config
	transaction *nhpconfig.FileTransaction
	snapshot    *nhpconfig.ImmutableConfigSnapshot
	writeErr    error
}

func (a *connectorConfigAccess) Close() error {
	if a == nil {
		return nil
	}
	var err error
	if a.transaction != nil {
		err = errors.Join(err, a.transaction.Close())
		a.transaction = nil
	}
	if a.snapshot != nil {
		err = errors.Join(err, a.snapshot.Close())
		a.snapshot = nil
	}
	return err
}

type connectorStateContinuity interface {
	ValidateContinuity() error
}

type connectorIdentityTransactionContinuity struct {
	sdk connectorStateContinuity
	txn *connectorIdentityCacheTxn
}

func (g connectorIdentityTransactionContinuity) ValidateContinuity() error {
	if g.sdk != nil {
		if err := g.sdk.ValidateContinuity(); err != nil {
			return err
		}
	}
	if err := validateConnectorIdentityCacheNamespace(g.txn); err != nil {
		return fmt.Errorf("%w: validate Connector identity namespace: %w", qurl.ErrAgentStateContinuity, err)
	}
	if g.sdk != nil {
		if err := g.sdk.ValidateContinuity(); err != nil {
			return err
		}
	}
	return nil
}

func (r *connectorRuntime) ValidateContinuity() error {
	if r == nil || r.Store == nil {
		return fmt.Errorf("%w: Connector runtime has no SDK state store", qurl.ErrAgentStateContinuity)
	}
	return r.Store.ValidateContinuity()
}

func (r *connectorRuntime) Close() error {
	if r == nil {
		return nil
	}
	if r.shared != nil {
		// prepareConnectorRun transfers Binding to the knocker by clearing the
		// wrapper field. Mirror that ownership into the shared runtime before
		// closing so the binding is destroyed exactly once.
		r.shared.Binding = r.Binding
		err := r.shared.Close()
		r.shared = nil
		r.Binding = nil
		r.Store = nil
		r.UDPOpts = nil
		return err
	}
	r.Binding = nil
	r.Store = nil
	r.UDPOpts = nil
	return nil
}

func runCmdFunc(_ *cobra.Command, _ []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return runConnectorCommand(ctx)
}

// runConnectorCommand is the entire run-command body behind runCmdFunc's
// signal.NotifyContext wrapper. The split exists so tests can drive
// cancellation during native registration/warm-open with an injected context;
// the production path must keep entering through runCmdFunc so SIGINT/SIGTERM
// stay bound to this context.
func runConnectorCommand(ctx context.Context) (retErr error) {
	printBanner()
	exeBinDir := "."
	if ep, err := os.Executable(); err == nil {
		exeBinDir = filepath.ToSlash(filepath.Dir(ep))
	}
	machineID := getMachineID()
	frpconfig.GetValues().Envs["QURL_MACHINE_ID"] = machineID
	frpconfig.GetValues().Envs["QURL_BIN_DIR"] = exeBinDir
	fmt.Printf("  Machine ID: %s%s%s\n", colorCyan, machineID, colorReset)

	auditLogger, err := initEarlyAuditLogger(machineID)
	if err != nil {
		slog.WarnContext(ctx, "audit: failed to initialize early audit logger; falling back to NopLogger", "err", err.Error())
		auditLogger = audit.NopLogger{}
	}
	audit.SetDefault(auditLogger)
	defer func() { _ = audit.Default().Close() }()

	cfgPath, err := nhpconfig.Discover(cfgFile)
	if err != nil {
		return fmt.Errorf("no config found. Create qurl-proxy.yaml or use --config flag.\nRun 'qurl-connector add --target http://localhost:8080 --id myapp' to get started")
	}
	cfg, runtime, admitter, err := prepareConnectorRun(ctx, cfgPath)
	if err != nil {
		return err
	}
	defer func() {
		retErr = errors.Join(retErr, runtime.Close())
	}()
	defer func() { retErr = errors.Join(retErr, admitter.Close()) }()

	fmt.Printf("  Config: %s%s%s\n", colorCyan, cfgPath, colorReset)
	return startFRPFromConfig(ctx, cfgPath, machineID, cfg, runtime.AgentID, admitter)
}

func prepareConnectorRun(ctx context.Context, cfgPath string) (_ *nhpconfig.Config, _ connectorRuntime, _ *share.NativeAdmitter, retErr error) {
	canonicalConfigPath, err := nhpconfig.CanonicalPath(cfgPath)
	if err != nil {
		return nil, connectorRuntime{}, nil, fmt.Errorf("resolving config path: %w", err)
	}
	cfgPath = canonicalConfigPath
	configAccess, err := acquireConnectorRunReadOnlyConfig(cfgPath)
	if err != nil {
		return nil, connectorRuntime{}, nil, err
	}
	releaseConfigAccess := func() error {
		if configAccess == nil {
			return nil
		}
		err := configAccess.Close()
		configAccess = nil
		return err
	}
	cfg := configAccess.config
	if len(cfg.Routes) == 0 {
		return nil, connectorRuntime{}, nil, errors.Join(
			errors.New("no routes configured. Run 'qurl-connector add' to configure a service first"),
			releaseConfigAccess(),
		)
	}
	if err := validateConnectorRunRoutes(cfg); err != nil {
		return nil, connectorRuntime{}, nil, errors.Join(err, releaseConfigAccess())
	}

	stateDir := agentstate.ResolveDir("")
	var runtime connectorRuntime
	prepareErr := withConnectorIdentityCacheLockContext(ctx, stateDir, func(txnCtx context.Context, txn *connectorIdentityCacheTxn) error {
		if err := ensureConnectorIdentityCacheInitializedLocked(txn); err != nil {
			return err
		}
		if err := preflightConnectorIdentityCacheGraphLocked(cfg, txn); err != nil {
			return err
		}
		// Preserve config -> state lock ordering for concurrent remove, then
		// release the immutable run snapshot before bounded network work.
		if err := releaseConfigAccess(); err != nil {
			return fmt.Errorf("release config access after state-lock handoff: %w", err)
		}
		var err error
		runtime, err = openConnectorRuntime(txnCtx, cfg)
		if err != nil {
			return fmt.Errorf("native agent runtime: %w", err)
		}
		continuity := connectorIdentityTransactionContinuity{sdk: runtime.Store, txn: txn}
		if err := gateConnectorStateContinuity(continuity, "bind Connector identity cache", func() error {
			cache, err := loadConnectorIdentityCacheUnlocked(txn)
			if err != nil {
				return err
			}
			return cache.bindAgentIDLocked(txn, runtime.AgentID)
		}); err != nil {
			return fmt.Errorf("bind Connector identity continuity to registered device: %w", err)
		}
		if err := resolveConnectorIdentitiesLocked(txnCtx, cfg, runtime.Binding, runtime.UDPOpts, txn, continuity, qurl.ResolveRegisteredAgentConnectorResource); err != nil {
			return fmt.Errorf("resolve qURL Connector resources over NHP: %w", err)
		}
		return nil
	})
	if configAccess != nil {
		prepareErr = errors.Join(prepareErr, releaseConfigAccess())
	}
	if prepareErr != nil {
		return nil, connectorRuntime{}, nil, errors.Join(prepareErr, runtime.Close())
	}
	if err := nhpconfig.Validate(cfg); err != nil {
		return nil, connectorRuntime{}, nil, errors.Join(
			fmt.Errorf("validate resolved Connector config: %w", err),
			runtime.Close(),
		)
	}
	if err := runtime.ValidateContinuity(); err != nil {
		return nil, connectorRuntime{}, nil, errors.Join(
			fmt.Errorf("validate SDK state before qURL Connector runtime handoff: %w", err),
			runtime.Close(),
		)
	}

	resourceID := cfg.PrimaryResourceID()
	knockResourceID := knockResourceIDOrEmpty(cfg, resourceID)
	if knockResourceID == "" {
		return nil, connectorRuntime{}, nil, errors.Join(
			fmt.Errorf("missing NHP knock resource for qURL Connector %q", resourceID),
			runtime.Close(),
		)
	}
	if runtime.shared == nil {
		return nil, connectorRuntime{}, nil, errors.Join(errors.New("shared native runtime is unavailable"), runtime.Close())
	}
	admitter, err := share.NewNativeAdmitter(ctx, runtime.shared)
	if err != nil {
		return nil, connectorRuntime{}, nil, errors.Join(err, runtime.Close())
	}
	// Binding and state ownership moved to the shared admitter. Runtime retains
	// only non-owning identity fields for the command's final handoff.
	runtime.Binding = nil
	runtime.Store = nil
	return cfg, runtime, admitter, nil
}

// acquireConnectorRunReadOnlyConfig opens the config for `run`, which READS it
// and never writes it.
//
// The canonical Docker deployment mounts the config read-only:
//
//	-v /etc/qurl/qurl-proxy.yaml:/work/qurl-proxy.yaml:ro
//
// /work is root-owned and not writable by the nonroot runtime user, by design
// (see docker/Dockerfile). A mutating config transaction wants a sibling
// `.lock` next to the config, which that mount cannot host -- so `run` must not
// open one. It previously did, purely because it shared `remove`'s accessor,
// and reached the correct read-only path only by matching an allowlist of
// errnos from the failed write. Any mount whose failure spelled itself
// differently fell off that path and surfaced as a startup error, which made
// the DOCUMENTED deployment depend on which errno a filesystem happened to
// return.
//
// Reading directly removes that coupling: the documented mount is the primary
// path, not a recovery from a failed write. The security properties are
// unchanged -- OpenImmutableConfigSnapshot still pins the parent directory,
// requires a single-link regular file that is not group/other-writable, and
// revalidates the pinned handle before and after the read. It also stops `run`
// from holding the config lock for the connector's whole lifetime, which
// blocked `add`/`remove` for no reason.
//
// The sibling lock is deliberately NOT consulted here. It persists for the life
// of a writable deployment -- mutual exclusion is advisory flock ON that file,
// not its existence -- so requiring it to be absent would reject every normal
// install, and requiring it to be present would reject the read-only mount this
// function exists to serve. A reader does not need the writers' lock: config
// replacement is atomic (temp + rename), so a torn read is impossible, and
// OpenImmutableConfigSnapshot revalidates the pinned handle after reading, which
// detects a mutation that landed mid-read.
func acquireConnectorRunReadOnlyConfig(cfgPath string) (_ *connectorConfigAccess, retErr error) {
	cfg, snapshot, err := nhpconfig.OpenImmutableConfigSnapshot(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("open Connector config for reading: %w%s", err, describeConfigAccessContext(cfgPath))
	}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, snapshot.Close())
		}
	}()
	return &connectorConfigAccess{
		config:   cfg,
		snapshot: snapshot,
		writeErr: errors.New("run opened the configuration read-only"),
	}, nil
}

// describeConfigAccessContext appends the facts needed to diagnose a config
// open failure -- the effective identity and the actual owner/mode of the file
// and its parent. Without these, an EACCES from inside a container is only
// guessable from the outside, which is exactly the position a failing proof run
// left us in.
func describeConfigAccessContext(cfgPath string) string {
	var b strings.Builder
	fmt.Fprintf(&b, " [euid=%d egid=%d", os.Geteuid(), os.Getegid())
	for label, path := range map[string]string{"config": cfgPath, "parent": filepath.Dir(cfgPath)} {
		info, err := os.Lstat(path) //nolint:gosec // G703: diagnostic-only stat of the caller-selected config path; it never opens or follows the path.
		if err != nil {
			fmt.Fprintf(&b, " %s=<stat failed: %v>", label, err)
			continue
		}
		fmt.Fprintf(&b, " %s=%s", label, info.Mode())
		b.WriteString(describeFileOwnership(info))
	}
	b.WriteString("]")
	return b.String()
}

func acquireConnectorRunConfigAccess(ctx context.Context, cfgPath string) (_ *connectorConfigAccess, retErr error) {
	if ctx == nil {
		return nil, errors.New("Connector config context is nil")
	}
	lockPath := cfgPath + ".lock"
	_, beforeErr := os.Lstat(lockPath) //nolint:gosec // G703: this existence-only preflight never follows or opens the caller-selected path; the transaction/snapshot paths below canonicalize and pin the namespace before access.
	if beforeErr != nil && !errors.Is(beforeErr, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect config transaction lock before Connector startup: %w", beforeErr)
	}
	lockCtx, cancel := context.WithTimeout(ctx, connectorConfigLockWaitTimeout)
	txn, err := acquireConnectorConfigTransaction(lockCtx, cfgPath)
	cancel()
	if err == nil {
		cfg, loadErr := txn.Load()
		if loadErr != nil {
			return nil, errors.Join(
				fmt.Errorf("loading config: %w", loadErr),
				txn.Close(),
			)
		}
		return &connectorConfigAccess{config: cfg, transaction: txn}, nil
	}
	// The canonical Docker YAML is a read-only bind mount. Run never mutates it,
	// so only a safe root-owned namespace or a proven inability to create a
	// previously absent sibling lock may use the pinned immutable snapshot.
	fallbackEligible := errors.Is(err, pinnedfs.ErrNamespaceNotOwned) ||
		errors.Is(err, nhpconfig.ErrConfigContinuityLockMissing) ||
		errors.Is(err, os.ErrPermission) ||
		errors.Is(err, syscall.EROFS)
	if !fallbackEligible || !errors.Is(beforeErr, os.ErrNotExist) {
		return nil, fmt.Errorf("acquire config transaction for Connector startup: %w", err)
	}

	beforeConnectorImmutableConfigFallback()
	cfg, snapshot, snapshotErr := nhpconfig.OpenImmutableConfigSnapshot(cfgPath)
	if snapshotErr != nil {
		return nil, errors.Join(
			fmt.Errorf("acquire config transaction for Connector startup: %w", err),
			fmt.Errorf("open pinned immutable config fallback: %w", snapshotErr),
		)
	}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, snapshot.Close())
		}
	}()
	if absentErr := snapshot.RequireSiblingAbsent(filepath.Base(lockPath)); absentErr != nil {
		return nil, errors.Join(
			fmt.Errorf("acquire config transaction for Connector startup: %w", err),
			fmt.Errorf("prove config transaction lock remained absent: %w", absentErr),
		)
	}
	return &connectorConfigAccess{
		config:   cfg,
		snapshot: snapshot,
		writeErr: fmt.Errorf("configuration mount does not support atomic updates: %w", err),
	}, nil
}

// validateConnectorRunRoutes is the last local-only gate before native
// registration can consume an enrollment credential or mutate SDK state. The
// low-level config package still supports ResourceID-free custom FRP routes,
// but the qurl-connector run command manages every route as a device-owned HTTP
// Connector resource and must reject incompatible shapes before remote work.
func validateConnectorRunRoutes(cfg *nhpconfig.Config) error {
	if cfg == nil {
		return errors.New("Connector config is nil")
	}
	fallbackID := routeIDEnvFallback()
	seen := make(map[string]int, len(cfg.Routes))
	for i, route := range cfg.Routes {
		if route.Type != nhpconfig.RouteTypeHTTP {
			return fmt.Errorf("routes[%d] (%s): qURL Connector run supports managed HTTP routes only; got %q", i, route.ID, route.Type)
		}
		if len(route.CustomDomains) != 0 {
			return fmt.Errorf("routes[%d] (%s): managed qURL Connector routes cannot set custom_domains", i, route.ID)
		}
		id := routeIDWithFallback(cfg, route, fallbackID)
		if id == "" {
			return fmt.Errorf("routes[%d] needs id or the single-route %s fallback", i, envConnectorID)
		}
		if previous, duplicate := seen[id]; duplicate {
			return fmt.Errorf("routes[%d] and routes[%d] use duplicate Connector id %q", previous, i, id)
		}
		seen[id] = i
		if route.ResourceID == "" {
			if err := nhpconfig.ValidateSlug(id); err != nil {
				return fmt.Errorf("routes[%d] (%s): invalid Connector id before native registration: %w", i, id, err)
			}
		}
		if route.ResourceID == "" && (route.Subdomain != "" || route.LoadBalancerGroup != "") {
			return fmt.Errorf("routes[%d] (%s): omit subdomain and load_balancer_group until the producer returns connector_routing_id", i, id)
		}
	}
	return nil
}

func openConnectorRuntime(ctx context.Context, cfg *nhpconfig.Config) (_ connectorRuntime, retErr error) {
	nativeConfig, err := connectorNativeRuntimeConfig(cfg)
	if err != nil {
		return connectorRuntime{}, err
	}
	sharedRuntime, err := share.OpenNativeRuntime(ctx, nativeConfig)
	if err != nil {
		return connectorRuntime{}, err
	}
	runtime := connectorRuntime{
		Binding: sharedRuntime.Binding, Store: sharedRuntime, Hub: sharedRuntime.Hub,
		UDPOpts: append([]qurl.AgentRuntimeUDPOption(nil), sharedRuntime.UDPOptions...),
		AgentID: sharedRuntime.AgentID, shared: sharedRuntime,
	}
	boundary := proofprovenance.BoundaryWarmOpen
	switch sharedRuntime.OpenKind {
	case share.NativeOpenRegistration:
		boundary = proofprovenance.BoundaryRegistration
	case share.NativeOpenRefresh:
		boundary = proofprovenance.BoundaryAssignmentRefresh
	}
	runtime, err = finalizeStrictOperationalBoundary(runtime, boundary)
	if err != nil {
		return connectorRuntime{}, errors.Join(err, runtime.Close())
	}
	return runtime, nil
}

func connectorNativeRuntimeConfig(cfg *nhpconfig.Config) (share.NativeRuntimeConfig, error) {
	sessionOperations, err := connectorNativeSessionAuthority()
	if err != nil {
		return share.NativeRuntimeConfig{}, err
	}
	hub, err := connectorHubBootstrap()
	if err != nil {
		return share.NativeRuntimeConfig{}, err
	}
	udpOpts, err := connectorUDPOptions(cfg)
	if err != nil {
		return share.NativeRuntimeConfig{}, err
	}
	mode, err := registrationRefreshMode()
	if err != nil {
		return share.NativeRuntimeConfig{}, err
	}
	return share.NativeRuntimeConfig{
		StateDir: agentstate.ResolveDir(""), AgentID: agentstate.ConfiguredAgentID(), Hub: hub,
		Hostname: runtimeHostname(), Version: clientVersionMeta(version.Version),
		EnrollmentCredential: enrollmentCredential(), RefreshMode: mode,
		UDPOptions: udpOpts, SessionOperations: sessionOperations,
	}, nil
}

// connectorNativeSessionAuthority resolves authenticated account context before
// registration can consume a credential or send a packet. The owner is never
// inferred from a CRID, route, or NHP response. NHP deployment coordinates are
// private server configuration and are not present in this binary.
func connectorNativeSessionAuthority() (share.NativeSessionOperationAuthority, error) {
	ownerID := strings.TrimSpace(os.Getenv(envNativeOwnerID))
	authority := share.NativeSessionOperationAuthority{OwnerID: ownerID}
	if err := share.ValidateNativeSessionOperationAuthority(authority); err != nil {
		return share.NativeSessionOperationAuthority{}, fmt.Errorf("native session authority from %s: %w", envNativeOwnerID, err)
	}
	return authority, nil
}

func finalizeStrictOperationalBoundary(runtime connectorRuntime, boundary proofprovenance.Boundary) (connectorRuntime, error) {
	destroyBinding := func() {
		if runtime.Binding != nil {
			runtime.Binding.Destroy()
		}
	}
	if err := runtime.ValidateContinuity(); err != nil {
		destroyBinding()
		return connectorRuntime{}, fmt.Errorf("validate SDK state before strict operational provenance: %w", err)
	}
	if err := proofprovenance.Record(runtime.Hub, runtime.Binding, boundary); err != nil {
		destroyBinding()
		return connectorRuntime{}, fmt.Errorf("strict operational provenance: %w", err)
	}
	if err := runtime.ValidateContinuity(); err != nil {
		destroyBinding()
		return connectorRuntime{}, fmt.Errorf("validate SDK state after strict operational provenance: %w", err)
	}
	return runtime, nil
}

func connectorHubBootstrap() (qurl.HubBootstrap, error) {
	host, hostSet := os.LookupEnv(envHubHost)
	portRaw, portSet := os.LookupEnv(envHubPort)
	key, keySet := os.LookupEnv(envHubServerPublicKey)
	setCount := 0
	for _, set := range []bool{hostSet, portSet, keySet} {
		if set {
			setCount++
		}
	}
	if setCount != 0 && setCount != 3 {
		return qurl.HubBootstrap{}, fmt.Errorf("%s, %s, and %s must be set together", envHubHost, envHubPort, envHubServerPublicKey)
	}
	if setCount == 0 {
		host = defaultHubHost
		portRaw = strconv.Itoa(defaultHubPort)
		key = defaultHubServerPublicKeyB64
	} else {
		for _, required := range []struct{ name, value string }{
			{envHubHost, host},
			{envHubPort, portRaw},
			{envHubServerPublicKey, key},
		} {
			if strings.TrimSpace(required.value) == "" {
				return qurl.HubBootstrap{}, fmt.Errorf("%s must be non-empty when the custom Hub triple is set", required.name)
			}
		}
	}
	host = strings.TrimSpace(host)
	key = strings.TrimSpace(key)
	portRaw = strings.TrimSpace(portRaw)
	port, err := strconv.Atoi(portRaw)
	if err != nil {
		return qurl.HubBootstrap{}, fmt.Errorf("%s must be a valid port: %w", envHubPort, err)
	}
	// A pinned trust-root endpoint must have one byte spelling; Atoi alone
	// accepts "0443" and "+443".
	if strconv.Itoa(port) != portRaw {
		return qurl.HubBootstrap{}, fmt.Errorf("%s must be a valid port in canonical decimal form; got %q", envHubPort, portRaw)
	}
	if key == "" && setCount == 0 {
		return qurl.HubBootstrap{}, fmt.Errorf("this build has no pinned production Hub key; set the all-or-none %s/%s/%s custom deployment triple", envHubHost, envHubPort, envHubServerPublicKey)
	}
	hub := qurl.HubBootstrap{Host: host, Port: port, ServerPublicKeyB64: key}
	if err := validateConnectorHubBootstrap(hub); err != nil {
		return qurl.HubBootstrap{}, err
	}
	return hub, nil
}

// validateConnectorHubBootstrap mirrors qurl-go's native-assignment trust-root
// checks at configuration load time. qurl-go remains authoritative before
// network I/O; this early check prevents a warm persisted lease from masking a
// malformed replacement Hub pin until a later refresh. pkg/hubpin owns the
// canonical key validation used by this path and diagnostics.
func validateConnectorHubBootstrap(hub qurl.HubBootstrap) error {
	if !validConnectorHubHost(hub.Host) {
		return fmt.Errorf("%s must be a canonical lowercase DNS name", envHubHost)
	}
	if hub.Port != defaultHubPort {
		return fmt.Errorf("%s must be the standard NHP UDP port %d", envHubPort, defaultHubPort)
	}
	if _, err := hubpin.DecodeServerPublicKeyB64(hub.ServerPublicKeyB64); err != nil {
		return fmt.Errorf("%s %w", envHubServerPublicKey, err)
	}
	return nil
}

func validConnectorHubHost(host string) bool {
	if host == "" || len(host) > 253 || strings.HasSuffix(host, ".") || net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			b := label[i]
			if !((b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-') {
				return false
			}
		}
	}
	return true
}

func registrationRefreshMode() (string, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv(envRefreshMode)))
	if mode == "" {
		mode = "auto"
	}
	switch mode {
	case "auto", "disabled":
		return mode, nil
	default:
		return "", fmt.Errorf("%s must be auto or disabled; got %q", envRefreshMode, mode)
	}
}

func enrollmentCredential() string { return getToken() }

func runtimeHostname() string {
	host, err := os.Hostname()
	if err != nil {
		return "qurl-connector"
	}
	return normalizeRuntimeHostname(host)
}

func normalizeRuntimeHostname(host string) string {
	// Hostname metadata is byte-bounded on the wire. An invalid encoding is not
	// safe to reinterpret; use the deterministic fallback instead. For valid
	// input, remove complete trailing runes until truncation cannot split one.
	if !utf8.ValidString(host) {
		return "qurl-connector"
	}
	if strings.TrimSpace(host) == "" {
		return "qurl-connector"
	}
	for len(host) > 255 {
		_, size := utf8.DecodeLastRuneInString(host)
		host = host[:len(host)-size]
	}
	return host
}

func connectorUDPOptions(cfg *nhpconfig.Config) ([]qurl.AgentRuntimeUDPOption, error) {
	dialer, err := connectorEgressUDPDialer(cfg)
	if err != nil || dialer == nil {
		return nil, err
	}
	return []qurl.AgentRuntimeUDPOption{qurl.WithAgentRuntimeUDPDialer(dialer)}, nil
}

// connectorEgressUDPDialer returns (nil, nil) when no shared egress source IP
// is configured; qurl-go's closed option set cannot be introspected, so the
// dialer construction stays separately visible.
func connectorEgressUDPDialer(cfg *nhpconfig.Config) (*net.Dialer, error) {
	if cfg == nil || strings.TrimSpace(cfg.Server.EgressLocalIP) == "" {
		return nil, nil
	}
	ip := net.ParseIP(strings.TrimSpace(cfg.Server.EgressLocalIP))
	if ip == nil {
		return nil, fmt.Errorf("server.egress_local_ip %q is not an IP address", cfg.Server.EgressLocalIP)
	}
	return &net.Dialer{LocalAddr: &net.UDPAddr{IP: ip}}, nil
}

func gateConnectorStateContinuity(gate connectorStateContinuity, operation string, fn func() error) error {
	if gate != nil {
		if err := gate.ValidateContinuity(); err != nil {
			return fmt.Errorf("validate SDK state before %s: %w", operation, err)
		}
	}
	operationErr := fn()
	if gate == nil {
		return operationErr
	}
	if err := gate.ValidateContinuity(); err != nil {
		return errors.Join(operationErr, fmt.Errorf("validate SDK state after %s: %w", operation, err))
	}
	return operationErr
}

func gateConnectorStateResult[T any](gate connectorStateContinuity, operation string, fn func() (T, error)) (T, error) {
	var result T
	err := gateConnectorStateContinuity(gate, operation, func() error {
		var err error
		result, err = fn()
		return err
	})
	if err != nil {
		var zero T
		return zero, err
	}
	return result, nil
}

func resolveConnectorIdentities(
	ctx context.Context,
	cfg *nhpconfig.Config,
	binding *qurl.AgentRuntimeBinding,
	udpOpts []qurl.AgentRuntimeUDPOption,
	stateDir, agentID string,
	continuity connectorStateContinuity,
	resolve connectorResourceResolveFunc,
) error {
	return withConnectorIdentityCacheLockContext(ctx, stateDir, func(txnCtx context.Context, txn *connectorIdentityCacheTxn) error {
		transactionContinuity := connectorIdentityTransactionContinuity{sdk: continuity, txn: txn}
		if err := rejectLegacyConnectorIdentityStateLocked(txn); err != nil {
			return err
		}
		cache, err := loadConnectorIdentityCacheUnlocked(txn)
		if err != nil {
			return err
		}
		if err := gateConnectorStateContinuity(transactionContinuity, "bind Connector identity cache", func() error {
			return cache.bindAgentIDLocked(txn, agentID)
		}); err != nil {
			return err
		}
		return resolveConnectorIdentitiesLocked(txnCtx, cfg, binding, udpOpts, txn, transactionContinuity, resolve)
	})
}

func preflightConnectorIdentityCacheGraphLocked(cfg *nhpconfig.Config, txn *connectorIdentityCacheTxn) error {
	if cfg == nil {
		return errors.New("Connector config is nil")
	}
	cache, err := loadConnectorIdentityCacheUnlocked(txn)
	if err != nil {
		return err
	}
	configuredIDs, err := validateConfiguredConnectorIdentityGraph(cfg, cache)
	if err != nil {
		return err
	}
	return cache.rejectOrphanIdentities(configuredIDs)
}

func validateConfiguredConnectorIdentityGraph(cfg *nhpconfig.Config, cache *connectorIdentityCache) (map[string]struct{}, error) {
	if cfg == nil {
		return nil, errors.New("Connector config is nil")
	}
	if cache == nil {
		return nil, errors.New("Connector identity cache is nil")
	}
	fallbackID := routeIDEnvFallback()
	configuredIDs := make(map[string]struct{}, len(cfg.Routes))
	resourceOwners := make(map[string]string, len(cfg.Routes))
	for i, route := range cfg.Routes {
		id := routeIDWithFallback(cfg, route, fallbackID)
		if err := nhpconfig.ValidateSlug(id); err != nil {
			return nil, fmt.Errorf("routes[%d] (%s): invalid Connector id: %w", i, id, err)
		}
		if _, duplicate := configuredIDs[id]; duplicate {
			return nil, fmt.Errorf("routes[%d]: duplicate Connector id %q", i, id)
		}
		configuredIDs[id] = struct{}{}
		cachedResourceID, cached := cache.resourceID(id)
		if route.ResourceID != "" && cached && route.ResourceID != cachedResourceID {
			return nil, fmt.Errorf("route %q: pinned resource_id %q conflicts with cached resource_id %q", id, route.ResourceID, cachedResourceID)
		}
		resourceID := route.ResourceID
		if resourceID == "" {
			resourceID = cachedResourceID
		}
		if resourceID == "" {
			continue
		}
		if err := validateCachedConnectorResourceID(resourceID); err != nil {
			return nil, fmt.Errorf("route %q: invalid resource_id: %w", id, err)
		}
		if owner, duplicate := resourceOwners[resourceID]; duplicate {
			return nil, fmt.Errorf("routes %q and %q resolve to duplicate resource_id %q", owner, id, resourceID)
		}
		resourceOwners[resourceID] = id
	}
	return configuredIDs, nil
}

func resolveConnectorIdentitiesLocked(
	ctx context.Context,
	cfg *nhpconfig.Config,
	binding *qurl.AgentRuntimeBinding,
	udpOpts []qurl.AgentRuntimeUDPOption,
	txn *connectorIdentityCacheTxn,
	continuity connectorStateContinuity,
	resolve connectorResourceResolveFunc,
) error {
	if binding == nil {
		return errors.New("registered agent runtime binding is nil")
	}
	if resolve == nil {
		return errors.New("native Connector resource resolver is nil")
	}
	if err := nhpconfig.ValidateManagedRouteIdentities(cfg.Routes); err != nil {
		return fmt.Errorf("configured Connector identity graph is invalid: %w", err)
	}
	fallbackID := routeIDEnvFallback()
	seen := make(map[string]int, len(cfg.Routes))
	cache, err := loadConnectorIdentityCacheUnlocked(txn)
	if err != nil {
		return err
	}
	type identityResolution struct {
		index              int
		id                 string
		expectedResourceID string
	}
	resolutions := make([]identityResolution, 0, len(cfg.Routes))
	requestedResources := make(map[string]string, len(cfg.Routes))
	configuredIDs := make(map[string]struct{}, len(cfg.Routes))
	for i := range cfg.Routes {
		route := &cfg.Routes[i]
		id := routeIDWithFallback(cfg, *route, fallbackID)
		if strings.TrimSpace(route.ID) == "" && id != "" {
			route.ID = id
		}
		if id == "" && route.ResourceID == "" {
			return fmt.Errorf("routes[%d] needs id or %s", i, envConnectorID)
		}
		if err := nhpconfig.ValidateSlug(id); err != nil {
			return fmt.Errorf("routes[%d] (%s): invalid Connector id: %w", i, id, err)
		}
		if previous, duplicate := seen[id]; duplicate {
			return fmt.Errorf("routes[%d] and routes[%d] use duplicate Connector id %q", previous, i, id)
		}
		seen[id] = i
		configuredIDs[id] = struct{}{}

		cachedResourceID, cached := cache.resourceID(id)
		if route.ResourceID != "" && cached && cachedResourceID != route.ResourceID {
			return fmt.Errorf("route %q: pinned resource_id %q conflicts with cached resource_id %q", id, route.ResourceID, cachedResourceID)
		}
		expectedResourceID := route.ResourceID
		if expectedResourceID == "" && cached {
			expectedResourceID = cachedResourceID
		}
		if expectedResourceID != "" {
			if err := validateCachedConnectorResourceID(expectedResourceID); err != nil {
				return fmt.Errorf("route %q: invalid resource_id: %w", id, err)
			}
			if owner, duplicate := requestedResources[expectedResourceID]; duplicate {
				return fmt.Errorf("routes %q and %q assert duplicate resource_id %q before NHP resource discovery", owner, id, expectedResourceID)
			}
			requestedResources[expectedResourceID] = id
		}
		if pending, ok := cache.pendingRequest(id); ok {
			pendingExpected := ""
			if pending.ExpectedResourceID != nil {
				pendingExpected = *pending.ExpectedResourceID
			}
			if pendingExpected != expectedResourceID {
				return fmt.Errorf("route %q: durable NHP request asserts resource_id %q, but current continuity state requires %q", id, pendingExpected, expectedResourceID)
			}
		}
		resolutions = append(resolutions, identityResolution{index: i, id: id, expectedResourceID: expectedResourceID})
	}
	if err := cache.rejectOrphanIdentities(configuredIDs); err != nil {
		return err
	}

	for _, resolution := range resolutions {
		route := &cfg.Routes[resolution.index]
		configuredRoutingID := route.ConnectorRoutingID
		request, err := gateConnectorStateResult(continuity, "persist exact Connector resource LST request", func() (*qurl.NativeConnectorResourceRequest, error) {
			return cache.ensurePendingRequestLocked(txn, resolution.id, resolution.expectedResourceID)
		})
		if err != nil {
			return fmt.Errorf("route %q: persist exact NHP request before dispatch: %w", resolution.id, err)
		}
		result, resolveErr := gateConnectorStateResult(continuity, "resolve Connector resource over assigned-cell NHP", func() (*qurl.ConnectorResourceResolution, error) {
			return resolve(ctx, binding, request, udpOpts...)
		})
		terminal := authoritativeConnectorResourceRejection(resolveErr)
		if resolveErr != nil {
			if terminal {
				if clearErr := gateConnectorStateContinuity(continuity, "clear terminal Connector resource LST request", func() error {
					return cache.clearPendingLocked(txn, resolution.id)
				}); clearErr != nil {
					return errors.Join(
						fmt.Errorf("route %q: %w", resolution.id, resolveErr),
						fmt.Errorf("clear terminal NHP request: %w", clearErr),
					)
				}
			}
			state := "preserved for exact replay"
			if terminal {
				state = "cleared after authenticated terminal rejection"
			}
			return fmt.Errorf("route %q: native Connector resource discovery failed; exact request is %s: %w", resolution.id, state, resolveErr)
		}
		if result == nil || result.Resource == nil {
			return fmt.Errorf("route %q: assigned cell returned no Connector resource; exact pending request is preserved", resolution.id)
		}
		resource := result.Resource
		if resolution.expectedResourceID != "" && resource.ResourceID != resolution.expectedResourceID {
			return fmt.Errorf("route %q: assigned cell returned resource_id %q for continuity assertion %q", resolution.id, resource.ResourceID, resolution.expectedResourceID)
		}
		if resource.Slug != resolution.id {
			return fmt.Errorf("route %q: assigned cell returned mismatched Connector id %q", resolution.id, resource.Slug)
		}
		if err := gateConnectorStateContinuity(continuity, "persist complete Connector resource binding", func() error {
			return cache.recordResolutionLocked(txn, resolution.id, resource)
		}); err != nil {
			return fmt.Errorf("route %q: persist authenticated Connector binding before startup: %w", resolution.id, err)
		}
		// Persist first: a cold NHP request may have created this resource, so a
		// conflicting hand-written routing pin must not make its exact identity
		// disappear from local cleanup state. Then fail closed instead of silently
		// overwriting an operator assertion with the producer value.
		if configuredRoutingID != "" && configuredRoutingID != resource.ConnectorRoutingID {
			return fmt.Errorf("route %q: configured connector_routing_id %q conflicts with authenticated producer value %q; exact resource binding is retained for explicit cleanup", resolution.id, configuredRoutingID, resource.ConnectorRoutingID)
		}
		if existingResourceID, existingKnockResourceID, conflict := cfg.FirstDifferentKnockResourceID(resource.ResourceID, resource.KnockResourceID); conflict {
			overrideNote := ""
			if strings.TrimSpace(os.Getenv(EnvKnockResourceID)) != "" {
				overrideNote = fmt.Sprintf("; %s overrides only the runtime knock operand and does not merge qURL service-assigned admission targets", EnvKnockResourceID)
			}
			return fmt.Errorf("route %q: assigned cell returned knock_resource_id %q, but resource %q on this Connector session uses %q; one FRP control session cannot span NHP admission targets%s", resolution.id, resource.KnockResourceID, existingResourceID, existingKnockResourceID, overrideNote)
		}
		route.ResourceID = resource.ResourceID
		route.ConnectorRoutingID = resource.ConnectorRoutingID
		cfg.SetKnockResourceID(resource.ResourceID, resource.KnockResourceID)
	}
	if err := nhpconfig.ValidateManagedRouteIdentities(cfg.Routes); err != nil {
		return fmt.Errorf("assigned cell returned an invalid Connector identity graph: %w", err)
	}
	return nil
}

func authoritativeConnectorResourceRejection(err error) bool {
	return errors.Is(err, qurl.ErrConnectorResourceIdentityRejected) ||
		errors.Is(err, qurl.ErrConnectorResourceEntitlementDenied) ||
		errors.Is(err, qurl.ErrConnectorResourceIdentityConflict) ||
		errors.Is(err, qurl.ErrConnectorResourceQuotaExceeded) ||
		errors.Is(err, qurl.ErrConnectorResourceRequestRejected)
}

func startFRPFromConfig(ctx context.Context, cfgPath, machineID string, cfg *nhpconfig.Config, agentID string, admitter *share.NativeAdmitter) error {
	if err := swapAuditLoggerFromYAML(cfg, machineID, agentID); err != nil {
		slog.WarnContext(ctx, "audit: YAML-driven audit logger swap failed; keeping early-init logger", "err", err.Error())
	}
	resolveReplicaDiscriminator(ctx, cfg)
	common, proxyCfgs, visitorCfgs, err := nhpconfig.GenerateFRPClientConfig(cfg, machineID)
	if err != nil {
		return fmt.Errorf("generating Connector config: %w", err)
	}
	// FRP's HTTP admin API is opt-in. When disabled, leave
	// common.WebServer at its zero value so FRP skips the listener entirely.
	// Operators can opt in through YAML or QURL_ADMIN_ENABLED=true.
	//
	// FRP binds this listener inside frpclient.NewService, at construction,
	// from a clone of common.WebServer -- one listener per FRP control
	// session. startSharedService serves every route on ONE session, which
	// is what makes this one admin listener per process: a session per
	// route had the second route's NewService fail with address-in-use and
	// retry forever. The make-before-break overlap at rotation, where the
	// replacement session is constructed while the old one still holds the
	// port, predates multi-route serving and is unchanged here.
	if cfg.Server.EgressLocalIP != "" {
		common.Transport.ConnectServerLocalIP = cfg.Server.EgressLocalIP
	}
	if cfg.Admin.Enabled {
		password, err := adminAuthPassword(&cfg.Admin)
		if err != nil {
			return fmt.Errorf("admin auth: %w", err)
		}
		common.WebServer.Addr, common.WebServer.Port = cfg.Admin.Addr, cfg.Admin.Port
		common.WebServer.User, common.WebServer.Password = "admin", password
		slog.WarnContext(ctx, "admin API enabled: FRP binds its listener per control session, so each admission rotation replaces the session cold instead of make-before-break; expect a brief serving gap per admission window",
			"addr", cfg.Admin.Addr, "port", cfg.Admin.Port)
	}
	applyLogPresentation(common, logLevel, colorEnabled)
	if err := common.Complete(); err != nil {
		return fmt.Errorf("completing config: %w", err)
	}
	if common.Transport.ProxyURL != "" {
		return errors.New("FRP http_proxy/proxyURL is incompatible with native UDP admission because the proxy would change the Connector session source address; unset it or use an explicitly supported shared-egress topology")
	}
	for _, proxy := range proxyCfgs {
		proxy.Complete()
	}
	warning, err := validation.ValidateAllClientConfig(common, proxyCfgs, visitorCfgs, &security.UnsafeFeatures{})
	if warning != nil {
		fmt.Printf("  %sWarning: %v%s\n", colorYellow, warning, colorReset)
	}
	if err != nil {
		return fmt.Errorf("config validation: %w", err)
	}
	fmt.Printf("  %s%d route(s) configured%s\n", colorGreen, len(cfg.Routes), colorReset)
	if admitter == nil {
		return errors.New("Connector lifecycle implementation is unavailable")
	}
	return startSharedService(ctx, common, cfgPath, cfg, admitter)
}

// sharedServiceAdmitter is the admitter surface the shared runtime needs:
// resource-bound admissions plus the post-serving assignment-refresh reset.
// *share.NativeAdmitter is the production implementation; tests supply a fake.
type sharedServiceAdmitter interface {
	share.Admitter
	MarkServingHealthy() error
}

// startSharedService serves every configured route on one NHP admission and
// one FRP control session.
//
// One session per route was the previous shape: a share.ResourceRunner per
// route under an errgroup. That had three defects, all removed here by
// construction rather than patched:
//
//   - Sibling teardown. A route whose resource was revoked server-side
//     returned ErrResourceGone from its runner, the errgroup canceled every
//     healthy sibling, and the process exited 1 with the revoked route still
//     in the config -- so the supervisor crashlooped and the good shares went
//     down with the bad one. The session group retires a gone route in place
//     (OnRouteFailed) and keeps serving the rest; Run returns only when ctx
//     ends, when no route is left (share.ErrGroupEmpty), or when the group's
//     own admission is terminally refused.
//   - The ready block lied. It latched on the first route's OnServing and
//     printed every configured route as live. It is now driven per route by
//     OnRouteServing and waits for every route still configured (see
//     readyAnnouncer).
//   - Admin port collision. With admin.enabled, every per-route
//     frpclient.NewService cloned common.WebServer and bound the admin
//     listener at construction, so the second route's session failed with
//     address-in-use and retried forever. One session is one listener; see
//     the admin wiring in startFRPFromConfig.
//
// It is also the affordable shape. A session per route costs a knock, a
// Login, a NewProxy authorization and a registration heartbeat stream each,
// on every rotation; one session costs one knock and one Login for the whole
// set, and only the per-proxy NewProxy authorizations scale with the route
// count. A restart with N routes is one knock and one Login.
func startSharedService(ctx context.Context, common *v1.ClientCommonConfig, cfgPath string, qcfg *nhpconfig.Config, admitter sharedServiceAdmitter) error {
	sessions, err := newSharedServiceSessions(common, cfgPath)
	if err != nil {
		return err
	}
	announcer := newReadyAnnouncer(readyRoutes(qcfg), os.Stdout, stdoutIsTerminal())
	return runSharedService(ctx, qcfg, admitter, sessions, announcer)
}

// newSharedServiceSessions builds the FRP session factory for the group. It
// carries the same common config, client version and config path the
// per-route factories did; the routes themselves belong to the group runner.
func newSharedServiceSessions(common *v1.ClientCommonConfig, cfgPath string) (*share.FRPSessionGroupFactory, error) {
	return share.NewFRPSessionGroupFactory(share.FRPGroupFactoryConfig{
		Common: common, ClientVersion: clientVersionMeta(version.Version), ConfigPath: cfgPath,
	})
}

// runSharedService runs the group until a terminal condition.
//
// A revocation can reach the process through the admission as well as
// through a NewProxy: the admitted resource is the primary route's, the SDK
// authenticates it on every knock separately from the shared knock resource,
// and a Login the tunnel server rejects as resource-gone ends the session
// with the same error. Either way the group returns ErrResourceGone; the
// primary route is then retired in place and the rest re-admitted under the
// next route, so the healthy siblings survive. Routes already retired per
// proxy stay retired across that re-admission. If the refusal is really
// about the knock resource every route shares, each successive admission is
// refused too; the cost is one knock per remaining route before the process
// exits with the same error, never a stuck loop.
func runSharedService(ctx context.Context, qcfg *nhpconfig.Config, admitter sharedServiceAdmitter, sessions share.SessionGroupFactory, announcer *readyAnnouncer) error {
	if qcfg == nil {
		return errors.New("shared Connector runtime requires at least one resource")
	}
	defer announcer.stop()
	remaining := *qcfg
	remaining.Routes = append([]nhpconfig.Route(nil), qcfg.Routes...)
	for {
		runner, err := newSharedServiceRunner(ctx, &remaining, admitter, sessions, announcer)
		if err != nil {
			return err
		}
		announcer.setLiveProbe(func() []string {
			var serving []string
			for routeID, state := range runner.RouteStates() {
				if state.Phase == share.RouteServing {
					serving = append(serving, routeID)
				}
			}
			return serving
		})
		err = runner.Run(ctx)
		if errors.Is(err, share.ErrGroupEmpty) {
			return allRoutesRetiredError(err)
		}
		if !errors.Is(err, share.ErrResourceGone) || ctx.Err() != nil {
			return err
		}
		primary, rest := splitPrimaryRoute(&remaining)
		if primary == nil {
			return err
		}
		retireSharedRoute(ctx, announcer, primary.ID, primary.ResourceID, "admission_resource_gone", err)
		rest = withoutRoutes(rest, announcer.retiredRoutes())
		if len(rest) == 0 {
			return allRoutesRetiredError(err)
		}
		remaining.Routes = rest
	}
}

// withoutRoutes drops the routes with the given IDs, preserving order.
func withoutRoutes(routes []nhpconfig.Route, ids []string) []nhpconfig.Route {
	drop := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		drop[id] = struct{}{}
	}
	kept := make([]nhpconfig.Route, 0, len(routes))
	for _, route := range routes {
		if _, gone := drop[route.ID]; !gone {
			kept = append(kept, route)
		}
	}
	return kept
}

func allRoutesRetiredError(err error) error {
	return fmt.Errorf("%w: every configured route was retired as permanently unavailable; remove them with 'qurl-connector remove' before restarting", err)
}

// splitPrimaryRoute separates the route whose resource the group admits from
// the rest, or returns nil when no route carries a routing identity.
func splitPrimaryRoute(qcfg *nhpconfig.Config) (*nhpconfig.Route, []nhpconfig.Route) {
	primaryResourceID := qcfg.PrimaryResourceID()
	if primaryResourceID == "" {
		return nil, nil
	}
	for i := range qcfg.Routes {
		if qcfg.Routes[i].ResourceID != primaryResourceID {
			continue
		}
		primary := qcfg.Routes[i]
		rest := make([]nhpconfig.Route, 0, len(qcfg.Routes)-1)
		rest = append(rest, qcfg.Routes[:i]...)
		rest = append(rest, qcfg.Routes[i+1:]...)
		return &primary, rest
	}
	return nil, nil
}

// retireSharedRoute is the one place a route leaves the running set: it is
// logged, put on the audit stream, and dropped from the ready block. The
// process keeps serving; the route stays in the config until the operator
// removes it. reason is the audit tag: resource_not_found when the tunnel
// server refused the route's NewProxy, admission_resource_gone when the
// knock for its admission was refused.
func retireSharedRoute(ctx context.Context, announcer *readyAnnouncer, routeID, resourceID, reason string, err error) {
	slog.WarnContext(ctx, "connector: route retired; its resource is permanently unavailable and the other routes keep serving",
		"route", routeID, "resource_id", resourceID, "reason", reason, "err", err.Error())
	audit.Default().Log(audit.Entry{
		Event: audit.EventProxyDeny, Outcome: audit.OutcomeDeny, Reason: reason,
		RouteID: routeID, ResourceID: resourceID, Error: err.Error(),
	})
	announcer.routeRetired(routeID)
}

// newSharedServiceRunner builds the one session group for qcfg's routes.
//
// Every managed route on a Connector is admitted through the same NHP knock
// resource: resolveConnectorIdentitiesLocked refuses a route whose assigned
// knock resource differs from its siblings' (FirstDifferentKnockResourceID)
// before the runtime starts, because one FRP control session cannot span
// admission targets. The group therefore knocks once, for the primary
// resource, exactly as the single-route runtime did. The check below is the
// runtime's own guard on that invariant, so a config that reached this point
// by another path fails clearly instead of registering proxies under an
// admission that does not cover them.
//
// The admitted resource is the primary route's (the first route carrying a
// connector routing ID), so removing that route re-points the admission at
// the next one on the following start. That is benign: the admitter's
// per-resource state is the pending-operation journal and an in-memory
// placement backoff, an absent journal is an empty one, and startup recovery
// scans every resource's journal regardless of which one is admitted next.
//
// ctx scopes only the callbacks' log context; Run(ctx) is what scopes the
// runner's lifetime.
func newSharedServiceRunner(ctx context.Context, qcfg *nhpconfig.Config, admitter sharedServiceAdmitter, sessions share.SessionGroupFactory, announcer *readyAnnouncer) (*share.SessionGroupRunner, error) {
	if qcfg == nil || len(qcfg.Routes) == 0 {
		return nil, errors.New("shared Connector runtime requires at least one resource")
	}
	resourceID := qcfg.PrimaryResourceID()
	if resourceID == "" {
		return nil, errors.New("shared Connector runtime has no resolved primary resource")
	}
	knockResourceID := knockResourceIDOrEmpty(qcfg, resourceID)
	if knockResourceID == "" {
		return nil, fmt.Errorf("missing NHP knock resource for qURL Connector %q", resourceID)
	}
	routes := make([]share.LocalHTTPRoute, 0, len(qcfg.Routes))
	resourceIDs := make(map[string]string, len(qcfg.Routes))
	for _, route := range qcfg.Routes {
		// An empty knock resource is a route that was never hydrated, which is
		// a different problem from two routes on different admission targets.
		switch routeKnock := knockResourceIDOrEmpty(qcfg, route.ResourceID); {
		case routeKnock == "":
			return nil, fmt.Errorf("route %q: missing NHP knock resource for qURL Connector %q", route.ID, route.ResourceID)
		case routeKnock != knockResourceID:
			return nil, fmt.Errorf("route %q: NHP knock resource %q differs from the Connector session's %q (resource %q); one FRP control session cannot span NHP admission targets", route.ID, routeKnock, knockResourceID, resourceID)
		}
		routes = append(routes, share.LocalHTTPRoute{
			RouteID: route.ID, LocalIP: route.LocalIP, LocalPort: route.LocalPort,
			ResourceID: route.ResourceID, ConnectorRoutingID: route.ConnectorRoutingID,
		})
		resourceIDs[route.ID] = route.ResourceID
	}
	return share.NewSessionGroupRunner(share.SessionGroupConfig{
		KnockResourceID: knockResourceID, ResourceID: resourceID, Routes: routes,
		Admitter: admitter, Sessions: sessions,
		OnServing: func(share.Admission) {
			if err := admitter.MarkServingHealthy(); err != nil {
				slog.WarnContext(ctx, "connector: failed to clear assignment-refresh state after serving", "err", err.Error())
			}
			announcer.sessionPromoted(readyFallbackWait)
		},
		OnRouteServing: func(routeID string, _ share.Admission) {
			announcer.routeServing(routeID)
		},
		OnRouteFailed: func(routeID string, err error) {
			if !errors.Is(err, share.ErrResourceGone) {
				// ErrRouteNotServing: the route stays in the group and FRP's
				// same-session retry keeps registering it.
				slog.WarnContext(ctx, "connector: route did not come up on the replacement session; it stays configured and keeps retrying",
					"route", routeID, "err", err.Error())
				return
			}
			// Retired in place: the tunnel server permanently refused this
			// route's proxy, so the group withdrew it and its siblings keep
			// serving.
			retireSharedRoute(ctx, announcer, routeID, resourceIDs[routeID], "resource_not_found", err)
		},
		OnRetry: func(err error, wait time.Duration) {
			slog.WarnContext(ctx, "connector: NHP admission or FRP session attempt failed; retrying",
				"wait", wait.String(), "err", err.Error())
		},
		OnRotationLeadCapped: func(routes int, need, lead time.Duration) {
			slog.WarnContext(ctx, "connector: admission window is short for this route count; a rotation may promote before every route re-registers",
				"routes", routes, "lead_needed", need.String(), "lead", lead.String())
		},
	})
}

// readyRoutes lists the configured routes for the ready block: what the
// customer calls each route and where it points locally.
func readyRoutes(qcfg *nhpconfig.Config) []readyRoute {
	if qcfg == nil {
		return nil
	}
	routes := make([]readyRoute, 0, len(qcfg.Routes))
	for _, route := range qcfg.Routes {
		routes = append(routes, readyRoute{
			routeID: route.ID,
			target:  net.JoinHostPort(route.LocalIP, strconv.Itoa(route.LocalPort)),
		})
	}
	return routes
}

// applyLogPresentation stamps the FRP client's log settings from this process's
// own output decisions.
//
// Color is the load-bearing half. FRP colorizes its console stream on a switch
// of its own, so gating only our prints would leave a journal half-escaped —
// our lines clean and every `start proxy success` still wrapped in \x1b[.
// Passing the resolved colorEnabled keeps the two streams agreeing about where
// stdout is going.
//
// Nothing is being overridden here: the generated FRP config never set
// DisablePrintColor, so its value was FRP's interactive-by-default rather than
// an operator decision, and there is no YAML or env knob that expresses one.
func applyLogPresentation(common *v1.ClientCommonConfig, level string, useColor bool) {
	common.Log.Level = level
	common.Log.DisablePrintColor = !useColor
}

func clientVersionMeta(clientVersion string) string {
	trimmed := strings.TrimSpace(clientVersion)
	if match := makefileTimestampVersionRe.FindStringSubmatch(trimmed); match != nil {
		return match[1] + match[2]
	}
	if trimmed == "" {
		return "dev"
	}
	return trimmed
}

func printBanner() {
	const banner = `
   ___  _   _ ____  _
  / _ \| | | |  _ \| |
 | | | | | | | |_) | |
 | |_| | |_| |  _ <| |___
  \__\_\\___/|_| \_\_____|  Connector
`
	fmt.Printf("%s%s%s%s", colorBold, colorCyan, banner, colorReset)
	fmt.Printf("  %s%s (client)%s\n\n", colorGreen, version.Short(), colorReset)
}

func adminAuthPassword(cfg *nhpconfig.AdminConfig) (string, error) {
	if cfg != nil && strings.TrimSpace(cfg.Password) != "" {
		return cfg.Password, nil
	}
	machineID := getMachineID()
	if machineID == "" || machineID == unknownMachineID {
		return "", errors.New("machine ID is unavailable; set admin.password or disable admin.enabled")
	}
	return machineID, nil
}

func getMachineID() string {
	machineIDOnce.Do(func() {
		id, err := machineid.ProtectedID("qurl-frp")
		if err != nil || len(id) < 8 {
			cachedMachineID = unknownMachineID
			return
		}
		cachedMachineID = id[:8]
	})
	return cachedMachineID
}

func resolveReplicaDiscriminator(ctx context.Context, cfg *nhpconfig.Config) {
	resolveReplicaDiscriminatorWithResolver(ctx, cfg, nil)
}

// logDiscriminatorResolved emits the "replica discriminator resolved" line,
// including the pre-normalization raw value only when it differs from the
// resolved discriminator.
func logDiscriminatorResolved(ctx context.Context, source, discriminator, raw string) {
	logArgs := []any{
		"source", source,
		"discriminator", discriminator,
	}
	if raw != "" && raw != discriminator {
		logArgs = append(logArgs, "raw", raw)
	}
	slog.InfoContext(ctx, "replica discriminator resolved", logArgs...)
}

func resolveReplicaDiscriminatorWithResolver(ctx context.Context, cfg *nhpconfig.Config, resolver *replica.Resolver) {
	if raw := strings.TrimSpace(cfg.Server.ReplicaDiscriminator); raw != "" {
		normalized := replica.Normalize(raw)
		if normalized == "" {
			slog.WarnContext(ctx, "server.replica_discriminator dropped after normalization; falling through to resolver chain",
				"raw", raw)
			cfg.Server.ReplicaDiscriminator = ""
		} else {
			cfg.Server.ReplicaDiscriminator = normalized
			logDiscriminatorResolved(ctx, string(replica.SourceExplicit), normalized, raw)
			return
		}
	}
	r := resolver
	if r == nil {
		r = &replica.Resolver{}
	}
	disc, meta, err := r.Resolve(ctx)
	if err != nil {
		// Preserve the current safe single-replica behavior if a future resolver
		// mode introduces a hard error: continue without a salt, but say so.
		slog.WarnContext(ctx, "replica discriminator resolver returned error; continuing without salt",
			"err", err.Error())
		return
	}
	cfg.Server.ReplicaDiscriminator = disc
	logDiscriminatorResolved(ctx, string(meta.Source), disc, meta.Raw)
	if meta.Warning != "" {
		slog.WarnContext(ctx, "replica discriminator warning",
			"warning", meta.Warning,
			"source", string(meta.Source),
		)
	}
	for _, warning := range r.Warnings() {
		slog.WarnContext(ctx, "replica discriminator warning",
			"warning", warning)
	}
	if softErrs := r.Errors(); softErrs != nil {
		slog.DebugContext(ctx, "replica discriminator soft errors",
			"errs", softErrs.Error())
	}
}
