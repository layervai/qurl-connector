package share

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	qurl "github.com/layervai/qurl-go/qurl"
	"github.com/layervai/qurl-go/relayknock/nativeudp"

	"github.com/layervai/qurl-connector/pkg/agentstate"
)

type NativeRuntimeConfig struct {
	StateDir                     string
	AgentID                      string
	Hub                          qurl.HubBootstrap
	Hostname                     string
	Version                      string
	ClientBaseURL                string
	EnrollmentCredential         string
	EnrollmentCredentialProvider qurl.AgentEnrollmentCredentialProvider
	// RecoveryCredentialProvider is invoked after the pinned Hub authenticates
	// the persisted agent and rejects its device credential, or when the same
	// state contains a valid pending credential-recovery episode. It must return
	// a live qurl:agent account credential. The provider and its result are never
	// retained after OpenNativeRuntime returns.
	RecoveryCredentialProvider func(context.Context) (string, error)
	RefreshMode                string
	UDPOptions                 []qurl.AgentRuntimeUDPOption
	SessionOperations          NativeSessionOperationAuthority
}

// nativeRefreshConfig is the credential-free subset retained after opening
// the persisted agent. Enrollment credentials are only registration inputs;
// assignment refresh authenticates with the sealed agent state.
type nativeRefreshConfig struct {
	StateDir          string
	AgentID           string
	Hub               qurl.HubBootstrap
	ClientBaseURL     string
	RefreshMode       string
	UDPOptions        []qurl.AgentRuntimeUDPOption
	SessionOperations NativeSessionOperationAuthority
}

// NativeRuntime is one opened, persisted qurl-go agent runtime. Callers may use
// Client and Binding for native resource discovery before transferring the
// runtime into NewNativeAdmitter.
type NativeRuntime struct {
	Client            *qurl.Client
	Binding           *qurl.AgentRuntimeBinding
	AgentID           string
	Hub               qurl.HubBootstrap
	UDPOptions        []qurl.AgentRuntimeUDPOption
	OpenKind          NativeOpenKind
	SessionOperations NativeSessionOperationAuthority

	store      nativeStateStore
	refreshCfg nativeRefreshConfig

	credentialRecoveryMu                 sync.Mutex
	deviceAuthorizationRecoveryAttempted bool
}

type NativeOpenKind string

const (
	NativeOpenWarm         NativeOpenKind = "warm"
	NativeOpenRegistration NativeOpenKind = "registration"
	NativeOpenRefresh      NativeOpenKind = "refresh"
	NativeOpenRecovery     NativeOpenKind = "recovery"
)

type nativeStateStore interface {
	Handoff() (qurl.AgentStateStore, error)
	ValidateContinuity() error
	LoadRegistrationRefreshMarker() (agentstate.RefreshMarker, bool, error)
	RequestRegistrationRefresh(string) error
	MarkRegistrationRefreshAttempted() error
	MarkRegistrationRefreshSucceeded() error
	ClearRegistrationRefreshMarker() error
	ScanSessionOperationResources(context.Context) agentstate.SessionOperationResourceScan
	LoadSessionOperations(context.Context, string) ([]agentstate.SessionOperationRecord, error)
	CreateSessionOperation(context.Context, agentstate.SessionOperationRecord) error
	TransitionSessionOperation(context.Context, agentstate.SessionOperationRecord, agentstate.SessionOperationRecord) error
	DeleteSessionOperation(context.Context, agentstate.SessionOperationRecord) error
	Close() error
}

var (
	newNativeStateStore = func(dir, agentID string) (nativeStateStore, error) {
		return agentstate.NewSDKStore(dir, agentID)
	}
	connectNativeRuntime = qurl.ConnectAgentRuntime
	refreshNativeRuntime = qurl.RefreshAgentRuntime
	recoverNativeRuntime = qurl.RecoverAgentRuntimeWithCredentialProvider
	waitNativeRefresh    = sleepWithContext
	knockNativeRuntime   = qurl.KnockRegisteredAgent
	retireNativeSession  = qurl.RetireRegisteredAgentSession
	takeNativeKey        = func(binding *qurl.AgentRuntimeBinding) []byte { return binding.TakeDeviceStaticPrivateKey() }
)

var errNativeRefreshBackoffPending = errors.New("native assignment refresh backoff is pending")

// errNativeDeviceAuthorizationRecoveryNotAllowed reports that a caller tried
// to spend account recovery authority outside the one narrow explicit-login
// repair. The repair is available only after a warm runtime receives the exact
// registered-device invalid-api-key response, and only once per runtime.
var errNativeDeviceAuthorizationRecoveryNotAllowed = errors.New("native device authorization recovery is not allowed")

const (
	nativeRefreshReasonImmediate = "stale or expired native assignment placement"
	nativeRefreshReasonSustained = "sustained native NHP knock failures"
)

func OpenNativeRuntime(ctx context.Context, cfg NativeRuntimeConfig) (_ *NativeRuntime, retErr error) {
	if ctx == nil {
		return nil, errors.New("open native runtime: context is nil")
	}
	if strings.TrimSpace(cfg.StateDir) == "" {
		return nil, errors.New("open native runtime: state directory is empty")
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.RefreshMode))
	if mode == "" {
		mode = "auto"
	}
	if mode != "auto" && mode != "disabled" {
		return nil, fmt.Errorf("open native runtime: refresh mode %q must be auto or disabled", mode)
	}
	store, err := newNativeStateStore(cfg.StateDir, strings.TrimSpace(cfg.AgentID))
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, store.Close())
		}
	}()

	marker, present, err := store.LoadRegistrationRefreshMarker()
	if err != nil {
		if !errors.Is(err, agentstate.ErrInvalidRefreshMarker) {
			return nil, fmt.Errorf("load assignment refresh state: %w", err)
		}
		slog.WarnContext(ctx, "discarding corrupt non-secret assignment refresh state", "err", err)
		if clearErr := store.ClearRegistrationRefreshMarker(); clearErr != nil {
			return nil, errors.Join(
				fmt.Errorf("load assignment refresh state: %w", err),
				fmt.Errorf("clear corrupt assignment refresh state: %w", clearErr),
			)
		}
		marker = agentstate.RefreshMarker{}
		present = false
	}
	if present && marker.RefreshSucceededUnixMilli > 0 {
		runtime, openErr := warmOpenNativeRuntime(ctx, cfg, store, mode)
		if openErr == nil {
			return runtime, nil
		}
		if mayConsumeNativeRecoveryAuthority(openErr) {
			return recoverNativeCredential(ctx, cfg, store, openErr, mode)
		}
		// Offline open and Hub refresh share the same local transient-error
		// sentinels. Reuse the closed refresh classifier so new or corrupt local
		// state still fails closed instead of widening unattended retries. Offline
		// open is network-free and cannot return an authenticated identity reject;
		// missing state stays permanent so a surviving marker cannot mint a new
		// immutable identity.
		if !errors.Is(openErr, qurl.ErrAssignmentLeaseExpired) && permanentRefreshError(openErr) {
			return nil, openErr
		}
	}
	if present {
		runtime, refreshErr := refreshUntilOpen(ctx, refreshConfig(cfg, mode), store, marker, mode)
		if refreshErr == nil {
			return runtime, nil
		}
		return recoverNativeCredential(ctx, cfg, store, refreshErr, mode)
	}

	runtime, openErr := warmOpenNativeRuntime(ctx, cfg, store, mode)
	if openErr == nil {
		return runtime, nil
	}
	if errors.Is(openErr, qurl.ErrAssignmentLeaseExpired) {
		if err := store.RequestRegistrationRefresh("assigned NHP cell lease expired"); err != nil {
			return nil, fmt.Errorf("record assignment refresh request: %w", err)
		}
		marker, present, err = store.LoadRegistrationRefreshMarker()
		if err != nil || !present {
			return nil, errors.Join(errors.New("assignment refresh state missing after lease expiry"), err)
		}
		runtime, refreshErr := refreshUntilOpen(ctx, refreshConfig(cfg, mode), store, marker, mode)
		if refreshErr == nil {
			return runtime, nil
		}
		return recoverNativeCredential(ctx, cfg, store, refreshErr, mode)
	}
	if mayConsumeNativeRecoveryAuthority(openErr) {
		return recoverNativeCredential(ctx, cfg, store, openErr, mode)
	}
	if !errors.Is(openErr, qurl.ErrAgentStateNotFound) {
		return nil, openErr
	}

	registerOptions := []qurl.AgentRuntimeRegistrationOption{
		qurl.WithAgentRuntimeHub(cfg.Hub),
		qurl.WithAgentRuntimeMetadata(normalizeNativeHostname(cfg.Hostname), cfg.Version),
		qurl.WithAgentRuntimeHeadlessEnrollment(),
	}
	if cfg.AgentID != "" {
		registerOptions = append(registerOptions, qurl.WithAgentRuntimeIdentity(strings.TrimSpace(cfg.AgentID)))
	}
	if cfg.ClientBaseURL != "" {
		registerOptions = append(registerOptions, qurl.WithAgentClientBaseURL(cfg.ClientBaseURL))
	}
	switch {
	case cfg.EnrollmentCredentialProvider != nil:
		registerOptions = append(registerOptions, qurl.WithAgentRuntimeEnrollmentCredentialProvider(cfg.EnrollmentCredentialProvider))
	case cfg.EnrollmentCredential != "":
		registerOptions = append(registerOptions, qurl.WithAgentRuntimeEnrollmentCredential(cfg.EnrollmentCredential))
	default:
		return nil, errors.New("open native runtime: enrollment credential is required for first registration")
	}
	for _, option := range cfg.UDPOptions {
		registerOptions = append(registerOptions, option)
	}
	state, err := store.Handoff()
	if err != nil {
		return nil, err
	}
	client, binding, err := connectNativeRuntime(ctx, state, registerOptions...)
	if err != nil {
		return nil, err
	}
	return assembleNativeRuntime(client, binding, store, refreshConfig(cfg, mode), NativeOpenRegistration)
}

func warmOpenNativeRuntime(ctx context.Context, cfg NativeRuntimeConfig, store nativeStateStore, mode string) (*NativeRuntime, error) {
	state, err := store.Handoff()
	if err != nil {
		return nil, err
	}
	options := []qurl.AgentRuntimeRegistrationOption{qurl.WithAgentRuntimeOfflineOpen()}
	if cfg.ClientBaseURL != "" {
		options = append(options, qurl.WithAgentClientBaseURL(cfg.ClientBaseURL))
	}
	client, binding, err := connectNativeRuntime(ctx, state, options...)
	if err != nil {
		return nil, err
	}
	return assembleNativeRuntime(client, binding, store, refreshConfig(cfg, mode), NativeOpenWarm)
}

func mayConsumeNativeRecoveryAuthority(err error) bool {
	for _, unsafe := range []error{
		qurl.ErrInvalidAgentState,
		qurl.ErrAgentStateContinuity,
		qurl.ErrAgentSetupLock,
		qurl.ErrDeviceCredentialMissing,
		qurl.ErrRecoveryCredentialRejected,
		qurl.ErrCredentialRecoveryIdentityRejected,
		qurl.ErrCredentialRecoveryRevokeRequired,
		qurl.ErrCredentialRecoveryRequestRejected,
		qurl.ErrCredentialRecoveryAssignmentRequired,
		qurl.ErrCredentialRecoveryCandidateConflict,
		qurl.ErrCredentialRecoveryInvalidResponse,
		qurl.ErrCredentialRecoveryExpired,
		qurl.ErrCredentialRecoveredAssignmentRefreshRequired,
	} {
		if errors.Is(err, unsafe) {
			return false
		}
	}
	if errors.Is(err, qurl.ErrAssignmentIdentityRejected) {
		return true
	}
	// The outer typed pending error may be wrapped; only its Cause must be the
	// exact unwrapped qurl-go pending-episode sentinel. Joined top-level unsafe
	// causes are rejected above, while wrapped or joined pending causes fail
	// closed so new, malformed, and terminal upstream states cannot spend it.
	var pending *qurl.NativeCredentialRecoveryRequiredError
	return errors.As(err, &pending) && pending != nil &&
		pending.Cause == qurl.ErrCredentialRecoveryRequired //nolint:errorlint // Exact sentinel is the allowlist boundary.
}

func recoverNativeCredential(ctx context.Context, cfg NativeRuntimeConfig, store nativeStateStore, triggerErr error, mode string) (*NativeRuntime, error) {
	if !mayConsumeNativeRecoveryAuthority(triggerErr) || cfg.RecoveryCredentialProvider == nil {
		return nil, triggerErr
	}
	state, err := store.Handoff()
	if err != nil {
		return nil, fmt.Errorf("open native state for credential recovery: %w", err)
	}
	options := nativeCredentialRecoveryOptions(cfg.Hub, cfg.AgentID, cfg.ClientBaseURL, cfg.UDPOptions)
	client, binding, err := recoverNativeRuntime(ctx, validatedNativeRecoveryCredentialProvider(cfg.RecoveryCredentialProvider), state, options...)
	if err != nil {
		// Do not join triggerErr here. A valid pending episode remains durable,
		// while a Hub outage or rate limit must stay retryable for the daemon.
		return nil, fmt.Errorf("recover native credential: %w", err)
	}
	return assembleRefreshedNativeRuntime(ctx, client, binding, store, refreshConfig(cfg, mode), NativeOpenRecovery)
}

func validatedNativeRecoveryCredentialProvider(provider func(context.Context) (string, error)) qurl.AgentRuntimeRecoveryCredentialProvider {
	return func(ctx context.Context) (string, error) {
		credential, err := provider(ctx)
		if err != nil {
			return "", err
		}
		credential = strings.TrimSpace(credential)
		if credential == "" {
			return "", errors.New("native credential recovery authority is empty")
		}
		return credential, nil
	}
}

func nativeCredentialRecoveryOptions(hub qurl.HubBootstrap, agentID, clientBaseURL string, udpOptions []qurl.AgentRuntimeUDPOption) []qurl.AgentRuntimeRecoveryOption {
	options := make([]qurl.AgentRuntimeRecoveryOption, 0, len(udpOptions)+3)
	options = append(options, qurl.WithAgentRuntimeRecoveryHub(hub))
	if expected := strings.TrimSpace(agentID); expected != "" {
		options = append(options, qurl.WithExpectedAgentRuntimeRecoveryAgentID(expected))
	}
	if clientBaseURL != "" {
		options = append(options, qurl.WithAgentClientBaseURL(clientBaseURL))
	}
	for _, option := range udpOptions {
		options = append(options, option)
	}
	return options
}

func refreshConfig(cfg NativeRuntimeConfig, mode string) nativeRefreshConfig {
	return nativeRefreshConfig{
		StateDir: cfg.StateDir, AgentID: strings.TrimSpace(cfg.AgentID), Hub: cfg.Hub,
		ClientBaseURL: cfg.ClientBaseURL, RefreshMode: mode,
		UDPOptions:        append([]qurl.AgentRuntimeUDPOption(nil), cfg.UDPOptions...),
		SessionOperations: cfg.SessionOperations,
	}
}

func refreshUntilOpen(ctx context.Context, cfg nativeRefreshConfig, store nativeStateStore, marker agentstate.RefreshMarker, mode string) (*NativeRuntime, error) {
	if mode == "disabled" {
		return nil, fmt.Errorf("native assignment refresh is disabled while recovery is required: %s", marker.Reason)
	}
	for {
		if marker.NextAttemptUnixMilli > 0 {
			if wait := time.Until(time.UnixMilli(marker.NextAttemptUnixMilli)); wait > 0 {
				if err := waitNativeRefresh(ctx, wait); err != nil {
					return nil, err
				}
			}
		}
		if err := store.MarkRegistrationRefreshAttempted(); err != nil {
			return nil, fmt.Errorf("advance assignment refresh retry state: %w", err)
		}
		state, err := store.Handoff()
		if err != nil {
			return nil, err
		}
		options := make([]qurl.AgentRuntimeRefreshOption, 0, len(cfg.UDPOptions)+1)
		if cfg.ClientBaseURL != "" {
			options = append(options, qurl.WithAgentClientBaseURL(cfg.ClientBaseURL))
		}
		for _, option := range cfg.UDPOptions {
			options = append(options, option)
		}
		client, binding, refreshErr := refreshNativeRuntime(ctx, cfg.Hub, state, options...)
		if refreshErr == nil {
			return assembleRefreshedNativeRuntime(ctx, client, binding, store, cfg, NativeOpenRefresh)
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if permanentRefreshError(refreshErr) {
			return nil, refreshErr
		}
		marker, _, err = store.LoadRegistrationRefreshMarker()
		if err != nil {
			return nil, fmt.Errorf("reload assignment refresh retry state: %w", err)
		}
	}
}

func assembleRefreshedNativeRuntime(ctx context.Context, client *qurl.Client, binding *qurl.AgentRuntimeBinding, store nativeStateStore, cfg nativeRefreshConfig, kind NativeOpenKind) (*NativeRuntime, error) {
	runtime, err := assembleNativeRuntime(client, binding, store, cfg, kind)
	if err != nil {
		return nil, err
	}
	if err := store.MarkRegistrationRefreshSucceeded(); err != nil {
		// The authenticated assignment and binding are already persisted and
		// usable. This marker is a non-secret retry breadcrumb, so its write is
		// non-fatal just like RequestRegistrationRefresh. Keeping the runtime
		// avoids discarding a valid binding or closing an admitter-owned store.
		slog.WarnContext(ctx, "could not record successful assignment refresh handoff; continuing with persisted assignment", "err", err)
	}
	return runtime, nil
}

func permanentRefreshError(err error) bool {
	if err == nil {
		return false
	}
	// Refresh is unattended only for failures that can heal without changing
	// identity, policy, or durable state. qurl-go's assignment operation has
	// already exhausted its bounded inner budget when these sentinels escape;
	// the persisted outer marker supplies the longer crash-safe backoff.
	for _, sentinel := range []error{
		qurl.ErrAssignmentUnavailable,
		qurl.ErrAssignmentRecoveryRequired,
		qurl.ErrAssignmentReassignmentRequired,
		qurl.ErrAssignmentRateLimited,
		nativeudp.ErrResolve,
		nativeudp.ErrTransport,
		nativeudp.ErrNoReply,
		nativeudp.ErrServerUnauthenticated,
		qurl.ErrAgentBindingPersistence,
		qurl.ErrAgentStateKeyWrapper,
	} {
		if errors.Is(err, sentinel) {
			return false
		}
	}
	// A file-backed state store can report a transient local I/O failure while
	// qurl-go also annotates it with ErrInvalidRegisterConfig. Keep that
	// retryable, but fail closed on permission failures rather than hot-looping
	// against a namespace the daemon cannot safely access.
	var pathErr *os.PathError
	if errors.As(err, &pathErr) && !errors.Is(err, os.ErrPermission) {
		return false
	}
	// Unknown failures are terminal. Expanding the automatic loop by default
	// would turn new config, state, or authenticated producer errors into an
	// indefinite daemon wait instead of making the broken invariant visible.
	return true
}

// IsPermanentNativeOpenError reports bootstrap, credential, policy, identity,
// and corrupt-state failures that an unattended daemon must surface instead
// of retrying forever. Network/placement unavailability and rate limiting are
// deliberately absent: callers may retry those with bounded backoff.
func IsPermanentNativeOpenError(err error) bool {
	if err == nil {
		return false
	}
	var deny *qurl.ServerDenyError
	if errors.As(err, &deny) {
		return true
	}
	for _, sentinel := range []error{
		qurl.ErrInvalidClientConfig,
		qurl.ErrInvalidBootstrapConfig,
		qurl.ErrInvalidAgentState,
		qurl.ErrInsecureAgentStatePermissions,
		qurl.ErrAgentStateContinuity,
		qurl.ErrAgentSetupLock,
		qurl.ErrInvalidRegisterConfig,
		qurl.ErrRegistrationInvalidInput,
		qurl.ErrRegistrationDisabled,
		qurl.ErrKeyRejected,
		qurl.ErrRegistrationKeyKindDisallowed,
		qurl.ErrDeviceKeyQuotaExceeded,
		qurl.ErrAgentIdentityConflict,
		qurl.ErrRegisterReplyMalformed,
		qurl.ErrInvalidAssignmentConfig,
		qurl.ErrAssignmentInvalidResponse,
		qurl.ErrAssignmentIdentityRejected,
		qurl.ErrAssignmentQuotaExceeded,
		qurl.ErrAssignmentRequestRejected,
		qurl.ErrAssignmentKeyRejected,
		qurl.ErrAssignmentRegistrationDisabled,
		qurl.ErrAssignmentBootstrapConsumed,
		qurl.ErrAssignmentTicketInvalid,
		qurl.ErrAssignmentTicketExpired,
		qurl.ErrCompletionIdentityRejected,
		qurl.ErrCompletionCredentialConflict,
		qurl.ErrCompletionRequestRejected,
		qurl.ErrCredentialRecoveryRequired,
		qurl.ErrDeviceCredentialMissing,
		qurl.ErrRecoveryCredentialRejected,
		qurl.ErrCredentialRecoveryIdentityRejected,
		qurl.ErrCredentialRecoveryRevokeRequired,
		qurl.ErrCredentialRecoveryRequestRejected,
		qurl.ErrCredentialRecoveryAssignmentRequired,
		qurl.ErrCredentialRecoveryCandidateConflict,
		qurl.ErrCredentialRecoveryInvalidResponse,
		qurl.ErrCredentialRecoveryExpired,
	} {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}

func assembleNativeRuntime(client *qurl.Client, binding *qurl.AgentRuntimeBinding, store nativeStateStore, cfg nativeRefreshConfig, kind NativeOpenKind) (*NativeRuntime, error) {
	if client == nil || binding == nil {
		if binding != nil {
			binding.Destroy()
		}
		return nil, errors.New("qurl-go returned an incomplete native runtime")
	}
	if configured := strings.TrimSpace(cfg.AgentID); configured != "" && binding.AgentID != configured {
		binding.Destroy()
		return nil, fmt.Errorf("configured agent identity %q conflicts with persisted identity %q", configured, binding.AgentID)
	}
	if err := store.ValidateContinuity(); err != nil {
		binding.Destroy()
		return nil, err
	}
	return &NativeRuntime{
		Client: client, Binding: binding, AgentID: binding.AgentID, Hub: cfg.Hub, OpenKind: kind,
		store: store, UDPOptions: append([]qurl.AgentRuntimeUDPOption(nil), cfg.UDPOptions...),
		refreshCfg: cfg, SessionOperations: cfg.SessionOperations,
	}, nil
}

func normalizeNativeHostname(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return "qurl-connector"
	}
	if len(host) > 255 {
		host = host[:255]
	}
	return host
}

func (r *NativeRuntime) MarkServingHealthy() error {
	if r == nil || r.store == nil {
		return errors.New("native runtime is closed")
	}
	return r.store.ClearRegistrationRefreshMarker()
}

func (r *NativeRuntime) Handoff() (qurl.AgentStateStore, error) {
	if r == nil || r.store == nil {
		return nil, errors.New("native runtime is closed")
	}
	return r.store.Handoff()
}

func (r *NativeRuntime) ValidateContinuity() error {
	if r == nil || r.store == nil {
		return errors.New("native runtime is closed")
	}
	return r.store.ValidateContinuity()
}

func (r *NativeRuntime) LoadRegistrationRefreshMarker() (agentstate.RefreshMarker, bool, error) {
	if r == nil || r.store == nil {
		return agentstate.RefreshMarker{}, false, errors.New("native runtime is closed")
	}
	return r.store.LoadRegistrationRefreshMarker()
}

func (r *NativeRuntime) RequestRegistrationRefresh(reason string) error {
	if r == nil || r.store == nil {
		return errors.New("native runtime is closed")
	}
	return r.store.RequestRegistrationRefresh(reason)
}

func (r *NativeRuntime) MarkRegistrationRefreshAttempted() error {
	if r == nil || r.store == nil {
		return errors.New("native runtime is closed")
	}
	return r.store.MarkRegistrationRefreshAttempted()
}

func (r *NativeRuntime) ClearRegistrationRefreshMarker() error {
	return r.MarkServingHealthy()
}

// RecoverCredentialAfterDeviceAuthorizationFailure performs the one recovery
// attempt allowed after explicit login has already validated an account key,
// a credential-free warm open succeeded, and the first registered-device REST
// request returned HTTP 401 with problem code api_key_invalid. provider must
// return that same validated account key.
//
// The method rejects every other status, problem code, open kind, and repeated
// call before reading provider or touching durable state. It never retries the
// recovery operation. The caller must have exclusive ownership of r and may
// retry its registered-device request once only after this method succeeds.
func (r *NativeRuntime) RecoverCredentialAfterDeviceAuthorizationFailure(
	ctx context.Context,
	statusCode int,
	problemCode string,
	provider func(context.Context) (string, error),
) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is nil", errNativeDeviceAuthorizationRecoveryNotAllowed)
	}
	if r == nil || r.store == nil {
		return fmt.Errorf("%w: native runtime is closed", errNativeDeviceAuthorizationRecoveryNotAllowed)
	}
	if r.OpenKind != NativeOpenWarm || statusCode != http.StatusUnauthorized || problemCode != "api_key_invalid" {
		return errNativeDeviceAuthorizationRecoveryNotAllowed
	}
	if provider == nil {
		return fmt.Errorf("%w: validated account credential provider is nil", errNativeDeviceAuthorizationRecoveryNotAllowed)
	}

	r.credentialRecoveryMu.Lock()
	defer r.credentialRecoveryMu.Unlock()
	if r.deviceAuthorizationRecoveryAttempted {
		return fmt.Errorf("%w: recovery was already attempted", errNativeDeviceAuthorizationRecoveryNotAllowed)
	}
	// Consume the in-process authority before any fallible work. A failed call
	// must be resumed by a new explicit login, which reopens durable recovery
	// state through qurl-go instead of looping on the same REST rejection.
	r.deviceAuthorizationRecoveryAttempted = true

	state, err := r.store.Handoff()
	if err != nil {
		return fmt.Errorf("open native state for device authorization recovery: %w", err)
	}
	options := nativeCredentialRecoveryOptions(r.refreshCfg.Hub, r.AgentID, r.refreshCfg.ClientBaseURL, r.refreshCfg.UDPOptions)
	client, binding, err := recoverNativeRuntime(ctx, validatedNativeRecoveryCredentialProvider(provider), state, options...)
	if err != nil {
		return fmt.Errorf("recover native credential after device authorization rejection: %w", err)
	}
	replacement, err := assembleRefreshedNativeRuntime(ctx, client, binding, r.store, r.refreshCfg, NativeOpenRecovery)
	if err != nil {
		return err
	}

	oldBinding := r.Binding
	r.Client = replacement.Client
	r.Binding = replacement.Binding
	r.AgentID = replacement.AgentID
	r.Hub = replacement.Hub
	r.UDPOptions = replacement.UDPOptions
	r.OpenKind = replacement.OpenKind
	r.SessionOperations = replacement.SessionOperations
	r.refreshCfg = replacement.refreshCfg
	// r continues to own the store. The short-lived replacement is only an
	// assembly guard and must not become a second logical owner.
	replacement.store = nil
	if oldBinding != nil && oldBinding != r.Binding {
		oldBinding.Destroy()
	}
	return nil
}

func (r *NativeRuntime) Close() error {
	if r == nil {
		return nil
	}
	if r.Binding != nil {
		r.Binding.Destroy()
		r.Binding = nil
	}
	var err error
	if r.store != nil {
		err = r.store.Close()
		r.store = nil
	}
	r.Client = nil
	r.UDPOptions = nil
	r.SessionOperations = NativeSessionOperationAuthority{}
	return err
}

type NativeAdmitter struct {
	// runtimeMu prevents refresh or close from replacing the binding and key
	// while a native exchange uses them. Ordinary operations take a read lock,
	// so unrelated resources can recover and retire concurrently.
	runtimeMu              sync.RWMutex
	refreshMu              sync.Mutex
	knockMu                sync.Mutex
	stateMu                sync.Mutex
	resources              keyedResourceLocks
	recoveryWG             sync.WaitGroup
	recoveryPermanentOnce  sync.Once
	retirementRecoveryWake chan struct{}

	binding                     *qurl.AgentRuntimeBinding
	privateKey                  []byte
	udpOpts                     []qurl.AgentRuntimeUDPOption
	store                       nativeStateStore
	refreshCfg                  nativeRefreshConfig
	operations                  nativeSessionOperationController
	placementFailures           map[string]nativePlacementFailureState
	generation                  uint64
	closed                      bool
	live                        map[nativeAdmissionKey]nativeLiveAdmission
	pending                     map[nativeAdmissionKey]bool
	retirementRecoveryResources map[string]struct{}
	lifecycle                   context.Context
	cancel                      context.CancelFunc
}

type nativePlacementFailureState struct {
	generation uint64
	failures   int
	// immediateUsed survives assignment-generation changes and a successful
	// refresh handoff. It is cleared after this resource admits successfully,
	// or released when the refresh itself fails. The agent-global durable marker
	// bounds all later Hub attempts within the same unresolved serving episode.
	// A confirmed healthy route ends that episode; a later lease failure can
	// start a new immediate refresh. A spent entry can remain until success or
	// Close. Its practical bound is the caller's configured resource set;
	// NativeAdmitter does not enforce a separate key-count limit.
	immediateUsed bool
}

const (
	runtimeRefreshReaderGrace          = 250 * time.Millisecond
	nativeOrphanRecoveryInitialBackoff = 250 * time.Millisecond
	nativeOrphanRecoveryMaxBackoff     = 30 * time.Second
)

type nativeRetirementRecoveryAttempt struct {
	notBefore time.Time
	backoff   time.Duration
}

type nativeRetirementRecoverySchedule map[string]nativeRetirementRecoveryAttempt

func (s nativeRetirementRecoverySchedule) queue(resourceID string, now time.Time) {
	if resourceID == "" {
		return
	}
	if _, exists := s[resourceID]; exists {
		return
	}
	s[resourceID] = nativeRetirementRecoveryAttempt{
		notBefore: now,
		backoff:   nativeOrphanRecoveryInitialBackoff,
	}
}

func (s nativeRetirementRecoverySchedule) retry(resourceID string, now time.Time) {
	attempt, exists := s[resourceID]
	if !exists {
		attempt.backoff = nativeOrphanRecoveryInitialBackoff
	}
	if attempt.backoff <= 0 {
		attempt.backoff = nativeOrphanRecoveryInitialBackoff
	}
	attempt.notBefore = now.Add(attempt.backoff)
	attempt.backoff = min(attempt.backoff*2, nativeOrphanRecoveryMaxBackoff)
	s[resourceID] = attempt
}

func (s nativeRetirementRecoverySchedule) due(now time.Time) []string {
	resources := make([]string, 0, len(s))
	for resourceID, attempt := range s {
		if !attempt.notBefore.After(now) {
			resources = append(resources, resourceID)
		}
	}
	sort.Strings(resources)
	return resources
}

func (s nativeRetirementRecoverySchedule) nextDelay(now time.Time) (time.Duration, bool) {
	var earliest time.Time
	for _, attempt := range s {
		if earliest.IsZero() || attempt.notBefore.Before(earliest) {
			earliest = attempt.notBefore
		}
	}
	if earliest.IsZero() {
		return 0, false
	}
	if !earliest.After(now) {
		return 0, true
	}
	return earliest.Sub(now), true
}

type keyedResourceLocks struct {
	mu    sync.Mutex
	locks map[string]*keyedResourceLock
}

type keyedResourceLock struct {
	mu   sync.Mutex
	refs int
}

func (l *keyedResourceLocks) lock(resourceID string) func() {
	l.mu.Lock()
	if l.locks == nil {
		l.locks = make(map[string]*keyedResourceLock)
	}
	entry := l.locks[resourceID]
	if entry == nil {
		entry = &keyedResourceLock{}
		l.locks[resourceID] = entry
	}
	entry.refs++
	l.mu.Unlock()
	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		l.mu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(l.locks, resourceID)
		}
		l.mu.Unlock()
	}
}

// nativeAdmissionKey is the complete exported exact-session identity. Session
// IDs are allocated independently by each NHP server process, so the numeric
// ID alone is not unique across a cell move or server restart.
type nativeAdmissionKey struct {
	cellID                string
	sessionID             uint64
	sessionIssuedAtMillis int64
	runID                 string
	runAttempt            uint64
}

type nativeLiveAdmission struct {
	resourceID  string
	operationID string
	receipt     qurl.NativeSessionReceipt
}

func NewNativeAdmitter(ctx context.Context, runtime *NativeRuntime) (*NativeAdmitter, error) {
	if ctx == nil {
		return nil, errors.New("build native admitter: context is nil")
	}
	if runtime == nil || runtime.Binding == nil || runtime.store == nil {
		return nil, errors.New("build native admitter: runtime is incomplete")
	}
	operations, err := newDurableNativeSessionOperations(runtime.store, runtime.SessionOperations)
	if err != nil {
		return nil, err
	}
	key := takeNativeKey(runtime.Binding)
	if len(key) != 32 {
		clear(key)
		return nil, fmt.Errorf("build native admitter: device key is %d bytes, want 32", len(key))
	}
	lifecycle, cancel := context.WithCancel(ctx)
	admitter := &NativeAdmitter{
		binding: runtime.Binding, privateKey: key, store: runtime.store,
		udpOpts:    append([]qurl.AgentRuntimeUDPOption(nil), runtime.UDPOptions...),
		refreshCfg: runtime.refreshCfg, operations: operations,
		live:                        make(map[nativeAdmissionKey]nativeLiveAdmission),
		pending:                     make(map[nativeAdmissionKey]bool),
		retirementRecoveryWake:      make(chan struct{}, 1),
		retirementRecoveryResources: make(map[string]struct{}),
		lifecycle:                   lifecycle,
		cancel:                      cancel,
	}
	runtime.Binding = nil
	runtime.store = nil
	runtime.Client = nil
	runtime.UDPOptions = nil
	runtime.refreshCfg = nativeRefreshConfig{}
	runtime.SessionOperations = NativeSessionOperationAuthority{}
	// Startup cleanup must not take down healthy sibling shares. It is still
	// fail-closed for each resource: that resource's lock and journal remain in
	// place until authenticated recovery succeeds.
	admitter.startRecoveryWorkers()
	return admitter, nil
}

func (a *NativeAdmitter) startRecoveryWorkers() {
	a.recoveryWG.Add(2)
	go a.recoverOrphanedSessionOperations()
	go func() {
		defer a.recoveryWG.Done()
		a.recoverQueuedNativeRetirements()
	}()
}

func (a *NativeAdmitter) recoverOrphanedSessionOperations() {
	defer a.recoveryWG.Done()
	backoff := nativeOrphanRecoveryInitialBackoff
	permanentResources := make(map[string]struct{})
	for {
		err := a.recoverAllPendingExcludingPermanent(a.lifecycle, permanentResources)
		if err == nil {
			break
		}
		if a.lifecycle.Err() != nil {
			return
		}
		slog.WarnContext(a.lifecycle, "durable native session cleanup failed; retrying", "err", err)
		if !waitForNativeRetirementRecovery(a.lifecycle, backoff) {
			return
		}
		backoff = min(backoff*2, nativeOrphanRecoveryMaxBackoff)
	}
}

func waitForNativeRetirementRecovery(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// queueNativeRetirementRecovery coalesces failures by protected resource. The
// single background worker gives every retry its existing bounded cleanup
// budget without creating one goroutine for every local share.
func (a *NativeAdmitter) queueNativeRetirementRecovery(resourceID string) {
	if a == nil || resourceID == "" || a.lifecycle == nil || a.retirementRecoveryWake == nil ||
		a.lifecycle.Err() != nil {
		return
	}
	a.stateMu.Lock()
	if a.retirementRecoveryResources == nil {
		a.retirementRecoveryResources = make(map[string]struct{})
	}
	_, queued := a.retirementRecoveryResources[resourceID]
	a.retirementRecoveryResources[resourceID] = struct{}{}
	a.stateMu.Unlock()
	if queued {
		return
	}
	select {
	case a.retirementRecoveryWake <- struct{}{}:
	default:
	}
}

func (a *NativeAdmitter) takeNativeRetirementRecoveryResources() []string {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	resources := make([]string, 0, len(a.retirementRecoveryResources))
	for resourceID := range a.retirementRecoveryResources {
		resources = append(resources, resourceID)
	}
	clear(a.retirementRecoveryResources)
	return resources
}

func (a *NativeAdmitter) recoverQueuedNativeRetirements() {
	schedule := make(nativeRetirementRecoverySchedule)
	for {
		now := time.Now()
		for _, resourceID := range a.takeNativeRetirementRecoveryResources() {
			schedule.queue(resourceID, now)
		}
		for _, resourceID := range schedule.due(now) {
			permanent, err := a.recoverPendingNativeRetirements(a.lifecycle, resourceID)
			if a.lifecycle.Err() != nil {
				return
			}
			switch {
			case err == nil:
				delete(schedule, resourceID)
			case permanent:
				delete(schedule, resourceID)
				slog.ErrorContext(a.lifecycle, "durable native session retirement requires operator attention",
					"resource_id", resourceID, "err", err)
			default:
				schedule.retry(resourceID, time.Now())
				slog.WarnContext(a.lifecycle, "durable native session retirement failed; retrying",
					"resource_id", resourceID, "err", err)
			}
		}
		if a.lifecycle.Err() != nil {
			return
		}
		delay, scheduled := schedule.nextDelay(time.Now())
		if !scheduled {
			select {
			case <-a.lifecycle.Done():
				return
			case <-a.retirementRecoveryWake:
			}
			continue
		}
		timer := time.NewTimer(delay)
		select {
		case <-a.lifecycle.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		case <-a.retirementRecoveryWake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
		}
	}
}

func (a *NativeAdmitter) dropNativeRetirementRecovery(resourceID string) {
	a.stateMu.Lock()
	delete(a.retirementRecoveryResources, resourceID)
	a.stateMu.Unlock()
}

func (a *NativeAdmitter) recoverPendingNativeRetirements(ctx context.Context, resourceID string) (bool, error) {
	unlockResource := a.resources.lock(resourceID)
	defer unlockResource()
	a.runtimeMu.RLock()
	defer a.runtimeMu.RUnlock()
	if a.closed || a.binding == nil || len(a.privateKey) != 32 || a.operations == nil {
		return false, errors.New("recover native retirement: native admitter is closed")
	}
	err := a.retirePendingForResource(ctx, resourceID)
	permanent := isPermanentNativeRetirementError(err)
	if permanent {
		// retireOne queues every failure before returning. Remove that stale wake
		// while the resource lock still excludes a new foreground retirement.
		a.dropNativeRetirementRecovery(resourceID)
	}
	return permanent, err
}

func isPermanentNativeRetirementError(err error) bool {
	if err == nil {
		return false
	}
	type multiUnwrapper interface{ Unwrap() []error }
	if joined, ok := err.(multiUnwrapper); ok {
		causes := joined.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !isPermanentNativeRetirementError(cause) {
				return false
			}
		}
		return true
	}
	if cause := errors.Unwrap(err); cause != nil {
		return isPermanentNativeRetirementError(cause)
	}
	var deny *qurl.ServerDenyError
	if errors.As(err, &deny) {
		return true
	}
	for _, sentinel := range []error{
		qurl.ErrInvalidNativeSessionOperation,
		agentstate.ErrSessionOperationConflict,
		agentstate.ErrSessionOperationJournalCorrupt,
	} {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}

func (a *NativeAdmitter) recoverAllPending(ctx context.Context) error {
	return a.recoverAllPendingExcludingPermanent(ctx, nil)
}

func (a *NativeAdmitter) recoverAllPendingExcludingPermanent(ctx context.Context,
	permanentResources map[string]struct{},
) error {
	if ctx == nil {
		return errors.New("recover native session operations: context is nil")
	}
	a.runtimeMu.RLock()
	store := a.store
	closed := a.closed
	a.runtimeMu.RUnlock()
	if closed || store == nil {
		return errors.New("recover native session operations: native admitter is closed")
	}
	scan := store.ScanSessionOperationResources(ctx)
	if scan.PermanentError != nil {
		// A corrupt journal remains fail-closed when its own resource next
		// admits. Report it once without suppressing valid sibling cleanup or
		// spinning the retry loop on state that cannot heal by itself.
		a.recoveryPermanentOnce.Do(func() {
			slog.ErrorContext(ctx, "durable native session journal requires operator attention", "err", scan.PermanentError)
		})
	}
	var recoveryErr error
	if scan.RetryableError != nil {
		recoveryErr = fmt.Errorf("enumerate native session operations: %w", scan.RetryableError)
	}
	for _, resourceID := range scan.ResourceIDs {
		if _, permanent := permanentResources[resourceID]; permanent {
			continue
		}
		if err := ctx.Err(); err != nil {
			return errors.Join(recoveryErr, err)
		}
		unlockResource := a.resources.lock(resourceID)
		a.runtimeMu.RLock()
		if a.closed || a.binding == nil || len(a.privateKey) != 32 || a.operations == nil {
			a.runtimeMu.RUnlock()
			unlockResource()
			return errors.Join(recoveryErr, errors.New("recover native session operations: native admitter is closed"))
		}
		err := a.operations.RecoverPending(
			ctx, a.binding, a.privateKey, resourceID, a.liveOperationIDs(resourceID), a.udpOpts,
		)
		a.runtimeMu.RUnlock()
		unlockResource()
		if isPermanentNativeRetirementError(err) {
			if permanentResources != nil {
				permanentResources[resourceID] = struct{}{}
			}
			slog.ErrorContext(ctx, "durable native session retirement requires operator attention",
				"resource_id", resourceID, "err", err)
			continue
		}
		if err != nil {
			recoveryErr = errors.Join(recoveryErr, err)
		}
	}
	return recoveryErr
}

func (a *NativeAdmitter) withLifecycle(ctx context.Context) (context.Context, context.CancelFunc) {
	bound, cancel := context.WithCancel(ctx)
	if a == nil || a.lifecycle == nil {
		return bound, cancel
	}
	if a.lifecycle.Err() != nil {
		cancel()
		return bound, cancel
	}
	stop := context.AfterFunc(a.lifecycle, cancel)
	return bound, func() {
		stop()
		cancel()
	}
}

func (a *NativeAdmitter) Admit(ctx context.Context, knockResourceID, resourceID string) (Admission, error) {
	if ctx == nil {
		return Admission{}, errors.New("admit native resource: context is nil")
	}
	ctx, cancel := a.withLifecycle(ctx)
	defer cancel()
	unlockResource := a.resources.lock(resourceID)
	defer unlockResource()

	admission, err, generation, refreshEligible := a.admitOnce(ctx, knockResourceID, resourceID)
	if err == nil {
		a.resetPlacementFailures(resourceID)
		return admission, nil
	}
	if !refreshEligible {
		return Admission{}, err
	}
	if !refreshableKnockError(err) {
		a.clearPlacementFailureCount(resourceID)
		return Admission{}, err
	}
	thresholdReached := a.recordPlacementFailure(resourceID, generation)
	immediate := !thresholdReached && immediatePlacementRefresh(err) && a.claimImmediatePlacementRefresh(resourceID)
	if !immediate && !thresholdReached {
		return Admission{}, err
	}
	refreshReason := nativeRefreshReasonSustained
	if immediate {
		refreshReason = nativeRefreshReasonImmediate
	}
	if refreshErr := a.refresh(ctx, generation, refreshReason); refreshErr != nil {
		// A failed refresh produced no usable assignment for this admitter. Restore
		// its one-shot credit; the agent-global durable marker still preserves the
		// backoff for every Hub attempt, including authenticated rejections.
		if immediate {
			a.releaseImmediatePlacementRefresh(resourceID)
		}
		return Admission{}, errors.Join(err, refreshErr)
	}
	admission, retryErr, _, _ := a.admitOnce(ctx, knockResourceID, resourceID)
	if retryErr == nil {
		a.resetPlacementFailures(resourceID)
	}
	return admission, retryErr
}

// immediatePlacementRefresh identifies authenticated local placement state
// that cannot admit another durable session without a Hub refresh. Waiting for
// several identical attempts only consumes the remaining lease margin; the
// sustained-failure threshold remains for transport and reply-path failures.
func immediatePlacementRefresh(err error) bool {
	return errors.Is(err, qurl.ErrAssignmentLeaseExpired) ||
		errors.Is(err, qurl.ErrNativeSessionOperationLeaseMargin) ||
		errors.Is(err, qurl.ErrAssignmentRecoveryRequired) ||
		errors.Is(err, qurl.ErrAssignmentReassignmentRequired)
}

func (a *NativeAdmitter) admitOnce(ctx context.Context, knockResourceID,
	resourceID string,
) (Admission, error, uint64, bool) {
	a.runtimeMu.RLock()
	defer a.runtimeMu.RUnlock()
	if a.closed || a.binding == nil || len(a.privateKey) != 32 {
		return Admission{}, errors.New("native admitter is closed"), a.generation, false
	}
	if a.operations == nil {
		return Admission{}, errors.New("native admitter has no durable session-operation authority"), a.generation, false
	}
	generation := a.generation
	if err := a.operations.RecoverPending(ctx, a.binding, a.privateKey, resourceID, a.liveOperationIDs(resourceID), a.udpOpts); err != nil {
		// Recovery is source-fenced to the operation's persisted cell. Assignment
		// refresh cannot change that endpoint, so this resource remains blocked by
		// its durable record without changing the live-placement failure budget.
		return Admission{}, fmt.Errorf("recover prior native session operation before replacement: %w", err), generation, false
	}
	if err := a.retirePendingForResource(ctx, resourceID); err != nil {
		return Admission{}, fmt.Errorf("retire prior native NHP session before replacement: %w", err), generation, false
	}
	admission, err := a.knock(ctx, knockResourceID, resourceID)
	return admission, err, generation, true
}

func (a *NativeAdmitter) knock(ctx context.Context, knockResourceID, resourceID string) (Admission, error) {
	runID, err := qurl.NewCycleRunID()
	if err != nil {
		return Admission{}, err
	}
	// Each admission cycle owns a fresh RunID. Ambiguous results recover that
	// same durable operation, so a new local retry attempt is never invented.
	const runAttempt = uint64(1)
	// qurl-go requires preparation, the durable dispatch commit, and the knock
	// to be one critical section on a shared binding. Recovery and retirement
	// use their own source-fenced endpoint and do not take this lock.
	a.knockMu.Lock()
	operation, err := a.operations.PrepareDispatch(ctx, a.binding, a.privateKey, knockResourceID, resourceID, runID, runAttempt)
	if err != nil {
		a.knockMu.Unlock()
		return Admission{}, err
	}
	result, err := knockNativeRuntime(
		ctx, a.binding, a.privateKey, knockResourceID,
		qurl.NativeKnockOptions{RunID: runID, RunAttempt: runAttempt, ProtectedResourceID: resourceID, Operation: operation}, a.udpOpts...,
	)
	a.knockMu.Unlock()
	if err != nil {
		cleanupErr := a.recoverOperationCleanup(resourceID, operation.OperationID)
		var deny *qurl.ServerDenyError
		if errors.As(err, &deny) && deny.ErrCode == "52004" {
			return Admission{}, withNativeSessionCleanupError(fmt.Errorf("%w: %w", ErrResourceGone, err), cleanupErr)
		}
		return Admission{}, withNativeSessionCleanupError(err, cleanupErr)
	}
	if result == nil {
		cleanupErr := a.recoverOperationCleanup(resourceID, operation.OperationID)
		return Admission{}, withNativeSessionCleanupError(errors.New("native knock returned no admission"), cleanupErr)
	}
	if err := a.operations.RecordMapped(ctx, resourceID, *operation, result.SessionReceipt); err != nil {
		cleanupErr := a.recoverOperationCleanup(resourceID, operation.OperationID)
		return Admission{}, withNativeSessionCleanupError(err, cleanupErr)
	}
	admission := Admission{
		KnockResourceID: knockResourceID, ResourceID: resourceID,
		RunID: runID, Token: result.ACToken, ResourceHost: result.ResourceHost,
		RunAttempt: runAttempt, SessionID: result.SessionID, SessionReceipt: result.SessionReceipt,
		OpenTime: time.Duration(result.OpenTime) * time.Second,
	}
	if err := validateAdmission(admission, knockResourceID, resourceID); err != nil {
		// The authenticated ACK may already have opened server-side authority.
		// Track and retire that exact receipt even when a stricter local
		// invariant (for example canonical host:port) rejects the result.
		key, trackErr := a.trackAdmission(admission, operation.OperationID)
		if trackErr != nil {
			cleanupErr := a.recoverOperationCleanup(resourceID, operation.OperationID)
			return Admission{}, withNativeSessionCleanupError(errors.Join(err, trackErr), cleanupErr)
		}
		a.stateMu.Lock()
		a.pending[key] = true
		live := a.live[key]
		a.stateMu.Unlock()
		return Admission{}, withNativeSessionCleanupError(err, a.retireOne(ctx, key, live))
	}
	if _, err := a.trackAdmission(admission, operation.OperationID); err != nil {
		cleanupErr := a.recoverOperationCleanup(resourceID, operation.OperationID)
		return Admission{}, withNativeSessionCleanupError(err, cleanupErr)
	}
	return admission, nil
}

func (a *NativeAdmitter) recoverOperationCleanup(resourceID, operationID string) error {
	parent := context.Background()
	if a.lifecycle != nil {
		parent = a.lifecycle
	}
	cleanupCtx, cancelCleanup := context.WithTimeout(parent, nativeSessionCleanupBudget)
	defer cancelCleanup()
	return a.operations.RecoverOperation(
		cleanupCtx, a.binding, a.privateKey, resourceID, operationID, a.udpOpts,
	)
}

func withNativeSessionCleanupError(primary, cleanup error) error {
	if cleanup == nil {
		return primary
	}
	if primary == nil {
		return errors.New("durable native session cleanup failed: " + cleanup.Error())
	}
	// Cleanup diagnostics stay visible, but only the primary exchange controls
	// errors.Is/errors.As placement classification.
	return nativeSessionCleanupDiagnostic{primary: primary, cleanup: cleanup}
}

type nativeSessionCleanupDiagnostic struct {
	primary error
	cleanup error
}

func (e nativeSessionCleanupDiagnostic) Error() string {
	return e.primary.Error() + "; durable native session cleanup also failed: " + e.cleanup.Error()
}

func (e nativeSessionCleanupDiagnostic) Unwrap() error { return e.primary }

func refreshableKnockError(err error) bool {
	if err == nil {
		return false
	}
	var deny *qurl.ServerDenyError
	if errors.As(err, &deny) {
		// An authenticated deny proves the assigned cell and key path are live.
		// Reassigning cannot repair resource, policy, or access-control failures.
		return false
	}
	// These sentinels are produced when the binding's live placement can no
	// longer admit a session. They deliberately take precedence over the
	// invalid-input/deadline errors a bounded renewal may also wrap.
	if immediatePlacementRefresh(err) {
		return true
	}
	if errors.Is(err, qurl.ErrInvalidNativeKnockInput) ||
		errors.Is(err, qurl.ErrMalformedReply) ||
		errors.Is(err, qurl.ErrServerOverloaded) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return errors.Is(err, nativeudp.ErrResolve) ||
		errors.Is(err, nativeudp.ErrTransport) ||
		errors.Is(err, nativeudp.ErrNoReply) ||
		errors.Is(err, nativeudp.ErrServerUnauthenticated)
}

func (a *NativeAdmitter) refresh(ctx context.Context, failedGeneration uint64, reason string) error {
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	a.runtimeMu.RLock()
	if a.closed || a.binding == nil || len(a.privateKey) != 32 {
		a.runtimeMu.RUnlock()
		return errors.New("refresh native admission runtime: native admitter is closed")
	}
	if a.generation != failedGeneration {
		a.runtimeMu.RUnlock()
		return nil
	}
	store := a.store
	refreshCfg := a.refreshCfg
	a.runtimeMu.RUnlock()

	runtime, key, err := prepareRefreshedRuntime(ctx, store, refreshCfg, reason)
	if err != nil {
		return err
	}
	if err := a.lockRuntimeForRefresh(ctx); err != nil {
		discardRefreshedRuntime(runtime, key)
		return err
	}
	defer a.runtimeMu.Unlock()
	if a.closed || a.store != store || a.binding == nil || len(a.privateKey) != 32 {
		discardRefreshedRuntime(runtime, key)
		return errors.New("refresh native admission runtime: native admitter is closed")
	}
	if a.generation != failedGeneration {
		discardRefreshedRuntime(runtime, key)
		return nil
	}
	oldBinding := a.binding
	oldKey := a.privateKey
	a.binding = runtime.Binding
	a.privateKey = key
	a.udpOpts = append(a.udpOpts[:0], runtime.UDPOptions...)
	runtime.Binding = nil
	runtime.store = nil
	a.generation++
	clear(oldKey)
	oldBinding.Destroy()
	return nil
}

func prepareRefreshedRuntime(ctx context.Context, store nativeStateStore, cfg nativeRefreshConfig, reason string) (*NativeRuntime, []byte, error) {
	if store == nil {
		return nil, nil, errors.New("refresh native admission runtime: state store is closed")
	}
	if err := store.RequestRegistrationRefresh(reason); err != nil {
		return nil, nil, fmt.Errorf("request assignment refresh: %w", err)
	}
	marker, present, err := store.LoadRegistrationRefreshMarker()
	if err != nil || !present {
		return nil, nil, errors.Join(fmt.Errorf("assignment refresh state missing after %s", reason), err)
	}
	runtime, err := refreshReadyOnce(ctx, cfg, store, marker, cfg.RefreshMode)
	if err != nil {
		return nil, nil, err
	}
	key := takeNativeKey(runtime.Binding)
	if len(key) != 32 {
		got := len(key)
		discardRefreshedRuntime(runtime, key)
		return nil, nil, fmt.Errorf("refreshed native runtime key is %d bytes, want 32", got)
	}
	return runtime, key, nil
}

// refreshReadyOnce is the live-admission refresh boundary. It never sleeps
// through persisted backoff and makes at most one Hub request. The daemon can
// therefore reconcile another resource or close a confirmed-healthy episode
// while the durable marker controls when the next request is allowed. Startup
// recovery uses refreshUntilOpen because no serving sibling exists there.
func refreshReadyOnce(ctx context.Context, cfg nativeRefreshConfig, store nativeStateStore, marker agentstate.RefreshMarker, mode string) (*NativeRuntime, error) {
	if mode == "disabled" {
		return nil, fmt.Errorf("native assignment refresh is disabled while recovery is required: %s", marker.Reason)
	}
	if marker.NextAttemptUnixMilli > 0 && time.Now().Before(time.UnixMilli(marker.NextAttemptUnixMilli)) {
		return nil, errNativeRefreshBackoffPending
	}
	if err := store.MarkRegistrationRefreshAttempted(); err != nil {
		return nil, fmt.Errorf("advance assignment refresh retry state: %w", err)
	}
	state, err := store.Handoff()
	if err != nil {
		return nil, err
	}
	options := make([]qurl.AgentRuntimeRefreshOption, 0, len(cfg.UDPOptions)+1)
	if cfg.ClientBaseURL != "" {
		options = append(options, qurl.WithAgentClientBaseURL(cfg.ClientBaseURL))
	}
	for _, option := range cfg.UDPOptions {
		options = append(options, option)
	}
	client, binding, err := refreshNativeRuntime(ctx, cfg.Hub, state, options...)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return assembleRefreshedNativeRuntime(ctx, client, binding, store, cfg, NativeOpenRefresh)
}

func (a *NativeAdmitter) lockRuntimeForRefresh(ctx context.Context) error {
	if ctx == nil {
		return errors.New("refresh native admission runtime: context is nil")
	}
	if a.runtimeMu.TryLock() {
		return nil
	}
	// Give already-admitted sibling work one short grace period to finish
	// without a queued writer stopping new readers. The grace is fixed, so a
	// continuous reader stream cannot starve the refresh.
	grace := time.NewTimer(runtimeRefreshReaderGrace)
	defer grace.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-grace.C:
	}
	if a.runtimeMu.TryLock() {
		return nil
	}
	acquired := make(chan struct{})
	go func() {
		a.runtimeMu.Lock()
		close(acquired)
	}()
	select {
	case <-acquired:
		return nil
	case <-ctx.Done():
		// The queued writer must eventually take and release the lock. Abandoning
		// it would leak ownership and deadlock the next operation.
		go func() {
			<-acquired
			a.runtimeMu.Unlock()
		}()
		return ctx.Err()
	}
}

func discardRefreshedRuntime(runtime *NativeRuntime, key []byte) {
	clear(key)
	if runtime == nil {
		return
	}
	if runtime.Binding != nil {
		runtime.Binding.Destroy()
	}
	runtime.Binding = nil
	runtime.store = nil
	runtime.Client = nil
}

func (a *NativeAdmitter) recordPlacementFailure(resourceID string, generation uint64) bool {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if a.placementFailures == nil {
		a.placementFailures = make(map[string]nativePlacementFailureState)
	}
	state := a.placementFailures[resourceID]
	if state.generation != generation {
		state.generation = generation
		state.failures = 0
	}
	state.failures++
	a.placementFailures[resourceID] = state
	return state.failures >= 5
}

func (a *NativeAdmitter) claimImmediatePlacementRefresh(resourceID string) bool {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if a.placementFailures == nil {
		a.placementFailures = make(map[string]nativePlacementFailureState)
	}
	state := a.placementFailures[resourceID]
	if state.immediateUsed {
		return false
	}
	state.immediateUsed = true
	a.placementFailures[resourceID] = state
	return true
}

func (a *NativeAdmitter) releaseImmediatePlacementRefresh(resourceID string) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	state, ok := a.placementFailures[resourceID]
	if !ok || !state.immediateUsed {
		return
	}
	state.immediateUsed = false
	a.placementFailures[resourceID] = state
}

// clearPlacementFailureCount resets only the sustained-failure budget. It
// does not re-arm the once-per-resource immediate refresh; only a successful
// admission can start a new immediate-refresh episode.
func (a *NativeAdmitter) clearPlacementFailureCount(resourceID string) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	state, ok := a.placementFailures[resourceID]
	if !ok {
		return
	}
	if !state.immediateUsed {
		delete(a.placementFailures, resourceID)
		return
	}
	state.failures = 0
	a.placementFailures[resourceID] = state
}

func (a *NativeAdmitter) resetPlacementFailures(resourceID string) {
	a.stateMu.Lock()
	delete(a.placementFailures, resourceID)
	a.stateMu.Unlock()
}

// Retire durably closes only the exact NHP session represented by admission.
// A failed retirement remains pending and must succeed before the same
// resource can obtain another admission.
func (a *NativeAdmitter) Retire(ctx context.Context, admission Admission) error {
	if ctx == nil {
		return errors.New("retire native admission: context is nil")
	}
	ctx, cancel := a.withLifecycle(ctx)
	defer cancel()
	if err := validateAdmissionReceipt(admission); err != nil {
		return err
	}
	unlockResource := a.resources.lock(admission.ResourceID)
	defer unlockResource()
	a.runtimeMu.RLock()
	defer a.runtimeMu.RUnlock()
	if a.closed || a.binding == nil || len(a.privateKey) != 32 {
		return errors.New("native admitter is closed")
	}
	key := admissionKey(admission.SessionReceipt)
	a.stateMu.Lock()
	a.ensureAdmissionMapsLocked()
	live, ok := a.live[key]
	if !ok {
		a.stateMu.Unlock()
		return nil
	}
	if live.resourceID != admission.ResourceID || !sameSessionReceipt(live.receipt, admission.SessionReceipt) {
		a.stateMu.Unlock()
		return errors.New("retire native admission: exact-session receipt does not match the live admission")
	}
	a.pending[key] = true
	a.stateMu.Unlock()
	return a.retireOne(ctx, key, live)
}

func (a *NativeAdmitter) ensureAdmissionMapsLocked() {
	if a.live == nil {
		a.live = make(map[nativeAdmissionKey]nativeLiveAdmission)
	}
	if a.pending == nil {
		a.pending = make(map[nativeAdmissionKey]bool)
	}
}

func (a *NativeAdmitter) trackAdmission(admission Admission, operationID string) (nativeAdmissionKey, error) {
	if err := validateAdmissionReceipt(admission); err != nil {
		return nativeAdmissionKey{}, err
	}
	if operationID == "" {
		return nativeAdmissionKey{}, errors.New("track native admission: operation ID is empty")
	}
	key := admissionKey(admission.SessionReceipt)
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	a.ensureAdmissionMapsLocked()
	if existing, ok := a.live[key]; ok &&
		(existing.resourceID != admission.ResourceID || existing.operationID != operationID ||
			!sameSessionReceipt(existing.receipt, admission.SessionReceipt)) {
		return nativeAdmissionKey{}, errors.New("track native admission: exact-session identity conflicts with a live admission")
	}
	a.live[key] = nativeLiveAdmission{resourceID: admission.ResourceID, operationID: operationID, receipt: admission.SessionReceipt}
	return key, nil
}

func admissionKey(receipt qurl.NativeSessionReceipt) nativeAdmissionKey {
	return nativeAdmissionKey{
		cellID: receipt.CellID, sessionID: receipt.SessionID,
		sessionIssuedAtMillis: receipt.SessionIssuedAtMillis,
		runID:                 receipt.RunID, runAttempt: receipt.RunAttempt,
	}
}

func (a *NativeAdmitter) retirePendingForResource(ctx context.Context, resourceID string) error {
	for {
		a.stateMu.Lock()
		a.ensureAdmissionMapsLocked()
		var key nativeAdmissionKey
		var live nativeLiveAdmission
		found := false
		for candidate := range a.pending {
			candidateLive, ok := a.live[candidate]
			if !ok {
				delete(a.pending, candidate)
				continue
			}
			if candidateLive.resourceID == resourceID {
				key, live, found = candidate, candidateLive, true
				break
			}
		}
		a.stateMu.Unlock()
		if !found {
			return nil
		}
		if err := a.retireOne(ctx, key, live); err != nil {
			return err
		}
	}
}

func (a *NativeAdmitter) retireOne(ctx context.Context, key nativeAdmissionKey, live nativeLiveAdmission) error {
	if a.operations == nil {
		return errors.New("native admitter has no durable session-operation authority")
	}
	if err := a.operations.Retire(ctx, a.binding, a.privateKey, live.resourceID, live.operationID, live.receipt, a.udpOpts); err != nil {
		a.queueNativeRetirementRecovery(live.resourceID)
		return err
	}
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	current, present := a.live[key]
	if !present {
		delete(a.pending, key)
		return nil
	}
	if current.resourceID != live.resourceID || current.operationID != live.operationID ||
		!sameSessionReceipt(current.receipt, live.receipt) {
		return errors.New("retire native admission: live session changed during exact retirement")
	}
	delete(a.pending, key)
	delete(a.live, key)
	live.receipt = qurl.NativeSessionReceipt{}
	return nil
}

func (a *NativeAdmitter) liveOperationIDs(resourceID string) map[string]struct{} {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	a.ensureAdmissionMapsLocked()
	operations := make(map[string]struct{})
	for _, live := range a.live {
		if live.resourceID == resourceID && live.operationID != "" {
			operations[live.operationID] = struct{}{}
		}
	}
	return operations
}

func sameSessionReceipt(a, b qurl.NativeSessionReceipt) bool {
	return a.CellID == b.CellID && a.SessionID == b.SessionID &&
		a.SessionIssuedAtMillis == b.SessionIssuedAtMillis && a.RunID == b.RunID && a.RunAttempt == b.RunAttempt
}

func (a *NativeAdmitter) MarkServingHealthy() error {
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	a.runtimeMu.RLock()
	defer a.runtimeMu.RUnlock()
	if a.closed || a.store == nil {
		return errors.New("native admitter is closed")
	}
	return a.store.ClearRegistrationRefreshMarker()
}

func (a *NativeAdmitter) Close() error {
	if a == nil {
		return nil
	}
	// Cancel background recovery and every operation created through Admit or
	// Retire before waiting for the runtime write lock. Shutdown does not wait
	// for a stale issuing cell's cleanup budget.
	if a.cancel != nil {
		a.cancel()
	}
	a.recoveryWG.Wait()
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	a.runtimeMu.Lock()
	if a.closed {
		a.runtimeMu.Unlock()
		return nil
	}
	a.closed = true
	binding := a.binding
	privateKey := a.privateKey
	udpOpts := a.udpOpts
	store := a.store
	operations := a.operations
	var closeErr error
	a.stateMu.Lock()
	liveAdmissions := make(map[nativeAdmissionKey]nativeLiveAdmission, len(a.live))
	for key, live := range a.live {
		liveAdmissions[key] = live
	}
	a.stateMu.Unlock()
	if binding != nil && len(privateKey) == 32 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		type closeResult struct {
			key nativeAdmissionKey
			err error
		}
		results := make(chan closeResult, len(liveAdmissions))
		var retireWG sync.WaitGroup
		// Durable exact retirement is safe to fan out through one binding. Each
		// operation owns its source-fenced endpoint and its own file transition,
		// packet, socket, and reply. The private key stays read-only until this
		// wait completes. Parallel calls prevent one silent issuing cell from
		// consuming the whole shutdown budget before sibling closes start.
		for key, live := range liveAdmissions {
			retireWG.Add(1)
			go func(key nativeAdmissionKey, live nativeLiveAdmission) {
				defer retireWG.Done()
				var err error
				if operations == nil {
					err = errors.New("native admitter has no durable session-operation authority")
				} else {
					err = operations.Retire(ctx, binding, privateKey, live.resourceID, live.operationID, live.receipt, udpOpts)
				}
				results <- closeResult{key: key, err: err}
			}(key, live)
		}
		retireWG.Wait()
		close(results)
		for result := range results {
			if result.err != nil {
				closeErr = errors.Join(closeErr, result.err)
				continue
			}
			a.stateMu.Lock()
			delete(a.pending, result.key)
			delete(a.live, result.key)
			a.stateMu.Unlock()
		}
		cancel()
	}
	a.binding = nil
	a.privateKey = nil
	a.udpOpts = nil
	a.store = nil
	a.operations = nil
	a.stateMu.Lock()
	a.live = nil
	a.pending = nil
	a.retirementRecoveryResources = nil
	a.placementFailures = nil
	a.stateMu.Unlock()
	a.runtimeMu.Unlock()
	clear(privateKey)
	if binding != nil {
		binding.Destroy()
	}
	if store != nil {
		closeErr = errors.Join(closeErr, store.Close())
	}
	return closeErr
}
