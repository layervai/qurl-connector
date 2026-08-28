package share

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
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
	// RecoveryCredentialProvider is invoked only after the pinned Hub
	// authenticates the persisted agent and rejects its device credential.
	// It must return a live qurl:agent account credential. The provider and its
	// result are never retained after OpenNativeRuntime returns.
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
	recoverNativeRuntime = qurl.RecoverAgentRuntime
	waitNativeRefresh    = sleepWithContext
	knockNativeRuntime   = qurl.KnockRegisteredAgent
	retireNativeSession  = qurl.RetireRegisteredAgentSession
	takeNativeKey        = func(binding *qurl.AgentRuntimeBinding) []byte { return binding.TakeDeviceStaticPrivateKey() }
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
		return recoverRejectedNativeIdentity(ctx, cfg, store, refreshErr, mode)
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
		return recoverRejectedNativeIdentity(ctx, cfg, store, refreshErr, mode)
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

func recoverRejectedNativeIdentity(ctx context.Context, cfg NativeRuntimeConfig, store nativeStateStore, refreshErr error, mode string) (*NativeRuntime, error) {
	if !errors.Is(refreshErr, qurl.ErrAssignmentIdentityRejected) || cfg.RecoveryCredentialProvider == nil {
		return nil, refreshErr
	}
	credential, err := cfg.RecoveryCredentialProvider(ctx)
	if err != nil {
		return nil, errors.Join(refreshErr, fmt.Errorf("resolve native credential recovery authority: %w", err))
	}
	credential = strings.TrimSpace(credential)
	if credential == "" {
		return nil, errors.Join(refreshErr, errors.New("native credential recovery authority is empty"))
	}
	state, err := store.Handoff()
	if err != nil {
		return nil, errors.Join(refreshErr, err)
	}
	options := make([]qurl.AgentRuntimeRecoveryOption, 0, len(cfg.UDPOptions)+3)
	options = append(options, qurl.WithAgentRuntimeRecoveryHub(cfg.Hub))
	if expected := strings.TrimSpace(cfg.AgentID); expected != "" {
		options = append(options, qurl.WithExpectedAgentRuntimeRecoveryAgentID(expected))
	}
	if cfg.ClientBaseURL != "" {
		options = append(options, qurl.WithAgentClientBaseURL(cfg.ClientBaseURL))
	}
	for _, option := range cfg.UDPOptions {
		options = append(options, option)
	}
	client, binding, err := recoverNativeRuntime(ctx, credential, state, options...)
	credential = ""
	if err != nil {
		return nil, fmt.Errorf("recover rejected native identity: %w", err)
	}
	return assembleRefreshedNativeRuntime(ctx, client, binding, store, refreshConfig(cfg, mode), NativeOpenRecovery)
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
	runtimeMu sync.RWMutex
	refreshMu sync.Mutex
	knockMu   sync.Mutex
	stateMu   sync.Mutex
	resources keyedResourceLocks

	binding    *qurl.AgentRuntimeBinding
	privateKey []byte
	udpOpts    []qurl.AgentRuntimeUDPOption
	store      nativeStateStore
	refreshCfg nativeRefreshConfig
	operations nativeSessionOperationController
	failures   int
	failureGen uint64
	generation uint64
	closed     bool
	live       map[nativeAdmissionKey]nativeLiveAdmission
	pending    map[nativeAdmissionKey]bool
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

func NewNativeAdmitter(runtime *NativeRuntime) (*NativeAdmitter, error) {
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
	admitter := &NativeAdmitter{
		binding: runtime.Binding, privateKey: key, store: runtime.store,
		udpOpts:    append([]qurl.AgentRuntimeUDPOption(nil), runtime.UDPOptions...),
		refreshCfg: runtime.refreshCfg, operations: operations,
		live:    make(map[nativeAdmissionKey]nativeLiveAdmission),
		pending: make(map[nativeAdmissionKey]bool),
	}
	runtime.Binding = nil
	runtime.store = nil
	runtime.Client = nil
	runtime.UDPOptions = nil
	runtime.refreshCfg = nativeRefreshConfig{}
	runtime.SessionOperations = NativeSessionOperationAuthority{}
	return admitter, nil
}

func (a *NativeAdmitter) Admit(ctx context.Context, knockResourceID, resourceID string) (Admission, error) {
	if ctx == nil {
		return Admission{}, errors.New("admit native resource: context is nil")
	}
	unlockResource := a.resources.lock(resourceID)
	defer unlockResource()

	admission, err, generation, refreshEligible := a.admitOnce(ctx, knockResourceID, resourceID)
	if err == nil {
		a.resetPlacementFailures(generation)
		return admission, nil
	}
	if !refreshEligible || !refreshableKnockError(err) {
		a.resetPlacementFailures(generation)
		return Admission{}, err
	}
	if !a.recordPlacementFailure(generation) {
		return Admission{}, err
	}
	if refreshErr := a.refresh(ctx, generation); refreshErr != nil {
		return Admission{}, errors.Join(err, refreshErr)
	}
	admission, retryErr, retryGeneration, _ := a.admitOnce(ctx, knockResourceID, resourceID)
	if retryErr == nil {
		a.resetPlacementFailures(retryGeneration)
	}
	return admission, retryErr
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
			return Admission{}, errors.Join(fmt.Errorf("%w: %w", ErrResourceGone, err), cleanupErr)
		}
		return Admission{}, errors.Join(err, cleanupErr)
	}
	if result == nil {
		cleanupErr := a.recoverOperationCleanup(resourceID, operation.OperationID)
		return Admission{}, errors.Join(errors.New("native knock returned no admission"), cleanupErr)
	}
	if err := a.operations.RecordMapped(ctx, resourceID, *operation, result.SessionReceipt); err != nil {
		cleanupErr := a.recoverOperationCleanup(resourceID, operation.OperationID)
		return Admission{}, errors.Join(err, cleanupErr)
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
			return Admission{}, errors.Join(err, trackErr)
		}
		a.stateMu.Lock()
		a.pending[key] = true
		live := a.live[key]
		a.stateMu.Unlock()
		return Admission{}, errors.Join(err, a.retireOne(ctx, key, live))
	}
	if _, err := a.trackAdmission(admission, operation.OperationID); err != nil {
		cleanupErr := a.recoverOperationCleanup(resourceID, operation.OperationID)
		return Admission{}, errors.Join(err, cleanupErr)
	}
	return admission, nil
}

func (a *NativeAdmitter) recoverOperationCleanup(resourceID, operationID string) error {
	cleanupCtx, cancelCleanup := nativeSessionCleanupContext()
	defer cancelCleanup()
	return a.operations.RecoverOperation(
		cleanupCtx, a.binding, a.privateKey, resourceID, operationID, a.udpOpts,
	)
}

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
	if errors.Is(err, qurl.ErrAssignmentLeaseExpired) ||
		errors.Is(err, qurl.ErrNativeSessionOperationLeaseMargin) ||
		errors.Is(err, qurl.ErrAssignmentRecoveryRequired) ||
		errors.Is(err, qurl.ErrAssignmentReassignmentRequired) {
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

func (a *NativeAdmitter) refresh(ctx context.Context, failedGeneration uint64) error {
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	a.runtimeMu.Lock()
	defer a.runtimeMu.Unlock()
	if a.closed || a.binding == nil || len(a.privateKey) != 32 {
		return errors.New("refresh native admission runtime: native admitter is closed")
	}
	if a.generation != failedGeneration {
		return nil
	}
	if err := a.refreshRuntimeLocked(ctx); err != nil {
		return err
	}
	a.generation++
	a.resetPlacementFailures(a.generation)
	return nil
}

func (a *NativeAdmitter) refreshRuntimeLocked(ctx context.Context) error {
	if a.store == nil {
		return errors.New("refresh native admission runtime: state store is closed")
	}
	if err := a.store.RequestRegistrationRefresh("sustained native NHP knock failures"); err != nil {
		return fmt.Errorf("request assignment refresh: %w", err)
	}
	marker, present, err := a.store.LoadRegistrationRefreshMarker()
	if err != nil || !present {
		return errors.Join(errors.New("assignment refresh state missing after sustained knock failures"), err)
	}
	runtime, err := refreshUntilOpen(ctx, a.refreshCfg, a.store, marker, a.refreshCfg.RefreshMode)
	if err != nil {
		return err
	}
	key := takeNativeKey(runtime.Binding)
	if len(key) != 32 {
		clear(key)
		runtime.Binding.Destroy()
		runtime.Binding = nil
		runtime.store = nil
		return fmt.Errorf("refreshed native runtime key is %d bytes, want 32", len(key))
	}
	oldBinding := a.binding
	clear(a.privateKey)
	a.binding = runtime.Binding
	a.privateKey = key
	a.udpOpts = append(a.udpOpts[:0], runtime.UDPOptions...)
	runtime.Binding = nil
	runtime.store = nil
	if oldBinding != nil {
		oldBinding.Destroy()
	}
	return nil
}

func (a *NativeAdmitter) recordPlacementFailure(generation uint64) bool {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if a.failureGen != generation {
		a.failureGen = generation
		a.failures = 0
	}
	a.failures++
	return a.failures >= 5
}

func (a *NativeAdmitter) resetPlacementFailures(generation uint64) {
	a.stateMu.Lock()
	a.failureGen = generation
	a.failures = 0
	a.stateMu.Unlock()
}

// Retire durably closes only the exact NHP session represented by admission.
// A failed retirement remains pending and must succeed before the same
// resource can obtain another admission.
func (a *NativeAdmitter) Retire(ctx context.Context, admission Admission) error {
	if ctx == nil {
		return errors.New("retire native admission: context is nil")
	}
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
