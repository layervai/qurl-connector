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
	RefreshMode                  string
	UDPOptions                   []qurl.AgentRuntimeUDPOption
}

// nativeRefreshConfig is the credential-free subset retained after opening
// the persisted agent. Enrollment credentials are only registration inputs;
// assignment refresh authenticates with the sealed agent state.
type nativeRefreshConfig struct {
	StateDir      string
	AgentID       string
	Hub           qurl.HubBootstrap
	ClientBaseURL string
	RefreshMode   string
	UDPOptions    []qurl.AgentRuntimeUDPOption
}

// NativeRuntime is one opened, persisted qurl-go agent runtime. Callers may use
// Client and Binding for native resource discovery before transferring the
// runtime into NewNativeAdmitter.
type NativeRuntime struct {
	Client     *qurl.Client
	Binding    *qurl.AgentRuntimeBinding
	AgentID    string
	Hub        qurl.HubBootstrap
	UDPOptions []qurl.AgentRuntimeUDPOption
	OpenKind   NativeOpenKind

	store      nativeStateStore
	refreshCfg nativeRefreshConfig
}

type NativeOpenKind string

const (
	NativeOpenWarm         NativeOpenKind = "warm"
	NativeOpenRegistration NativeOpenKind = "registration"
	NativeOpenRefresh      NativeOpenKind = "refresh"
)

type nativeStateStore interface {
	Handoff() (qurl.AgentStateStore, error)
	ValidateContinuity() error
	LoadRegistrationRefreshMarker() (agentstate.RefreshMarker, bool, error)
	RequestRegistrationRefresh(string) error
	MarkRegistrationRefreshAttempted() error
	ClearRegistrationRefreshMarker() error
	Close() error
}

var (
	newNativeStateStore = func(dir, agentID string) (nativeStateStore, error) {
		return agentstate.NewSDKStore(dir, agentID)
	}
	connectNativeRuntime = qurl.ConnectAgentRuntime
	refreshNativeRuntime = qurl.RefreshAgentRuntime
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
	if present {
		return refreshUntilOpen(ctx, refreshConfig(cfg, mode), store, marker, mode)
	}

	state, err := store.Handoff()
	if err != nil {
		return nil, err
	}
	openOptions := []qurl.AgentRuntimeRegistrationOption{qurl.WithAgentRuntimeOfflineOpen()}
	if cfg.ClientBaseURL != "" {
		openOptions = append(openOptions, qurl.WithAgentClientBaseURL(cfg.ClientBaseURL))
	}
	client, binding, openErr := connectNativeRuntime(ctx, state, openOptions...)
	if openErr == nil {
		return assembleNativeRuntime(client, binding, store, refreshConfig(cfg, mode), NativeOpenWarm)
	}
	if errors.Is(openErr, qurl.ErrAssignmentLeaseExpired) {
		if err := store.RequestRegistrationRefresh("assigned NHP cell lease expired"); err != nil {
			return nil, fmt.Errorf("record assignment refresh request: %w", err)
		}
		marker, present, err = store.LoadRegistrationRefreshMarker()
		if err != nil || !present {
			return nil, errors.Join(errors.New("assignment refresh state missing after lease expiry"), err)
		}
		return refreshUntilOpen(ctx, refreshConfig(cfg, mode), store, marker, mode)
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
	state, err = store.Handoff()
	if err != nil {
		return nil, err
	}
	client, binding, err = connectNativeRuntime(ctx, state, registerOptions...)
	if err != nil {
		return nil, err
	}
	return assembleNativeRuntime(client, binding, store, refreshConfig(cfg, mode), NativeOpenRegistration)
}

func refreshConfig(cfg NativeRuntimeConfig, mode string) nativeRefreshConfig {
	return nativeRefreshConfig{
		StateDir: cfg.StateDir, AgentID: strings.TrimSpace(cfg.AgentID), Hub: cfg.Hub,
		ClientBaseURL: cfg.ClientBaseURL, RefreshMode: mode,
		UDPOptions: append([]qurl.AgentRuntimeUDPOption(nil), cfg.UDPOptions...),
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
			return assembleNativeRuntime(client, binding, store, cfg, NativeOpenRefresh)
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
		refreshCfg: cfg,
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
	return err
}

type NativeAdmitter struct {
	mu sync.Mutex

	binding    *qurl.AgentRuntimeBinding
	privateKey []byte
	udpOpts    []qurl.AgentRuntimeUDPOption
	store      nativeStateStore
	refreshCfg nativeRefreshConfig
	failures   int
	closed     bool
	live       map[nativeAdmissionKey]nativeLiveAdmission
	pending    map[nativeAdmissionKey]bool
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
	resourceID string
	receipt    qurl.NativeSessionReceipt
}

func NewNativeAdmitter(runtime *NativeRuntime) (*NativeAdmitter, error) {
	if runtime == nil || runtime.Binding == nil || runtime.store == nil {
		return nil, errors.New("build native admitter: runtime is incomplete")
	}
	key := takeNativeKey(runtime.Binding)
	if len(key) != 32 {
		clear(key)
		return nil, fmt.Errorf("build native admitter: device key is %d bytes, want 32", len(key))
	}
	admitter := &NativeAdmitter{
		binding: runtime.Binding, privateKey: key, store: runtime.store,
		udpOpts:    append([]qurl.AgentRuntimeUDPOption(nil), runtime.UDPOptions...),
		refreshCfg: runtime.refreshCfg,
		live:       make(map[nativeAdmissionKey]nativeLiveAdmission),
		pending:    make(map[nativeAdmissionKey]bool),
	}
	runtime.Binding = nil
	runtime.store = nil
	runtime.Client = nil
	runtime.UDPOptions = nil
	runtime.refreshCfg = nativeRefreshConfig{}
	return admitter, nil
}

func (a *NativeAdmitter) Admit(ctx context.Context, knockResourceID, resourceID string) (Admission, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.binding == nil || len(a.privateKey) != 32 {
		return Admission{}, errors.New("native admitter is closed")
	}
	a.ensureAdmissionMapsLocked()
	if err := a.retirePendingForResourceLocked(ctx, resourceID); err != nil {
		return Admission{}, fmt.Errorf("retire prior native NHP session before replacement: %w", err)
	}
	admission, err := a.knockLocked(ctx, knockResourceID, resourceID)
	if err == nil {
		a.failures = 0
		return admission, nil
	}
	if !refreshableKnockError(err) {
		// A non-placement result breaks the consecutive placement-failure
		// streak. In particular, an authenticated deny proves that the current
		// cell and key path are live, so a later transport failure starts a new
		// recovery budget.
		a.failures = 0
		return Admission{}, err
	}
	a.failures++
	if a.failures < 5 {
		return Admission{}, err
	}
	if refreshErr := a.refreshLocked(ctx); refreshErr != nil {
		return Admission{}, errors.Join(err, refreshErr)
	}
	a.failures = 0
	return a.knockLocked(ctx, knockResourceID, resourceID)
}

func (a *NativeAdmitter) knockLocked(ctx context.Context, knockResourceID, resourceID string) (Admission, error) {
	runID, err := qurl.NewCycleRunID()
	if err != nil {
		return Admission{}, err
	}
	result, err := knockNativeRuntime(
		ctx, a.binding, a.privateKey, knockResourceID,
		qurl.NativeKnockOptions{RunID: runID, RunAttempt: 1}, a.udpOpts...,
	)
	if err != nil {
		var deny *qurl.ServerDenyError
		if errors.As(err, &deny) && deny.ErrCode == "52004" {
			return Admission{}, fmt.Errorf("%w: %w", ErrResourceGone, err)
		}
		return Admission{}, err
	}
	if result == nil {
		return Admission{}, errors.New("native knock returned no admission")
	}
	admission := Admission{
		KnockResourceID: knockResourceID, ResourceID: resourceID,
		RunID: runID, Token: result.ACToken, ResourceHost: result.ResourceHost,
		RunAttempt: 1, SessionID: result.SessionID, SessionReceipt: result.SessionReceipt,
		OpenTime: time.Duration(result.OpenTime) * time.Second,
	}
	if err := validateAdmission(admission, knockResourceID, resourceID); err != nil {
		// The authenticated ACK may already have opened server-side authority.
		// Track and retire that exact receipt even when a stricter local
		// invariant (for example canonical host:port) rejects the result.
		key, trackErr := a.trackAdmissionLocked(admission)
		if trackErr != nil {
			return Admission{}, errors.Join(err, trackErr)
		}
		a.pending[key] = true
		return Admission{}, errors.Join(err, a.retireOneLocked(ctx, key, a.live[key]))
	}
	if _, err := a.trackAdmissionLocked(admission); err != nil {
		return Admission{}, err
	}
	return admission, nil
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

func (a *NativeAdmitter) refreshLocked(ctx context.Context) error {
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

// Retire durably closes only the exact NHP session represented by admission.
// A failed retirement remains pending and must succeed before the same
// resource can obtain another admission.
func (a *NativeAdmitter) Retire(ctx context.Context, admission Admission) error {
	if ctx == nil {
		return errors.New("retire native admission: context is nil")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.binding == nil || len(a.privateKey) != 32 {
		return errors.New("native admitter is closed")
	}
	a.ensureAdmissionMapsLocked()
	if err := validateAdmissionReceipt(admission); err != nil {
		return err
	}
	key := admissionKey(admission.SessionReceipt)
	live, ok := a.live[key]
	if !ok {
		return nil
	}
	if live.resourceID != admission.ResourceID || !sameSessionReceipt(live.receipt, admission.SessionReceipt) {
		return errors.New("retire native admission: exact-session receipt does not match the live admission")
	}
	a.pending[key] = true
	return a.retireOneLocked(ctx, key, live)
}

func (a *NativeAdmitter) ensureAdmissionMapsLocked() {
	if a.live == nil {
		a.live = make(map[nativeAdmissionKey]nativeLiveAdmission)
	}
	if a.pending == nil {
		a.pending = make(map[nativeAdmissionKey]bool)
	}
}

func (a *NativeAdmitter) trackAdmissionLocked(admission Admission) (nativeAdmissionKey, error) {
	if err := validateAdmissionReceipt(admission); err != nil {
		return nativeAdmissionKey{}, err
	}
	key := admissionKey(admission.SessionReceipt)
	if existing, ok := a.live[key]; ok &&
		(existing.resourceID != admission.ResourceID || !sameSessionReceipt(existing.receipt, admission.SessionReceipt)) {
		return nativeAdmissionKey{}, errors.New("track native admission: exact-session identity conflicts with a live admission")
	}
	a.live[key] = nativeLiveAdmission{resourceID: admission.ResourceID, receipt: admission.SessionReceipt}
	return key, nil
}

func admissionKey(receipt qurl.NativeSessionReceipt) nativeAdmissionKey {
	return nativeAdmissionKey{
		cellID: receipt.CellID, sessionID: receipt.SessionID,
		sessionIssuedAtMillis: receipt.SessionIssuedAtMillis,
		runID:                 receipt.RunID, runAttempt: receipt.RunAttempt,
	}
}

func (a *NativeAdmitter) retirePendingForResourceLocked(ctx context.Context, resourceID string) error {
	for key := range a.pending {
		live, ok := a.live[key]
		if !ok {
			delete(a.pending, key)
			continue
		}
		if live.resourceID != resourceID {
			continue
		}
		if err := a.retireOneLocked(ctx, key, live); err != nil {
			return err
		}
	}
	return nil
}

func (a *NativeAdmitter) retireOneLocked(ctx context.Context, key nativeAdmissionKey, live nativeLiveAdmission) error {
	if _, err := retireNativeSession(ctx, a.binding, a.privateKey, live.receipt, a.udpOpts...); err != nil {
		return err
	}
	delete(a.pending, key)
	delete(a.live, key)
	live.receipt = qurl.NativeSessionReceipt{}
	return nil
}

func sameSessionReceipt(a, b qurl.NativeSessionReceipt) bool {
	return a.CellID == b.CellID && a.SessionID == b.SessionID &&
		a.SessionIssuedAtMillis == b.SessionIssuedAtMillis && a.RunID == b.RunID && a.RunAttempt == b.RunAttempt
}

func (a *NativeAdmitter) MarkServingHealthy() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.store == nil {
		return errors.New("native admitter is closed")
	}
	return a.store.ClearRegistrationRefreshMarker()
}

func (a *NativeAdmitter) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	binding := a.binding
	privateKey := a.privateKey
	udpOpts := a.udpOpts
	store := a.store
	var closeErr error
	if binding != nil && len(privateKey) == 32 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		type closeResult struct {
			key nativeAdmissionKey
			err error
		}
		results := make(chan closeResult, len(a.live))
		var retireWG sync.WaitGroup
		// Exact retirement is safe to fan out through one binding. qurl-go's
		// RetireRegisteredAgentSession does not renew or mutate the binding: it
		// reads the binding's immutable identity, takes the issuing endpoint from
		// each immutable receipt, and gives every call its own config, packet,
		// UDP socket, and reply buffer. The private key stays read-only until this
		// wait completes. Parallel calls are required here so one silent issuing
		// cell cannot consume the whole shutdown budget and prevent later exact
		// receipts from being attempted.
		for key, live := range a.live {
			retireWG.Add(1)
			go func(key nativeAdmissionKey, receipt qurl.NativeSessionReceipt) {
				defer retireWG.Done()
				_, err := retireNativeSession(ctx, binding, privateKey, receipt, udpOpts...)
				results <- closeResult{key: key, err: err}
			}(key, live.receipt)
		}
		retireWG.Wait()
		close(results)
		for result := range results {
			if result.err != nil {
				closeErr = errors.Join(closeErr, result.err)
				continue
			}
			delete(a.pending, result.key)
			delete(a.live, result.key)
		}
		cancel()
	}
	a.binding = nil
	a.privateKey = nil
	a.udpOpts = nil
	a.store = nil
	a.live = nil
	a.pending = nil
	a.mu.Unlock()
	clear(privateKey)
	if binding != nil {
		binding.Destroy()
	}
	if store != nil {
		closeErr = errors.Join(closeErr, store.Close())
	}
	return closeErr
}
