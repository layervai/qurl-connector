package share

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	qurl "github.com/layervai/qurl-go/qurl"
	"github.com/layervai/qurl-go/relayknock/nativeudp"

	"github.com/layervai/qurl-connector/pkg/agentstate"
)

type memoryNativeStore struct {
	mu      sync.Mutex
	marker  agentstate.RefreshMarker
	present bool
	loadErr error
	marks   int
	cleared int
	closed  int
}

func (*memoryNativeStore) Handoff() (qurl.AgentStateStore, error) { return nil, nil }
func (*memoryNativeStore) ValidateContinuity() error              { return nil }
func (s *memoryNativeStore) LoadRegistrationRefreshMarker() (agentstate.RefreshMarker, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.marker, s.present, s.loadErr
}
func (s *memoryNativeStore) RequestRegistrationRefresh(reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.present = true
	s.marker = agentstate.RefreshMarker{Version: 2, Reason: reason}
	return nil
}
func (s *memoryNativeStore) MarkRegistrationRefreshAttempted() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.marks++
	s.marker.AttemptCount++
	s.marker.LastAttemptUnixMilli = time.Now().UnixMilli()
	s.marker.NextAttemptUnixMilli = s.marker.LastAttemptUnixMilli + 1
	return nil
}
func (s *memoryNativeStore) ClearRegistrationRefreshMarker() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleared++
	s.present = false
	s.loadErr = nil
	return nil
}
func (s *memoryNativeStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed++
	return nil
}

func TestOpenNativeRuntimeAutomaticallyRetriesAssignmentRefresh(t *testing.T) {
	oldStore := newNativeStateStore
	oldRefresh := refreshNativeRuntime
	oldWait := waitNativeRefresh
	t.Cleanup(func() {
		newNativeStateStore = oldStore
		refreshNativeRuntime = oldRefresh
		waitNativeRefresh = oldWait
	})
	store := &memoryNativeStore{
		present: true,
		marker: agentstate.RefreshMarker{
			Version: 2, Reason: "network recovery", NextAttemptUnixMilli: time.Now().Add(time.Millisecond).UnixMilli(),
		},
	}
	newNativeStateStore = func(string, string) (nativeStateStore, error) { return store, nil }
	waits := 0
	waitNativeRefresh = func(context.Context, time.Duration) error {
		waits++
		return nil
	}
	attempts := 0
	refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		attempts++
		if attempts <= 3 {
			return nil, nil, errors.Join(errors.New("assignment retry budget exhausted"), qurl.ErrAssignmentRateLimited)
		}
		return &qurl.Client{}, &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, nil
	}
	runtime, err := OpenNativeRuntime(context.Background(), NativeRuntimeConfig{StateDir: "/private/state", RefreshMode: "auto"})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 4 || store.marks != 4 {
		t.Fatalf("refresh attempts=%d persisted attempts=%d, want 4", attempts, store.marks)
	}
	if waits == 0 {
		t.Fatal("persisted assignment refresh backoff was ignored")
	}
	if store.cleared != 0 {
		t.Fatal("refresh marker cleared before FRP reported serving")
	}
	if err := runtime.MarkServingHealthy(); err != nil {
		t.Fatal(err)
	}
	if store.cleared != 1 {
		t.Fatalf("healthy serving clears = %d, want 1", store.cleared)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAssignmentRateLimitRemainsInAutomaticOuterBackoff(t *testing.T) {
	if permanentRefreshError(errors.Join(errors.New("inner retry budget exhausted"), qurl.ErrAssignmentRateLimited)) {
		t.Fatal("assignment rate limiting must remain retryable by the persisted outer recovery loop")
	}
}

func TestAssignmentRefreshRetriesOnlyRecoverablePlacementAndPersistenceFailures(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		permanent bool
	}{
		{name: "nil"},
		{name: "assignment unavailable", err: qurl.ErrAssignmentUnavailable},
		{name: "assignment budget exhausted", err: errors.Join(qurl.ErrAssignmentRecoveryRequired, qurl.ErrAssignmentUnavailable)},
		{name: "assignment rate limited", err: qurl.ErrAssignmentRateLimited},
		{name: "reassignment in progress", err: qurl.ErrAssignmentReassignmentRequired},
		{name: "Hub transport", err: nativeudp.ErrTransport},
		{name: "Hub DNS", err: nativeudp.ErrResolve},
		{name: "Hub no reply", err: nativeudp.ErrNoReply},
		{name: "Hub authentication", err: nativeudp.ErrServerUnauthenticated},
		{name: "state save interrupted", err: qurl.ErrAgentBindingPersistence},
		{name: "state key service unavailable", err: qurl.ErrAgentStateKeyWrapper},
		{name: "state read I/O", err: errors.Join(qurl.ErrInvalidRegisterConfig, &os.PathError{Op: "read", Path: "agent-state", Err: errors.New("input/output error")})},
		{name: "state permission", err: errors.Join(qurl.ErrInvalidRegisterConfig, &os.PathError{Op: "open", Path: "agent-state", Err: os.ErrPermission}), permanent: true},
		{name: "invalid refresh config", err: qurl.ErrInvalidRegisterConfig, permanent: true},
		{name: "invalid client config", err: qurl.ErrInvalidClientConfig, permanent: true},
		{name: "invalid bootstrap config", err: qurl.ErrInvalidBootstrapConfig, permanent: true},
		{name: "corrupt state", err: errors.Join(qurl.ErrInvalidRegisterConfig, qurl.ErrInvalidAgentState), permanent: true},
		{name: "insecure state permissions", err: qurl.ErrInsecureAgentStatePermissions, permanent: true},
		{name: "missing completed state", err: errors.Join(qurl.ErrInvalidRegisterConfig, qurl.ErrAgentStateNotFound), permanent: true},
		{name: "credential recovery required", err: errors.Join(qurl.ErrInvalidRegisterConfig, qurl.ErrCredentialRecoveryRequired), permanent: true},
		{name: "invalid assignment config", err: qurl.ErrInvalidAssignmentConfig, permanent: true},
		{name: "invalid assignment response", err: qurl.ErrAssignmentInvalidResponse, permanent: true},
		{name: "assignment continuity", err: qurl.ErrAssignmentEndpointContinuity, permanent: true},
		{name: "authenticated assignment deny", err: qurl.ErrAssignmentIdentityRejected, permanent: true},
		{name: "unknown future error", err: errors.New("unexpected refresh failure"), permanent: true},
		{name: "caller canceled", err: context.Canceled, permanent: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := permanentRefreshError(test.err); got != test.permanent {
				t.Fatalf("permanentRefreshError(%v) = %t, want %t", test.err, got, test.permanent)
			}
		})
	}
}

func TestOpenNativeRuntimeStopsAutomaticRefreshOnCorruptCompletedState(t *testing.T) {
	oldStore := newNativeStateStore
	oldRefresh := refreshNativeRuntime
	oldWait := waitNativeRefresh
	t.Cleanup(func() {
		newNativeStateStore = oldStore
		refreshNativeRuntime = oldRefresh
		waitNativeRefresh = oldWait
	})
	store := &memoryNativeStore{present: true, marker: agentstate.RefreshMarker{Version: 2, Reason: "placement recovery"}}
	newNativeStateStore = func(string, string) (nativeStateStore, error) { return store, nil }
	waitNativeRefresh = func(context.Context, time.Duration) error { return nil }
	attempts := 0
	refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		attempts++
		return nil, nil, errors.Join(qurl.ErrInvalidRegisterConfig, qurl.ErrInvalidAgentState)
	}
	_, err := OpenNativeRuntime(context.Background(), NativeRuntimeConfig{StateDir: "/private/state", RefreshMode: "auto"})
	if !errors.Is(err, qurl.ErrInvalidAgentState) {
		t.Fatalf("OpenNativeRuntime() = %v, want corrupt-state error", err)
	}
	if attempts != 1 || store.marks != 1 || !store.present || store.cleared != 0 {
		t.Fatalf("corrupt refresh attempts=%d marks=%d present=%t clears=%d, want 1/1/true/0", attempts, store.marks, store.present, store.cleared)
	}
}

func TestNativeOpenPermanentClassification(t *testing.T) {
	for name, err := range map[string]error{
		"bad enrollment token": qurl.ErrAssignmentKeyRejected,
		"consumed token":       qurl.ErrAssignmentBootstrapConsumed,
		"registration policy":  qurl.ErrRegistrationDisabled,
		"corrupt state":        qurl.ErrInvalidAgentState,
		"authenticated deny":   &qurl.ServerDenyError{ErrCode: "52999"},
	} {
		t.Run(name, func(t *testing.T) {
			if !IsPermanentNativeOpenError(err) {
				t.Fatalf("%v classified retryable", err)
			}
		})
	}
	for name, err := range map[string]error{
		"assignment rate limit":  qurl.ErrAssignmentRateLimited,
		"registration rate":      qurl.ErrRegistrationRateLimited,
		"assignment unavailable": qurl.ErrAssignmentUnavailable,
		"endpoint no reply":      qurl.ErrEndpointNoReply,
		"server overload":        qurl.ErrServerOverloaded,
		"transport":              errors.New("temporary network failure"),
	} {
		t.Run(name, func(t *testing.T) {
			if IsPermanentNativeOpenError(err) {
				t.Fatalf("%v classified permanent", err)
			}
		})
	}
}

func TestOpenNativeRuntimeClearsCorruptRefreshStateAndWarmOpens(t *testing.T) {
	oldStore := newNativeStateStore
	oldConnect := connectNativeRuntime
	t.Cleanup(func() {
		newNativeStateStore = oldStore
		connectNativeRuntime = oldConnect
	})
	store := &memoryNativeStore{loadErr: errors.Join(agentstate.ErrInvalidRefreshMarker, errors.New("truncated JSON"))}
	newNativeStateStore = func(string, string) (nativeStateStore, error) { return store, nil }
	connectNativeRuntime = func(context.Context, qurl.AgentStateStore, ...qurl.AgentRuntimeRegistrationOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		return &qurl.Client{}, &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, nil
	}
	runtime, err := OpenNativeRuntime(context.Background(), NativeRuntimeConfig{StateDir: "/private/state"})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.OpenKind != NativeOpenWarm || store.cleared != 1 {
		t.Fatalf("open kind=%q clears=%d, want warm/1", runtime.OpenKind, store.cleared)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenNativeRuntimeRetainsRefreshStateOnReadFailure(t *testing.T) {
	oldStore := newNativeStateStore
	t.Cleanup(func() { newNativeStateStore = oldStore })
	want := errors.New("input/output error")
	store := &memoryNativeStore{loadErr: want, present: true}
	newNativeStateStore = func(string, string) (nativeStateStore, error) { return store, nil }
	if _, err := OpenNativeRuntime(context.Background(), NativeRuntimeConfig{StateDir: "/private/state"}); !errors.Is(err, want) {
		t.Fatalf("OpenNativeRuntime() = %v, want I/O error", err)
	}
	if store.cleared != 0 || !store.present {
		t.Fatalf("I/O failure mutated refresh state: clears=%d present=%t", store.cleared, store.present)
	}
	if store.closed != 1 {
		t.Fatalf("store closes = %d, want 1", store.closed)
	}
}

func TestNativeAdmitterRecoversSustainedStaleAssignmentWithoutOperatorInput(t *testing.T) {
	oldKnock := knockNativeRuntime
	oldRefresh := refreshNativeRuntime
	oldWait := waitNativeRefresh
	oldTakeKey := takeNativeKey
	t.Cleanup(func() {
		knockNativeRuntime = oldKnock
		refreshNativeRuntime = oldRefresh
		waitNativeRefresh = oldWait
		takeNativeKey = oldTakeKey
	})
	store := &memoryNativeStore{}
	waitNativeRefresh = func(context.Context, time.Duration) error { return nil }
	takeNativeKey = func(*qurl.AgentRuntimeBinding) []byte { return make([]byte, 32) }
	knocks := 0
	knockNativeRuntime = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte, _ string, opts qurl.NativeKnockOptions, _ ...qurl.AgentRuntimeUDPOption) (*qurl.NativeKnockResult, error) {
		knocks++
		if knocks <= 5 {
			return nil, nativeudp.ErrTransport
		}
		return &qurl.NativeKnockResult{
			ACToken: "token", ResourceHost: "frp.example:7000", SessionID: 77, OpenTime: 120,
			SessionReceipt: testSessionReceipt(77, opts.RunID, opts.RunAttempt),
		}, nil
	}
	refreshes := 0
	refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		refreshes++
		if refreshes <= 2 {
			return nil, nil, qurl.ErrAssignmentUnavailable
		}
		return &qurl.Client{}, &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, nil
	}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		store: store, refreshCfg: nativeRefreshConfig{AgentID: "agent-one", RefreshMode: "auto"},
	}
	for attempt := 1; attempt < 5; attempt++ {
		if _, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource"); !errors.Is(err, nativeudp.ErrTransport) {
			t.Fatalf("knock %d = %v, want transport failure", attempt, err)
		}
	}
	admission, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource")
	if err != nil {
		t.Fatal(err)
	}
	if admission.SessionID != 77 || admission.KnockResourceID != "q_catalog_key" || admission.ResourceID != "public-resource" {
		t.Fatalf("recovered admission = %+v", admission)
	}
	if refreshes != 3 || store.marks != 3 || knocks != 6 {
		t.Fatalf("refreshes=%d persisted attempts=%d knocks=%d, want 3/3/6", refreshes, store.marks, knocks)
	}
	if store.cleared != 0 {
		t.Fatal("assignment recovery cleared before a serving FRP session")
	}
	if err := admitter.MarkServingHealthy(); err != nil || store.cleared != 1 {
		t.Fatalf("MarkServingHealthy() = %v, clears=%d", err, store.cleared)
	}
}

func TestRefreshableKnockErrorClassification(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil},
		{name: "authenticated resource deny", err: &qurl.ServerDenyError{ErrCode: "52004"}},
		{name: "authenticated policy deny", err: &qurl.ServerDenyError{ErrCode: "52001"}},
		{name: "authenticated canonical deny", err: &qurl.ServerDenyError{ErrCode: "52025"}},
		{name: "authenticated future deny", err: &qurl.ServerDenyError{ErrCode: "52999"}},
		{name: "invalid input", err: qurl.ErrInvalidNativeKnockInput},
		{name: "malformed reply", err: qurl.ErrMalformedReply},
		{name: "server overloaded", err: qurl.ErrServerOverloaded},
		{name: "caller canceled", err: context.Canceled},
		{name: "caller deadline", err: context.DeadlineExceeded},
		{name: "bare assignment unavailable", err: qurl.ErrAssignmentUnavailable},
		{name: "bare assignment rate limit", err: qurl.ErrAssignmentRateLimited},
		{name: "unknown", err: errors.New("unexpected admission failure")},
		{name: "DNS", err: nativeudp.ErrResolve, want: true},
		{name: "transport", err: nativeudp.ErrTransport, want: true},
		{name: "no reply", err: nativeudp.ErrNoReply, want: true},
		{name: "server authentication", err: nativeudp.ErrServerUnauthenticated, want: true},
		{name: "expired placement wrapped as invalid input", err: errors.Join(qurl.ErrInvalidNativeKnockInput, qurl.ErrAssignmentLeaseExpired), want: true},
		{name: "bounded live placement recovery", err: errors.Join(qurl.ErrAssignmentRecoveryRequired, qurl.ErrAssignmentUnavailable, context.DeadlineExceeded), want: true},
		{name: "authoritative relocation", err: qurl.ErrAssignmentReassignmentRequired, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := refreshableKnockError(test.err); got != test.want {
				t.Fatalf("refreshableKnockError(%v) = %t, want %t", test.err, got, test.want)
			}
		})
	}
}

func TestNativeAdmitterRefreshesOnlySustainedPlacementFailures(t *testing.T) {
	oldKnock := knockNativeRuntime
	oldRefresh := refreshNativeRuntime
	oldTakeKey := takeNativeKey
	t.Cleanup(func() {
		knockNativeRuntime = oldKnock
		refreshNativeRuntime = oldRefresh
		takeNativeKey = oldTakeKey
	})
	takeNativeKey = func(*qurl.AgentRuntimeBinding) []byte { return make([]byte, 32) }

	tests := []struct {
		name        string
		err         error
		wantRefresh bool
	}{
		{name: "authenticated policy deny", err: &qurl.ServerDenyError{ErrCode: "52001"}},
		{name: "authenticated future deny", err: &qurl.ServerDenyError{ErrCode: "52999"}},
		{name: "overload", err: qurl.ErrServerOverloaded},
		{name: "malformed reply", err: qurl.ErrMalformedReply},
		{name: "invalid input", err: qurl.ErrInvalidNativeKnockInput},
		{name: "canceled", err: context.Canceled},
		{name: "deadline", err: context.DeadlineExceeded},
		{name: "unknown", err: errors.New("unknown failure")},
		{name: "DNS", err: nativeudp.ErrResolve, wantRefresh: true},
		{name: "no reply", err: nativeudp.ErrNoReply, wantRefresh: true},
		{name: "transport", err: nativeudp.ErrTransport, wantRefresh: true},
		{name: "server authentication", err: nativeudp.ErrServerUnauthenticated, wantRefresh: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &memoryNativeStore{}
			knockNativeRuntime = func(context.Context, *qurl.AgentRuntimeBinding, []byte, string, qurl.NativeKnockOptions, ...qurl.AgentRuntimeUDPOption) (*qurl.NativeKnockResult, error) {
				return nil, test.err
			}
			refreshes := 0
			refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
				refreshes++
				return &qurl.Client{}, &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, nil
			}
			admitter := &NativeAdmitter{
				binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
				store: store, refreshCfg: nativeRefreshConfig{AgentID: "agent-one", RefreshMode: "auto"},
			}
			for attempt := 0; attempt < 5; attempt++ {
				_, _ = admitter.Admit(context.Background(), "q_catalog_key", "public-resource")
			}
			wantRefreshes := 0
			if test.wantRefresh {
				wantRefreshes = 1
			}
			if refreshes != wantRefreshes || store.marks != wantRefreshes {
				t.Fatalf("refreshes=%d persisted attempts=%d, want %d", refreshes, store.marks, wantRefreshes)
			}
			if !test.wantRefresh && store.present {
				t.Fatal("non-placement failure armed assignment refresh state")
			}
		})
	}
}

func TestNativeAdmitterDisabledModeDoesNotRefreshAfterLiveFailures(t *testing.T) {
	oldKnock := knockNativeRuntime
	oldRefresh := refreshNativeRuntime
	t.Cleanup(func() {
		knockNativeRuntime = oldKnock
		refreshNativeRuntime = oldRefresh
	})
	knockNativeRuntime = func(context.Context, *qurl.AgentRuntimeBinding, []byte, string, qurl.NativeKnockOptions, ...qurl.AgentRuntimeUDPOption) (*qurl.NativeKnockResult, error) {
		return nil, nativeudp.ErrNoReply
	}
	refreshes := 0
	refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		refreshes++
		return &qurl.Client{}, &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, nil
	}
	store := &memoryNativeStore{}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		store: store, refreshCfg: nativeRefreshConfig{AgentID: "agent-one", RefreshMode: "disabled"},
	}
	for attempt := 1; attempt <= 4; attempt++ {
		if _, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource"); !errors.Is(err, nativeudp.ErrNoReply) {
			t.Fatalf("attempt %d = %v, want no-reply failure", attempt, err)
		}
	}
	_, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource")
	if err == nil || !strings.Contains(err.Error(), "assignment refresh is disabled") {
		t.Fatalf("fifth attempt = %v, want disabled diagnostic", err)
	}
	if refreshes != 0 || store.marks != 0 || !store.present {
		t.Fatalf("disabled mode refreshes=%d marks=%d marker-present=%t, want 0/0/true", refreshes, store.marks, store.present)
	}
}

func TestNativeAdmitterCountsOnlyConsecutivePlacementFailures(t *testing.T) {
	oldKnock := knockNativeRuntime
	oldRefresh := refreshNativeRuntime
	oldTakeKey := takeNativeKey
	t.Cleanup(func() {
		knockNativeRuntime = oldKnock
		refreshNativeRuntime = oldRefresh
		takeNativeKey = oldTakeKey
	})
	takeNativeKey = func(*qurl.AgentRuntimeBinding) []byte { return make([]byte, 32) }
	knocks := 0
	knockNativeRuntime = func(context.Context, *qurl.AgentRuntimeBinding, []byte, string, qurl.NativeKnockOptions, ...qurl.AgentRuntimeUDPOption) (*qurl.NativeKnockResult, error) {
		knocks++
		if knocks == 5 {
			return nil, &qurl.ServerDenyError{ErrCode: "52001"}
		}
		return nil, nativeudp.ErrNoReply
	}
	refreshes := 0
	refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		refreshes++
		return &qurl.Client{}, &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, nil
	}
	store := &memoryNativeStore{}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		store: store, refreshCfg: nativeRefreshConfig{AgentID: "agent-one", RefreshMode: "auto"},
	}
	for attempt := 1; attempt <= 9; attempt++ {
		_, _ = admitter.Admit(context.Background(), "q_catalog_key", "public-resource")
	}
	if refreshes != 0 || store.present {
		t.Fatalf("four failures, a live deny, and four failures refreshed: refreshes=%d marker=%t", refreshes, store.present)
	}
	_, _ = admitter.Admit(context.Background(), "q_catalog_key", "public-resource")
	if refreshes != 1 || store.marks != 1 {
		t.Fatalf("fifth consecutive failure refreshes=%d marks=%d, want 1/1", refreshes, store.marks)
	}
}

func TestNativeAdmitterDoesNotRetainEnrollmentCredential(t *testing.T) {
	oldTakeKey := takeNativeKey
	oldRetire := retireNativeSession
	t.Cleanup(func() {
		takeNativeKey = oldTakeKey
		retireNativeSession = oldRetire
	})
	takeNativeKey = func(*qurl.AgentRuntimeBinding) []byte { return make([]byte, 32) }
	retireNativeSession = func(context.Context, *qurl.AgentRuntimeBinding, []byte, qurl.NativeSessionReceipt, ...qurl.AgentRuntimeUDPOption) (*qurl.NativeSessionRetirement, error) {
		return &qurl.NativeSessionRetirement{}, nil
	}
	provider := func(context.Context, qurl.AgentEnrollmentCredentialRequest) (string, error) {
		return "enroll-token", nil
	}
	runtime := &NativeRuntime{
		Binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"},
		store:   &memoryNativeStore{},
		refreshCfg: refreshConfig(NativeRuntimeConfig{
			StateDir: "/private/state", AgentID: "agent-one",
			EnrollmentCredential: "secret", EnrollmentCredentialProvider: provider,
		}, "auto"),
	}
	admitter, err := NewNativeAdmitter(runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer admitter.Close()
	if admitter.refreshCfg.StateDir != "/private/state" || admitter.refreshCfg.AgentID != "agent-one" {
		t.Fatalf("retained refresh config = %+v", admitter.refreshCfg)
	}
	// The dedicated retained type deliberately has no credential or provider
	// fields; this assertion also guards accidental retention via the runtime.
	if runtime.refreshCfg.StateDir != "" || runtime.refreshCfg.AgentID != "" ||
		runtime.refreshCfg.ClientBaseURL != "" || runtime.refreshCfg.RefreshMode != "" ||
		len(runtime.refreshCfg.UDPOptions) != 0 {
		t.Fatalf("transferred runtime retained refresh config = %+v", runtime.refreshCfg)
	}
}

func TestNativeAdmitterRetiresOnlyExactLiveSessions(t *testing.T) {
	oldRetire := retireNativeSession
	t.Cleanup(func() { retireNativeSession = oldRetire })
	var retired []uint64
	retireNativeSession = func(_ context.Context, binding *qurl.AgentRuntimeBinding, key []byte, receipt qurl.NativeSessionReceipt, _ ...qurl.AgentRuntimeUDPOption) (*qurl.NativeSessionRetirement, error) {
		retired = append(retired, receipt.SessionID)
		if binding == nil || len(key) != 32 {
			t.Fatal("exact retirement lost native runtime identity")
		}
		return &qurl.NativeSessionRetirement{SessionReceipt: receipt}, nil
	}
	receipt1 := testSessionReceipt(1, "run-one", 1)
	receipt2 := testSessionReceipt(2, "run-two", 1)
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		store: &memoryNativeStore{},
		live: map[nativeAdmissionKey]nativeLiveAdmission{
			admissionKey(receipt1): {resourceID: "resource-one", receipt: receipt1},
			admissionKey(receipt2): {resourceID: "resource-two", receipt: receipt2},
		},
		pending: make(map[nativeAdmissionKey]bool),
	}
	admission1 := Admission{
		ResourceID: "resource-one", RunID: "run-one", RunAttempt: 1, Token: "token",
		ResourceHost: "127.0.0.1:7000", SessionID: 1, SessionReceipt: receipt1, OpenTime: time.Minute,
	}
	if err := admitter.Retire(context.Background(), admission1); err != nil {
		t.Fatal(err)
	}
	if len(retired) != 1 || retired[0] != 1 {
		t.Fatalf("exact retirements = %v, want [1]", retired)
	}
	if err := admitter.Close(); err != nil {
		t.Fatal(err)
	}
	if len(retired) != 2 || retired[1] != 2 {
		t.Fatalf("close retirements = %v, want [1 2]", retired)
	}
	if err := admitter.Close(); err != nil || len(retired) != 2 {
		t.Fatalf("repeated Close = %v, retirements=%v", err, retired)
	}
}

func TestNativeAdmitterCloseAttemptsEveryLiveSessionWithinSharedBudget(t *testing.T) {
	oldRetire := retireNativeSession
	t.Cleanup(func() { retireNativeSession = oldRetire })

	firstReceipt := testSessionReceipt(1, "run-one", 1)
	secondReceipt := testSessionReceipt(2, "run-two", 1)
	secondStarted := make(chan struct{})
	var secondOnce sync.Once
	retireNativeSession = func(ctx context.Context, _ *qurl.AgentRuntimeBinding, _ []byte, receipt qurl.NativeSessionReceipt, _ ...qurl.AgentRuntimeUDPOption) (*qurl.NativeSessionRetirement, error) {
		switch receipt.SessionID {
		case firstReceipt.SessionID:
			select {
			case <-secondStarted:
				return nil, errors.New("first retirement stalled")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		case secondReceipt.SessionID:
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("second retirement started with an expired shared budget: %w", err)
			}
			secondOnce.Do(func() { close(secondStarted) })
			return &qurl.NativeSessionRetirement{SessionReceipt: receipt}, nil
		default:
			return nil, fmt.Errorf("unexpected receipt: %+v", receipt)
		}
	}

	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		store: &memoryNativeStore{},
		live: map[nativeAdmissionKey]nativeLiveAdmission{
			admissionKey(firstReceipt):  {resourceID: "resource-one", receipt: firstReceipt},
			admissionKey(secondReceipt): {resourceID: "resource-two", receipt: secondReceipt},
		},
		pending: make(map[nativeAdmissionKey]bool),
	}
	err := admitter.Close()
	if err == nil || !strings.Contains(err.Error(), "first retirement stalled") {
		t.Fatalf("Close() error = %v, want first retirement failure", err)
	}
	if strings.Contains(err.Error(), "second retirement started with an expired shared budget") {
		t.Fatalf("Close() starved the second retirement: %v", err)
	}
	select {
	case <-secondStarted:
	default:
		t.Fatal("Close() did not attempt the second exact retirement")
	}
}

func TestNativeAdmitterKeepsSameNumericSessionIDsFromDifferentCellsDistinct(t *testing.T) {
	oldKnock := knockNativeRuntime
	oldRetire := retireNativeSession
	t.Cleanup(func() {
		knockNativeRuntime = oldKnock
		retireNativeSession = oldRetire
	})

	knocks := 0
	knockNativeRuntime = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte, _ string, opts qurl.NativeKnockOptions, _ ...qurl.AgentRuntimeUDPOption) (*qurl.NativeKnockResult, error) {
		knocks++
		receipt := testSessionReceipt(77, opts.RunID, opts.RunAttempt)
		receipt.CellID = fmt.Sprintf("cell%d", knocks)
		receipt.SessionIssuedAtMillis = int64(knocks)
		return &qurl.NativeKnockResult{
			ACToken: "token", ResourceHost: "127.0.0.1:7000", SessionID: 77, OpenTime: 60,
			SessionReceipt: receipt,
		}, nil
	}
	var retired []qurl.NativeSessionReceipt
	retireNativeSession = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte, receipt qurl.NativeSessionReceipt, _ ...qurl.AgentRuntimeUDPOption) (*qurl.NativeSessionRetirement, error) {
		retired = append(retired, receipt)
		return &qurl.NativeSessionRetirement{SessionReceipt: receipt}, nil
	}

	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		store: &memoryNativeStore{},
	}
	first, err := admitter.Admit(context.Background(), "q_one", "resource-one")
	if err != nil {
		t.Fatal(err)
	}
	second, err := admitter.Admit(context.Background(), "q_two", "resource-two")
	if err != nil {
		t.Fatal(err)
	}
	if len(admitter.live) != 2 {
		t.Fatalf("live admissions = %d, want two exact receipts sharing numeric session ID", len(admitter.live))
	}
	if err := admitter.Retire(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if len(admitter.live) != 1 || len(retired) != 1 || retired[0].CellID != "cell1" {
		t.Fatalf("first exact retirement live=%d retired=%+v", len(admitter.live), retired)
	}
	if err := admitter.Retire(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if len(admitter.live) != 0 || len(retired) != 2 || retired[1].CellID != "cell2" {
		t.Fatalf("second exact retirement live=%d retired=%+v", len(admitter.live), retired)
	}
}

func TestNativeAdmitterRetiresPostACKAdmissionRejectedByLocalValidation(t *testing.T) {
	oldKnock := knockNativeRuntime
	oldRetire := retireNativeSession
	t.Cleanup(func() {
		knockNativeRuntime = oldKnock
		retireNativeSession = oldRetire
	})

	malformed := true
	knockNativeRuntime = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte, _ string, opts qurl.NativeKnockOptions, _ ...qurl.AgentRuntimeUDPOption) (*qurl.NativeKnockResult, error) {
		receipt := testSessionReceipt(91, opts.RunID, opts.RunAttempt)
		host := "127.0.0.1:7000"
		if malformed {
			host = "missing-port"
		}
		return &qurl.NativeKnockResult{
			ACToken: "token", ResourceHost: host, SessionID: 91, OpenTime: 60,
			SessionReceipt: receipt,
		}, nil
	}
	retireCalls := 0
	failRetirement := false
	retireNativeSession = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte, receipt qurl.NativeSessionReceipt, _ ...qurl.AgentRuntimeUDPOption) (*qurl.NativeSessionRetirement, error) {
		retireCalls++
		if failRetirement {
			return nil, nativeudp.ErrNoReply
		}
		return &qurl.NativeSessionRetirement{SessionReceipt: receipt}, nil
	}

	newAdmitter := func() *NativeAdmitter {
		return &NativeAdmitter{
			binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
			store: &memoryNativeStore{},
		}
	}
	t.Run("successful cleanup", func(t *testing.T) {
		retireCalls = 0
		failRetirement = false
		malformed = true
		admitter := newAdmitter()
		_, err := admitter.Admit(context.Background(), "q_one", "resource-one")
		if err == nil || !strings.Contains(err.Error(), "canonical host:port") {
			t.Fatalf("Admit() = %v, want local host validation failure", err)
		}
		if retireCalls != 1 || len(admitter.live) != 0 || len(admitter.pending) != 0 {
			t.Fatalf("post-ACK cleanup calls=%d live=%d pending=%d", retireCalls, len(admitter.live), len(admitter.pending))
		}
	})
	t.Run("failed cleanup is retried before replacement", func(t *testing.T) {
		retireCalls = 0
		failRetirement = true
		malformed = true
		admitter := newAdmitter()
		_, err := admitter.Admit(context.Background(), "q_one", "resource-one")
		if err == nil || !errors.Is(err, nativeudp.ErrNoReply) {
			t.Fatalf("Admit() = %v, want joined local-validation and retirement failure", err)
		}
		if retireCalls != 1 || len(admitter.live) != 1 || len(admitter.pending) != 1 {
			t.Fatalf("retained cleanup calls=%d live=%d pending=%d", retireCalls, len(admitter.live), len(admitter.pending))
		}
		failRetirement = false
		malformed = false
		if _, err := admitter.Admit(context.Background(), "q_one", "resource-one"); err != nil {
			t.Fatalf("replacement after exact cleanup = %v", err)
		}
		if retireCalls != 2 || len(admitter.pending) != 0 {
			t.Fatalf("replacement cleanup calls=%d pending=%d", retireCalls, len(admitter.pending))
		}
	})
}

func TestNativeAdmitterRetriesFailedRetirementBeforeSameResourceReplacement(t *testing.T) {
	oldRetire := retireNativeSession
	oldKnock := knockNativeRuntime
	t.Cleanup(func() {
		retireNativeSession = oldRetire
		knockNativeRuntime = oldKnock
	})

	retireCalls := 0
	var retireMu sync.Mutex
	retireNativeSession = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte, receipt qurl.NativeSessionReceipt, _ ...qurl.AgentRuntimeUDPOption) (*qurl.NativeSessionRetirement, error) {
		retireMu.Lock()
		retireCalls++
		call := retireCalls
		retireMu.Unlock()
		if receipt.SessionID == 1 && call == 1 {
			return nil, nativeudp.ErrNoReply
		}
		return &qurl.NativeSessionRetirement{SessionReceipt: receipt}, nil
	}
	nextSession := uint64(10)
	knockNativeRuntime = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte, _ string, opts qurl.NativeKnockOptions, _ ...qurl.AgentRuntimeUDPOption) (*qurl.NativeKnockResult, error) {
		if opts.RunAttempt != 1 {
			t.Fatalf("RunAttempt = %d, want 1", opts.RunAttempt)
		}
		nextSession++
		return &qurl.NativeKnockResult{
			ACToken: "token", ResourceHost: "127.0.0.1:7000", SessionID: nextSession, OpenTime: 60,
			SessionReceipt: testSessionReceipt(nextSession, opts.RunID, opts.RunAttempt),
		}, nil
	}

	receipt := testSessionReceipt(1, "run-one", 1)
	admission := Admission{
		ResourceID: "resource-one", RunID: "run-one", RunAttempt: 1,
		SessionID: 1, SessionReceipt: receipt,
	}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		store:   &memoryNativeStore{},
		live:    map[nativeAdmissionKey]nativeLiveAdmission{admissionKey(receipt): {resourceID: "resource-one", receipt: receipt}},
		pending: make(map[nativeAdmissionKey]bool),
	}
	defer admitter.Close()

	if err := admitter.Retire(context.Background(), admission); !errors.Is(err, nativeudp.ErrNoReply) {
		t.Fatalf("first Retire() = %v, want no-reply failure", err)
	}
	if _, err := admitter.Admit(context.Background(), "q_two", "resource-two"); err != nil {
		t.Fatalf("sibling admission was blocked by resource-one retirement: %v", err)
	}
	if retireCalls != 1 {
		t.Fatalf("sibling admission retried another resource retirement: calls=%d", retireCalls)
	}
	if _, err := admitter.Admit(context.Background(), "q_one", "resource-one"); err != nil {
		t.Fatalf("same-resource admission did not recover pending retirement: %v", err)
	}
	if retireCalls != 2 {
		t.Fatalf("same-resource admission retirement calls=%d, want 2", retireCalls)
	}
}
