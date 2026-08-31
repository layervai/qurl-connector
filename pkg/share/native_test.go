package share

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	qurl "github.com/layervai/qurl-go/qurl"
	"github.com/layervai/qurl-go/relayknock/nativeudp"

	"github.com/layervai/qurl-connector/pkg/agentstate"
)

type memoryNativeStore struct {
	mu               sync.Mutex
	marker           agentstate.RefreshMarker
	present          bool
	loadErr          error
	requestErr       error
	successErr       error
	attemptBackoff   time.Duration
	marks            int
	succeeded        int
	cleared          int
	closed           int
	operations       map[string][]agentstate.SessionOperationRecord
	scanPermanentErr error
	scanRetryableErr error
	handoffErr       error
	handoffErrAt     int
	handoffCalls     int
}

func (s *memoryNativeStore) Handoff() (qurl.AgentStateStore, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handoffCalls++
	if s.handoffErr != nil && (s.handoffErrAt == 0 || s.handoffCalls >= s.handoffErrAt) {
		return nil, s.handoffErr
	}
	return nil, nil
}
func (*memoryNativeStore) ValidateContinuity() error { return nil }
func (s *memoryNativeStore) LoadRegistrationRefreshMarker() (agentstate.RefreshMarker, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.marker, s.present, s.loadErr
}
func (s *memoryNativeStore) RequestRegistrationRefresh(reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.requestErr != nil {
		return s.requestErr
	}
	// Match the production store's presence gate: opening the same episode again
	// must preserve its attempt count and next-at time.
	if s.present {
		return nil
	}
	s.present = true
	s.marker = agentstate.RefreshMarker{Version: 2, Reason: reason}
	return nil
}
func (s *memoryNativeStore) MarkRegistrationRefreshAttempted() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.marks++
	s.marker.AttemptCount++
	now := time.Now()
	s.marker.LastAttemptUnixMilli = now.UnixMilli()
	base := s.attemptBackoff
	if base <= 0 {
		base = time.Millisecond
	}
	shift := min(s.marker.AttemptCount-1, uint32(8))
	delay := base * time.Duration(1<<shift)
	if delay > 5*time.Minute {
		delay = 5 * time.Minute
	}
	s.marker.NextAttemptUnixMilli = now.Add(delay).UnixMilli()
	s.marker.RefreshSucceededUnixMilli = 0
	return nil
}
func (s *memoryNativeStore) MarkRegistrationRefreshSucceeded() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.succeeded++
	if s.successErr != nil {
		return s.successErr
	}
	s.marker.RefreshSucceededUnixMilli = max(time.Now().UnixMilli(), s.marker.LastAttemptUnixMilli)
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

func (s *memoryNativeStore) LoadSessionOperations(_ context.Context, resourceID string) ([]agentstate.SessionOperationRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]agentstate.SessionOperationRecord(nil), s.operations[resourceID]...), nil
}

func (s *memoryNativeStore) ScanSessionOperationResources(context.Context) agentstate.SessionOperationResourceScan {
	s.mu.Lock()
	defer s.mu.Unlock()
	resources := make([]string, 0, len(s.operations))
	for resourceID, records := range s.operations {
		if len(records) > 0 {
			resources = append(resources, resourceID)
		}
	}
	sort.Strings(resources)
	return agentstate.SessionOperationResourceScan{
		ResourceIDs: resources, PermanentError: s.scanPermanentErr, RetryableError: s.scanRetryableErr,
	}
}

func (s *memoryNativeStore) CreateSessionOperation(_ context.Context, record agentstate.SessionOperationRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.operations == nil {
		s.operations = make(map[string][]agentstate.SessionOperationRecord)
	}
	resourceID := record.Operation.ProtectedResourceID
	for _, current := range s.operations[resourceID] {
		if current.Operation.OperationID == record.Operation.OperationID {
			return agentstate.ErrSessionOperationConflict
		}
	}
	s.operations[resourceID] = append(s.operations[resourceID], record)
	return nil
}

func (s *memoryNativeStore) TransitionSessionOperation(_ context.Context, previous, next agentstate.SessionOperationRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	resourceID := previous.Operation.ProtectedResourceID
	for index, current := range s.operations[resourceID] {
		if reflect.DeepEqual(current, previous) {
			s.operations[resourceID][index] = next
			return nil
		}
	}
	return agentstate.ErrSessionOperationConflict
}

func (s *memoryNativeStore) DeleteSessionOperation(_ context.Context, terminal agentstate.SessionOperationRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	resourceID := terminal.Operation.ProtectedResourceID
	for index, current := range s.operations[resourceID] {
		if reflect.DeepEqual(current, terminal) {
			s.operations[resourceID] = append(s.operations[resourceID][:index], s.operations[resourceID][index+1:]...)
			return nil
		}
	}
	return agentstate.ErrSessionOperationConflict
}

type testNativeSessionOperations struct{}

func (testNativeSessionOperations) RecoverPending(context.Context, *qurl.AgentRuntimeBinding, []byte, string, map[string]struct{}, []qurl.AgentRuntimeUDPOption) error {
	return nil
}

type recoveryFailureOperations struct {
	testNativeSessionOperations
	err error
}

type retirementFailureOperations struct {
	testNativeSessionOperations
	err error
}

type blockingQueuedRetirementOperations struct {
	testNativeSessionOperations
	mu                sync.Mutex
	calls             int
	backgroundStarted chan struct{}
	backgroundStopped chan struct{}
	startOnce         sync.Once
	stopOnce          sync.Once
}

type signalingRetirementOperations struct {
	testNativeSessionOperations
	started chan struct{}
	once    sync.Once
}

func (o *signalingRetirementOperations) Retire(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
	_, _ string, _ qurl.NativeSessionReceipt, _ []qurl.AgentRuntimeUDPOption,
) error {
	o.once.Do(func() { close(o.started) })
	return nil
}

func (o *blockingQueuedRetirementOperations) Retire(ctx context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
	_, _ string, _ qurl.NativeSessionReceipt, _ []qurl.AgentRuntimeUDPOption,
) error {
	o.mu.Lock()
	o.calls++
	call := o.calls
	o.mu.Unlock()
	if call == 1 {
		return nativeudp.ErrNoReply
	}
	if call == 2 {
		o.startOnce.Do(func() { close(o.backgroundStarted) })
		<-ctx.Done()
		o.stopOnce.Do(func() { close(o.backgroundStopped) })
		return ctx.Err()
	}
	return nil
}

type dispatchFailureOperations struct {
	testNativeSessionOperations
	err error
}

type fanoutDispatchFailureOperations struct {
	testNativeSessionOperations
	mu    sync.Mutex
	calls int
	ready chan<- struct{}
	err   error
}

type missingRefreshMarkerStore struct{ *memoryNativeStore }

func (missingRefreshMarkerStore) RequestRegistrationRefresh(string) error { return nil }

func (o dispatchFailureOperations) PrepareDispatch(context.Context, *qurl.AgentRuntimeBinding, []byte,
	string, string, string, uint64,
) (*qurl.NativeSessionOperation, error) {
	return nil, o.err
}

func (o *fanoutDispatchFailureOperations) PrepareDispatch(context.Context, *qurl.AgentRuntimeBinding, []byte,
	string, string, string, uint64,
) (*qurl.NativeSessionOperation, error) {
	o.mu.Lock()
	o.calls++
	call := o.calls
	o.mu.Unlock()
	if call <= cap(o.ready) {
		o.ready <- struct{}{}
	}
	return nil, o.err
}

func (o retirementFailureOperations) Retire(context.Context, *qurl.AgentRuntimeBinding, []byte,
	string, string, qurl.NativeSessionReceipt, []qurl.AgentRuntimeUDPOption,
) error {
	return o.err
}

type cleanupFailureOperations struct {
	testNativeSessionOperations
	err error
}

func (o cleanupFailureOperations) RecoverOperation(context.Context, *qurl.AgentRuntimeBinding, []byte,
	string, string, []qurl.AgentRuntimeUDPOption,
) error {
	return o.err
}

func (o recoveryFailureOperations) RecoverPending(context.Context, *qurl.AgentRuntimeBinding, []byte, string, map[string]struct{}, []qurl.AgentRuntimeUDPOption) error {
	return o.err
}

func (testNativeSessionOperations) RecoverOperation(context.Context, *qurl.AgentRuntimeBinding, []byte, string, string, []qurl.AgentRuntimeUDPOption) error {
	return nil
}

func (testNativeSessionOperations) PrepareDispatch(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
	knockResourceID, protectedResourceID, runID string, runAttempt uint64,
) (*qurl.NativeSessionOperation, error) {
	return &qurl.NativeSessionOperation{
		ResourceID: knockResourceID, ProtectedResourceID: protectedResourceID,
		OperationID: runID, RunID: runID, RunAttempt: runAttempt,
	}, nil
}

func (testNativeSessionOperations) RecordMapped(context.Context, string, qurl.NativeSessionOperation, qurl.NativeSessionReceipt) error {
	return nil
}

func (testNativeSessionOperations) Retire(ctx context.Context, binding *qurl.AgentRuntimeBinding, privateKey []byte,
	_, _ string, receipt qurl.NativeSessionReceipt, options []qurl.AgentRuntimeUDPOption,
) error {
	_, err := retireNativeSession(ctx, binding, privateKey, receipt, options...)
	return err
}

func testNativeSessionAuthority() NativeSessionOperationAuthority {
	return NativeSessionOperationAuthority{OwnerID: "owner-one"}
}

type makeBeforeBreakTestOperations struct {
	next      int
	preserves []map[string]struct{}
}

type blockingRecoveryOperations struct {
	testNativeSessionOperations
	resource string
	started  chan struct{}
	release  chan struct{}
	once     sync.Once
}

func (o *blockingRecoveryOperations) RecoverPending(ctx context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
	resourceID string, _ map[string]struct{}, _ []qurl.AgentRuntimeUDPOption,
) error {
	if resourceID != o.resource {
		return nil
	}
	o.once.Do(func() { close(o.started) })
	select {
	case <-o.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type prepareFenceOperations struct {
	testNativeSessionOperations
	mu             sync.Mutex
	prepares       int
	secondPrepared chan struct{}
	secondReady    chan struct{}
	readyOnce      sync.Once
	prepareOnce    sync.Once
}

type durableRetirementFenceOperations struct {
	controller *durableNativeSessionOperations
}

func (o *durableRetirementFenceOperations) RecoverPending(ctx context.Context, binding *qurl.AgentRuntimeBinding,
	privateKey []byte, resourceID string, preserve map[string]struct{}, udpOptions []qurl.AgentRuntimeUDPOption,
) error {
	return o.controller.RecoverPending(ctx, binding, privateKey, resourceID, preserve, udpOptions)
}

func (o *durableRetirementFenceOperations) RecoverOperation(ctx context.Context, binding *qurl.AgentRuntimeBinding,
	privateKey []byte, resourceID, operationID string, udpOptions []qurl.AgentRuntimeUDPOption,
) error {
	return o.controller.RecoverOperation(ctx, binding, privateKey, resourceID, operationID, udpOptions)
}

func (*durableRetirementFenceOperations) PrepareDispatch(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
	knockResourceID, protectedResourceID, runID string, runAttempt uint64,
) (*qurl.NativeSessionOperation, error) {
	return &qurl.NativeSessionOperation{
		OperationID: strings.Repeat("9", 64), ResourceID: knockResourceID,
		ProtectedResourceID: protectedResourceID, RunID: runID, RunAttempt: runAttempt,
	}, nil
}

func (*durableRetirementFenceOperations) RecordMapped(context.Context, string, qurl.NativeSessionOperation, qurl.NativeSessionReceipt) error {
	return nil
}

func (o *durableRetirementFenceOperations) Retire(ctx context.Context, binding *qurl.AgentRuntimeBinding,
	privateKey []byte, resourceID, operationID string, receipt qurl.NativeSessionReceipt,
	udpOptions []qurl.AgentRuntimeUDPOption,
) error {
	return o.controller.Retire(ctx, binding, privateKey, resourceID, operationID, receipt, udpOptions)
}

func (o *prepareFenceOperations) RecoverPending(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
	resourceID string, _ map[string]struct{}, _ []qurl.AgentRuntimeUDPOption,
) error {
	if resourceID == "resource-two" {
		o.readyOnce.Do(func() { close(o.secondReady) })
	}
	return nil
}

func (o *prepareFenceOperations) PrepareDispatch(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
	knockResourceID, protectedResourceID, runID string, runAttempt uint64,
) (*qurl.NativeSessionOperation, error) {
	o.mu.Lock()
	o.prepares++
	if o.prepares == 2 {
		o.prepareOnce.Do(func() { close(o.secondPrepared) })
	}
	o.mu.Unlock()
	return &qurl.NativeSessionOperation{
		ResourceID: knockResourceID, ProtectedResourceID: protectedResourceID,
		OperationID: runID, RunID: runID, RunAttempt: runAttempt,
	}, nil
}

func (o *makeBeforeBreakTestOperations) RecoverPending(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
	_ string, preserve map[string]struct{}, _ []qurl.AgentRuntimeUDPOption,
) error {
	copySet := make(map[string]struct{}, len(preserve))
	for operationID := range preserve {
		copySet[operationID] = struct{}{}
	}
	o.preserves = append(o.preserves, copySet)
	return nil
}

func (*makeBeforeBreakTestOperations) RecoverOperation(context.Context, *qurl.AgentRuntimeBinding, []byte,
	string, string, []qurl.AgentRuntimeUDPOption,
) error {
	return nil
}

func (o *makeBeforeBreakTestOperations) PrepareDispatch(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
	knockResourceID, protectedResourceID, runID string, runAttempt uint64,
) (*qurl.NativeSessionOperation, error) {
	o.next++
	return &qurl.NativeSessionOperation{
		OperationID: fmt.Sprintf("operation-%d", o.next), ResourceID: knockResourceID,
		ProtectedResourceID: protectedResourceID, RunID: runID, RunAttempt: runAttempt,
	}, nil
}

func (*makeBeforeBreakTestOperations) RecordMapped(context.Context, string, qurl.NativeSessionOperation, qurl.NativeSessionReceipt) error {
	return nil
}

func (*makeBeforeBreakTestOperations) Retire(context.Context, *qurl.AgentRuntimeBinding, []byte,
	string, string, qurl.NativeSessionReceipt, []qurl.AgentRuntimeUDPOption,
) error {
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
	if store.succeeded != 1 || store.cleared != 0 || !store.present || store.marker.RefreshSucceededUnixMilli == 0 {
		t.Fatalf("successful assignment handoff = succeeded=%d cleared=%d present=%t marker=%#v", store.succeeded, store.cleared, store.present, store.marker)
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

func TestNativeAdmitterKeepsSourceFencedRecoveryOutOfRefreshClassifier(t *testing.T) {
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		operations: recoveryFailureOperations{err: nativeudp.ErrNoReply}, generation: 7,
	}
	admission, err, generation, refreshEligible := admitter.admitOnce(context.Background(), "q_catalog", "resource-one")
	if !reflect.DeepEqual(admission, Admission{}) || err == nil || generation != 7 || refreshEligible || !refreshableKnockError(err) {
		t.Fatalf("recovery refresh classification = %#v, %v, generation=%d, eligible=%t", admission, err, generation, refreshEligible)
	}
}

func TestNativeAdmitterRetirementFailurePreservesPlacementFailureBudget(t *testing.T) {
	want := errors.New("retirement failed")
	receipt := testSessionReceipt(1, "run-one", 1)
	key := admissionKey(receipt)
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		operations: retirementFailureOperations{err: want}, generation: 7,
		placementFailures: map[string]nativePlacementFailureState{
			"resource-one": {generation: 7, failures: 4},
		},
		live: map[nativeAdmissionKey]nativeLiveAdmission{
			key: {resourceID: "resource-one", operationID: "operation-one", receipt: receipt},
		},
		pending: map[nativeAdmissionKey]bool{key: true},
	}
	if _, err := admitter.Admit(context.Background(), "q_catalog", "resource-one"); !errors.Is(err, want) {
		t.Fatalf("Admit() = %v, want retirement failure", err)
	}
	if state := admitter.placementFailures["resource-one"]; state.generation != 7 || state.failures != 4 {
		t.Fatalf("placement budget after retirement failure = %+v, want generation 7 count 4", state)
	}
}

func TestNativeAdmitterClassifiesKnockWithoutCleanupSentinels(t *testing.T) {
	oldKnock := knockNativeRuntime
	t.Cleanup(func() { knockNativeRuntime = oldKnock })
	knockNativeRuntime = func(context.Context, *qurl.AgentRuntimeBinding, []byte, string,
		qurl.NativeKnockOptions, ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeKnockResult, error) {
		return nil, nativeudp.ErrNoReply
	}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		operations: cleanupFailureOperations{err: qurl.ErrMalformedReply},
	}
	_, err := admitter.Admit(context.Background(), "q_catalog", "resource-one")
	if !errors.Is(err, nativeudp.ErrNoReply) {
		t.Fatalf("Admit() = %v, want primary no-reply sentinel", err)
	}
	if errors.Is(err, qurl.ErrMalformedReply) {
		t.Fatalf("cleanup sentinel escaped into placement classification: %v", err)
	}
	if !strings.Contains(err.Error(), "durable native session cleanup also failed") {
		t.Fatalf("cleanup diagnostic missing from %v", err)
	}
}

func TestOpenNativeRuntimeWarmOpensSuccessfulRefreshHandoffWithoutRepeatingHub(t *testing.T) {
	oldStore := newNativeStateStore
	oldConnect := connectNativeRuntime
	oldRefresh := refreshNativeRuntime
	t.Cleanup(func() {
		newNativeStateStore = oldStore
		connectNativeRuntime = oldConnect
		refreshNativeRuntime = oldRefresh
	})
	now := time.Now().UnixMilli()
	store := &memoryNativeStore{present: true, marker: agentstate.RefreshMarker{
		Version: 3, Reason: "assigned NHP cell lease expired", AttemptCount: 1,
		StartedAtUnix: now/1000 - 1, LastAttemptUnixMilli: now - 1,
		RefreshSucceededUnixMilli: now,
	}}
	newNativeStateStore = func(string, string) (nativeStateStore, error) { return store, nil }
	connects := 0
	connectNativeRuntime = func(context.Context, qurl.AgentStateStore, ...qurl.AgentRuntimeRegistrationOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		connects++
		return &qurl.Client{}, &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, nil
	}
	refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		t.Fatal("successful cross-process handoff repeated the Hub refresh")
		return nil, nil, nil
	}

	runtime, err := OpenNativeRuntime(context.Background(), NativeRuntimeConfig{StateDir: "/private/state", RefreshMode: "auto"})
	if err != nil {
		t.Fatal(err)
	}
	if connects != 1 || runtime.OpenKind != NativeOpenWarm || store.marks != 0 || store.cleared != 0 || !store.present {
		t.Fatalf("handoff open = connects=%d kind=%q marks=%d clears=%d present=%t", connects, runtime.OpenKind, store.marks, store.cleared, store.present)
	}
	if err := runtime.MarkServingHealthy(); err != nil {
		t.Fatal(err)
	}
	if store.cleared != 1 || store.present {
		t.Fatalf("serving confirmation clears=%d present=%t, want 1/false", store.cleared, store.present)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenNativeRuntimeRefreshesRetryableSuccessfulHandoffWarmOpenFailures(t *testing.T) {
	oldStore := newNativeStateStore
	oldConnect := connectNativeRuntime
	oldRefresh := refreshNativeRuntime
	oldWait := waitNativeRefresh
	t.Cleanup(func() {
		newNativeStateStore = oldStore
		connectNativeRuntime = oldConnect
		refreshNativeRuntime = oldRefresh
		waitNativeRefresh = oldWait
	})
	for name, warmErr := range map[string]error{
		"expired assignment lease": qurl.ErrAssignmentLeaseExpired,
		"transient key wrapper":    qurl.ErrAgentStateKeyWrapper,
	} {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UnixMilli()
			waits := 0
			waitNativeRefresh = func(context.Context, time.Duration) error {
				waits++
				return nil
			}
			store := &memoryNativeStore{present: true, marker: agentstate.RefreshMarker{
				Version: 3, Reason: "assigned NHP cell lease expired", AttemptCount: 1,
				StartedAtUnix: now/1000 - 1, LastAttemptUnixMilli: now - 1,
				NextAttemptUnixMilli: now + int64(time.Minute/time.Millisecond), RefreshSucceededUnixMilli: now,
			}}
			newNativeStateStore = func(string, string) (nativeStateStore, error) { return store, nil }
			connectNativeRuntime = func(context.Context, qurl.AgentStateStore, ...qurl.AgentRuntimeRegistrationOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
				return nil, nil, warmErr
			}
			refreshCalls := 0
			refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
				refreshCalls++
				return &qurl.Client{}, &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, nil
			}

			runtime, err := OpenNativeRuntime(context.Background(), NativeRuntimeConfig{StateDir: "/private/state", RefreshMode: "auto"})
			if err != nil {
				t.Fatal(err)
			}
			if runtime.OpenKind != NativeOpenRefresh || refreshCalls != 1 || waits != 1 || store.marks != 1 ||
				store.succeeded != 1 || store.marker.RefreshSucceededUnixMilli == 0 {
				t.Fatalf("handoff recovery = kind=%q refresh=%d waits=%d marks=%d success=%d marker=%#v",
					runtime.OpenKind, refreshCalls, waits, store.marks, store.succeeded, store.marker)
			}
			if err := runtime.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOpenNativeRuntimeSuccessfulHandoffPermanentWarmOpenFailureDoesNotContactHub(t *testing.T) {
	oldStore := newNativeStateStore
	oldConnect := connectNativeRuntime
	oldRefresh := refreshNativeRuntime
	t.Cleanup(func() {
		newNativeStateStore = oldStore
		connectNativeRuntime = oldConnect
		refreshNativeRuntime = oldRefresh
	})
	now := time.Now().UnixMilli()
	store := &memoryNativeStore{present: true, marker: agentstate.RefreshMarker{
		Version: 3, AttemptCount: 1, StartedAtUnix: now/1000 - 1,
		LastAttemptUnixMilli: now - 1, NextAttemptUnixMilli: now + 1, RefreshSucceededUnixMilli: now,
	}}
	newNativeStateStore = func(string, string) (nativeStateStore, error) { return store, nil }
	connectNativeRuntime = func(context.Context, qurl.AgentStateStore, ...qurl.AgentRuntimeRegistrationOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		return nil, nil, qurl.ErrInvalidAgentState
	}
	refreshCalls := 0
	refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		refreshCalls++
		return nil, nil, errors.New("unexpected Hub refresh")
	}
	if _, err := OpenNativeRuntime(context.Background(), NativeRuntimeConfig{StateDir: "/private/state", RefreshMode: "auto"}); !errors.Is(err, qurl.ErrInvalidAgentState) {
		t.Fatalf("permanent handoff warm-open failure = %v, want invalid agent state", err)
	}
	if refreshCalls != 0 || store.closed != 1 {
		t.Fatalf("permanent handoff failure = refresh calls %d store closes %d, want 0/1", refreshCalls, store.closed)
	}
}

func TestAssembleRefreshedNativeRuntimeMarkerFailureKeepsRuntimeAndCallerStore(t *testing.T) {
	want := errors.New("marker write failed")
	store := &memoryNativeStore{successErr: want}
	runtime, err := assembleRefreshedNativeRuntime(
		context.Background(), &qurl.Client{}, &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, store,
		nativeRefreshConfig{}, NativeOpenRefresh,
	)
	if err != nil || runtime == nil || runtime.Binding == nil {
		t.Fatalf("assemble marker failure = (%#v, %v), want usable runtime", runtime, err)
	}
	if store.closed != 0 || store.succeeded != 1 {
		t.Fatalf("caller store after marker failure = closes=%d success calls=%d, want 0/1", store.closed, store.succeeded)
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

func TestOpenNativeRuntimeRecoversAuthenticatedRejectedIdentity(t *testing.T) {
	oldStore := newNativeStateStore
	oldRefresh := refreshNativeRuntime
	oldRecover := recoverNativeRuntime
	oldWait := waitNativeRefresh
	t.Cleanup(func() {
		newNativeStateStore = oldStore
		refreshNativeRuntime = oldRefresh
		recoverNativeRuntime = oldRecover
		waitNativeRefresh = oldWait
	})
	store := &memoryNativeStore{
		present: true,
		marker:  agentstate.RefreshMarker{Version: 2, Reason: "assigned NHP cell lease expired"},
	}
	newNativeStateStore = func(string, string) (nativeStateStore, error) { return store, nil }
	waitNativeRefresh = func(context.Context, time.Duration) error { return nil }
	refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		return nil, nil, errors.Join(errors.New("Hub rejected persisted key"), qurl.ErrAssignmentIdentityRejected)
	}
	providerCalls := 0
	recoveryCalls := 0
	recoverNativeRuntime = func(ctx context.Context, provider qurl.AgentRuntimeRecoveryCredentialProvider, _ qurl.AgentStateStore, options ...qurl.AgentRuntimeRecoveryOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		recoveryCalls++
		credential, err := provider(ctx)
		if err != nil {
			return nil, nil, err
		}
		if credential != "lv_test_recoverycredentialabcdefghijklmnopqrstuvwxyz0123456789" {
			t.Fatalf("recovery credential = %q", credential)
		}
		if len(options) != 3 {
			t.Fatalf("recovery options = %d, want Hub, expected agent, and base URL", len(options))
		}
		return &qurl.Client{}, &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, nil
	}
	runtime, err := OpenNativeRuntime(context.Background(), NativeRuntimeConfig{
		StateDir: "/private/state", AgentID: "agent-one", ClientBaseURL: "https://api.example.test",
		RecoveryCredentialProvider: func(context.Context) (string, error) {
			providerCalls++
			return "lv_test_recoverycredentialabcdefghijklmnopqrstuvwxyz0123456789", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.OpenKind != NativeOpenRecovery || runtime.AgentID != "agent-one" {
		t.Fatalf("recovered runtime = kind %q agent %q", runtime.OpenKind, runtime.AgentID)
	}
	if providerCalls != 1 || recoveryCalls != 1 || store.marks != 1 {
		t.Fatalf("provider=%d recovery=%d refresh marks=%d, want 1/1/1", providerCalls, recoveryCalls, store.marks)
	}
	if store.succeeded != 1 || store.cleared != 0 || !store.present {
		t.Fatalf("credential recovery handoff = succeeded=%d cleared=%d present=%t", store.succeeded, store.cleared, store.present)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNativeRuntimeRepairsWarmDeviceAuthorizationOnce(t *testing.T) {
	oldStore := newNativeStateStore
	oldConnect := connectNativeRuntime
	oldRecover := recoverNativeRuntime
	t.Cleanup(func() {
		newNativeStateStore = oldStore
		connectNativeRuntime = oldConnect
		recoverNativeRuntime = oldRecover
	})

	store := &memoryNativeStore{}
	newNativeStateStore = func(string, string) (nativeStateStore, error) { return store, nil }
	oldBinding := &qurl.AgentRuntimeBinding{AgentID: "agent-one"}
	connectNativeRuntime = func(context.Context, qurl.AgentStateStore, ...qurl.AgentRuntimeRegistrationOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		return &qurl.Client{}, oldBinding, nil
	}
	runtime, err := OpenNativeRuntime(context.Background(), NativeRuntimeConfig{
		StateDir: "/private/state", AgentID: "agent-one", ClientBaseURL: "https://api.example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.OpenKind != NativeOpenWarm {
		t.Fatalf("initial open kind = %q, want warm", runtime.OpenKind)
	}

	providerCalls := 0
	recoveryCalls := 0
	newBinding := &qurl.AgentRuntimeBinding{AgentID: "agent-one"}
	recoverNativeRuntime = func(ctx context.Context, provider qurl.AgentRuntimeRecoveryCredentialProvider, _ qurl.AgentStateStore, options ...qurl.AgentRuntimeRecoveryOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		recoveryCalls++
		credential, providerErr := provider(ctx)
		if providerErr != nil {
			return nil, nil, providerErr
		}
		if credential != "lv_test_validatedaccountcredentialabcdefghijklmnopqrstuvwxyz" {
			t.Fatalf("recovery credential = %q", credential)
		}
		if len(options) != 3 {
			t.Fatalf("recovery options = %d, want Hub, expected agent, and base URL", len(options))
		}
		return &qurl.Client{}, newBinding, nil
	}
	err = runtime.RecoverCredentialAfterDeviceAuthorizationFailure(
		context.Background(), http.StatusUnauthorized, "api_key_invalid",
		func(context.Context) (string, error) {
			providerCalls++
			return "lv_test_validatedaccountcredentialabcdefghijklmnopqrstuvwxyz", nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.OpenKind != NativeOpenRecovery || runtime.Binding != newBinding || runtime.AgentID != "agent-one" {
		t.Fatalf("repaired runtime = kind %q binding %p agent %q", runtime.OpenKind, runtime.Binding, runtime.AgentID)
	}
	if providerCalls != 1 || recoveryCalls != 1 || store.handoffCalls != 2 || store.succeeded != 1 {
		t.Fatalf("repair calls provider/recovery/handoff/succeeded=%d/%d/%d/%d, want 1/1/2/1",
			providerCalls, recoveryCalls, store.handoffCalls, store.succeeded)
	}

	err = runtime.RecoverCredentialAfterDeviceAuthorizationFailure(
		context.Background(), http.StatusUnauthorized, "api_key_invalid",
		func(context.Context) (string, error) {
			providerCalls++
			return "must-not-be-read", nil
		},
	)
	if !errors.Is(err, errNativeDeviceAuthorizationRecoveryNotAllowed) {
		t.Fatalf("second repair error = %v, want one-shot rejection", err)
	}
	if providerCalls != 1 || recoveryCalls != 1 || store.handoffCalls != 2 {
		t.Fatalf("second repair spent authority: provider/recovery/handoff=%d/%d/%d", providerCalls, recoveryCalls, store.handoffCalls)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNativeRuntimeDeviceAuthorizationRecoveryGateFailsClosed(t *testing.T) {
	oldRecover := recoverNativeRuntime
	t.Cleanup(func() { recoverNativeRuntime = oldRecover })
	recoveryCalls := 0
	recoverNativeRuntime = func(context.Context, qurl.AgentRuntimeRecoveryCredentialProvider, qurl.AgentStateStore, ...qurl.AgentRuntimeRecoveryOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		recoveryCalls++
		return nil, nil, errors.New("unexpected recovery")
	}

	tests := []struct {
		name        string
		ctx         context.Context
		kind        NativeOpenKind
		statusCode  int
		problemCode string
		provider    func(context.Context) (string, error)
	}{
		{name: "nil context", kind: NativeOpenWarm, statusCode: http.StatusUnauthorized, problemCode: "api_key_invalid", provider: func(context.Context) (string, error) { return "key", nil }},
		{name: "forbidden", ctx: context.Background(), kind: NativeOpenWarm, statusCode: http.StatusForbidden, problemCode: "api_key_invalid", provider: func(context.Context) (string, error) { return "key", nil }},
		{name: "other unauthorized", ctx: context.Background(), kind: NativeOpenWarm, statusCode: http.StatusUnauthorized, problemCode: "account_disabled", provider: func(context.Context) (string, error) { return "key", nil }},
		{name: "noncanonical code", ctx: context.Background(), kind: NativeOpenWarm, statusCode: http.StatusUnauthorized, problemCode: " api_key_invalid ", provider: func(context.Context) (string, error) { return "key", nil }},
		{name: "registration open", ctx: context.Background(), kind: NativeOpenRegistration, statusCode: http.StatusUnauthorized, problemCode: "api_key_invalid", provider: func(context.Context) (string, error) { return "key", nil }},
		{name: "nil provider", ctx: context.Background(), kind: NativeOpenWarm, statusCode: http.StatusUnauthorized, problemCode: "api_key_invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &memoryNativeStore{}
			providerCalls := 0
			provider := test.provider
			if provider != nil {
				provider = func(ctx context.Context) (string, error) {
					providerCalls++
					return test.provider(ctx)
				}
			}
			runtime := &NativeRuntime{
				Client: &qurl.Client{}, Binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"},
				AgentID: "agent-one", OpenKind: test.kind, store: store,
			}
			err := runtime.RecoverCredentialAfterDeviceAuthorizationFailure(test.ctx, test.statusCode, test.problemCode, provider)
			if !errors.Is(err, errNativeDeviceAuthorizationRecoveryNotAllowed) {
				t.Fatalf("gate error = %v, want recovery-not-allowed", err)
			}
			if providerCalls != 0 || store.handoffCalls != 0 || recoveryCalls != 0 {
				t.Fatalf("gate spent authority: provider/handoff/recovery=%d/%d/%d", providerCalls, store.handoffCalls, recoveryCalls)
			}
		})
	}
}

func TestNativeRuntimeDeviceAuthorizationRecoveryFailureDoesNotLoopOrReplace(t *testing.T) {
	oldRecover := recoverNativeRuntime
	t.Cleanup(func() { recoverNativeRuntime = oldRecover })
	want := qurl.ErrCredentialRecoveryUnavailable
	providerCalls := 0
	recoveryCalls := 0
	recoverNativeRuntime = func(ctx context.Context, provider qurl.AgentRuntimeRecoveryCredentialProvider, _ qurl.AgentStateStore, _ ...qurl.AgentRuntimeRecoveryOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		recoveryCalls++
		if _, err := provider(ctx); err != nil {
			return nil, nil, err
		}
		return nil, nil, want
	}
	oldClient := &qurl.Client{}
	oldBinding := &qurl.AgentRuntimeBinding{AgentID: "agent-one"}
	store := &memoryNativeStore{}
	runtime := &NativeRuntime{
		Client: oldClient, Binding: oldBinding, AgentID: "agent-one", OpenKind: NativeOpenWarm,
		store: store, refreshCfg: nativeRefreshConfig{AgentID: "agent-one"},
	}
	provider := func(context.Context) (string, error) {
		providerCalls++
		return "lv_test_validatedaccountcredentialabcdefghijklmnopqrstuvwxyz", nil
	}
	err := runtime.RecoverCredentialAfterDeviceAuthorizationFailure(context.Background(), http.StatusUnauthorized, "api_key_invalid", provider)
	if !errors.Is(err, want) {
		t.Fatalf("repair error = %v, want recovery failure", err)
	}
	if runtime.Client != oldClient || runtime.Binding != oldBinding || runtime.OpenKind != NativeOpenWarm {
		t.Fatal("failed repair replaced the warm runtime")
	}
	err = runtime.RecoverCredentialAfterDeviceAuthorizationFailure(context.Background(), http.StatusUnauthorized, "api_key_invalid", provider)
	if !errors.Is(err, errNativeDeviceAuthorizationRecoveryNotAllowed) {
		t.Fatalf("second repair error = %v, want one-shot rejection", err)
	}
	if providerCalls != 1 || recoveryCalls != 1 || store.handoffCalls != 1 {
		t.Fatalf("failed repair looped: provider/recovery/handoff=%d/%d/%d", providerCalls, recoveryCalls, store.handoffCalls)
	}
}

func TestNativeRuntimeDeviceAuthorizationAssemblyFailureDoesNotLoopOrReplace(t *testing.T) {
	oldRecover := recoverNativeRuntime
	t.Cleanup(func() { recoverNativeRuntime = oldRecover })
	providerCalls := 0
	recoveryCalls := 0
	recoverNativeRuntime = func(ctx context.Context, provider qurl.AgentRuntimeRecoveryCredentialProvider, _ qurl.AgentStateStore, _ ...qurl.AgentRuntimeRecoveryOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		recoveryCalls++
		if _, err := provider(ctx); err != nil {
			return nil, nil, err
		}
		return &qurl.Client{}, &qurl.AgentRuntimeBinding{AgentID: "agent-two"}, nil
	}
	oldClient := &qurl.Client{}
	oldBinding := &qurl.AgentRuntimeBinding{AgentID: "agent-one"}
	store := &memoryNativeStore{}
	runtime := &NativeRuntime{
		Client: oldClient, Binding: oldBinding, AgentID: "agent-one", OpenKind: NativeOpenWarm,
		store: store, refreshCfg: nativeRefreshConfig{AgentID: "agent-one"},
	}
	provider := func(context.Context) (string, error) {
		providerCalls++
		return "lv_test_validatedaccountcredentialabcdefghijklmnopqrstuvwxyz", nil
	}
	err := runtime.RecoverCredentialAfterDeviceAuthorizationFailure(
		context.Background(), http.StatusUnauthorized, "api_key_invalid", provider,
	)
	if err == nil || !strings.Contains(err.Error(), "conflicts with persisted identity") {
		t.Fatalf("assembly error = %v, want identity conflict", err)
	}
	if runtime.Client != oldClient || runtime.Binding != oldBinding || runtime.OpenKind != NativeOpenWarm {
		t.Fatal("failed assembly replaced the warm runtime")
	}
	err = runtime.RecoverCredentialAfterDeviceAuthorizationFailure(
		context.Background(), http.StatusUnauthorized, "api_key_invalid", provider,
	)
	if !errors.Is(err, errNativeDeviceAuthorizationRecoveryNotAllowed) {
		t.Fatalf("second repair error = %v, want one-shot rejection", err)
	}
	if providerCalls != 1 || recoveryCalls != 1 || store.handoffCalls != 1 {
		t.Fatalf("failed assembly looped: provider/recovery/handoff=%d/%d/%d", providerCalls, recoveryCalls, store.handoffCalls)
	}
}

func TestOpenNativeRuntimeResumesPersistedCredentialRecovery(t *testing.T) {
	oldStore := newNativeStateStore
	oldConnect := connectNativeRuntime
	oldRefresh := refreshNativeRuntime
	oldRecover := recoverNativeRuntime
	oldWait := waitNativeRefresh
	t.Cleanup(func() {
		newNativeStateStore = oldStore
		connectNativeRuntime = oldConnect
		refreshNativeRuntime = oldRefresh
		recoverNativeRuntime = oldRecover
		waitNativeRefresh = oldWait
	})
	pending := &qurl.NativeCredentialRecoveryRequiredError{
		AgentID: "agent-one", Cause: qurl.ErrCredentialRecoveryRequired,
	}
	tests := []struct {
		name          string
		store         *memoryNativeStore
		wantWarmCalls int
		wantRefresh   int
	}{
		{
			name: "pending refresh episode",
			store: &memoryNativeStore{present: true, marker: agentstate.RefreshMarker{
				Version: 2, Reason: "placement recovery",
			}},
			wantRefresh: 1,
		},
		{
			name:          "pending warm open",
			store:         &memoryNativeStore{},
			wantWarmCalls: 1,
		},
		{
			name: "pending successful handoff warm open",
			store: &memoryNativeStore{present: true, marker: agentstate.RefreshMarker{
				Version: 3, AttemptCount: 1, StartedAtUnix: 1,
				LastAttemptUnixMilli: 1, NextAttemptUnixMilli: 2, RefreshSucceededUnixMilli: 1,
			}},
			wantWarmCalls: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			newNativeStateStore = func(string, string) (nativeStateStore, error) { return test.store, nil }
			waitNativeRefresh = func(context.Context, time.Duration) error { return nil }
			warmCalls := 0
			connectNativeRuntime = func(context.Context, qurl.AgentStateStore, ...qurl.AgentRuntimeRegistrationOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
				warmCalls++
				return nil, nil, pending
			}
			refreshCalls := 0
			refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
				refreshCalls++
				return nil, nil, pending
			}
			providerCalls := 0
			recoveryCalls := 0
			recoverNativeRuntime = func(ctx context.Context, provider qurl.AgentRuntimeRecoveryCredentialProvider, _ qurl.AgentStateStore, _ ...qurl.AgentRuntimeRecoveryOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
				recoveryCalls++
				credential, err := provider(ctx)
				if err != nil {
					return nil, nil, err
				}
				if credential != "lv_test_recoverycredentialabcdefghijklmnopqrstuvwxyz0123456789" {
					return nil, nil, fmt.Errorf("recovery credential = %q", credential)
				}
				return &qurl.Client{}, &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, nil
			}
			runtime, err := OpenNativeRuntime(context.Background(), NativeRuntimeConfig{
				StateDir: "/private/state", AgentID: "agent-one",
				RecoveryCredentialProvider: func(context.Context) (string, error) {
					providerCalls++
					return "lv_test_recoverycredentialabcdefghijklmnopqrstuvwxyz0123456789", nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if runtime.OpenKind != NativeOpenRecovery || runtime.AgentID != "agent-one" {
				t.Fatalf("resumed runtime = kind %q agent %q", runtime.OpenKind, runtime.AgentID)
			}
			if warmCalls != test.wantWarmCalls || refreshCalls != test.wantRefresh || providerCalls != 1 || recoveryCalls != 1 {
				t.Fatalf("resume calls warm/refresh/provider/recovery=%d/%d/%d/%d, want %d/%d/1/1",
					warmCalls, refreshCalls, providerCalls, recoveryCalls, test.wantWarmCalls, test.wantRefresh)
			}
			if err := runtime.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOpenNativeRuntimeDoesNotResumePendingRecoveryWithoutAuthority(t *testing.T) {
	oldStore := newNativeStateStore
	oldConnect := connectNativeRuntime
	oldRefresh := refreshNativeRuntime
	oldRecover := recoverNativeRuntime
	oldWait := waitNativeRefresh
	t.Cleanup(func() {
		newNativeStateStore = oldStore
		connectNativeRuntime = oldConnect
		refreshNativeRuntime = oldRefresh
		recoverNativeRuntime = oldRecover
		waitNativeRefresh = oldWait
	})
	pending := &qurl.NativeCredentialRecoveryRequiredError{
		AgentID: "agent-one", Cause: qurl.ErrCredentialRecoveryRequired,
	}
	tests := []struct {
		name        string
		store       *memoryNativeStore
		wantWarm    int
		wantRefresh int
	}{
		{name: "ordinary warm open", store: &memoryNativeStore{}, wantWarm: 1},
		{
			name: "successful marker warm open",
			store: &memoryNativeStore{present: true, marker: agentstate.RefreshMarker{
				Version: 3, RefreshSucceededUnixMilli: 1,
			}},
			wantWarm: 1,
		},
		{
			name: "pending refresh marker",
			store: &memoryNativeStore{present: true, marker: agentstate.RefreshMarker{
				Version: 2, Reason: "placement recovery",
			}},
			wantRefresh: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			newNativeStateStore = func(string, string) (nativeStateStore, error) { return test.store, nil }
			waitNativeRefresh = func(context.Context, time.Duration) error { return nil }
			warmCalls := 0
			connectNativeRuntime = func(context.Context, qurl.AgentStateStore, ...qurl.AgentRuntimeRegistrationOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
				warmCalls++
				return nil, nil, pending
			}
			refreshCalls := 0
			refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
				refreshCalls++
				return nil, nil, pending
			}
			recoveryCalls := 0
			recoverNativeRuntime = func(context.Context, qurl.AgentRuntimeRecoveryCredentialProvider, qurl.AgentStateStore, ...qurl.AgentRuntimeRecoveryOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
				recoveryCalls++
				return nil, nil, errors.New("recovery ran without explicit account authority")
			}
			_, err := OpenNativeRuntime(context.Background(), NativeRuntimeConfig{StateDir: "/private/state"})
			if !errors.Is(err, qurl.ErrCredentialRecoveryRequired) || warmCalls != test.wantWarm || refreshCalls != test.wantRefresh || recoveryCalls != 0 {
				t.Fatalf("open error=%v warm/refresh/recovery=%d/%d/%d, want pending recovery and %d/%d/0",
					err, warmCalls, refreshCalls, recoveryCalls, test.wantWarm, test.wantRefresh)
			}
		})
	}
}

func TestOpenNativeRuntimeKeepsRecoveryFailureRetryable(t *testing.T) {
	oldStore := newNativeStateStore
	oldConnect := connectNativeRuntime
	oldRecover := recoverNativeRuntime
	t.Cleanup(func() {
		newNativeStateStore = oldStore
		connectNativeRuntime = oldConnect
		recoverNativeRuntime = oldRecover
	})
	pending := &qurl.NativeCredentialRecoveryRequiredError{
		AgentID: "agent-one", Cause: qurl.ErrCredentialRecoveryRequired,
	}
	wantRecoveryErr := qurl.ErrCredentialRecoveryUnavailable
	newNativeStateStore = func(string, string) (nativeStateStore, error) { return &memoryNativeStore{}, nil }
	connectNativeRuntime = func(context.Context, qurl.AgentStateStore, ...qurl.AgentRuntimeRegistrationOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		return nil, nil, pending
	}
	recoverNativeRuntime = func(context.Context, qurl.AgentRuntimeRecoveryCredentialProvider, qurl.AgentStateStore, ...qurl.AgentRuntimeRecoveryOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		return nil, nil, wantRecoveryErr
	}
	_, err := OpenNativeRuntime(context.Background(), NativeRuntimeConfig{
		StateDir: "/private/state",
		RecoveryCredentialProvider: func(context.Context) (string, error) {
			return "lv_test_recoverycredentialabcdefghijklmnopqrstuvwxyz0123456789", nil
		},
	})
	if errors.Is(err, qurl.ErrCredentialRecoveryRequired) || !errors.Is(err, wantRecoveryErr) || IsPermanentNativeOpenError(err) {
		t.Fatalf("open error=%v, want retryable recovery failure without terminal pending trigger", err)
	}
}

func TestMayConsumeNativeRecoveryAuthorityRejectsUnsafeLocalStates(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"authenticated identity rejection", qurl.ErrAssignmentIdentityRejected, true},
		{"valid pending episode", fmt.Errorf("open saved state: %w", &qurl.NativeCredentialRecoveryRequiredError{Cause: qurl.ErrCredentialRecoveryRequired}), true},
		{"bare recovery sentinel", qurl.ErrCredentialRecoveryRequired, false},
		{"missing credential", &qurl.NativeCredentialRecoveryRequiredError{Cause: qurl.ErrDeviceCredentialMissing}, false},
		{"malformed pending state", &qurl.NativeCredentialRecoveryRequiredError{Cause: qurl.ErrInvalidAgentState}, false},
		{"wrapped pending sentinel", &qurl.NativeCredentialRecoveryRequiredError{Cause: fmt.Errorf("unexpected wrapper: %w", qurl.ErrCredentialRecoveryRequired)}, false},
		{"expired pending episode", &qurl.NativeCredentialRecoveryRequiredError{Cause: errors.Join(qurl.ErrCredentialRecoveryRequired, qurl.ErrCredentialRecoveryExpired)}, false},
		{"revoke-required pending episode", &qurl.NativeCredentialRecoveryRequiredError{Cause: errors.Join(qurl.ErrCredentialRecoveryRequired, qurl.ErrCredentialRecoveryRevokeRequired)}, false},
		{"conflicting pending episode", &qurl.NativeCredentialRecoveryRequiredError{Cause: errors.Join(qurl.ErrCredentialRecoveryRequired, qurl.ErrCredentialRecoveryCandidateConflict)}, false},
		{"identity-rejected pending episode", &qurl.NativeCredentialRecoveryRequiredError{Cause: errors.Join(qurl.ErrCredentialRecoveryRequired, qurl.ErrCredentialRecoveryIdentityRejected)}, false},
		{"credential-rejected pending episode", &qurl.NativeCredentialRecoveryRequiredError{Cause: errors.Join(qurl.ErrCredentialRecoveryRequired, qurl.ErrRecoveryCredentialRejected)}, false},
		{"top-level missing credential", errors.Join(&qurl.NativeCredentialRecoveryRequiredError{Cause: qurl.ErrCredentialRecoveryRequired}, qurl.ErrDeviceCredentialMissing), false},
		{"top-level malformed state", errors.Join(&qurl.NativeCredentialRecoveryRequiredError{Cause: qurl.ErrCredentialRecoveryRequired}, qurl.ErrInvalidAgentState), false},
		{"top-level state continuity failure", errors.Join(&qurl.NativeCredentialRecoveryRequiredError{Cause: qurl.ErrCredentialRecoveryRequired}, qurl.ErrAgentStateContinuity), false},
		{"top-level setup lock failure", errors.Join(&qurl.NativeCredentialRecoveryRequiredError{Cause: qurl.ErrCredentialRecoveryRequired}, qurl.ErrAgentSetupLock), false},
		{"top-level expired episode", errors.Join(&qurl.NativeCredentialRecoveryRequiredError{Cause: qurl.ErrCredentialRecoveryRequired}, qurl.ErrCredentialRecoveryExpired), false},
		{"unrelated error", qurl.ErrInvalidAssignmentConfig, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := mayConsumeNativeRecoveryAuthority(test.err); got != test.want {
				t.Fatalf("mayConsumeNativeRecoveryAuthority(%v) = %t, want %t", test.err, got, test.want)
			}
		})
	}
}

func TestMayConsumeNativeRecoveryAuthorityAcceptsRealPendingState(t *testing.T) {
	deviceKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	publicKey := base64.StdEncoding.EncodeToString(deviceKey.PublicKey().Bytes())
	state := &qurl.AgentState{
		AgentID:        "agent-one",
		PrivateKeyB64:  base64.StdEncoding.EncodeToString(deviceKey.Bytes()),
		PublicKeyB64:   publicKey,
		RegisteredAt:   &now,
		SchemaVersion:  7,
		DeviceAPIKey:   "lv_live_" + base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		DeviceAPIKeyID: "key_DeviceKey123",
		Assignment: &qurl.AgentAssignment{
			CellID: "cell-a", AssignmentGeneration: 1, EndpointRevision: 1,
			LeaseExpiresAt: now.Add(time.Hour),
			Endpoint: qurl.NHPUDPEndpoint{
				Host: "hub.nhp.layerv.ai", Port: 443,
				ServerPublicKeyB64: base64.StdEncoding.EncodeToString(serverKey.PublicKey().Bytes()),
			},
		},
		PendingCredentialRecoveryIssue: &qurl.PendingAgentCredentialRecoveryIssue{
			RequestNonce:                     base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
			ReplayNotAfter:                   now.Add(time.Hour),
			RecoveryCredentialFingerprintB64: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
			AgentID:                          "agent-one", AgentPublicKeyB64: publicKey,
			HubHost: "hub.nhp.layerv.ai", HubPort: 443,
			HubServerPublicKeyB64: base64.StdEncoding.EncodeToString(serverKey.PublicKey().Bytes()),
		},
	}
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := qurl.OpenFileAgentState(filepath.Join(stateDir, "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	_, _, openErr := qurl.ConnectAgentRuntime(context.Background(), store, qurl.WithAgentRuntimeOfflineOpen())
	var pending *qurl.NativeCredentialRecoveryRequiredError
	if !errors.As(openErr, &pending) || !mayConsumeNativeRecoveryAuthority(openErr) {
		t.Fatalf("real pending state error = %v, want typed resumable recovery", openErr)
	}
}

func TestOpenNativeRuntimeDoesNotRecoverWithoutExplicitAuthority(t *testing.T) {
	oldStore := newNativeStateStore
	oldRefresh := refreshNativeRuntime
	oldRecover := recoverNativeRuntime
	oldWait := waitNativeRefresh
	t.Cleanup(func() {
		newNativeStateStore = oldStore
		refreshNativeRuntime = oldRefresh
		recoverNativeRuntime = oldRecover
		waitNativeRefresh = oldWait
	})
	store := &memoryNativeStore{present: true, marker: agentstate.RefreshMarker{Version: 2, Reason: "placement recovery"}}
	newNativeStateStore = func(string, string) (nativeStateStore, error) { return store, nil }
	waitNativeRefresh = func(context.Context, time.Duration) error { return nil }
	refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		return nil, nil, qurl.ErrAssignmentIdentityRejected
	}
	recoverNativeRuntime = func(context.Context, qurl.AgentRuntimeRecoveryCredentialProvider, qurl.AgentStateStore, ...qurl.AgentRuntimeRecoveryOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		t.Fatal("recovery ran without an explicit credential provider")
		return nil, nil, nil
	}
	_, err := OpenNativeRuntime(context.Background(), NativeRuntimeConfig{StateDir: "/private/state"})
	if !errors.Is(err, qurl.ErrAssignmentIdentityRejected) {
		t.Fatalf("OpenNativeRuntime() = %v, want identity rejection", err)
	}
}

func TestOpenNativeRuntimeDoesNotSpendRecoveryAuthorityOnOtherFailures(t *testing.T) {
	oldStore := newNativeStateStore
	oldRefresh := refreshNativeRuntime
	oldRecover := recoverNativeRuntime
	oldWait := waitNativeRefresh
	t.Cleanup(func() {
		newNativeStateStore = oldStore
		refreshNativeRuntime = oldRefresh
		recoverNativeRuntime = oldRecover
		waitNativeRefresh = oldWait
	})
	store := &memoryNativeStore{present: true, marker: agentstate.RefreshMarker{Version: 2, Reason: "placement recovery"}}
	newNativeStateStore = func(string, string) (nativeStateStore, error) { return store, nil }
	waitNativeRefresh = func(context.Context, time.Duration) error { return nil }
	refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		return nil, nil, qurl.ErrInvalidAssignmentConfig
	}
	providerCalls := 0
	recoverNativeRuntime = func(context.Context, qurl.AgentRuntimeRecoveryCredentialProvider, qurl.AgentStateStore, ...qurl.AgentRuntimeRecoveryOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		t.Fatal("recovery ran for a non-identity failure")
		return nil, nil, nil
	}
	_, err := OpenNativeRuntime(context.Background(), NativeRuntimeConfig{
		StateDir: "/private/state",
		RecoveryCredentialProvider: func(context.Context) (string, error) {
			providerCalls++
			return "must-not-be-read", nil
		},
	})
	if !errors.Is(err, qurl.ErrInvalidAssignmentConfig) || providerCalls != 0 {
		t.Fatalf("OpenNativeRuntime() = %v, provider calls=%d, want original error and no recovery authority read", err, providerCalls)
	}
}

func TestOpenNativeRuntimeRecoveryProviderFailureStaysRetryable(t *testing.T) {
	oldStore := newNativeStateStore
	oldRefresh := refreshNativeRuntime
	oldRecover := recoverNativeRuntime
	oldWait := waitNativeRefresh
	t.Cleanup(func() {
		newNativeStateStore = oldStore
		refreshNativeRuntime = oldRefresh
		recoverNativeRuntime = oldRecover
		waitNativeRefresh = oldWait
	})
	store := &memoryNativeStore{present: true, marker: agentstate.RefreshMarker{Version: 2, Reason: "placement recovery"}}
	newNativeStateStore = func(string, string) (nativeStateStore, error) { return store, nil }
	waitNativeRefresh = func(context.Context, time.Duration) error { return nil }
	refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		return nil, nil, qurl.ErrAssignmentIdentityRejected
	}
	recoverNativeRuntime = func(ctx context.Context, provider qurl.AgentRuntimeRecoveryCredentialProvider, _ qurl.AgentStateStore, _ ...qurl.AgentRuntimeRecoveryOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		_, err := provider(ctx)
		return nil, nil, err
	}
	want := errors.New("account credential unavailable")
	_, err := OpenNativeRuntime(context.Background(), NativeRuntimeConfig{
		StateDir:                   "/private/state",
		RecoveryCredentialProvider: func(context.Context) (string, error) { return "", want },
	})
	if errors.Is(err, qurl.ErrAssignmentIdentityRejected) || !errors.Is(err, want) || IsPermanentNativeOpenError(err) {
		t.Fatalf("OpenNativeRuntime() = %v, want retryable provider failure without terminal trigger", err)
	}
}

func TestOpenNativeRuntimeRecoveryProviderRejectsEmptyAuthorityBeforeRecoveryIO(t *testing.T) {
	oldStore := newNativeStateStore
	oldRefresh := refreshNativeRuntime
	oldRecover := recoverNativeRuntime
	oldWait := waitNativeRefresh
	t.Cleanup(func() {
		newNativeStateStore = oldStore
		refreshNativeRuntime = oldRefresh
		recoverNativeRuntime = oldRecover
		waitNativeRefresh = oldWait
	})
	store := &memoryNativeStore{present: true, marker: agentstate.RefreshMarker{Version: 2, Reason: "placement recovery"}}
	newNativeStateStore = func(string, string) (nativeStateStore, error) { return store, nil }
	waitNativeRefresh = func(context.Context, time.Duration) error { return nil }
	refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		return nil, nil, qurl.ErrAssignmentIdentityRejected
	}
	providerCalls := 0
	recoveryIO := 0
	recoverNativeRuntime = func(ctx context.Context, provider qurl.AgentRuntimeRecoveryCredentialProvider, _ qurl.AgentStateStore, _ ...qurl.AgentRuntimeRecoveryOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		if _, err := provider(ctx); err != nil {
			return nil, nil, err
		}
		recoveryIO++
		return nil, nil, errors.New("unexpected recovery I/O")
	}
	_, err := OpenNativeRuntime(context.Background(), NativeRuntimeConfig{
		StateDir: "/private/state",
		RecoveryCredentialProvider: func(context.Context) (string, error) {
			providerCalls++
			return " \t\n", nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "recovery authority is empty") {
		t.Fatalf("OpenNativeRuntime() = %v, want empty recovery authority error", err)
	}
	if providerCalls != 1 || recoveryIO != 0 {
		t.Fatalf("empty recovery authority calls provider/I/O=%d/%d, want 1/0", providerCalls, recoveryIO)
	}
}

func TestOpenNativeRuntimeRecoveryStateHandoffFailureStaysRetryable(t *testing.T) {
	oldStore := newNativeStateStore
	oldConnect := connectNativeRuntime
	t.Cleanup(func() {
		newNativeStateStore = oldStore
		connectNativeRuntime = oldConnect
	})
	want := errors.New("temporary state handoff failure")
	store := &memoryNativeStore{handoffErr: want, handoffErrAt: 2}
	newNativeStateStore = func(string, string) (nativeStateStore, error) { return store, nil }
	connectNativeRuntime = func(context.Context, qurl.AgentStateStore, ...qurl.AgentRuntimeRegistrationOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		return nil, nil, &qurl.NativeCredentialRecoveryRequiredError{Cause: qurl.ErrCredentialRecoveryRequired}
	}
	_, err := OpenNativeRuntime(context.Background(), NativeRuntimeConfig{
		StateDir: "/private/state",
		RecoveryCredentialProvider: func(context.Context) (string, error) {
			return "lv_test_recoverycredentialabcdefghijklmnopqrstuvwxyz0123456789", nil
		},
	})
	if errors.Is(err, qurl.ErrCredentialRecoveryRequired) || !errors.Is(err, want) || IsPermanentNativeOpenError(err) {
		t.Fatalf("OpenNativeRuntime() = %v, want retryable state handoff failure without terminal trigger", err)
	}
}

func TestNativeOpenPermanentClassification(t *testing.T) {
	for name, err := range map[string]error{
		"bad enrollment token":               qurl.ErrAssignmentKeyRejected,
		"consumed token":                     qurl.ErrAssignmentBootstrapConsumed,
		"registration policy":                qurl.ErrRegistrationDisabled,
		"corrupt state":                      qurl.ErrInvalidAgentState,
		"state continuity":                   qurl.ErrAgentStateContinuity,
		"state setup lock":                   qurl.ErrAgentSetupLock,
		"authenticated deny":                 &qurl.ServerDenyError{ErrCode: "52999"},
		"pending recovery without authority": qurl.ErrCredentialRecoveryRequired,
		"missing device credential":          qurl.ErrDeviceCredentialMissing,
		"recovery credential rejected":       qurl.ErrRecoveryCredentialRejected,
		"recovery identity rejected":         qurl.ErrCredentialRecoveryIdentityRejected,
		"recovery revoke required":           qurl.ErrCredentialRecoveryRevokeRequired,
		"recovery request rejected":          qurl.ErrCredentialRecoveryRequestRejected,
		"recovery assignment required":       qurl.ErrCredentialRecoveryAssignmentRequired,
		"recovery candidate conflict":        qurl.ErrCredentialRecoveryCandidateConflict,
		"recovery response invalid":          qurl.ErrCredentialRecoveryInvalidResponse,
		"recovery expired":                   qurl.ErrCredentialRecoveryExpired,
	} {
		t.Run(name, func(t *testing.T) {
			if !IsPermanentNativeOpenError(err) {
				t.Fatalf("%v classified retryable", err)
			}
		})
	}
	for name, err := range map[string]error{
		"assignment rate limit":           qurl.ErrAssignmentRateLimited,
		"registration rate":               qurl.ErrRegistrationRateLimited,
		"assignment unavailable":          qurl.ErrAssignmentUnavailable,
		"endpoint no reply":               qurl.ErrEndpointNoReply,
		"server overload":                 qurl.ErrServerOverloaded,
		"recovery unavailable":            qurl.ErrCredentialRecoveryUnavailable,
		"recovery rate limited":           qurl.ErrCredentialRecoveryRateLimited,
		"replacement unavailable":         qurl.ErrCredentialReplacementUnavailable,
		"recovery retry required":         qurl.ErrCredentialRecoveryRetryRequired,
		"recovery grant renewal required": qurl.ErrCredentialRecoveryGrantRejected,
		"recovery candidate persistence":  qurl.ErrCredentialRecoveryCandidatePersistence,
		"recovered assignment refresh":    qurl.ErrCredentialRecoveredAssignmentRefreshRequired,
		"transport":                       errors.New("temporary network failure"),
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
	store := &memoryNativeStore{attemptBackoff: time.Second}
	waitNativeRefresh = func(_ context.Context, delay time.Duration) error {
		return fmt.Errorf("live refresh waited %s through persisted backoff", delay)
	}
	takeNativeKey = func(*qurl.AgentRuntimeBinding) []byte { return make([]byte, 32) }
	refreshes := 0
	knocks := 0
	knockNativeRuntime = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte, _ string, opts qurl.NativeKnockOptions, _ ...qurl.AgentRuntimeUDPOption) (*qurl.NativeKnockResult, error) {
		knocks++
		if refreshes < 3 {
			return nil, nativeudp.ErrTransport
		}
		return &qurl.NativeKnockResult{
			ACToken: "token", ResourceHost: "frp.example:7000", SessionID: 77, OpenTime: 120,
			SessionReceipt: testSessionReceipt(77, opts.RunID, opts.RunAttempt),
		}, nil
	}
	refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		refreshes++
		if refreshes <= 2 {
			return nil, nil, qurl.ErrAssignmentUnavailable
		}
		return &qurl.Client{}, &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, nil
	}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		operations: testNativeSessionOperations{},
		store:      store, refreshCfg: nativeRefreshConfig{AgentID: "agent-one", RefreshMode: "auto"},
	}
	for attempt := 1; attempt < 5; attempt++ {
		if _, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource"); !errors.Is(err, nativeudp.ErrTransport) {
			t.Fatalf("knock %d = %v, want transport failure", attempt, err)
		}
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource"); !errors.Is(err, nativeudp.ErrTransport) || !errors.Is(err, qurl.ErrAssignmentUnavailable) {
			t.Fatalf("refresh attempt %d = %v, want transport and assignment unavailable", attempt, err)
		}
		if refreshes != attempt || store.marks != attempt {
			t.Fatalf("after refresh attempt %d refreshes=%d marks=%d", attempt, refreshes, store.marks)
		}
		store.mu.Lock()
		store.marker.NextAttemptUnixMilli = time.Now().Add(-time.Second).UnixMilli()
		store.mu.Unlock()
	}
	admission, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource")
	if err != nil {
		t.Fatal(err)
	}
	if admission.SessionID != 77 || admission.KnockResourceID != "q_catalog_key" || admission.ResourceID != "public-resource" {
		t.Fatalf("recovered admission = %+v", admission)
	}
	if refreshes != 3 || store.marks != 3 || knocks != 8 {
		t.Fatalf("refreshes=%d persisted attempts=%d knocks=%d, want 3/3/8", refreshes, store.marks, knocks)
	}
	store.mu.Lock()
	sustainedReason := store.marker.Reason
	store.mu.Unlock()
	if sustainedReason != nativeRefreshReasonSustained {
		t.Fatalf("sustained refresh reason=%q, want %q", sustainedReason, nativeRefreshReasonSustained)
	}
	if store.cleared != 0 {
		t.Fatal("assignment recovery cleared before a serving FRP session")
	}
	if err := admitter.MarkServingHealthy(); err != nil || store.cleared != 1 {
		t.Fatalf("MarkServingHealthy() = %v, clears=%d", err, store.cleared)
	}
}

func TestNativeAdmitterBindsProtectedResourceIntoKnock(t *testing.T) {
	oldKnock := knockNativeRuntime
	t.Cleanup(func() { knockNativeRuntime = oldKnock })
	want := "protected-resource"
	knockNativeRuntime = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte, knockResourceID string,
		opts qurl.NativeKnockOptions, _ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeKnockResult, error) {
		if knockResourceID != "q_catalog_key" || opts.ProtectedResourceID != want || opts.Operation == nil ||
			opts.Operation.ResourceID != knockResourceID || opts.Operation.ProtectedResourceID != want {
			t.Fatalf("knock binding = catalog %q protected %q operation %#v", knockResourceID, opts.ProtectedResourceID, opts.Operation)
		}
		return &qurl.NativeKnockResult{
			ACToken: "token", ResourceHost: "127.0.0.1:7000", SessionID: 77, OpenTime: 60,
			SessionReceipt: testSessionReceipt(77, opts.RunID, opts.RunAttempt),
		}, nil
	}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		operations: testNativeSessionOperations{},
		store:      &memoryNativeStore{},
	}
	if _, err := admitter.Admit(context.Background(), "q_catalog_key", want); err != nil {
		t.Fatal(err)
	}
}

func TestNativeAdmitterSlowRecoveryDoesNotBlockSiblingResource(t *testing.T) {
	oldKnock := knockNativeRuntime
	t.Cleanup(func() { knockNativeRuntime = oldKnock })
	var knockMu sync.Mutex
	nextSession := uint64(90)
	knockNativeRuntime = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte, _ string,
		opts qurl.NativeKnockOptions, _ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeKnockResult, error) {
		knockMu.Lock()
		nextSession++
		sessionID := nextSession
		knockMu.Unlock()
		return &qurl.NativeKnockResult{
			ACToken: "token", ResourceHost: "127.0.0.1:7000", SessionID: sessionID, OpenTime: 60,
			SessionReceipt: testSessionReceipt(sessionID, opts.RunID, opts.RunAttempt),
		}, nil
	}
	operations := &blockingRecoveryOperations{
		resource: "resource-one", started: make(chan struct{}), release: make(chan struct{}),
	}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		operations: operations, store: &memoryNativeStore{},
	}
	defer admitter.Close()

	firstDone := make(chan error, 1)
	go func() {
		_, err := admitter.Admit(context.Background(), "q_one", "resource-one")
		firstDone <- err
	}()
	select {
	case <-operations.started:
	case <-time.After(time.Second):
		t.Fatal("slow recovery did not start")
	}
	secondDone := make(chan error, 1)
	go func() {
		_, err := admitter.Admit(context.Background(), "q_two", "resource-two")
		secondDone <- err
	}()
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("sibling admission = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("slow recovery blocked an unrelated resource")
	}
	close(operations.release)
	if err := <-firstDone; err != nil {
		t.Fatalf("released admission = %v", err)
	}
}

func TestNativeAdmitterPreparedRefreshDoesNotBlockSiblingResource(t *testing.T) {
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

	var knockMu sync.Mutex
	nextSession := uint64(120)
	knockNativeRuntime = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte, _ string,
		opts qurl.NativeKnockOptions, _ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeKnockResult, error) {
		knockMu.Lock()
		nextSession++
		sessionID := nextSession
		knockMu.Unlock()
		return &qurl.NativeKnockResult{
			ACToken: "token", ResourceHost: "127.0.0.1:7000", SessionID: sessionID, OpenTime: 60,
			SessionReceipt: testSessionReceipt(sessionID, opts.RunID, opts.RunAttempt),
		}, nil
	}
	waitNativeRefresh = func(context.Context, time.Duration) error { return nil }
	takeNativeKey = func(*qurl.AgentRuntimeBinding) []byte { return make([]byte, 32) }
	refreshPrepared := make(chan struct{})
	refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore,
		...qurl.AgentRuntimeRefreshOption,
	) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		close(refreshPrepared)
		return &qurl.Client{}, &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, nil
	}

	operations := &blockingRecoveryOperations{
		resource: "resource-one", started: make(chan struct{}), release: make(chan struct{}),
	}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		operations: operations, store: &memoryNativeStore{},
		refreshCfg: nativeRefreshConfig{AgentID: "agent-one", RefreshMode: "auto"},
	}
	defer admitter.Close()

	firstDone := make(chan error, 1)
	go func() {
		_, err := admitter.Admit(context.Background(), "q_one", "resource-one")
		firstDone <- err
	}()
	select {
	case <-operations.started:
	case <-time.After(time.Second):
		t.Fatal("slow recovery did not start")
	}
	refreshDone := make(chan error, 1)
	go func() { refreshDone <- admitter.refresh(context.Background(), 0, nativeRefreshReasonSustained) }()
	select {
	case <-refreshPrepared:
	case <-time.After(time.Second):
		t.Fatal("replacement runtime was not prepared")
	}

	secondDone := make(chan error, 1)
	go func() {
		_, err := admitter.Admit(context.Background(), "q_two", "resource-two")
		secondDone <- err
	}()
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("sibling admission = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("prepared refresh blocked an unrelated resource")
	}
	close(operations.release)
	if err := <-firstDone; err != nil {
		t.Fatalf("released admission = %v", err)
	}
	if err := <-refreshDone; err != nil {
		t.Fatalf("refresh = %v", err)
	}
}

func TestNativeAdmitterRefreshQueuesAfterBoundedReaderGrace(t *testing.T) {
	admitter := &NativeAdmitter{}
	admitter.runtimeMu.RLock()
	refreshDone := make(chan error, 1)
	go func() { refreshDone <- admitter.lockRuntimeForRefresh(context.Background()) }()

	// After the bounded grace, the refresh has a real queued writer. A reader
	// arriving now must wait instead of extending writer starvation.
	time.Sleep(runtimeRefreshReaderGrace + 100*time.Millisecond)
	readerAcquired := make(chan struct{})
	go func() {
		admitter.runtimeMu.RLock()
		close(readerAcquired)
		admitter.runtimeMu.RUnlock()
	}()
	select {
	case <-readerAcquired:
		t.Fatal("reader bypassed a queued runtime refresh")
	case <-time.After(25 * time.Millisecond):
	}

	admitter.runtimeMu.RUnlock()
	select {
	case err := <-refreshDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued runtime refresh did not acquire the lock")
	}
	select {
	case <-readerAcquired:
		t.Fatal("reader acquired while refresh owned the runtime lock")
	default:
	}
	admitter.runtimeMu.Unlock()
	select {
	case <-readerAcquired:
	case <-time.After(time.Second):
		t.Fatal("reader did not resume after refresh released the lock")
	}
}

func TestNativeAdmitterRefreshLockHonorsCancellationDuringReaderGrace(t *testing.T) {
	admitter := &NativeAdmitter{}
	admitter.runtimeMu.RLock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := admitter.lockRuntimeForRefresh(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled refresh lock = %v, want context cancellation", err)
	}
	admitter.runtimeMu.RUnlock()
	admitter.runtimeMu.Lock()
	admitter.runtimeMu.Unlock()
}

func TestNativeAdmitterSerializesOnlyPrepareCommitAndKnockAcrossResources(t *testing.T) {
	oldKnock := knockNativeRuntime
	t.Cleanup(func() { knockNativeRuntime = oldKnock })
	firstKnock := make(chan struct{})
	releaseFirst := make(chan struct{})
	var once sync.Once
	var resultMu sync.Mutex
	nextSession := uint64(100)
	knockNativeRuntime = func(ctx context.Context, _ *qurl.AgentRuntimeBinding, _ []byte, _ string,
		opts qurl.NativeKnockOptions, _ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeKnockResult, error) {
		blocked := false
		once.Do(func() {
			blocked = true
			close(firstKnock)
		})
		if blocked {
			select {
			case <-releaseFirst:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		resultMu.Lock()
		nextSession++
		sessionID := nextSession
		resultMu.Unlock()
		return &qurl.NativeKnockResult{
			ACToken: "token", ResourceHost: "127.0.0.1:7000", SessionID: sessionID, OpenTime: 60,
			SessionReceipt: testSessionReceipt(sessionID, opts.RunID, opts.RunAttempt),
		}, nil
	}
	operations := &prepareFenceOperations{
		secondPrepared: make(chan struct{}), secondReady: make(chan struct{}),
	}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		operations: operations, store: &memoryNativeStore{},
	}
	defer admitter.Close()
	firstDone := make(chan error, 1)
	go func() {
		_, err := admitter.Admit(context.Background(), "q_one", "resource-one")
		firstDone <- err
	}()
	select {
	case <-firstKnock:
	case <-time.After(time.Second):
		t.Fatal("first knock did not start")
	}
	secondDone := make(chan error, 1)
	go func() {
		_, err := admitter.Admit(context.Background(), "q_two", "resource-two")
		secondDone <- err
	}()
	select {
	case <-operations.secondReady:
	case <-time.After(time.Second):
		t.Fatal("sibling did not finish independent recovery")
	}
	select {
	case <-operations.secondPrepared:
		t.Fatal("sibling prepared while the first operation had not finished its knock")
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatalf("first admission = %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second admission = %v", err)
	}
	select {
	case <-operations.secondPrepared:
	default:
		t.Fatal("sibling did not prepare after the first knock completed")
	}
}

func TestNativeAdmitterPreservesServingOperationDuringMakeBeforeBreak(t *testing.T) {
	oldKnock := knockNativeRuntime
	t.Cleanup(func() { knockNativeRuntime = oldKnock })
	knocks := 0
	knockNativeRuntime = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte, _ string,
		opts qurl.NativeKnockOptions, _ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeKnockResult, error) {
		knocks++
		receipt := testSessionReceipt(uint64(knocks), opts.RunID, opts.RunAttempt)
		return &qurl.NativeKnockResult{
			ACToken: "token", ResourceHost: "127.0.0.1:7000", SessionID: uint64(knocks), OpenTime: 60,
			SessionReceipt: receipt,
		}, nil
	}
	operations := &makeBeforeBreakTestOperations{}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		store: &memoryNativeStore{}, operations: operations,
	}
	first, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource")
	if err != nil {
		t.Fatal(err)
	}
	second, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource")
	if err != nil {
		t.Fatal(err)
	}
	if len(admitter.live) != 2 || len(operations.preserves) != 2 {
		t.Fatalf("make-before-break live=%d preserve calls=%d", len(admitter.live), len(operations.preserves))
	}
	if len(operations.preserves[0]) != 0 {
		t.Fatalf("first admission preserved stale operations: %+v", operations.preserves[0])
	}
	if _, ok := operations.preserves[1]["operation-1"]; !ok || len(operations.preserves[1]) != 1 {
		t.Fatalf("replacement did not preserve serving operation: %+v", operations.preserves[1])
	}
	if err := admitter.Retire(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := admitter.Retire(context.Background(), second); err != nil {
		t.Fatal(err)
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

func TestImmediatePlacementRefreshClassification(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil"},
		{name: "transport", err: nativeudp.ErrTransport},
		{name: "no reply", err: nativeudp.ErrNoReply},
		{name: "assignment unavailable", err: qurl.ErrAssignmentUnavailable},
		{name: "lease expired", err: qurl.ErrAssignmentLeaseExpired, want: true},
		{name: "journal margin", err: qurl.ErrNativeSessionOperationLeaseMargin, want: true},
		{name: "recovery required", err: qurl.ErrAssignmentRecoveryRequired, want: true},
		{name: "reassignment required", err: qurl.ErrAssignmentReassignmentRequired, want: true},
		{name: "wrapped margin", err: errors.Join(qurl.ErrNativeSessionOperationLeaseMargin, context.DeadlineExceeded), want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := immediatePlacementRefresh(test.err); got != test.want {
				t.Fatalf("immediatePlacementRefresh(%v) = %t, want %t", test.err, got, test.want)
			}
		})
	}
}

func TestNativeAdmitterIsolatesSustainedFailuresByResource(t *testing.T) {
	oldKnock := knockNativeRuntime
	oldRefresh := refreshNativeRuntime
	oldTakeKey := takeNativeKey
	t.Cleanup(func() {
		knockNativeRuntime = oldKnock
		refreshNativeRuntime = oldRefresh
		takeNativeKey = oldTakeKey
	})
	takeNativeKey = func(*qurl.AgentRuntimeBinding) []byte { return make([]byte, 32) }
	knockNativeRuntime = func(context.Context, *qurl.AgentRuntimeBinding, []byte, string, qurl.NativeKnockOptions, ...qurl.AgentRuntimeUDPOption) (*qurl.NativeKnockResult, error) {
		return nil, nativeudp.ErrTransport
	}
	refreshes := 0
	refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		refreshes++
		return &qurl.Client{}, &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, nil
	}
	store := &memoryNativeStore{}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		operations: testNativeSessionOperations{}, store: store,
		refreshCfg: nativeRefreshConfig{AgentID: "agent-one", RefreshMode: "auto"},
	}
	for attempt := 1; attempt <= 4; attempt++ {
		if _, err := admitter.Admit(context.Background(), "q_catalog_key", "resource-a"); !errors.Is(err, nativeudp.ErrTransport) {
			t.Fatalf("resource A attempt %d = %v, want transport failure", attempt, err)
		}
	}
	if _, err := admitter.Admit(context.Background(), "q_catalog_key", "resource-b"); !errors.Is(err, nativeudp.ErrTransport) {
		t.Fatalf("resource B first attempt = %v, want transport failure", err)
	}
	if refreshes != 0 {
		t.Fatalf("resource B consumed resource A's failure budget: refreshes=%d", refreshes)
	}
	if _, err := admitter.Admit(context.Background(), "q_catalog_key", "resource-a"); !errors.Is(err, nativeudp.ErrTransport) {
		t.Fatalf("resource A threshold attempt = %v, want transport failure", err)
	}
	if refreshes != 1 || store.marks != 1 {
		t.Fatalf("resource A threshold refreshes=%d marks=%d, want 1/1", refreshes, store.marks)
	}
}

func TestNativeAdmitterIsolatesImmediateCreditByResource(t *testing.T) {
	oldRefresh := refreshNativeRuntime
	oldTakeKey := takeNativeKey
	t.Cleanup(func() {
		refreshNativeRuntime = oldRefresh
		takeNativeKey = oldTakeKey
	})
	takeNativeKey = func(*qurl.AgentRuntimeBinding) []byte { return make([]byte, 32) }
	refreshes := 0
	refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		refreshes++
		return &qurl.Client{}, &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, nil
	}
	store := &memoryNativeStore{attemptBackoff: time.Second}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		operations: dispatchFailureOperations{err: qurl.ErrNativeSessionOperationLeaseMargin},
		store:      store, refreshCfg: nativeRefreshConfig{AgentID: "agent-one", RefreshMode: "auto"},
	}
	if _, err := admitter.Admit(context.Background(), "q_catalog_key", "resource-a"); !errors.Is(err, qurl.ErrNativeSessionOperationLeaseMargin) {
		t.Fatalf("resource A first Admit() = %v, want lease margin", err)
	}
	if _, err := admitter.Admit(context.Background(), "q_catalog_key", "resource-a"); !errors.Is(err, qurl.ErrNativeSessionOperationLeaseMargin) {
		t.Fatalf("resource A second Admit() = %v, want lease margin", err)
	}
	if refreshes != 1 {
		t.Fatalf("resource A spent immediate credit refreshed %d times, want 1", refreshes)
	}
	if _, err := admitter.Admit(context.Background(), "q_catalog_key", "resource-b"); !errors.Is(err, qurl.ErrNativeSessionOperationLeaseMargin) || !errors.Is(err, errNativeRefreshBackoffPending) {
		t.Fatalf("resource B first Admit() = %v, want lease margin with persisted backoff", err)
	}
	if refreshes != 1 || store.marks != 1 {
		t.Fatalf("resource B bypassed shared backoff: refreshes=%d marks=%d, want 1/1", refreshes, store.marks)
	}
	store.mu.Lock()
	store.marker.NextAttemptUnixMilli = time.Now().Add(-time.Second).UnixMilli()
	store.mu.Unlock()
	if _, err := admitter.Admit(context.Background(), "q_catalog_key", "resource-b"); !errors.Is(err, qurl.ErrNativeSessionOperationLeaseMargin) {
		t.Fatalf("resource B retry Admit() = %v, want lease margin", err)
	}
	if refreshes != 2 || store.marks != 2 {
		t.Fatalf("resource B immediate credit refreshes=%d marks=%d, want 2/2", refreshes, store.marks)
	}
}

func TestNativeAdmitterCollapsesConcurrentImmediateRefreshesByGeneration(t *testing.T) {
	oldRefresh := refreshNativeRuntime
	oldTakeKey := takeNativeKey
	t.Cleanup(func() {
		refreshNativeRuntime = oldRefresh
		takeNativeKey = oldTakeKey
	})
	takeNativeKey = func(*qurl.AgentRuntimeBinding) []byte { return make([]byte, 32) }

	const resourceCount = 8
	ready := make(chan struct{}, resourceCount)
	operations := &fanoutDispatchFailureOperations{
		ready: ready, err: qurl.ErrNativeSessionOperationLeaseMargin,
	}
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var refreshMu sync.Mutex
	refreshes := 0
	refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		refreshMu.Lock()
		refreshes++
		attempt := refreshes
		refreshMu.Unlock()
		if attempt == 1 {
			close(refreshStarted)
			<-releaseRefresh
		}
		return &qurl.Client{}, &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, nil
	}
	store := &memoryNativeStore{attemptBackoff: time.Second}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		operations: operations, store: store,
		refreshCfg: nativeRefreshConfig{AgentID: "agent-one", RefreshMode: "auto"},
	}
	errs := make(chan error, resourceCount)
	for resource := 0; resource < resourceCount; resource++ {
		resourceID := fmt.Sprintf("resource-%d", resource)
		go func() {
			_, err := admitter.Admit(context.Background(), "q_catalog_key", resourceID)
			errs <- err
		}()
	}
	<-refreshStarted
	for resource := 0; resource < resourceCount; resource++ {
		<-ready
	}
	close(releaseRefresh)
	for resource := 0; resource < resourceCount; resource++ {
		if err := <-errs; !errors.Is(err, qurl.ErrNativeSessionOperationLeaseMargin) {
			t.Fatalf("concurrent Admit() = %v, want lease margin", err)
		}
	}
	refreshMu.Lock()
	gotRefreshes := refreshes
	refreshMu.Unlock()
	store.mu.Lock()
	gotMarks := store.marks
	store.mu.Unlock()
	admitter.runtimeMu.RLock()
	generation := admitter.generation
	admitter.runtimeMu.RUnlock()
	if gotRefreshes != 1 || gotMarks != 1 || generation != 1 {
		t.Fatalf("concurrent fan-out refreshes=%d marks=%d generation=%d, want 1/1/1", gotRefreshes, gotMarks, generation)
	}
}

func TestNativeAdmitterRefreshesLeaseMarginImmediately(t *testing.T) {
	oldRefresh := refreshNativeRuntime
	oldTakeKey := takeNativeKey
	t.Cleanup(func() {
		refreshNativeRuntime = oldRefresh
		takeNativeKey = oldTakeKey
	})
	takeNativeKey = func(*qurl.AgentRuntimeBinding) []byte { return make([]byte, 32) }
	refreshes := 0
	refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		refreshes++
		return &qurl.Client{}, &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, nil
	}
	store := &memoryNativeStore{}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		operations: dispatchFailureOperations{err: qurl.ErrNativeSessionOperationLeaseMargin},
		store:      store, refreshCfg: nativeRefreshConfig{AgentID: "agent-one", RefreshMode: "auto"},
	}
	if _, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource"); !errors.Is(err, qurl.ErrNativeSessionOperationLeaseMargin) {
		t.Fatalf("Admit() = %v, want retry failure after one refresh", err)
	}
	if refreshes != 1 || store.marks != 1 {
		t.Fatalf("refreshes=%d persisted attempts=%d, want 1/1 on first margin failure", refreshes, store.marks)
	}
	store.mu.Lock()
	immediateReason := store.marker.Reason
	store.mu.Unlock()
	if immediateReason != nativeRefreshReasonImmediate {
		t.Fatalf("immediate refresh reason=%q, want %q", immediateReason, nativeRefreshReasonImmediate)
	}
	if err := admitter.MarkServingHealthy(); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	markerPresent := store.present
	store.mu.Unlock()
	if markerPresent {
		t.Fatal("serving confirmation did not close the persisted refresh episode")
	}
	if _, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource"); !errors.Is(err, qurl.ErrNativeSessionOperationLeaseMargin) {
		t.Fatalf("second Admit() after episode clear = %v, want margin failure without another immediate refresh", err)
	}
	if refreshes != 1 || store.marks != 1 {
		t.Fatalf("second margin failure refreshes=%d persisted attempts=%d, want bounded 1/1", refreshes, store.marks)
	}
}

func TestPrepareRefreshedRuntimeReportsExactMissingMarkerReason(t *testing.T) {
	store := missingRefreshMarkerStore{memoryNativeStore: &memoryNativeStore{}}
	_, _, err := prepareRefreshedRuntime(
		context.Background(), store, nativeRefreshConfig{RefreshMode: "auto"}, nativeRefreshReasonImmediate,
	)
	if err == nil || !strings.Contains(err.Error(), nativeRefreshReasonImmediate) || strings.Contains(err.Error(), nativeRefreshReasonSustained) {
		t.Fatalf("prepareRefreshedRuntime() = %v, want exact immediate reason", err)
	}
}

func TestNativeAdmitterDoesNotRearmImmediateRefreshAfterInterleavedFailure(t *testing.T) {
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
		switch knocks {
		case 1, 2, 4:
			return nil, qurl.ErrNativeSessionOperationLeaseMargin
		case 3:
			return nil, qurl.ErrServerOverloaded
		default:
			return nil, errors.New("unexpected knock")
		}
	}
	refreshes := 0
	refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		refreshes++
		return &qurl.Client{}, &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, nil
	}
	store := &memoryNativeStore{}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		operations: testNativeSessionOperations{},
		store:      store, refreshCfg: nativeRefreshConfig{AgentID: "agent-one", RefreshMode: "auto"},
	}
	if _, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource"); !errors.Is(err, qurl.ErrNativeSessionOperationLeaseMargin) {
		t.Fatalf("first Admit() = %v, want lease-margin retry failure", err)
	}
	if _, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource"); !errors.Is(err, qurl.ErrServerOverloaded) {
		t.Fatalf("interleaved Admit() = %v, want overload", err)
	}
	if _, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource"); !errors.Is(err, qurl.ErrNativeSessionOperationLeaseMargin) {
		t.Fatalf("third Admit() = %v, want lease margin", err)
	}
	if refreshes != 1 || store.marks != 1 {
		t.Fatalf("interleaved failures refreshed %d times and marked %d times, want 1/1", refreshes, store.marks)
	}
}

func TestNativeAdmitterDoesNotSpendImmediateRefreshAtSustainedThreshold(t *testing.T) {
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
		if knocks <= 4 {
			return nil, nativeudp.ErrTransport
		}
		return nil, qurl.ErrNativeSessionOperationLeaseMargin
	}
	refreshes := 0
	refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		refreshes++
		return &qurl.Client{}, &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, nil
	}
	store := &memoryNativeStore{}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		operations: testNativeSessionOperations{},
		store:      store, refreshCfg: nativeRefreshConfig{AgentID: "agent-one", RefreshMode: "auto"},
	}
	for attempt := 1; attempt <= 4; attempt++ {
		if _, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource"); !errors.Is(err, nativeudp.ErrTransport) {
			t.Fatalf("transport attempt %d = %v, want transport failure", attempt, err)
		}
	}
	if _, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource"); !errors.Is(err, qurl.ErrNativeSessionOperationLeaseMargin) {
		t.Fatalf("threshold Admit() = %v, want lease-margin retry failure", err)
	}
	if refreshes != 1 {
		t.Fatalf("threshold refreshes=%d, want 1", refreshes)
	}
	store.mu.Lock()
	store.marker.NextAttemptUnixMilli = time.Now().Add(-time.Second).UnixMilli()
	store.mu.Unlock()
	if _, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource"); !errors.Is(err, qurl.ErrNativeSessionOperationLeaseMargin) {
		t.Fatalf("post-threshold Admit() = %v, want lease-margin retry failure", err)
	}
	if refreshes != 2 || store.marks != 2 {
		t.Fatalf("threshold then immediate refreshes=%d marks=%d, want 2/2", refreshes, store.marks)
	}
}

func TestNativeAdmitterRestoresImmediateRefreshAfterCallerDeadline(t *testing.T) {
	oldRefresh := refreshNativeRuntime
	oldTakeKey := takeNativeKey
	t.Cleanup(func() {
		refreshNativeRuntime = oldRefresh
		takeNativeKey = oldTakeKey
	})
	takeNativeKey = func(*qurl.AgentRuntimeBinding) []byte { return make([]byte, 32) }
	refreshes := 0
	refreshNativeRuntime = func(ctx context.Context, _ qurl.HubBootstrap, _ qurl.AgentStateStore, _ ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		refreshes++
		if refreshes == 1 {
			<-ctx.Done()
			return nil, nil, ctx.Err()
		}
		return &qurl.Client{}, &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, nil
	}
	store := &memoryNativeStore{attemptBackoff: time.Second}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		operations: dispatchFailureOperations{err: qurl.ErrNativeSessionOperationLeaseMargin},
		store:      store, refreshCfg: nativeRefreshConfig{AgentID: "agent-one", RefreshMode: "auto"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := admitter.Admit(ctx, "q_catalog_key", "public-resource"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline Admit() = %v, want deadline", err)
	}
	if _, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource"); !errors.Is(err, qurl.ErrNativeSessionOperationLeaseMargin) || !errors.Is(err, errNativeRefreshBackoffPending) {
		t.Fatalf("backoff Admit() = %v, want lease margin with persisted backoff", err)
	}
	if refreshes != 1 {
		t.Fatalf("refresh calls during persisted backoff=%d, want 1", refreshes)
	}
	store.mu.Lock()
	store.marker.NextAttemptUnixMilli = time.Now().Add(-time.Second).UnixMilli()
	store.mu.Unlock()
	if _, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource"); !errors.Is(err, qurl.ErrNativeSessionOperationLeaseMargin) {
		t.Fatalf("retry Admit() = %v, want lease-margin retry failure", err)
	}
	if refreshes != 2 {
		t.Fatalf("refresh calls=%d, want immediate retry after caller deadline", refreshes)
	}
}

func TestNativeAdmitterRestoresImmediateRefreshAfterLocalMarkerFailure(t *testing.T) {
	oldRefresh := refreshNativeRuntime
	oldTakeKey := takeNativeKey
	t.Cleanup(func() {
		refreshNativeRuntime = oldRefresh
		takeNativeKey = oldTakeKey
	})
	takeNativeKey = func(*qurl.AgentRuntimeBinding) []byte { return make([]byte, 32) }
	refreshes := 0
	refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		refreshes++
		return &qurl.Client{}, &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, nil
	}
	markerErr := errors.New("refresh marker temporarily unavailable")
	store := &memoryNativeStore{requestErr: markerErr}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		operations: dispatchFailureOperations{err: qurl.ErrNativeSessionOperationLeaseMargin},
		store:      store, refreshCfg: nativeRefreshConfig{AgentID: "agent-one", RefreshMode: "auto"},
	}
	if _, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource"); !errors.Is(err, markerErr) {
		t.Fatalf("first Admit() = %v, want marker failure", err)
	}
	if refreshes != 0 {
		t.Fatalf("Hub refreshes after local marker failure=%d, want 0", refreshes)
	}
	store.mu.Lock()
	store.requestErr = nil
	store.mu.Unlock()
	if _, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource"); !errors.Is(err, qurl.ErrNativeSessionOperationLeaseMargin) {
		t.Fatalf("retry Admit() = %v, want lease-margin retry failure", err)
	}
	if refreshes != 1 || store.marks != 1 {
		t.Fatalf("retry refreshes=%d marks=%d, want 1/1", refreshes, store.marks)
	}
}

func TestNativeAdmitterRestoresImmediateRefreshAfterHubRejection(t *testing.T) {
	oldRefresh := refreshNativeRuntime
	oldTakeKey := takeNativeKey
	oldWait := waitNativeRefresh
	t.Cleanup(func() {
		refreshNativeRuntime = oldRefresh
		takeNativeKey = oldTakeKey
		waitNativeRefresh = oldWait
	})
	takeNativeKey = func(*qurl.AgentRuntimeBinding) []byte { return make([]byte, 32) }
	waits := 0
	waitNativeRefresh = func(_ context.Context, delay time.Duration) error {
		waits++
		return fmt.Errorf("live refresh waited %s through persisted backoff", delay)
	}
	refreshes := 0
	refreshNativeRuntime = func(context.Context, qurl.HubBootstrap, qurl.AgentStateStore, ...qurl.AgentRuntimeRefreshOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		refreshes++
		if refreshes == 1 {
			return nil, nil, qurl.ErrAssignmentQuotaExceeded
		}
		return &qurl.Client{}, &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, nil
	}
	store := &memoryNativeStore{attemptBackoff: time.Second}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		operations: dispatchFailureOperations{err: qurl.ErrNativeSessionOperationLeaseMargin},
		store:      store, refreshCfg: nativeRefreshConfig{AgentID: "agent-one", RefreshMode: "auto"},
	}
	if _, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource"); !errors.Is(err, qurl.ErrAssignmentQuotaExceeded) {
		t.Fatalf("first Admit() = %v, want Hub rejection", err)
	}
	store.mu.Lock()
	firstNextAttempt := store.marker.NextAttemptUnixMilli
	store.mu.Unlock()
	if _, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource"); !errors.Is(err, qurl.ErrNativeSessionOperationLeaseMargin) || !errors.Is(err, errNativeRefreshBackoffPending) {
		t.Fatalf("backoff Admit() = %v, want lease margin with persisted backoff", err)
	}
	if refreshes != 1 || store.marks != 1 || waits != 0 {
		t.Fatalf("during backoff refreshes=%d persisted attempts=%d waits=%d, want 1/1/0", refreshes, store.marks, waits)
	}
	store.mu.Lock()
	store.marker.NextAttemptUnixMilli = time.Now().Add(-time.Second).UnixMilli()
	store.mu.Unlock()
	if _, err := admitter.Admit(context.Background(), "q_catalog_key", "public-resource"); !errors.Is(err, qurl.ErrNativeSessionOperationLeaseMargin) {
		t.Fatalf("ready retry Admit() = %v, want lease-margin retry failure", err)
	}
	store.mu.Lock()
	secondNextAttempt := store.marker.NextAttemptUnixMilli
	store.mu.Unlock()
	if refreshes != 2 || store.marks != 2 || waits != 0 || secondNextAttempt <= firstNextAttempt {
		t.Fatalf("ready retry refreshes=%d marks=%d waits=%d next=%d after %d, want 2/2/0 and growing backoff",
			refreshes, store.marks, waits, secondNextAttempt, firstNextAttempt)
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
				operations: testNativeSessionOperations{},
				store:      store, refreshCfg: nativeRefreshConfig{AgentID: "agent-one", RefreshMode: "auto"},
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
		operations: testNativeSessionOperations{},
		store:      store, refreshCfg: nativeRefreshConfig{AgentID: "agent-one", RefreshMode: "disabled"},
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
		operations: testNativeSessionOperations{},
		store:      store, refreshCfg: nativeRefreshConfig{AgentID: "agent-one", RefreshMode: "auto"},
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
		Binding:           &qurl.AgentRuntimeBinding{AgentID: "agent-one"},
		store:             &memoryNativeStore{},
		SessionOperations: testNativeSessionAuthority(),
		refreshCfg: refreshConfig(NativeRuntimeConfig{
			StateDir: "/private/state", AgentID: "agent-one",
			EnrollmentCredential: "secret", EnrollmentCredentialProvider: provider,
			SessionOperations: testNativeSessionAuthority(),
		}, "auto"),
	}
	admitter, err := NewNativeAdmitter(context.Background(), runtime)
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
		len(runtime.refreshCfg.UDPOptions) != 0 || runtime.SessionOperations != (NativeSessionOperationAuthority{}) {
		t.Fatalf("transferred runtime retained refresh config = %+v", runtime.refreshCfg)
	}
}

func TestNewNativeAdmitterStartsWhileOrphanRecoveryRetriesAndCloseCancels(t *testing.T) {
	oldTakeKey := takeNativeKey
	oldRecover := recoverNativeSessionOperation
	t.Cleanup(func() {
		takeNativeKey = oldTakeKey
		recoverNativeSessionOperation = oldRecover
	})
	takeNativeKey = func(*qurl.AgentRuntimeBinding) []byte { return make([]byte, 32) }
	store := &memoryNativeStore{}
	prepared := testPreparedDurableRecord(t)
	if err := store.CreateSessionOperation(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	dispatching := prepared
	dispatching.Status = agentstate.SessionOperationDispatching
	if err := store.TransitionSessionOperation(context.Background(), prepared, dispatching); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	var once sync.Once
	recoverNativeSessionOperation = func(ctx context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
		_ qurl.NativeSessionOperation, _ qurl.NHPUDPEndpoint, _ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		once.Do(func() { close(started) })
		<-ctx.Done()
		return nil, ctx.Err()
	}
	runtime := &NativeRuntime{
		Binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, store: store,
		SessionOperations: testNativeSessionAuthority(),
	}
	admitter, err := NewNativeAdmitter(context.Background(), runtime)
	if err != nil {
		t.Fatalf("NewNativeAdmitter blocked on orphan recovery: %v", err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("background orphan recovery did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- admitter.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel background orphan recovery")
	}
}

func TestNewNativeAdmitterCallerCancellationStopsOrphanRecovery(t *testing.T) {
	oldTakeKey := takeNativeKey
	oldRecover := recoverNativeSessionOperation
	t.Cleanup(func() {
		takeNativeKey = oldTakeKey
		recoverNativeSessionOperation = oldRecover
	})
	takeNativeKey = func(*qurl.AgentRuntimeBinding) []byte { return make([]byte, 32) }
	store := &memoryNativeStore{}
	prepared := testPreparedDurableRecord(t)
	prepared.Status = agentstate.SessionOperationDispatching
	if err := store.CreateSessionOperation(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	stopped := make(chan struct{})
	var once sync.Once
	recoverNativeSessionOperation = func(ctx context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
		_ qurl.NativeSessionOperation, _ qurl.NHPUDPEndpoint, _ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		once.Do(func() { close(started) })
		<-ctx.Done()
		close(stopped)
		return nil, ctx.Err()
	}
	runtime := &NativeRuntime{
		Binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, store: store,
		SessionOperations: testNativeSessionAuthority(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	admitter, err := NewNativeAdmitter(ctx, runtime)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("background orphan recovery did not start")
	}
	cancel()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("caller cancellation did not stop background orphan recovery")
	}
	if err := admitter.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNativeAdmitterCanceledRetireWakesBoundedResourceRecovery(t *testing.T) {
	oldRecover := recoverNativeSessionOperation
	oldWait := waitNativeSessionRecovery
	t.Cleanup(func() {
		recoverNativeSessionOperation = oldRecover
		waitNativeSessionRecovery = oldWait
	})
	store := &memoryNativeStore{}
	mapped, receipt := seedMappedDurableRecord(t, store)
	operations, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	firstStarted := make(chan struct{})
	recovered := make(chan struct{})
	var recoverOnce sync.Once
	var callsMu sync.Mutex
	calls := 0
	waitNativeSessionRecovery = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	recoverNativeSessionOperation = func(ctx context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
		_ qurl.NativeSessionOperation, _ qurl.NHPUDPEndpoint, _ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		callsMu.Lock()
		calls++
		call := calls
		callsMu.Unlock()
		switch call {
		case 1:
			close(firstStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		case 2:
			return nil, nativeudp.ErrNoReply
		default:
			recoverOnce.Do(func() { close(recovered) })
			return &qurl.NativeSessionOperationRecovery{Complete: true}, nil
		}
	}
	key := admissionKey(receipt)
	lifecycle, cancelLifecycle := context.WithCancel(context.Background())
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		operations: operations, store: store,
		live: map[nativeAdmissionKey]nativeLiveAdmission{
			key: {resourceID: mapped.Operation.ProtectedResourceID, operationID: mapped.Operation.OperationID, receipt: receipt},
		},
		pending:                     make(map[nativeAdmissionKey]bool),
		retirementRecoveryWake:      make(chan struct{}, 1),
		retirementRecoveryResources: make(map[string]struct{}),
		lifecycle:                   lifecycle,
		cancel:                      cancelLifecycle,
	}
	admitter.startRecoveryWorkers()
	t.Cleanup(func() {
		if err := admitter.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	retireCtx, cancelRetire := context.WithCancel(context.Background())
	retired := make(chan error, 1)
	go func() {
		retired <- admitter.Retire(retireCtx, Admission{
			ResourceID: mapped.Operation.ProtectedResourceID, RunID: receipt.RunID, RunAttempt: receipt.RunAttempt,
			SessionID: receipt.SessionID, SessionReceipt: receipt,
		})
	}()
	select {
	case <-firstStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("initial retirement did not start")
	}
	cancelRetire()
	if err := <-retired; !errors.Is(err, context.Canceled) {
		t.Fatalf("Retire() = %v, want caller cancellation", err)
	}
	select {
	case <-recovered:
	case <-time.After(3 * time.Second):
		t.Fatal("queued resource retirement did not recover")
	}
	var live, pending, queued, recordCount int
	deadline := time.Now().Add(2 * time.Second)
	for {
		admitter.stateMu.Lock()
		live, pending, queued = len(admitter.live), len(admitter.pending), len(admitter.retirementRecoveryResources)
		admitter.stateMu.Unlock()
		records, loadErr := store.LoadSessionOperations(context.Background(), mapped.Operation.ProtectedResourceID)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		recordCount = len(records)
		if live == 0 && pending == 0 && queued == 0 && recordCount == 0 {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	callsMu.Lock()
	recoveryCalls := calls
	callsMu.Unlock()
	if recoveryCalls != 3 || live != 0 || pending != 0 || queued != 0 || recordCount != 0 {
		t.Fatalf("recovery calls=%d live=%d pending=%d queued=%d records=%d, want 3/0/0/0/0",
			recoveryCalls, live, pending, queued, recordCount)
	}
}

func TestNativeAdmitterQueuedRetirementStartsWhileOrphanScanFails(t *testing.T) {
	receipt := testSessionReceipt(1, "run-one", 1)
	key := admissionKey(receipt)
	store := &memoryNativeStore{scanRetryableErr: errors.New("scan unavailable")}
	operations := &signalingRetirementOperations{started: make(chan struct{})}
	lifecycle, cancelLifecycle := context.WithCancel(context.Background())
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		operations: operations, store: store,
		live: map[nativeAdmissionKey]nativeLiveAdmission{
			key: {resourceID: "resource-one", operationID: "operation-one", receipt: receipt},
		},
		pending:                     map[nativeAdmissionKey]bool{key: true},
		retirementRecoveryWake:      make(chan struct{}, 1),
		retirementRecoveryResources: make(map[string]struct{}),
		lifecycle:                   lifecycle,
		cancel:                      cancelLifecycle,
	}
	admitter.startRecoveryWorkers()
	admitter.queueNativeRetirementRecovery("resource-one")
	select {
	case <-operations.started:
	case <-time.After(2 * time.Second):
		t.Fatal("queued retirement was gated behind the failing orphan scan")
	}
	if err := admitter.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNativeAdmitterCloseCancelsQueuedRetirementRecovery(t *testing.T) {
	receipt := testSessionReceipt(1, "run-one", 1)
	key := admissionKey(receipt)
	operations := &blockingQueuedRetirementOperations{
		backgroundStarted: make(chan struct{}),
		backgroundStopped: make(chan struct{}),
	}
	lifecycle, cancelLifecycle := context.WithCancel(context.Background())
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		operations: operations, store: &memoryNativeStore{},
		live: map[nativeAdmissionKey]nativeLiveAdmission{
			key: {resourceID: "resource-one", operationID: "operation-one", receipt: receipt},
		},
		pending:                     make(map[nativeAdmissionKey]bool),
		retirementRecoveryWake:      make(chan struct{}, 1),
		retirementRecoveryResources: make(map[string]struct{}),
		lifecycle:                   lifecycle,
		cancel:                      cancelLifecycle,
	}
	admitter.startRecoveryWorkers()
	if err := admitter.Retire(context.Background(), Admission{
		ResourceID: "resource-one", RunID: "run-one", RunAttempt: 1,
		SessionID: 1, SessionReceipt: receipt,
	}); !errors.Is(err, nativeudp.ErrNoReply) {
		t.Fatalf("Retire() = %v, want no-reply failure", err)
	}
	select {
	case <-operations.backgroundStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("queued retirement recovery did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- admitter.Close() }()
	select {
	case <-operations.backgroundStopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel queued retirement recovery")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not finish after queued retirement stopped")
	}
}

func TestNativeRetirementRecoveryScheduleDoesNotDelayNewSibling(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	schedule := make(nativeRetirementRecoverySchedule)
	schedule.queue("resource-stuck", now)
	for range 10 {
		schedule.retry("resource-stuck", now)
		now = schedule["resource-stuck"].notBefore
	}
	if schedule["resource-stuck"].backoff != nativeOrphanRecoveryMaxBackoff {
		t.Fatalf("stuck resource backoff = %s, want %s",
			schedule["resource-stuck"].backoff, nativeOrphanRecoveryMaxBackoff)
	}
	// Leave the stuck resource waiting at its maximum delay, then add a sibling.
	schedule.retry("resource-stuck", now)
	schedule.queue("resource-new", now)
	if got, want := schedule.due(now), []string{"resource-new"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("due resources = %v, want %v", got, want)
	}
	if delay, scheduled := schedule.nextDelay(now); !scheduled || delay != 0 {
		t.Fatalf("new sibling delay = %s, scheduled=%t; want immediate", delay, scheduled)
	}
}

func TestPermanentNativeRetirementErrorIsConservative(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "authenticated deny", err: &qurl.ServerDenyError{ErrCode: "52004"}, want: true},
		{name: "invalid durable operation", err: fmt.Errorf("recover: %w", qurl.ErrInvalidNativeSessionOperation), want: true},
		{name: "malformed authenticated reply", err: qurl.ErrMalformedReply, want: false},
		{name: "journal conflict", err: agentstate.ErrSessionOperationConflict, want: true},
		{name: "journal corruption", err: agentstate.ErrSessionOperationJournalCorrupt, want: true},
		{name: "no reply", err: nativeudp.ErrNoReply, want: false},
		{name: "local cancellation", err: context.Canceled, want: false},
		{
			name: "mixed permanent and transient",
			err:  errors.Join(&qurl.ServerDenyError{ErrCode: "52004"}, nativeudp.ErrNoReply),
			want: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isPermanentNativeRetirementError(test.err); got != test.want {
				t.Fatalf("isPermanentNativeRetirementError(%v) = %t, want %t", test.err, got, test.want)
			}
		})
	}
}

func TestNativeAdmitterPermanentRetirementFailureDoesNotRequeue(t *testing.T) {
	receipt := testSessionReceipt(1, "run-one", 1)
	key := admissionKey(receipt)
	lifecycle, cancelLifecycle := context.WithCancel(context.Background())
	defer cancelLifecycle()
	deny := &qurl.ServerDenyError{ErrCode: "52004"}
	admitter := &NativeAdmitter{
		binding:    &qurl.AgentRuntimeBinding{AgentID: "agent-one"},
		privateKey: make([]byte, 32),
		operations: retirementFailureOperations{err: deny},
		live: map[nativeAdmissionKey]nativeLiveAdmission{
			key: {resourceID: "resource-one", operationID: "operation-one", receipt: receipt},
		},
		pending:                     map[nativeAdmissionKey]bool{key: true},
		retirementRecoveryWake:      make(chan struct{}, 1),
		retirementRecoveryResources: make(map[string]struct{}),
		lifecycle:                   lifecycle,
	}
	permanent, err := admitter.recoverPendingNativeRetirements(lifecycle, "resource-one")
	if !permanent || !errors.Is(err, deny) {
		t.Fatalf("recovery permanent=%t error=%v, want authenticated deny", permanent, err)
	}
	admitter.stateMu.Lock()
	_, queued := admitter.retirementRecoveryResources["resource-one"]
	admitter.stateMu.Unlock()
	if queued {
		t.Fatal("permanent retirement failure was requeued")
	}
	if len(admitter.live) != 1 || len(admitter.pending) != 1 {
		t.Fatalf("permanent retirement released fail-closed state: live=%d pending=%d",
			len(admitter.live), len(admitter.pending))
	}
}

func TestNativeAdmitterPreRetireFailureStaysRetryable(t *testing.T) {
	admitter := &NativeAdmitter{}
	permanent, err := admitter.recoverPendingNativeRetirements(context.Background(), "resource-one")
	if err == nil || permanent {
		t.Fatalf("pre-retire recovery permanent=%t error=%v, want retryable incomplete-runtime error", permanent, err)
	}
}

func TestNativeAdmitterCloseDoesNotRaceLifecycleBinding(t *testing.T) {
	lifecycle, cancelLifecycle := context.WithCancel(context.Background())
	admitter := &NativeAdmitter{
		lifecycle: lifecycle,
		cancel:    cancelLifecycle,
		live:      make(map[nativeAdmissionKey]nativeLiveAdmission),
		pending:   make(map[nativeAdmissionKey]bool),
	}
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		for {
			ctx, cancel := admitter.withLifecycle(context.Background())
			cancel()
			if ctx.Err() != nil {
				close(done)
				return
			}
		}
	}()
	<-started
	if err := admitter.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("lifecycle binding did not observe close cancellation")
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
		operations: testNativeSessionOperations{},
		store:      &memoryNativeStore{},
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
		operations: testNativeSessionOperations{},
		store:      &memoryNativeStore{},
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
		operations: testNativeSessionOperations{},
		store:      &memoryNativeStore{},
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
			operations: testNativeSessionOperations{},
			store:      &memoryNativeStore{},
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
		if err == nil || errors.Is(err, nativeudp.ErrNoReply) ||
			!strings.Contains(err.Error(), "durable native session cleanup also failed") {
			t.Fatalf("Admit() = %v, want primary local-validation error with secondary retirement diagnostic", err)
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
		operations: testNativeSessionOperations{},
		store:      &memoryNativeStore{},
		live:       map[nativeAdmissionKey]nativeLiveAdmission{admissionKey(receipt): {resourceID: "resource-one", receipt: receipt}},
		pending:    make(map[nativeAdmissionKey]bool),
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

func TestNativeAdmitterFencesServingReplacementUntilDurableRetirementTerminal(t *testing.T) {
	oldRecover := recoverNativeSessionOperation
	oldWait := waitNativeSessionRecovery
	oldKnock := knockNativeRuntime
	t.Cleanup(func() {
		recoverNativeSessionOperation = oldRecover
		waitNativeSessionRecovery = oldWait
		knockNativeRuntime = oldKnock
	})

	store := &memoryNativeStore{}
	mapped, receipt := seedMappedDurableRecord(t, store)
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	controller.clock = func() time.Time { return time.UnixMilli(1_800_000_011_000).UTC() }

	// qurl-go maps authenticated 52029 replies to Complete=false and 52030 to
	// Complete=true. Keep the exact wire-code sequence visible at this seam so
	// the Connector fence cannot regress to treating a pending poll as terminal.
	codes := []string{"52029", "52029", "52029", "52030"}
	terminalPoll := make(chan struct{})
	allowTerminal := make(chan struct{})
	violation := make(chan error, 1)
	recoveryCalls := 0
	waits := 0
	oldAuthorityLive := true
	recoverNativeSessionOperation = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
		operation qurl.NativeSessionOperation, _ qurl.NHPUDPEndpoint, _ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		if operation.OperationID != mapped.Operation.OperationID {
			err := fmt.Errorf("recovered operation = %q, want original %q", operation.OperationID, mapped.Operation.OperationID)
			violation <- err
			return nil, err
		}
		if recoveryCalls >= len(codes) {
			err := errors.New("durable retirement polled after terminal 52030")
			violation <- err
			return nil, err
		}
		code := codes[recoveryCalls]
		recoveryCalls++
		if code == "52029" {
			return &qurl.NativeSessionOperationRecovery{Complete: false}, nil
		}
		close(terminalPoll)
		<-allowTerminal
		oldAuthorityLive = false
		return &qurl.NativeSessionOperationRecovery{Complete: true}, nil
	}
	waitNativeSessionRecovery = func(context.Context, time.Duration) error {
		waits++
		return nil
	}
	knockNativeRuntime = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte, _ string,
		opts qurl.NativeKnockOptions, _ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeKnockResult, error) {
		if oldAuthorityLive {
			err := errors.New("replacement admission overlapped nonterminal durable retirement")
			violation <- err
			return nil, err
		}
		replacement := testSessionReceipt(92, opts.RunID, opts.RunAttempt)
		replacement.CellID = "cell-02"
		return &qurl.NativeKnockResult{
			ACToken: "token", ResourceHost: "127.0.0.1:7000", SessionID: replacement.SessionID,
			OpenTime: 3600, SessionReceipt: replacement,
		}, nil
	}

	key := admissionKey(receipt)
	operations := &durableRetirementFenceOperations{controller: controller}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: mapped.Operation.AgentID}, privateKey: make([]byte, 32),
		operations: operations, store: store,
		live: map[nativeAdmissionKey]nativeLiveAdmission{
			key: {resourceID: testProtectedResourceID, operationID: mapped.Operation.OperationID, receipt: receipt},
		},
		pending: map[nativeAdmissionKey]bool{key: true},
	}
	factory := &overlapFactory{}
	serving := make(chan Admission, 1)
	runner, err := NewResourceRunner(ResourceConfig{
		KnockResourceID: "resource-b", ResourceID: testProtectedResourceID,
		Admitter: admitter, Sessions: factory, OnServing: func(admission Admission) { serving <- admission },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- runner.Run(ctx) }()

	select {
	case <-terminalPoll:
	case err := <-violation:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("durable retirement did not reach terminal 52030 poll")
	}
	factory.mu.Lock()
	startedBeforeTerminal := factory.next
	factory.mu.Unlock()
	if recoveryCalls != 4 || waits != 3 || startedBeforeTerminal != 0 || !oldAuthorityLive {
		t.Fatalf("pre-terminal recovery calls/waits/starts/live=%d/%d/%d/%t, want 4/3/0/true",
			recoveryCalls, waits, startedBeforeTerminal, oldAuthorityLive)
	}
	select {
	case admission := <-serving:
		t.Fatalf("replacement served before terminal retirement: %v", admission)
	case err := <-runDone:
		t.Fatalf("runner exited before terminal retirement: %v", err)
	default:
	}

	close(allowTerminal)
	select {
	case admission := <-serving:
		if admission.SessionID != 92 || oldAuthorityLive {
			t.Fatalf("replacement serving admission/live = %v/%t", admission, oldAuthorityLive)
		}
	case err := <-runDone:
		t.Fatalf("runner exited instead of serving replacement: %v", err)
	case err := <-violation:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("replacement did not serve after terminal 52030")
	}

	cancel()
	if err := <-runDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("runner shutdown = %v, want context cancellation", err)
	}
	factory.mu.Lock()
	servingCount, gap := factory.serving, factory.gap
	factory.mu.Unlock()
	if servingCount != 0 || gap || recoveryCalls != len(codes) {
		t.Fatalf("final serving/gap/recovery=%d/%t/%d, want 0/false/%d", servingCount, gap, recoveryCalls, len(codes))
	}
	if records, loadErr := store.LoadSessionOperations(context.Background(), testProtectedResourceID); loadErr != nil || len(records) != 0 {
		t.Fatalf("terminal durable retirement records=%+v err=%v", records, loadErr)
	}
}
