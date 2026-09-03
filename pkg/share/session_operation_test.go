package share

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	qurl "github.com/layervai/qurl-go/qurl"
	"github.com/layervai/qurl-go/relayknock/nativeudp"

	"github.com/layervai/qurl-connector/pkg/agentstate"
)

const testProtectedResourceID = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcOtuxu2qhc3gt1E7BiEU0CLqEDlXDwzZq0JnESgMAwERX6y_XXF5Cn5SKITWIZQmUhCZ0pHHlVn7SmFUTAnTGQ"

func testDurableOperation() qurl.NativeSessionOperation {
	return qurl.NativeSessionOperation{
		AgentID: "agent-a", AgentKeySchema: 2, AgentPublicKeyB64: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=",
		AuthServiceID: "agent",
		BindingSchema: 2, BindingSHA256: "ce4bdb9b1607bf430bc706a580c3e252f9a182e51e646e51e886630c2acb4b7e",
		CellID: "cell-01", CredentialKind: "account", ExpiresAtMillis: 1_800_001_209_000,
		OperationID: "3b2a3a9eabea3af78d8c317ea710e7f0601580163e25c98d50d5e2e17b68f3cc",
		OwnerID:     "auth0|canary-owner", PreparedAtMillis: 1_800_000_009_000,
		ProtectedResourceID: testProtectedResourceID,
		ResourceID:          "resource-a", RunID: "0123456789abcdef", RunAttempt: 7, Schema: 2,
	}
}

func testDurableOperationForProtectedResource(resourceID string) qurl.NativeSessionOperation {
	operation := testDurableOperation()
	operation.ProtectedResourceID = resourceID
	canonical := struct {
		AgentID             string `json:"agent_id"`
		AgentKeySchema      int    `json:"agent_key_schema_version"`
		AgentPublicKeyB64   string `json:"agent_public_key_b64"`
		AuthServiceID       string `json:"auth_service_id"`
		BindingSchema       int    `json:"binding_schema"`
		CellID              string `json:"cell_id"`
		ConnectorIDClaim    string `json:"connector_id_claim"`
		CredentialKind      string `json:"enrollment_credential_kind"`
		ExpiresAtMillis     int64  `json:"expires_at_ms"`
		OperationID         string `json:"operation_id"`
		OwnerID             string `json:"owner_id"`
		PreparedAtMillis    int64  `json:"prepared_at_ms"`
		ProtectedResourceID string `json:"protected_resource_id"`
		ResourceID          string `json:"resource_id"`
		RunAttempt          uint64 `json:"run_attempt"`
		RunID               string `json:"run_id"`
	}{
		AgentID: operation.AgentID, AgentKeySchema: operation.AgentKeySchema,
		AgentPublicKeyB64: operation.AgentPublicKeyB64, AuthServiceID: operation.AuthServiceID,
		BindingSchema: operation.BindingSchema, CellID: operation.CellID,
		ConnectorIDClaim: operation.ConnectorIDClaim, CredentialKind: operation.CredentialKind,
		ExpiresAtMillis: operation.ExpiresAtMillis, OperationID: operation.OperationID,
		OwnerID: operation.OwnerID, PreparedAtMillis: operation.PreparedAtMillis,
		ProtectedResourceID: operation.ProtectedResourceID, ResourceID: operation.ResourceID,
		RunAttempt: operation.RunAttempt, RunID: operation.RunID,
	}
	raw, _ := json.Marshal(canonical)
	digest := sha256.Sum256(raw)
	operation.BindingSHA256 = hex.EncodeToString(digest[:])
	return operation
}

func testDurableRecoveryEndpoint() qurl.NHPUDPEndpoint {
	return qurl.NHPUDPEndpoint{
		Host: "cell-one.example.test", Port: 443,
		ServerPublicKeyB64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}
}

func testPreparedDurableRecord(t *testing.T) agentstate.SessionOperationRecord {
	t.Helper()
	record, err := agentstate.NewSessionOperationRecord(testDurableOperation(), testDurableRecoveryEndpoint())
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func seedMappedDurableRecord(t *testing.T, store *memoryNativeStore) (agentstate.SessionOperationRecord, qurl.NativeSessionReceipt) {
	t.Helper()
	prepared := testPreparedDurableRecord(t)
	if err := store.CreateSessionOperation(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	dispatching := prepared
	dispatching.Status = agentstate.SessionOperationDispatching
	if err := store.TransitionSessionOperation(context.Background(), prepared, dispatching); err != nil {
		t.Fatal(err)
	}
	receipt := qurl.NativeSessionReceipt{
		CellID: dispatching.Operation.CellID, SessionID: 91, SessionIssuedAtMillis: 1_800_000_010_000,
		RunID: dispatching.Operation.RunID, RunAttempt: dispatching.Operation.RunAttempt,
	}
	mapped := dispatching
	mapped.Status = agentstate.SessionOperationMapped
	mapped.Admission = admissionFromReceipt(receipt)
	if err := store.TransitionSessionOperation(context.Background(), dispatching, mapped); err != nil {
		t.Fatal(err)
	}
	return mapped, receipt
}

func TestDurableNativeSessionOperationPersistsEveryNetworkBoundary(t *testing.T) {
	oldPrepare := prepareLiveNativeSessionOperation
	oldRecover := recoverNativeSessionOperation
	t.Cleanup(func() {
		prepareLiveNativeSessionOperation = oldPrepare
		recoverNativeSessionOperation = oldRecover
	})
	store := &memoryNativeStore{}
	authority := NativeSessionOperationAuthority{OwnerID: "auth0|canary-owner"}
	controller, err := newDurableNativeSessionOperations(store, authority)
	if err != nil {
		t.Fatal(err)
	}
	controller.clock = func() time.Time { return time.UnixMilli(1_800_000_009_000).UTC() }
	const protected = testProtectedResourceID
	const runID = "0123456789abcdef"
	prepareLiveNativeSessionOperation = func(_ context.Context, _ *qurl.AgentRuntimeBinding, key []byte,
		input qurl.NativeSessionOperationInput,
	) (*qurl.NativeSessionOperation, qurl.NHPUDPEndpoint, error) {
		if len(key) != 32 || input.OwnerID != "auth0|canary-owner" ||
			input.ResourceID != "resource-a" || input.ProtectedResourceID != protected ||
			input.RunID != runID || input.RunAttempt != 7 || input.PreparedAtMillis != 1_800_000_009_000 ||
			input.ExpiresAtMillis != 1_800_001_209_000 {
			t.Fatalf("operation input = %+v", input)
		}
		if len(store.operations[protected]) != 0 {
			t.Fatal("operation was persisted before offline preparation completed")
		}
		operation := testDurableOperation()
		return &operation, testDurableRecoveryEndpoint(), nil
	}
	binding := &qurl.AgentRuntimeBinding{AgentID: "agent-one"}
	operation, err := controller.PrepareDispatch(context.Background(), binding, make([]byte, 32), "resource-a", protected, runID, 7)
	if err != nil {
		t.Fatal(err)
	}
	records, err := store.LoadSessionOperations(context.Background(), protected)
	if err != nil || len(records) != 1 || records[0].Status != agentstate.SessionOperationDispatching || records[0].Operation != *operation {
		t.Fatalf("dispatch records = %+v, err=%v", records, err)
	}
	record := records[0]
	receipt := qurl.NativeSessionReceipt{
		CellID: operation.CellID, SessionID: 91, SessionIssuedAtMillis: 1_800_000_010_000,
		RunID: runID, RunAttempt: 7,
	}
	if err := controller.RecordMapped(context.Background(), protected, *operation, receipt); err != nil {
		t.Fatal(err)
	}
	records, _ = store.LoadSessionOperations(context.Background(), protected)
	record = records[0]
	if record.Status != agentstate.SessionOperationMapped || record.Admission == nil || record.Admission.SessionID != 91 {
		t.Fatalf("mapped record = %+v", record)
	}

	recoverCalls := 0
	recoverNativeSessionOperation = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
		got qurl.NativeSessionOperation, _ qurl.NHPUDPEndpoint, options ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		recoverCalls++
		current := store.operations[protected][0]
		if current.Status != agentstate.SessionOperationClosing || got != *operation ||
			len(options) != 1 || options[0] == nil {
			t.Fatalf("recovery boundary record=%+v operation=%+v", current, got)
		}
		return &qurl.NativeSessionOperationRecovery{Complete: true}, nil
	}
	if err := controller.Retire(context.Background(), binding, make([]byte, 32), protected, operation.OperationID,
		receipt, testAgentRuntimeUDPOptions()); err != nil {
		t.Fatal(err)
	}
	if recoverCalls != 1 {
		t.Fatalf("recover calls=%d", recoverCalls)
	}
	if records, err := store.LoadSessionOperations(context.Background(), protected); err != nil || len(records) != 0 {
		t.Fatalf("terminal records=%+v err=%v", records, err)
	}
}

func TestDurableNativeSessionOperationSurvivesSDKStoreRestart(t *testing.T) {
	oldPrepare := prepareLiveNativeSessionOperation
	oldRecover := recoverNativeSessionOperation
	t.Cleanup(func() {
		prepareLiveNativeSessionOperation = oldPrepare
		recoverNativeSessionOperation = oldRecover
	})
	t.Setenv(agentstate.EnvKeyProvider, agentstate.KeyProviderFile)
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "state")
	store, err := agentstate.NewSDKStore(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	controller.clock = func() time.Time { return time.UnixMilli(1_800_000_009_000).UTC() }
	prepareLiveNativeSessionOperation = func(context.Context, *qurl.AgentRuntimeBinding, []byte,
		qurl.NativeSessionOperationInput,
	) (*qurl.NativeSessionOperation, qurl.NHPUDPEndpoint, error) {
		operation := testDurableOperation()
		return &operation, testDurableRecoveryEndpoint(), nil
	}
	operation, err := controller.PrepareDispatch(context.Background(), &qurl.AgentRuntimeBinding{AgentID: "agent-one"},
		make([]byte, 32), "resource-a", testProtectedResourceID, "0123456789abcdef", 7)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := agentstate.NewSDKStore(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovery, err := newDurableNativeSessionOperations(reopened, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	recovery.clock = controller.clock
	recoverNativeSessionOperation = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
		got qurl.NativeSessionOperation, _ qurl.NHPUDPEndpoint, options ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		if got != *operation || len(options) != 1 || options[0] == nil {
			t.Fatalf("restarted operation = %+v, want %+v", got, *operation)
		}
		return &qurl.NativeSessionOperationRecovery{Complete: true}, nil
	}
	if err := recovery.RecoverPending(context.Background(), &qurl.AgentRuntimeBinding{AgentID: "agent-one"},
		make([]byte, 32), testProtectedResourceID, nil,
		testAgentRuntimeUDPOptions()); err != nil {
		t.Fatal(err)
	}
	if records, err := reopened.LoadSessionOperations(context.Background(), testProtectedResourceID); err != nil || len(records) != 0 {
		t.Fatalf("restarted terminal records=%+v err=%v", records, err)
	}
}

func TestDurableNativeSessionOperationRecoversEveryEnumeratedResource(t *testing.T) {
	oldRecover := recoverNativeSessionOperation
	t.Cleanup(func() { recoverNativeSessionOperation = oldRecover })
	store := &memoryNativeStore{}
	first := testPreparedDurableRecord(t)
	secondOperation := testDurableOperationForProtectedResource("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2vPoafaVb5Lue-bfcCuoL-_CnVBKf8YvV94G8ozebA6RHEQUPsnguSt1yx2mTzDSogBmb9WYEVBDgX7vc2NKTg")
	second, err := agentstate.NewSessionOperationRecord(secondOperation, testDurableRecoveryEndpoint())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSessionOperation(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	firstDispatching := first
	firstDispatching.Status = agentstate.SessionOperationDispatching
	if err := store.TransitionSessionOperation(context.Background(), first, firstDispatching); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSessionOperation(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	recoverCalls := 0
	recoverNativeSessionOperation = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
		operation qurl.NativeSessionOperation, _ qurl.NHPUDPEndpoint, _ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		recoverCalls++
		if operation.ProtectedResourceID != first.Operation.ProtectedResourceID {
			t.Fatalf("recovered unexpected resource %q", operation.ProtectedResourceID)
		}
		return &qurl.NativeSessionOperationRecovery{Complete: true}, nil
	}
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		store: store, operations: controller,
	}
	if err := admitter.recoverAllPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.operations[first.Operation.ProtectedResourceID]) != 0 || len(store.operations[second.Operation.ProtectedResourceID]) != 0 {
		t.Fatalf("startup recovery retained operations: %+v", store.operations)
	}
	if recoverCalls != 1 {
		t.Fatalf("startup network recoveries = %d, want 1", recoverCalls)
	}
}

func TestNativeAdmitterOrphanRecoveryIsolatesSiblingResources(t *testing.T) {
	oldRecover := recoverNativeSessionOperation
	t.Cleanup(func() { recoverNativeSessionOperation = oldRecover })
	store := &memoryNativeStore{}
	failed := testPreparedDurableRecord(t)
	failed.Status = agentstate.SessionOperationDispatching
	healthyOperation := testDurableOperationForProtectedResource("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2vPoafaVb5Lue-bfcCuoL-_CnVBKf8YvV94G8ozebA6RHEQUPsnguSt1yx2mTzDSogBmb9WYEVBDgX7vc2NKTg")
	healthy, err := agentstate.NewSessionOperationRecord(healthyOperation, testDurableRecoveryEndpoint())
	if err != nil {
		t.Fatal(err)
	}
	store.operations = map[string][]agentstate.SessionOperationRecord{
		failed.Operation.ProtectedResourceID:  {failed},
		healthy.Operation.ProtectedResourceID: {healthy},
	}
	want := errors.New("issuing cell unavailable")
	recoverNativeSessionOperation = func(context.Context, *qurl.AgentRuntimeBinding, []byte,
		qurl.NativeSessionOperation, qurl.NHPUDPEndpoint, ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		return nil, want
	}
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		store: store, operations: controller,
	}
	err = admitter.recoverAllPending(context.Background())
	if !errors.Is(err, want) {
		t.Fatalf("recoverAllPending() = %v, want failed resource error", err)
	}
	if len(store.operations[failed.Operation.ProtectedResourceID]) != 1 {
		t.Fatalf("failed resource journal was discarded: %+v", store.operations)
	}
	if len(store.operations[healthy.Operation.ProtectedResourceID]) != 0 {
		t.Fatalf("healthy sibling recovery did not continue: %+v", store.operations)
	}
}

func TestNativeAdmitterOrphanRecoveryStopsRetryingPermanentRetirement(t *testing.T) {
	oldRecover := recoverNativeSessionOperation
	t.Cleanup(func() { recoverNativeSessionOperation = oldRecover })
	store := &memoryNativeStore{}
	record := testPreparedDurableRecord(t)
	record.Status = agentstate.SessionOperationDispatching
	store.operations = map[string][]agentstate.SessionOperationRecord{
		record.Operation.ProtectedResourceID: {record},
	}
	calls := 0
	recoverNativeSessionOperation = func(context.Context, *qurl.AgentRuntimeBinding, []byte,
		qurl.NativeSessionOperation, qurl.NHPUDPEndpoint, ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		calls++
		return nil, &qurl.ServerDenyError{ErrCode: "52004"}
	}
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		store: store, operations: controller,
	}
	if err := admitter.recoverAllPending(context.Background()); err != nil {
		t.Fatalf("recoverAllPending() = %v, want terminal failure reported without retry", err)
	}
	if calls != 1 {
		t.Fatalf("permanent retirement calls = %d, want 1", calls)
	}
	if len(store.operations[record.Operation.ProtectedResourceID]) != 1 {
		t.Fatalf("permanent retirement discarded fail-closed journal: %+v", store.operations)
	}
}

func TestNativeAdmitterOrphanRecoveryDoesNotRepeatPermanentSibling(t *testing.T) {
	oldRecover := recoverNativeSessionOperation
	t.Cleanup(func() { recoverNativeSessionOperation = oldRecover })
	store := &memoryNativeStore{}
	permanent := testPreparedDurableRecord(t)
	permanent.Status = agentstate.SessionOperationDispatching
	transientOperation := testDurableOperationForProtectedResource("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2vPoafaVb5Lue-bfcCuoL-_CnVBKf8YvV94G8ozebA6RHEQUPsnguSt1yx2mTzDSogBmb9WYEVBDgX7vc2NKTg")
	transient, err := agentstate.NewSessionOperationRecord(transientOperation, testDurableRecoveryEndpoint())
	if err != nil {
		t.Fatal(err)
	}
	transient.Status = agentstate.SessionOperationDispatching
	store.operations = map[string][]agentstate.SessionOperationRecord{
		permanent.Operation.ProtectedResourceID: {permanent},
		transient.Operation.ProtectedResourceID: {transient},
	}
	calls := make(map[string]int)
	transientErr := errors.New("issuing cell unavailable")
	recoverNativeSessionOperation = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
		operation qurl.NativeSessionOperation, _ qurl.NHPUDPEndpoint, _ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		calls[operation.ProtectedResourceID]++
		if operation.ProtectedResourceID == permanent.Operation.ProtectedResourceID {
			return nil, &qurl.ServerDenyError{ErrCode: "52004"}
		}
		return nil, transientErr
	}
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		store: store, operations: controller,
	}
	permanentResources := make(map[string]struct{})
	for range 2 {
		if err := admitter.recoverAllPendingExcludingPermanent(context.Background(), permanentResources); !errors.Is(err, transientErr) {
			t.Fatalf("recoverAllPendingExcludingPermanent() = %v, want transient sibling error", err)
		}
	}
	if calls[permanent.Operation.ProtectedResourceID] != 1 || calls[transient.Operation.ProtectedResourceID] != 2 {
		t.Fatalf("recovery calls = %+v, want permanent=1 transient=2", calls)
	}
	if _, marked := permanentResources[permanent.Operation.ProtectedResourceID]; !marked {
		t.Fatalf("permanent resource was not retained in the worker exclusion set: %+v", permanentResources)
	}
	if len(store.operations[permanent.Operation.ProtectedResourceID]) != 1 ||
		len(store.operations[transient.Operation.ProtectedResourceID]) != 1 {
		t.Fatalf("orphan recovery discarded fail-closed journals: %+v", store.operations)
	}
}

func TestNativeAdmitterOrphanRecoveryContinuesPastCorruptSiblingJournal(t *testing.T) {
	store := &memoryNativeStore{scanPermanentErr: agentstate.ErrSessionOperationJournalCorrupt}
	operation := testPreparedDurableRecord(t)
	if err := store.CreateSessionOperation(context.Background(), operation); err != nil {
		t.Fatal(err)
	}
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		store: store, operations: controller,
	}
	if err := admitter.recoverAllPending(context.Background()); err != nil {
		t.Fatalf("terminal sibling journal error stopped valid recovery: %v", err)
	}
	if len(store.operations[operation.Operation.ProtectedResourceID]) != 0 {
		t.Fatalf("valid sibling operation was not recovered: %+v", store.operations)
	}
}

func TestNativeAdmitterOrphanRecoveryRetriesNamespaceFailure(t *testing.T) {
	want := errors.New("temporary namespace read failure")
	store := &memoryNativeStore{scanRetryableErr: want}
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	admitter := &NativeAdmitter{
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, privateKey: make([]byte, 32),
		store: store, operations: controller,
	}
	if err := admitter.recoverAllPending(context.Background()); !errors.Is(err, want) {
		t.Fatalf("recoverAllPending() = %v, want retryable namespace error", err)
	}
}

func TestDurableNativeSessionRecoverySharesOneResourceDeadline(t *testing.T) {
	oldRecover := recoverNativeSessionOperation
	t.Cleanup(func() { recoverNativeSessionOperation = oldRecover })
	store := &memoryNativeStore{}
	first := testPreparedDurableRecord(t)
	first.Status = agentstate.SessionOperationDispatching
	second := first
	second.Operation.OperationID = strings.Repeat("4", 64)
	store.operations = map[string][]agentstate.SessionOperationRecord{
		testProtectedResourceID: {first, second},
	}
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	deadlines := make([]time.Time, 0, 2)
	recoverNativeSessionOperation = func(ctx context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
		_ qurl.NativeSessionOperation, _ qurl.NHPUDPEndpoint, _ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("recovery call has no cleanup deadline")
		}
		deadlines = append(deadlines, deadline)
		return nil, errors.New("retry later")
	}
	err = controller.RecoverPending(context.Background(), &qurl.AgentRuntimeBinding{AgentID: "agent-one"},
		make([]byte, 32), testProtectedResourceID, nil, nil)
	if err == nil || len(deadlines) != 2 {
		t.Fatalf("RecoverPending() = %v, deadlines=%v", err, deadlines)
	}
	if !deadlines[0].Equal(deadlines[1]) {
		t.Fatalf("per-operation deadlines differ: %v", deadlines)
	}
}

func TestDurableNativeSessionRecoveryClampsClockRegressionAndDefersToServer(t *testing.T) {
	oldRecover := recoverNativeSessionOperation
	oldWait := waitNativeSessionRecovery
	t.Cleanup(func() {
		recoverNativeSessionOperation = oldRecover
		waitNativeSessionRecovery = oldWait
	})
	store := &memoryNativeStore{}
	record := testPreparedDurableRecord(t)
	record.Status = agentstate.SessionOperationDispatching
	record.RecoveryAttempt = 1
	now := time.UnixMilli(1_900_000_000_000).UTC()
	record.RecoveryNotBeforeMilli = now.Add(time.Hour).UnixMilli()
	if err := store.CreateSessionOperation(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	controller.clock = func() time.Time { return now }
	var waited time.Duration
	waitNativeSessionRecovery = func(_ context.Context, delay time.Duration) error {
		waited = delay
		return nil
	}
	recoverCalls := 0
	recoverNativeSessionOperation = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
		_ qurl.NativeSessionOperation, _ qurl.NHPUDPEndpoint, _ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		recoverCalls++
		current := store.operations[testProtectedResourceID][0]
		if current.RecoveryNotBeforeMilli != record.RecoveryNotBeforeMilli+1 {
			t.Fatalf("monotonic recovery deadline = %d, want %d", current.RecoveryNotBeforeMilli, record.RecoveryNotBeforeMilli+1)
		}
		return &qurl.NativeSessionOperationRecovery{Complete: true}, nil
	}
	if err := controller.RecoverOperation(context.Background(), &qurl.AgentRuntimeBinding{AgentID: "agent-one"},
		make([]byte, 32), testProtectedResourceID, record.Operation.OperationID, nil); err != nil {
		t.Fatal(err)
	}
	if waited != nativeSessionRecoveryMaxDelay || recoverCalls != 1 {
		t.Fatalf("clock-regressed recovery wait=%s calls=%d", waited, recoverCalls)
	}
	if records, err := store.LoadSessionOperations(context.Background(), testProtectedResourceID); err != nil || len(records) != 0 {
		t.Fatalf("server-complete records=%+v err=%v", records, err)
	}
}

func TestDurableNativeSessionRecoveryContinuesAfterSiblingFailure(t *testing.T) {
	oldRecover := recoverNativeSessionOperation
	t.Cleanup(func() { recoverNativeSessionOperation = oldRecover })

	store := &memoryNativeStore{}
	first := testPreparedDurableRecord(t)
	if err := store.CreateSessionOperation(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	firstDispatching := first
	firstDispatching.Status = agentstate.SessionOperationDispatching
	if err := store.TransitionSessionOperation(context.Background(), first, firstDispatching); err != nil {
		t.Fatal(err)
	}
	secondOperation := testDurableOperation()
	secondOperation.OperationID = strings.Repeat("4", 64)
	second := first
	second.Operation = secondOperation
	// The in-memory test store deliberately bypasses journal validation here.
	// The test exercises sibling iteration, not operation construction; the
	// prepared sibling takes the local cancel path and never reaches the wire.
	store.operations[testProtectedResourceID] = append(store.operations[testProtectedResourceID], second)

	want := errors.New("first recovery failed")
	recoverNativeSessionOperation = func(context.Context, *qurl.AgentRuntimeBinding, []byte,
		qurl.NativeSessionOperation, qurl.NHPUDPEndpoint, ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		return nil, want
	}
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	err = controller.RecoverPending(context.Background(), &qurl.AgentRuntimeBinding{AgentID: "agent-one"},
		make([]byte, 32), testProtectedResourceID, nil, nil)
	if !errors.Is(err, want) {
		t.Fatalf("RecoverPending() = %v, want first recovery error", err)
	}
	records, loadErr := store.LoadSessionOperations(context.Background(), testProtectedResourceID)
	if loadErr != nil || len(records) != 1 || records[0].Operation.OperationID != first.Operation.OperationID {
		t.Fatalf("sibling recovery did not continue: records=%+v err=%v", records, loadErr)
	}
}

func TestDurableNativeSessionRecoveryCancelsPreparedOperationWithoutNetwork(t *testing.T) {
	oldRecover := recoverNativeSessionOperation
	t.Cleanup(func() { recoverNativeSessionOperation = oldRecover })
	store := &memoryNativeStore{}
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	const protected = testProtectedResourceID
	record := testPreparedDurableRecord(t)
	if err := store.CreateSessionOperation(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	recoverNativeSessionOperation = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
		_ qurl.NativeSessionOperation, _ qurl.NHPUDPEndpoint, _ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		t.Fatal("PREPARED operation crossed the network")
		return nil, nil
	}
	if err := controller.RecoverPending(context.Background(), &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, make([]byte, 32), protected, nil, nil); err != nil {
		t.Fatal(err)
	}
	if records, err := store.LoadSessionOperations(context.Background(), protected); err != nil || len(records) != 0 {
		t.Fatalf("canceled tombstone records=%+v err=%v", records, err)
	}
}

func TestDurableNativeSessionRetirementResumesClosingWithPersistedBackoff(t *testing.T) {
	oldRecover := recoverNativeSessionOperation
	oldWait := waitNativeSessionRecovery
	t.Cleanup(func() {
		recoverNativeSessionOperation = oldRecover
		waitNativeSessionRecovery = oldWait
	})
	store := &memoryNativeStore{}
	mapped, receipt := seedMappedDurableRecord(t, store)
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(1_800_000_011_000).UTC()
	controller.clock = func() time.Time { return now }
	var waits []time.Duration
	waitNativeSessionRecovery = func(_ context.Context, delay time.Duration) error {
		waits = append(waits, delay)
		now = now.Add(delay)
		return nil
	}
	recoverCalls := 0
	recoverNativeSessionOperation = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
		_ qurl.NativeSessionOperation, _ qurl.NHPUDPEndpoint, _ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		recoverCalls++
		current := store.operations[testProtectedResourceID][0]
		if current.Status != agentstate.SessionOperationClosing || current.RecoveryAttempt != uint32(recoverCalls) ||
			current.RecoveryNotBeforeMilli <= now.UnixMilli() {
			t.Fatalf("recovery %d crossed network before durable backoff: %+v", recoverCalls, current)
		}
		if recoverCalls == 1 {
			return nil, errors.New("recovery reply lost")
		}
		return &qurl.NativeSessionOperationRecovery{Complete: true}, nil
	}
	binding := &qurl.AgentRuntimeBinding{AgentID: mapped.Operation.AgentID}
	err = controller.Retire(context.Background(), binding, make([]byte, 32), testProtectedResourceID,
		mapped.Operation.OperationID, receipt, nil)
	if err == nil {
		t.Fatal("lost retirement and recovery replies were accepted")
	}
	err = controller.Retire(context.Background(), binding, make([]byte, 32), testProtectedResourceID,
		mapped.Operation.OperationID, receipt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if recoverCalls != 2 || len(waits) != 1 || waits[0] != nativeSessionRecoveryInitialDelay {
		t.Fatalf("resume recovery calls=%d waits=%v", recoverCalls, waits)
	}
	if records, loadErr := store.LoadSessionOperations(context.Background(), testProtectedResourceID); loadErr != nil || len(records) != 0 {
		t.Fatalf("resumed terminal records=%+v err=%v", records, loadErr)
	}
}

type failFirstSessionOperationDeleteStore struct {
	*memoryNativeStore
	err     error
	deletes int
}

func (s *failFirstSessionOperationDeleteStore) DeleteSessionOperation(ctx context.Context,
	terminal agentstate.SessionOperationRecord,
) error {
	s.deletes++
	if s.deletes == 1 {
		return s.err
	}
	return s.memoryNativeStore.DeleteSessionOperation(ctx, terminal)
}

func TestDurableNativeSessionRetirementResumesCommittedClosedTombstone(t *testing.T) {
	oldRecover := recoverNativeSessionOperation
	t.Cleanup(func() { recoverNativeSessionOperation = oldRecover })
	want := errors.New("delete terminal tombstone interrupted")
	store := &failFirstSessionOperationDeleteStore{memoryNativeStore: &memoryNativeStore{}, err: want}
	mapped, receipt := seedMappedDurableRecord(t, store.memoryNativeStore)
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	controller.clock = func() time.Time { return time.UnixMilli(1_800_000_011_000).UTC() }
	recoverCalls := 0
	recoverNativeSessionOperation = func(context.Context, *qurl.AgentRuntimeBinding, []byte,
		qurl.NativeSessionOperation, qurl.NHPUDPEndpoint, ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		recoverCalls++
		return &qurl.NativeSessionOperationRecovery{Complete: true}, nil
	}
	binding := &qurl.AgentRuntimeBinding{AgentID: mapped.Operation.AgentID}
	err = controller.Retire(context.Background(), binding, make([]byte, 32), testProtectedResourceID,
		mapped.Operation.OperationID, receipt, nil)
	if !errors.Is(err, want) {
		t.Fatalf("first Retire() = %v, want interrupted terminal deletion", err)
	}
	records, loadErr := store.LoadSessionOperations(context.Background(), testProtectedResourceID)
	if loadErr != nil || len(records) != 1 || records[0].Status != agentstate.SessionOperationClosed {
		t.Fatalf("committed terminal record = %+v, %v; want one CLOSED tombstone", records, loadErr)
	}
	if err := controller.Retire(context.Background(), binding, make([]byte, 32), testProtectedResourceID,
		mapped.Operation.OperationID, receipt, nil); err != nil {
		t.Fatalf("resume Retire() = %v, want terminal tombstone deletion", err)
	}
	if recoverCalls != 1 || store.deletes != 2 {
		t.Fatalf("resume network calls=%d deletes=%d, want 1/2", recoverCalls, store.deletes)
	}
	if records, loadErr := store.LoadSessionOperations(context.Background(), testProtectedResourceID); loadErr != nil || len(records) != 0 {
		t.Fatalf("resumed terminal records=%+v err=%v", records, loadErr)
	}
}

func TestDurableNativeSessionRetirementRejectsMismatchedClosedTombstone(t *testing.T) {
	oldRecover := recoverNativeSessionOperation
	t.Cleanup(func() { recoverNativeSessionOperation = oldRecover })
	store := &memoryNativeStore{}
	mapped, receipt := seedMappedDurableRecord(t, store)
	closing := mapped
	closing.Status = agentstate.SessionOperationClosing
	if err := store.TransitionSessionOperation(context.Background(), mapped, closing); err != nil {
		t.Fatal(err)
	}
	closed := closing
	closed.Status = agentstate.SessionOperationClosed
	if err := store.TransitionSessionOperation(context.Background(), closing, closed); err != nil {
		t.Fatal(err)
	}
	recoverCalls := 0
	recoverNativeSessionOperation = func(context.Context, *qurl.AgentRuntimeBinding, []byte,
		qurl.NativeSessionOperation, qurl.NHPUDPEndpoint, ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		recoverCalls++
		return &qurl.NativeSessionOperationRecovery{Complete: true}, nil
	}
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	receipt.SessionID++
	err = controller.Retire(context.Background(), &qurl.AgentRuntimeBinding{AgentID: mapped.Operation.AgentID},
		make([]byte, 32), testProtectedResourceID, mapped.Operation.OperationID, receipt, nil)
	if !errors.Is(err, agentstate.ErrSessionOperationConflict) || recoverCalls != 0 {
		t.Fatalf("mismatched CLOSED retirement = err %v, calls %d; want conflict without exchange", err, recoverCalls)
	}
	records, loadErr := store.LoadSessionOperations(context.Background(), testProtectedResourceID)
	if loadErr != nil || len(records) != 1 || records[0] != closed {
		t.Fatalf("mismatched CLOSED tombstone changed: records=%+v err=%v", records, loadErr)
	}
}

type concurrentSessionOperationRecoveryStore struct {
	*memoryNativeStore
	mu              sync.Mutex
	attempts        int
	firstArrived    chan struct{}
	secondCommitted chan struct{}
	staleReturned   chan struct{}
}

func (s *concurrentSessionOperationRecoveryStore) TransitionSessionOperation(ctx context.Context,
	previous, next agentstate.SessionOperationRecord,
) error {
	if previous.Status != agentstate.SessionOperationClosing || next.Status != agentstate.SessionOperationClosing ||
		next.RecoveryAttempt != 1 {
		return s.memoryNativeStore.TransitionSessionOperation(ctx, previous, next)
	}
	s.mu.Lock()
	s.attempts++
	attempt := s.attempts
	s.mu.Unlock()
	switch attempt {
	case 1:
		close(s.firstArrived)
		<-s.secondCommitted
		err := s.memoryNativeStore.TransitionSessionOperation(ctx, previous, next)
		close(s.staleReturned)
		return err
	case 2:
		<-s.firstArrived
		err := s.memoryNativeStore.TransitionSessionOperation(ctx, previous, next)
		close(s.secondCommitted)
		<-s.staleReturned
		return err
	default:
		return s.memoryNativeStore.TransitionSessionOperation(ctx, previous, next)
	}
}

func TestDurableNativeSessionRecoveryReconcilesConcurrentMonotonicCASLoss(t *testing.T) {
	oldRecover := recoverNativeSessionOperation
	oldWait := waitNativeSessionRecovery
	t.Cleanup(func() {
		recoverNativeSessionOperation = oldRecover
		waitNativeSessionRecovery = oldWait
	})
	memory := &memoryNativeStore{}
	mapped, _ := seedMappedDurableRecord(t, memory)
	closing := mapped
	closing.Status = agentstate.SessionOperationClosing
	if err := memory.TransitionSessionOperation(context.Background(), mapped, closing); err != nil {
		t.Fatal(err)
	}
	store := &concurrentSessionOperationRecoveryStore{
		memoryNativeStore: memory,
		firstArrived:      make(chan struct{}), secondCommitted: make(chan struct{}), staleReturned: make(chan struct{}),
	}
	first, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	second, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(1_800_000_011_000).UTC()
	first.clock = func() time.Time { return now }
	second.clock = func() time.Time { return now }
	waitNativeSessionRecovery = func(context.Context, time.Duration) error { return nil }
	var recoverMu sync.Mutex
	recoverCalls := 0
	recoverNativeSessionOperation = func(context.Context, *qurl.AgentRuntimeBinding, []byte,
		qurl.NativeSessionOperation, qurl.NHPUDPEndpoint, ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		recoverMu.Lock()
		recoverCalls++
		recoverMu.Unlock()
		return &qurl.NativeSessionOperationRecovery{Complete: true}, nil
	}
	binding := &qurl.AgentRuntimeBinding{AgentID: mapped.Operation.AgentID}
	errs := make(chan error, 2)
	for _, controller := range []*durableNativeSessionOperations{first, second} {
		go func() {
			errs <- controller.RecoverOperation(context.Background(), binding, make([]byte, 32),
				testProtectedResourceID, mapped.Operation.OperationID, nil)
		}()
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent RecoverOperation() = %v, want reconciled completion", err)
		}
	}
	store.mu.Lock()
	attempts := store.attempts
	store.mu.Unlock()
	recoverMu.Lock()
	calls := recoverCalls
	recoverMu.Unlock()
	if attempts != 2 || calls == 0 {
		t.Fatalf("concurrent CAS attempts=%d network calls=%d, want 2 and at least 1", attempts, calls)
	}
	if records, loadErr := store.LoadSessionOperations(context.Background(), testProtectedResourceID); loadErr != nil || len(records) != 0 {
		t.Fatalf("concurrent terminal records=%+v err=%v", records, loadErr)
	}
}

func TestDurableNativeSessionRecoveryRejectsDivergentConflictReload(t *testing.T) {
	store := &memoryNativeStore{}
	previous := testPreparedDurableRecord(t)
	previous.Status = agentstate.SessionOperationDispatching
	current := previous
	current.Operation.OwnerID = "different-owner"
	store.operations = map[string][]agentstate.SessionOperationRecord{
		testProtectedResourceID: {current},
	}
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	complete, err := controller.reconcileRecoveryConflict(
		context.Background(), testProtectedResourceID, previous, agentstate.ErrSessionOperationCASLost,
	)
	if complete || !errors.Is(err, agentstate.ErrSessionOperationConflict) {
		t.Fatalf("divergent conflict reload = (%t, %v), want fail-closed conflict", complete, err)
	}
}

func TestDurableNativeSessionRecoveryRejectsConcurrentPreparedAdmission(t *testing.T) {
	store := &memoryNativeStore{}
	previous := testPreparedDurableRecord(t)
	current := previous
	current.Status = agentstate.SessionOperationMapped
	current.Admission = &agentstate.SessionOperationAdmission{
		CellID: current.Operation.CellID, SessionID: 91,
		SessionIssuedAtMillis: 1_800_000_011_000,
		RunID:                 current.Operation.RunID, RunAttempt: current.Operation.RunAttempt,
	}
	store.operations = map[string][]agentstate.SessionOperationRecord{
		testProtectedResourceID: {current},
	}
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	complete, err := controller.reconcileRecoveryConflict(
		context.Background(), testProtectedResourceID, previous, agentstate.ErrSessionOperationCASLost,
	)
	if complete || !errors.Is(err, agentstate.ErrSessionOperationConflict) {
		t.Fatalf("concurrent PREPARED admission = (%t, %v), want fail-closed conflict", complete, err)
	}
}

func TestDurableNativeSessionRecoveryDoesNotReconcileValidationConflict(t *testing.T) {
	store := &memoryNativeStore{}
	previous := testPreparedDurableRecord(t)
	store.operations = map[string][]agentstate.SessionOperationRecord{}
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Errorf("%w: invalid transition", agentstate.ErrSessionOperationConflict)
	complete, err := controller.reconcileRecoveryConflict(
		context.Background(), testProtectedResourceID, previous, want,
	)
	if complete || !errors.Is(err, want) {
		t.Fatalf("validation conflict reconciliation = (%t, %v), want original failure", complete, err)
	}
}

func TestDurableNativeSessionRecoveryDoesNotDropJoinedLockReleaseError(t *testing.T) {
	store := &memoryNativeStore{}
	previous := testPreparedDurableRecord(t)
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	lockErr := errors.New("release operation lock")
	want := errors.Join(fmt.Errorf("write operation: %w", agentstate.ErrSessionOperationCASLost), lockErr)
	complete, err := controller.reconcileRecoveryConflict(
		context.Background(), testProtectedResourceID, previous, want,
	)
	if complete || !errors.Is(err, agentstate.ErrSessionOperationCASLost) || !errors.Is(err, lockErr) {
		t.Fatalf("joined lock release reconciliation = (%t, %v), want both failures", complete, err)
	}
}

func TestDurableNativeSessionRecoveryAcceptsPureWrappedCASLoss(t *testing.T) {
	store := &memoryNativeStore{}
	previous := testPreparedDurableRecord(t)
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	want := errors.Join(fmt.Errorf("write operation: %w", agentstate.ErrSessionOperationCASLost))
	complete, err := controller.reconcileRecoveryConflict(
		context.Background(), testProtectedResourceID, previous, want,
	)
	if !complete || err != nil {
		t.Fatalf("pure wrapped CAS reconciliation = (%t, %v), want completed deletion", complete, err)
	}
}

type removeUnexpectedAdmissionStore struct {
	*memoryNativeStore
	removed bool
}

func (s *removeUnexpectedAdmissionStore) TransitionSessionOperation(ctx context.Context,
	previous, next agentstate.SessionOperationRecord,
) error {
	if !s.removed && previous.Status == agentstate.SessionOperationDispatching &&
		next.Status == agentstate.SessionOperationMapped && next.Admission != nil {
		s.removed = true
		if err := s.memoryNativeStore.DeleteSessionOperation(ctx, previous); err != nil {
			return err
		}
		return agentstate.ErrSessionOperationCASLost
	}
	return s.memoryNativeStore.TransitionSessionOperation(ctx, previous, next)
}

func TestDurableNativeSessionRecoveryFailsClosedWhenUnexpectedAdmissionJournalDisappears(t *testing.T) {
	oldRecover := recoverNativeSessionOperation
	t.Cleanup(func() { recoverNativeSessionOperation = oldRecover })
	memory := &memoryNativeStore{}
	prepared := testPreparedDurableRecord(t)
	if err := memory.CreateSessionOperation(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	dispatching := prepared
	dispatching.Status = agentstate.SessionOperationDispatching
	if err := memory.TransitionSessionOperation(context.Background(), prepared, dispatching); err != nil {
		t.Fatal(err)
	}
	store := &removeUnexpectedAdmissionStore{memoryNativeStore: memory}
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	controller.clock = func() time.Time { return time.UnixMilli(1_800_000_011_000).UTC() }
	receipt := qurl.NativeSessionReceipt{
		CellID: dispatching.Operation.CellID, SessionID: 91,
		SessionIssuedAtMillis: 1_800_000_011_000,
		RunID:                 dispatching.Operation.RunID, RunAttempt: dispatching.Operation.RunAttempt,
	}
	recoverCalls := 0
	recoverNativeSessionOperation = func(context.Context, *qurl.AgentRuntimeBinding, []byte,
		qurl.NativeSessionOperation, qurl.NHPUDPEndpoint, ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		recoverCalls++
		return &qurl.NativeSessionOperationRecovery{UnexpectedAdmission: &receipt},
			&qurl.NativeSessionOperationUnexpectedAdmissionError{SessionReceipt: receipt}
	}
	err = controller.RecoverOperation(context.Background(), &qurl.AgentRuntimeBinding{AgentID: "agent-one"},
		make([]byte, 32), testProtectedResourceID, dispatching.Operation.OperationID, nil)
	if !errors.Is(err, agentstate.ErrSessionOperationConflict) || recoverCalls != 1 || !store.removed {
		t.Fatalf("disappeared unexpected admission = err %v, calls %d, removed %t; want fail closed after one exchange",
			err, recoverCalls, store.removed)
	}
}

func TestDurableNativeSessionRecoveryRejectsNilResult(t *testing.T) {
	oldRecover := recoverNativeSessionOperation
	t.Cleanup(func() { recoverNativeSessionOperation = oldRecover })
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
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	controller.clock = func() time.Time { return time.UnixMilli(1_800_000_011_000).UTC() }
	recoverNativeSessionOperation = func(context.Context, *qurl.AgentRuntimeBinding, []byte,
		qurl.NativeSessionOperation, qurl.NHPUDPEndpoint, ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		return nil, nil
	}
	err = controller.RecoverOperation(context.Background(), &qurl.AgentRuntimeBinding{AgentID: dispatching.Operation.AgentID},
		make([]byte, 32), testProtectedResourceID, dispatching.Operation.OperationID, nil)
	if err == nil {
		t.Fatal("nil recovery result was accepted")
	}
	records, loadErr := store.LoadSessionOperations(context.Background(), testProtectedResourceID)
	if loadErr != nil || len(records) != 1 || records[0].Status != agentstate.SessionOperationDispatching ||
		records[0].RecoveryAttempt != 1 {
		t.Fatalf("failed recovery record=%+v err=%v", records, loadErr)
	}
}

func TestDurableNativeSessionRecoveryContinuesAfterAdmissionExpiry(t *testing.T) {
	oldRecover := recoverNativeSessionOperation
	t.Cleanup(func() { recoverNativeSessionOperation = oldRecover })
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
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	controller.clock = func() time.Time { return time.UnixMilli(dispatching.Operation.ExpiresAtMillis + 1).UTC() }
	recoverNativeSessionOperation = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
		operation qurl.NativeSessionOperation, _ qurl.NHPUDPEndpoint, _ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		if operation.ExpiresAtMillis >= controller.clock().UnixMilli() {
			t.Fatal("fixture did not cross the admission expiry")
		}
		return &qurl.NativeSessionOperationRecovery{Complete: true}, nil
	}
	if err := controller.RecoverOperation(context.Background(), &qurl.AgentRuntimeBinding{AgentID: "agent-one"},
		make([]byte, 32), testProtectedResourceID, dispatching.Operation.OperationID, nil); err != nil {
		t.Fatal(err)
	}
	if records, err := store.LoadSessionOperations(context.Background(), testProtectedResourceID); err != nil || len(records) != 0 {
		t.Fatalf("expired operation recovery records=%+v err=%v", records, err)
	}
}

func TestDurableNativeSessionRecoveryHonorsCallerBudget(t *testing.T) {
	oldRecover := recoverNativeSessionOperation
	oldWait := waitNativeSessionRecovery
	t.Cleanup(func() {
		recoverNativeSessionOperation = oldRecover
		waitNativeSessionRecovery = oldWait
	})
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
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(1_800_000_011_000).UTC()
	controller.clock = func() time.Time { return now }
	recoverNativeSessionOperation = func(context.Context, *qurl.AgentRuntimeBinding, []byte,
		qurl.NativeSessionOperation, qurl.NHPUDPEndpoint, ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		return &qurl.NativeSessionOperationRecovery{}, nil
	}
	waitNativeSessionRecovery = sleepWithContext
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err = controller.RecoverOperation(ctx, &qurl.AgentRuntimeBinding{AgentID: "agent-one"},
		make([]byte, 32), testProtectedResourceID, dispatching.Operation.OperationID, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pending recovery budget = %v, want deadline", err)
	}
	records, loadErr := store.LoadSessionOperations(context.Background(), testProtectedResourceID)
	if loadErr != nil || len(records) != 1 || records[0].Status != agentstate.SessionOperationDispatching {
		t.Fatalf("budgeted recovery lost durable state: records=%+v err=%v", records, loadErr)
	}
}

func TestDurableNativeSessionRecoveryMapsUnexpectedAdmissionBeforeClose(t *testing.T) {
	oldRecover := recoverNativeSessionOperation
	oldWait := waitNativeSessionRecovery
	t.Cleanup(func() {
		recoverNativeSessionOperation = oldRecover
		waitNativeSessionRecovery = oldWait
	})
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
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(1_800_000_011_000).UTC()
	controller.clock = func() time.Time { return now }
	waitNativeSessionRecovery = func(_ context.Context, delay time.Duration) error {
		now = now.Add(delay)
		return nil
	}
	receipt := qurl.NativeSessionReceipt{
		CellID: dispatching.Operation.CellID, SessionID: 91, SessionIssuedAtMillis: 1_800_000_010_000,
		RunID: dispatching.Operation.RunID, RunAttempt: dispatching.Operation.RunAttempt,
	}
	recoverCalls := 0
	recoverNativeSessionOperation = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
		_ qurl.NativeSessionOperation, _ qurl.NHPUDPEndpoint, _ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		recoverCalls++
		current := store.operations[testProtectedResourceID][0]
		if recoverCalls == 1 {
			if current.Status != agentstate.SessionOperationDispatching {
				t.Fatalf("unexpected admission record = %+v", current)
			}
			return &qurl.NativeSessionOperationRecovery{UnexpectedAdmission: &receipt},
				&qurl.NativeSessionOperationUnexpectedAdmissionError{SessionReceipt: receipt}
		}
		if current.Status != agentstate.SessionOperationClosing || current.Admission == nil || current.Admission.SessionID != receipt.SessionID {
			t.Fatalf("unexpected admission was not fenced before recovery: %+v", current)
		}
		return &qurl.NativeSessionOperationRecovery{Complete: true}, nil
	}
	if err := controller.RecoverOperation(context.Background(), &qurl.AgentRuntimeBinding{AgentID: "agent-one"},
		make([]byte, 32), testProtectedResourceID, dispatching.Operation.OperationID, nil); err != nil {
		t.Fatal(err)
	}
	if recoverCalls != 2 {
		t.Fatalf("unexpected admission recovery calls=%d, want 2", recoverCalls)
	}
	if records, err := store.LoadSessionOperations(context.Background(), testProtectedResourceID); err != nil || len(records) != 0 {
		t.Fatalf("unexpected admission terminal records=%+v err=%v", records, err)
	}
}

func TestDurableNativeSessionRecoveryRejectsIncompleteUnexpectedAdmission(t *testing.T) {
	oldRecover := recoverNativeSessionOperation
	t.Cleanup(func() { recoverNativeSessionOperation = oldRecover })
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
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	controller.clock = func() time.Time { return time.UnixMilli(1_800_000_011_000).UTC() }
	receipt := qurl.NativeSessionReceipt{
		CellID: dispatching.Operation.CellID, SessionID: 91, SessionIssuedAtMillis: 1_800_000_010_000,
		RunID: dispatching.Operation.RunID, RunAttempt: dispatching.Operation.RunAttempt,
	}
	recoverNativeSessionOperation = func(context.Context, *qurl.AgentRuntimeBinding, []byte,
		qurl.NativeSessionOperation, qurl.NHPUDPEndpoint, ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		return nil, &qurl.NativeSessionOperationUnexpectedAdmissionError{SessionReceipt: receipt}
	}
	err = controller.RecoverOperation(context.Background(), &qurl.AgentRuntimeBinding{AgentID: "agent-one"},
		make([]byte, 32), testProtectedResourceID, dispatching.Operation.OperationID, nil)
	if !errors.Is(err, agentstate.ErrSessionOperationConflict) {
		t.Fatalf("incomplete unexpected admission = %v, want state conflict", err)
	}
	records, loadErr := store.LoadSessionOperations(context.Background(), testProtectedResourceID)
	if loadErr != nil || len(records) != 1 || records[0].Status != agentstate.SessionOperationDispatching {
		t.Fatalf("incomplete admission mutated journal: records=%+v err=%v", records, loadErr)
	}
}

func TestNativeSessionOperationAuthorityFailsClosed(t *testing.T) {
	tests := []NativeSessionOperationAuthority{
		{},
		{OwnerID: " owner"},
		{OwnerID: strings.Repeat("a", 257)},
	}
	for _, authority := range tests {
		if _, err := newDurableNativeSessionOperations(&memoryNativeStore{}, authority); err == nil {
			t.Fatalf("invalid authority accepted: %+v", authority)
		}
	}
}

// transitionRecordingStore wraps the production store so a test can assert
// which durable states a recovery committed, not only what remains afterwards.
type transitionRecordingStore struct {
	nativeStateStore
	mu          sync.Mutex
	transitions []agentstate.SessionOperationRecord
}

func (s *transitionRecordingStore) TransitionSessionOperation(ctx context.Context, previous, next agentstate.SessionOperationRecord) error {
	err := s.nativeStateStore.TransitionSessionOperation(ctx, previous, next)
	if err == nil {
		s.mu.Lock()
		s.transitions = append(s.transitions, next)
		s.mu.Unlock()
	}
	return err
}

func (s *transitionRecordingStore) committed() []agentstate.SessionOperationRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]agentstate.SessionOperationRecord(nil), s.transitions...)
}

// recoveryFixture drives the real agentstate.SDKStore so every journal rule
// (legal transitions, admission/terminal pairing, monotonic counters) applies
// exactly as in production. A permissive double would let an illegal terminal
// pass, which is the defect the first abandonment attempt shipped with.
type recoveryFixture struct {
	controller *durableNativeSessionOperations
	store      *transitionRecordingStore
	binding    *qurl.AgentRuntimeBinding
	operation  qurl.NativeSessionOperation
	pinned     qurl.NHPUDPEndpoint
	// current is a same-cell endpoint with a different server key, the shape a
	// blue/green cohort switch leaves behind.
	current   qurl.NHPUDPEndpoint
	now       time.Time
	exchanges []qurl.NHPUDPEndpoint
	waits     []time.Duration
}

func silentEndpoint(endpoint qurl.NHPUDPEndpoint) error {
	return &qurl.EndpointNoReplyError{Endpoint: fmt.Sprintf("%s:%d", endpoint.Host, endpoint.Port),
		Attempts: 3, Elapsed: 9 * time.Second, Last: nativeudp.ErrNoReply}
}

// newRecoveryFixture leaves one durable record in the journal: DISPATCHING
// when admitted is false, MAPPED (which recovery promotes to CLOSING) with a
// real admission otherwise. The current assignment is the pinned cell on a
// different server key unless a test replaces it.
func newRecoveryFixture(t *testing.T, admitted bool) *recoveryFixture {
	t.Helper()
	oldPrepare := prepareLiveNativeSessionOperation
	oldRecover := recoverNativeSessionOperation
	oldWait := waitNativeSessionRecovery
	oldAssignment := currentNativeAssignment
	t.Cleanup(func() {
		prepareLiveNativeSessionOperation = oldPrepare
		recoverNativeSessionOperation = oldRecover
		waitNativeSessionRecovery = oldWait
		currentNativeAssignment = oldAssignment
	})
	t.Setenv(agentstate.EnvKeyProvider, agentstate.KeyProviderFile)
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sdkStore, err := agentstate.NewSDKStore(filepath.Join(parent, "state"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sdkStore.Close() })
	store := &transitionRecordingStore{nativeStateStore: sdkStore}
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	f := &recoveryFixture{
		controller: controller, store: store,
		binding: &qurl.AgentRuntimeBinding{AgentID: "agent-one"},
		pinned:  testDurableRecoveryEndpoint(),
		now:     time.UnixMilli(1_800_000_009_000).UTC(),
	}
	f.current = f.pinned
	f.current.ServerPublicKeyB64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	controller.clock = func() time.Time { return f.now }
	prepareLiveNativeSessionOperation = func(context.Context, *qurl.AgentRuntimeBinding, []byte,
		qurl.NativeSessionOperationInput,
	) (*qurl.NativeSessionOperation, qurl.NHPUDPEndpoint, error) {
		operation := testDurableOperation()
		return &operation, testDurableRecoveryEndpoint(), nil
	}
	operation, err := controller.PrepareDispatch(context.Background(), f.binding, make([]byte, 32),
		"resource-a", testProtectedResourceID, "0123456789abcdef", 7)
	if err != nil {
		t.Fatal(err)
	}
	f.operation = *operation
	if admitted {
		receipt := qurl.NativeSessionReceipt{
			CellID: operation.CellID, SessionID: 91, SessionIssuedAtMillis: 1_800_000_010_000,
			RunID: operation.RunID, RunAttempt: operation.RunAttempt,
		}
		if err := controller.RecordMapped(context.Background(), testProtectedResourceID, *operation, receipt); err != nil {
			t.Fatal(err)
		}
	}
	store.mu.Lock()
	store.transitions = nil
	store.mu.Unlock()
	currentNativeAssignment = func(*qurl.AgentRuntimeBinding) qurl.AgentAssignment {
		return qurl.AgentAssignment{CellID: operation.CellID, Endpoint: f.current}
	}
	waitNativeSessionRecovery = func(_ context.Context, delay time.Duration) error {
		f.waits = append(f.waits, delay)
		f.now = f.now.Add(delay)
		return nil
	}
	return f
}

// answer installs the server stub: reply returns what each endpoint answers.
func (f *recoveryFixture) answer(t *testing.T, reply func(endpoint qurl.NHPUDPEndpoint, exchange int) (*qurl.NativeSessionOperationRecovery, error)) {
	t.Helper()
	recoverNativeSessionOperation = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
		got qurl.NativeSessionOperation, endpoint qurl.NHPUDPEndpoint, _ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		if got != f.operation {
			t.Fatalf("recovery exchanged a different operation: %+v", got)
		}
		f.exchanges = append(f.exchanges, endpoint)
		return reply(endpoint, len(f.exchanges))
	}
}

func (f *recoveryFixture) recover(ctx context.Context) error {
	return f.controller.RecoverOperation(ctx, f.binding, make([]byte, 32), testProtectedResourceID,
		f.operation.OperationID, nil)
}

func (f *recoveryFixture) records(t *testing.T) []agentstate.SessionOperationRecord {
	t.Helper()
	records, err := f.store.LoadSessionOperations(context.Background(), testProtectedResourceID)
	if err != nil {
		t.Fatal(err)
	}
	return records
}

func (f *recoveryFixture) pastAbandonMargin() time.Time {
	return time.UnixMilli(f.operation.ExpiresAtMillis).Add(nativeSessionRecoveryAbandonMargin + time.Second).UTC()
}

func countEndpoints(exchanges []qurl.NHPUDPEndpoint, endpoint qurl.NHPUDPEndpoint) int {
	count := 0
	for _, exchanged := range exchanges {
		if exchanged == endpoint {
			count++
		}
	}
	return count
}

func TestDurableNativeSessionRecoveryRefencesSilentPinnedEndpointToCurrentCellEndpoint(t *testing.T) {
	f := newRecoveryFixture(t, true)
	f.answer(t, func(endpoint qurl.NHPUDPEndpoint, _ int) (*qurl.NativeSessionOperationRecovery, error) {
		if endpoint == f.pinned {
			return nil, silentEndpoint(endpoint)
		}
		return &qurl.NativeSessionOperationRecovery{Complete: true}, nil
	})
	if err := f.recover(context.Background()); err != nil {
		t.Fatalf("re-fenced recovery = %v", err)
	}
	if len(f.exchanges) != 2 || f.exchanges[0] != f.pinned || f.exchanges[1] != f.current {
		t.Fatalf("exchanges = %+v, want pinned then current", f.exchanges)
	}
	if records := f.records(t); len(records) != 0 {
		t.Fatalf("52030 from the current endpoint must delete the row: %+v", records)
	}
	committed := f.store.committed()
	var moved, terminal *agentstate.SessionOperationRecord
	for index := range committed {
		record := &committed[index]
		if record.RecoveryEndpoint == f.current && moved == nil {
			moved = record
		}
		if record.Status == agentstate.SessionOperationClosed {
			terminal = record
		}
	}
	if moved == nil || moved.Status != agentstate.SessionOperationClosing || moved.PostExpiryNoReplyAttempts != 0 {
		t.Fatalf("the answering endpoint was not pinned durably before the terminal write: %+v", committed)
	}
	if terminal == nil || terminal.RecoveryEndpoint != f.current || terminal.Admission == nil {
		t.Fatalf("terminal record = %+v, want CLOSED on the current endpoint with its admission", terminal)
	}
}

func TestDurableNativeSessionRecoveryGoesStraightToTheAnsweringEndpointNextPass(t *testing.T) {
	f := newRecoveryFixture(t, true)
	f.answer(t, func(endpoint qurl.NHPUDPEndpoint, exchange int) (*qurl.NativeSessionOperationRecovery, error) {
		if endpoint == f.pinned {
			return nil, silentEndpoint(endpoint)
		}
		// 52029: still revoking. The loop polls again from the persisted record.
		return &qurl.NativeSessionOperationRecovery{Complete: exchange >= 3}, nil
	})
	if err := f.recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []qurl.NHPUDPEndpoint{f.pinned, f.current, f.current}
	if len(f.exchanges) != len(want) {
		t.Fatalf("exchanges = %+v, want %+v", f.exchanges, want)
	}
	for index := range want {
		if f.exchanges[index] != want[index] {
			t.Fatalf("exchange %d = %+v, want %+v", index, f.exchanges[index], want[index])
		}
	}
	if records := f.records(t); len(records) != 0 {
		t.Fatalf("records after terminal 52030 = %+v", records)
	}
}

func TestDurableNativeSessionRecoveryNeverRefencesAcrossCellsOrToTheSameEndpoint(t *testing.T) {
	for name, assignment := range map[string]func(*recoveryFixture) qurl.AgentAssignment{
		"other cell": func(f *recoveryFixture) qurl.AgentAssignment {
			return qurl.AgentAssignment{CellID: "cell-02", Endpoint: f.current}
		},
		"identical endpoint": func(f *recoveryFixture) qurl.AgentAssignment {
			return qurl.AgentAssignment{CellID: f.operation.CellID, Endpoint: f.pinned}
		},
		"malformed endpoint": func(f *recoveryFixture) qurl.AgentAssignment {
			return qurl.AgentAssignment{CellID: f.operation.CellID}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newRecoveryFixture(t, true)
			live := assignment(f)
			currentNativeAssignment = func(*qurl.AgentRuntimeBinding) qurl.AgentAssignment { return live }
			f.answer(t, func(endpoint qurl.NHPUDPEndpoint, _ int) (*qurl.NativeSessionOperationRecovery, error) {
				if endpoint != f.pinned {
					t.Fatalf("recovery left the pinned endpoint for %+v", endpoint)
				}
				return nil, silentEndpoint(endpoint)
			})
			err := f.recover(context.Background())
			if !errors.Is(err, qurl.ErrEndpointNoReply) || len(f.exchanges) != 1 {
				t.Fatalf("recovery = %v exchanges=%d, want one silent pinned exchange", err, len(f.exchanges))
			}
			records := f.records(t)
			if len(records) != 1 || records[0].RecoveryEndpoint != f.pinned || records[0].Status != agentstate.SessionOperationClosing {
				t.Fatalf("records = %+v, want the pinned CLOSING record untouched", records)
			}
		})
	}
}

// Silence alone never retires a record while the operation is live, and the
// abandon margin past expiry is part of "live": until then every failure keeps
// today's behavior and the post-expiry counter stays at zero.
func TestDurableNativeSessionRecoveryKeepsRetryingSilentEndpointsInsideExpiryAndMargin(t *testing.T) {
	for name, at := range map[string]func(*recoveryFixture) time.Time{
		"before expiry": func(f *recoveryFixture) time.Time {
			return time.UnixMilli(f.operation.ExpiresAtMillis).Add(-time.Minute).UTC()
		},
		"past expiry inside the margin": func(f *recoveryFixture) time.Time {
			// The fake wait advances the clock by each bounded delay, so start
			// far enough inside the margin that every pass stays inside it.
			return time.UnixMilli(f.operation.ExpiresAtMillis).Add(nativeSessionRecoveryAbandonMargin - time.Minute).UTC()
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newRecoveryFixture(t, true)
			f.now = at(f)
			f.answer(t, func(endpoint qurl.NHPUDPEndpoint, _ int) (*qurl.NativeSessionOperationRecovery, error) {
				return nil, silentEndpoint(endpoint)
			})
			const passes = nativeSessionRecoveryAbandonAttempts * 3
			for pass := 1; pass <= passes; pass++ {
				if err := f.recover(context.Background()); !errors.Is(err, qurl.ErrEndpointNoReply) {
					t.Fatalf("pass %d = %v, want the silent-endpoint error", pass, err)
				}
				records := f.records(t)
				if len(records) != 1 || records[0].Status != agentstate.SessionOperationClosing ||
					records[0].RecoveryAttempt != uint32(pass) || records[0].PostExpiryNoReplyAttempts != 0 ||
					records[0].RecoveryEndpoint != f.pinned {
					t.Fatalf("pass %d records = %+v, want CLOSING, attempt %d, no post-expiry failures", pass, records, pass)
				}
			}
			if pinned, current := countEndpoints(f.exchanges, f.pinned), countEndpoints(f.exchanges, f.current); pinned != passes || current != passes {
				t.Fatalf("exchanges pinned=%d current=%d, want %d each", pinned, current, passes)
			}
		})
	}
}

func TestDurableNativeSessionRecoveryAbandonsClosingRecordAfterPostExpirySilenceOnBothEndpoints(t *testing.T) {
	f := newRecoveryFixture(t, true)
	f.now = f.pastAbandonMargin()
	f.answer(t, func(endpoint qurl.NHPUDPEndpoint, _ int) (*qurl.NativeSessionOperationRecovery, error) {
		return nil, silentEndpoint(endpoint)
	})
	for pass := 1; pass < nativeSessionRecoveryAbandonAttempts; pass++ {
		if err := f.recover(context.Background()); !errors.Is(err, qurl.ErrEndpointNoReply) {
			t.Fatalf("pass %d = %v, want the silent-endpoint error", pass, err)
		}
		records := f.records(t)
		if len(records) != 1 || records[0].Status != agentstate.SessionOperationClosing ||
			records[0].PostExpiryNoReplyAttempts != uint32(pass) || records[0].RecoveryAttempt != uint32(pass) {
			t.Fatalf("pass %d records = %+v, want CLOSING with %d counted post-expiry failures", pass, records, pass)
		}
		// Step past the escalated persisted backoff the failure committed.
		f.now = f.now.Add(time.Minute)
	}
	if err := f.recover(context.Background()); err != nil {
		t.Fatalf("abandoning pass = %v, want success", err)
	}
	if records := f.records(t); len(records) != 0 {
		t.Fatalf("records after abandonment = %+v", records)
	}
	committed := f.store.committed()
	terminal := committed[len(committed)-1]
	if terminal.Status != agentstate.SessionOperationClosed || terminal.Admission == nil ||
		terminal.PostExpiryNoReplyAttempts != nativeSessionRecoveryAbandonAttempts ||
		terminal.RecoveryAttempt != nativeSessionRecoveryAbandonAttempts {
		t.Fatalf("terminal = %+v, want CLOSED with its admission after exactly %d post-expiry failures",
			terminal, nativeSessionRecoveryAbandonAttempts)
	}
	for _, record := range committed[:len(committed)-1] {
		if record.Status != agentstate.SessionOperationClosing {
			t.Fatalf("non-terminal transition left CLOSING: %+v", record)
		}
	}
	pinned, current := countEndpoints(f.exchanges, f.pinned), countEndpoints(f.exchanges, f.current)
	if pinned != nativeSessionRecoveryAbandonAttempts || current != nativeSessionRecoveryAbandonAttempts {
		t.Fatalf("exchanges pinned=%d current=%d, want %d each before abandonment",
			pinned, current, nativeSessionRecoveryAbandonAttempts)
	}
}

// The bound stands on its own when the pinned endpoint already is the current
// assignment: nothing can be re-fenced, every silent exchange still counts, and
// a DISPATCHING record (no admission) ends as CANCELED.
func TestDurableNativeSessionRecoveryAbandonsDispatchingRecordWhenThePinnedEndpointIsCurrent(t *testing.T) {
	f := newRecoveryFixture(t, false)
	f.now = f.pastAbandonMargin()
	currentNativeAssignment = func(*qurl.AgentRuntimeBinding) qurl.AgentAssignment {
		return qurl.AgentAssignment{CellID: f.operation.CellID, Endpoint: f.pinned}
	}
	f.answer(t, func(endpoint qurl.NHPUDPEndpoint, _ int) (*qurl.NativeSessionOperationRecovery, error) {
		if endpoint != f.pinned {
			t.Fatalf("unexpected exchange with %+v", endpoint)
		}
		return nil, fmt.Errorf("recover: %w", context.DeadlineExceeded)
	})
	for pass := 1; pass < nativeSessionRecoveryAbandonAttempts; pass++ {
		if err := f.recover(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("pass %d = %v, want deadline", pass, err)
		}
		f.now = f.now.Add(time.Minute)
	}
	if err := f.recover(context.Background()); err != nil {
		t.Fatalf("abandoning pass = %v", err)
	}
	if records := f.records(t); len(records) != 0 {
		t.Fatalf("records after abandonment = %+v", records)
	}
	committed := f.store.committed()
	terminal := committed[len(committed)-1]
	if terminal.Status != agentstate.SessionOperationCanceled || terminal.Admission != nil ||
		terminal.PostExpiryNoReplyAttempts != nativeSessionRecoveryAbandonAttempts {
		t.Fatalf("terminal = %+v, want CANCELED without admission", terminal)
	}
	if len(f.exchanges) != nativeSessionRecoveryAbandonAttempts {
		t.Fatalf("exchanges = %d, want %d pinned-only", len(f.exchanges), nativeSessionRecoveryAbandonAttempts)
	}
}

// A clock that steps forward past expiry manufactures no post-expiry
// exchanges, however many lifetime attempts the record already carries. The
// first pass after the step still asks the server, which stays the authority.
func TestDurableNativeSessionRecoveryClockStepPastExpiryDoesNotAbandon(t *testing.T) {
	for name, answers := range map[string]bool{"server answers": true, "server stays silent": false} {
		t.Run(name, func(t *testing.T) {
			f := newRecoveryFixture(t, true)
			f.now = time.UnixMilli(f.operation.PreparedAtMillis).Add(time.Minute).UTC()
			silent := true
			f.answer(t, func(endpoint qurl.NHPUDPEndpoint, _ int) (*qurl.NativeSessionOperationRecovery, error) {
				if silent {
					return nil, silentEndpoint(endpoint)
				}
				return &qurl.NativeSessionOperationRecovery{Complete: true}, nil
			})
			const lifetime = nativeSessionRecoveryAbandonAttempts * 2
			for pass := 1; pass <= lifetime; pass++ {
				if err := f.recover(context.Background()); !errors.Is(err, qurl.ErrEndpointNoReply) {
					t.Fatalf("pass %d = %v", pass, err)
				}
			}
			before := f.records(t)
			if len(before) != 1 || before[0].RecoveryAttempt != lifetime || before[0].PostExpiryNoReplyAttempts != 0 {
				t.Fatalf("records before the clock step = %+v", before)
			}
			f.now = f.pastAbandonMargin().Add(24 * time.Hour)
			silent = !answers
			exchangesBefore := len(f.exchanges)
			err := f.recover(context.Background())
			if len(f.exchanges) == exchangesBefore {
				t.Fatal("the pass after the clock step sent nothing; the server must be asked")
			}
			records := f.records(t)
			if answers {
				if err != nil || len(records) != 0 {
					t.Fatalf("server-completed retirement = %v records=%+v", err, records)
				}
				return
			}
			if !errors.Is(err, qurl.ErrEndpointNoReply) || len(records) != 1 ||
				records[0].Status != agentstate.SessionOperationClosing || records[0].PostExpiryNoReplyAttempts != 1 {
				t.Fatalf("first silent post-expiry pass = %v records=%+v, want one counted failure and no abandonment", err, records)
			}
		})
	}
}

func TestDurableNativeSessionRecoveryTypedDenyAfterExpiryIsNeverAbandoned(t *testing.T) {
	f := newRecoveryFixture(t, true)
	f.now = f.pastAbandonMargin()
	const polls = nativeSessionRecoveryAbandonAttempts + 2
	f.answer(t, func(endpoint qurl.NHPUDPEndpoint, exchange int) (*qurl.NativeSessionOperationRecovery, error) {
		if endpoint != f.pinned {
			t.Fatalf("an answering pinned endpoint must not be re-fenced: %+v", endpoint)
		}
		// 52029 until the server finishes revoking, then 52030.
		return &qurl.NativeSessionOperationRecovery{Complete: exchange > polls}, nil
	})
	if err := f.recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.exchanges) != polls+1 {
		t.Fatalf("exchanges = %d, want %d", len(f.exchanges), polls+1)
	}
	if records := f.records(t); len(records) != 0 {
		t.Fatalf("records after the server's 52030 = %+v", records)
	}
	for _, record := range f.store.committed() {
		if record.PostExpiryNoReplyAttempts != 0 {
			t.Fatalf("a typed deny was counted as silence: %+v", record)
		}
	}
}

func TestDurableNativeSessionRecoveryDefersInsideEscalatedPostExpiryBackoff(t *testing.T) {
	f := newRecoveryFixture(t, true)
	f.now = f.pastAbandonMargin()
	f.answer(t, func(endpoint qurl.NHPUDPEndpoint, _ int) (*qurl.NativeSessionOperationRecovery, error) {
		return nil, silentEndpoint(endpoint)
	})
	if err := f.recover(context.Background()); !errors.Is(err, qurl.ErrEndpointNoReply) {
		t.Fatal(err)
	}
	records := f.records(t)
	if len(records) != 1 || records[0].PostExpiryNoReplyAttempts != 1 {
		t.Fatalf("records = %+v", records)
	}
	backoff := time.UnixMilli(records[0].RecoveryNotBeforeMilli).Sub(f.now)
	if backoff != nativeSessionRecoveryNoReplyBackoff(1) || backoff <= nativeSessionRecoveryMaxDelay {
		t.Fatalf("persisted post-expiry backoff = %s, want %s", backoff, nativeSessionRecoveryNoReplyBackoff(1))
	}
	sent := len(f.exchanges)
	f.now = f.now.Add(time.Second)
	if err := f.recover(context.Background()); !errors.Is(err, errNativeSessionRecoveryDeferred) ||
		len(f.exchanges) != sent || len(f.waits) != 0 {
		t.Fatalf("pass inside the backoff = %v exchanges=%d waits=%v, want deferred without a packet or a sleep",
			err, len(f.exchanges), f.waits)
	}
	f.now = f.now.Add(backoff)
	if err := f.recover(context.Background()); !errors.Is(err, qurl.ErrEndpointNoReply) || len(f.exchanges) != sent+2 {
		t.Fatalf("pass after the backoff = %v exchanges=%d, want a fresh silent exchange on both endpoints", err, len(f.exchanges))
	}
	// A persisted deadline further away than the escalation ceiling can only
	// come from a clock correction; keep the one bounded wait, then proceed.
	f.now = f.now.Add(-2 * nativeSessionRecoveryNoReplyMaxDelay)
	sent = len(f.exchanges)
	if err := f.recover(context.Background()); !errors.Is(err, qurl.ErrEndpointNoReply) ||
		len(f.exchanges) != sent+2 || len(f.waits) != 1 || f.waits[0] != nativeSessionRecoveryMaxDelay {
		t.Fatalf("clock-regressed pass = %v exchanges=%d waits=%v, want one %s wait then an exchange",
			err, len(f.exchanges), f.waits, nativeSessionRecoveryMaxDelay)
	}
}

func TestNativeSessionRecoveryAbandonMarginCoversServerRecoveryMargin(t *testing.T) {
	const skew = 30 * time.Second
	if nativeSessionRecoveryAbandonMargin < qurl.NativeSessionOperationJournalMargin+nativeSessionCleanupBudget+skew {
		t.Fatalf("abandon margin %s must cover the SDK absent-recovery margin %s plus one cleanup budget %s and clock skew %s",
			nativeSessionRecoveryAbandonMargin, qurl.NativeSessionOperationJournalMargin, nativeSessionCleanupBudget, skew)
	}
	if nativeSessionRecoveryAbandonMargin < 5*time.Minute || nativeSessionRecoveryAbandonAttempts < 2 {
		t.Fatalf("abandonment bound margin=%s attempts=%d is too aggressive", nativeSessionRecoveryAbandonMargin, nativeSessionRecoveryAbandonAttempts)
	}
	for failures, want := range map[uint32]time.Duration{0: 2 * time.Second, 1: 4 * time.Second, 2: 8 * time.Second,
		3: 16 * time.Second, 4: nativeSessionRecoveryNoReplyMaxDelay, 40: nativeSessionRecoveryNoReplyMaxDelay} {
		if got := nativeSessionRecoveryNoReplyBackoff(failures); got != want {
			t.Fatalf("no-reply backoff(%d) = %s, want %s", failures, got, want)
		}
	}
}

func TestNativeSessionNoReplyClassification(t *testing.T) {
	silence := []error{
		qurl.ErrEndpointNoReply, silentEndpoint(testDurableRecoveryEndpoint()),
		nativeudp.ErrNoReply, nativeudp.ErrTransport, nativeudp.ErrResolve, nativeudp.ErrServerUnauthenticated,
		context.DeadlineExceeded, fmt.Errorf("recover: %w", context.DeadlineExceeded),
	}
	for _, err := range silence {
		if !isNativeSessionNoReplyError(err) {
			t.Errorf("%v should count as silence", err)
		}
	}
	decisions := []error{
		nil, context.Canceled, fmt.Errorf("%w: %w", qurl.ErrEndpointNoReply, context.Canceled),
		&qurl.ServerDenyError{ErrCode: "52029"}, &qurl.ServerDenyError{ErrCode: "52004"},
		&qurl.NativeSessionOperationUnexpectedAdmissionError{},
		qurl.ErrMalformedReply, qurl.ErrInvalidNativeSessionOperation, agentstate.ErrSessionOperationConflict,
		errors.New("recovery reply lost"),
	}
	for _, err := range decisions {
		if isNativeSessionNoReplyError(err) {
			t.Errorf("%v must not count as silence", err)
		}
	}
}

// The admission gate clears on the same pass that abandons the record: the
// resource is dark for the bounded window and then admits without any manual
// journal surgery.
func TestNativeAdmitterAdmitsOnceASilentExpiredRecoveryIsAbandoned(t *testing.T) {
	oldKnock := knockNativeRuntime
	t.Cleanup(func() { knockNativeRuntime = oldKnock })
	f := newRecoveryFixture(t, true)
	f.now = f.pastAbandonMargin()
	currentNativeAssignment = func(*qurl.AgentRuntimeBinding) qurl.AgentAssignment {
		return qurl.AgentAssignment{CellID: f.operation.CellID, Endpoint: f.pinned}
	}
	f.answer(t, func(endpoint qurl.NHPUDPEndpoint, _ int) (*qurl.NativeSessionOperationRecovery, error) {
		return nil, silentEndpoint(endpoint)
	})
	knocks := 0
	knockNativeRuntime = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte, _ string,
		opts qurl.NativeKnockOptions, _ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeKnockResult, error) {
		knocks++
		if records := f.records(t); len(records) != 0 {
			t.Fatalf("a replacement knock left while the journal still held %+v", records)
		}
		receipt := testSessionReceipt(92, opts.RunID, opts.RunAttempt)
		return &qurl.NativeKnockResult{
			ACToken: "token", ResourceHost: "127.0.0.1:7000", SessionID: receipt.SessionID,
			OpenTime: 3600, SessionReceipt: receipt,
		}, nil
	}
	admitter := &NativeAdmitter{
		binding: f.binding, privateKey: make([]byte, 32),
		operations: &durableRetirementFenceOperations{controller: f.controller}, store: f.store,
	}
	for pass := 1; pass < nativeSessionRecoveryAbandonAttempts; pass++ {
		_, err := admitter.Admit(context.Background(), "resource-a", testProtectedResourceID)
		if err == nil || !errors.Is(err, qurl.ErrEndpointNoReply) ||
			!strings.Contains(err.Error(), "recover prior native session operation before replacement") {
			t.Fatalf("pass %d admission = %v, want the recovery gate", pass, err)
		}
		if knocks != 0 {
			t.Fatalf("pass %d knocked while the record was still pending", pass)
		}
		f.now = f.now.Add(time.Minute)
	}
	admission, err := admitter.Admit(context.Background(), "resource-a", testProtectedResourceID)
	if err != nil || admission.SessionID != 92 || knocks != 1 {
		t.Fatalf("admission after abandonment = %+v, %v, knocks=%d", admission, err, knocks)
	}
}
