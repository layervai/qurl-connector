package share

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	qurl "github.com/layervai/qurl-go/qurl"

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
		got qurl.NativeSessionOperation, _ qurl.NHPUDPEndpoint, _ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		recoverCalls++
		current := store.operations[protected][0]
		if current.Status != agentstate.SessionOperationClosing || got != *operation {
			t.Fatalf("recovery boundary record=%+v operation=%+v", current, got)
		}
		return &qurl.NativeSessionOperationRecovery{Complete: true}, nil
	}
	if err := controller.Retire(context.Background(), binding, make([]byte, 32), protected, operation.OperationID, receipt, nil); err != nil {
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
		got qurl.NativeSessionOperation, _ qurl.NHPUDPEndpoint, _ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		if got != *operation {
			t.Fatalf("restarted operation = %+v, want %+v", got, *operation)
		}
		return &qurl.NativeSessionOperationRecovery{Complete: true}, nil
	}
	if err := recovery.RecoverPending(context.Background(), &qurl.AgentRuntimeBinding{AgentID: "agent-one"},
		make([]byte, 32), testProtectedResourceID, nil, nil); err != nil {
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
