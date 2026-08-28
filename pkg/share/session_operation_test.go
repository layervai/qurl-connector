package share

import (
	"context"
	"errors"
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
