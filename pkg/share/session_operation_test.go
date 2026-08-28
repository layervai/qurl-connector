package share

import (
	"context"
	"testing"
	"time"

	qurl "github.com/layervai/qurl-go/qurl"

	"github.com/layervai/qurl-connector/pkg/agentstate"
)

func TestDurableNativeSessionOperationPersistsEveryNetworkBoundary(t *testing.T) {
	oldPrepare := prepareLiveNativeSessionOperation
	oldRecover := recoverNativeSessionOperation
	oldRetire := retireNativeSession
	t.Cleanup(func() {
		prepareLiveNativeSessionOperation = oldPrepare
		recoverNativeSessionOperation = oldRecover
		retireNativeSession = oldRetire
	})
	store := &memoryNativeStore{}
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	controller.clock = func() time.Time { return time.UnixMilli(1_800_000_009_000).UTC() }
	const protected = "protected-resource"
	const runID = "0123456789abcdef"
	prepareLiveNativeSessionOperation = func(_ context.Context, _ *qurl.AgentRuntimeBinding, key []byte,
		input qurl.NativeSessionOperationInput,
	) (*qurl.NativeSessionOperation, qurl.AgentAssignment, error) {
		if len(key) != 32 || input.AWSAccountID != "111122223333" || input.AWSRegion != "us-east-2" ||
			input.OwnerID != "owner-one" || input.ResourceID != "knock-resource" || input.ProtectedResourceID != protected ||
			input.RunID != runID || input.RunAttempt != 1 || input.PreparedAtMillis != 1_800_000_009_000 ||
			input.ExpiresAtMillis != 1_800_001_209_000 {
			t.Fatalf("operation input = %+v", input)
		}
		if len(store.operations[protected]) != 0 {
			t.Fatal("operation was persisted before offline preparation completed")
		}
		return &qurl.NativeSessionOperation{
			AgentID: "agent-one", OperationID: "operation-one", BindingSHA256: "binding-one",
			CellID: "cell-one", OwnerID: input.OwnerID, ResourceID: input.ResourceID,
			ProtectedResourceID: input.ProtectedResourceID, RunID: input.RunID, RunAttempt: input.RunAttempt,
		}, qurl.AgentAssignment{CellID: "cell-one", Endpoint: qurl.NHPUDPEndpoint{
			Host: "cell-one.nhp.layerv.ai", Port: 443, ServerPublicKeyB64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		}}, nil
	}
	binding := &qurl.AgentRuntimeBinding{AgentID: "agent-one"}
	operation, err := controller.PrepareDispatch(context.Background(), binding, make([]byte, 32), "knock-resource", protected, runID, 1)
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
		RunID: runID, RunAttempt: 1,
	}
	if err := controller.RecordMapped(context.Background(), protected, *operation, receipt); err != nil {
		t.Fatal(err)
	}
	records, _ = store.LoadSessionOperations(context.Background(), protected)
	record = records[0]
	if record.Status != agentstate.SessionOperationMapped || record.Admission == nil || record.Admission.SessionID != 91 {
		t.Fatalf("mapped record = %+v", record)
	}

	retireCalls := 0
	retireNativeSession = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte, got qurl.NativeSessionReceipt,
		_ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionRetirement, error) {
		retireCalls++
		current := store.operations[protected][0]
		if current.Status != agentstate.SessionOperationClosing || !sameSessionReceipt(got, receipt) {
			t.Fatalf("retire boundary record=%+v receipt=%+v", current, got)
		}
		return &qurl.NativeSessionRetirement{SessionReceipt: got, State: "closing"}, nil
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
		return &qurl.NativeSessionOperationRecovery{
			State: agentstate.SessionOperationClosed, CellID: receipt.CellID, SessionID: receipt.SessionID,
			SessionIssuedAtMillis: receipt.SessionIssuedAtMillis, RunID: receipt.RunID, RunAttempt: receipt.RunAttempt,
		}, nil
	}
	if err := controller.Retire(context.Background(), binding, make([]byte, 32), protected, operation.OperationID, receipt, nil); err != nil {
		t.Fatal(err)
	}
	if retireCalls != 1 || recoverCalls != 1 {
		t.Fatalf("retire calls=%d recover calls=%d", retireCalls, recoverCalls)
	}
	if records, err := store.LoadSessionOperations(context.Background(), protected); err != nil || len(records) != 0 {
		t.Fatalf("terminal records=%+v err=%v", records, err)
	}
}

func TestDurableNativeSessionRecoveryTombstonesPreparedOperationBeforeReplacement(t *testing.T) {
	oldRecover := recoverNativeSessionOperation
	t.Cleanup(func() { recoverNativeSessionOperation = oldRecover })
	store := &memoryNativeStore{}
	controller, err := newDurableNativeSessionOperations(store, testNativeSessionAuthority())
	if err != nil {
		t.Fatal(err)
	}
	const protected = "protected-resource"
	record := agentstate.SessionOperationRecord{
		Schema: 1, Status: agentstate.SessionOperationPrepared,
		Operation: qurl.NativeSessionOperation{
			AgentID: "agent-one", OperationID: "operation-one", BindingSHA256: "binding-one",
			ProtectedResourceID: protected, ResourceID: "knock-resource", RunID: "0123456789abcdef", RunAttempt: 1,
		},
	}
	if err := store.CreateSessionOperation(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	recoverNativeSessionOperation = func(_ context.Context, _ *qurl.AgentRuntimeBinding, _ []byte,
		_ qurl.NativeSessionOperation, _ qurl.NHPUDPEndpoint, _ ...qurl.AgentRuntimeUDPOption,
	) (*qurl.NativeSessionOperationRecovery, error) {
		current := store.operations[protected][0]
		if current.Status != agentstate.SessionOperationDispatching {
			t.Fatalf("recovery crossed network with status %q", current.Status)
		}
		return &qurl.NativeSessionOperationRecovery{State: agentstate.SessionOperationCanceled}, nil
	}
	if err := controller.RecoverPending(context.Background(), &qurl.AgentRuntimeBinding{AgentID: "agent-one"}, make([]byte, 32), protected, nil, nil); err != nil {
		t.Fatal(err)
	}
	if records, err := store.LoadSessionOperations(context.Background(), protected); err != nil || len(records) != 0 {
		t.Fatalf("canceled tombstone records=%+v err=%v", records, err)
	}
}

func TestNativeSessionOperationAuthorityFailsClosed(t *testing.T) {
	valid := testNativeSessionAuthority()
	tests := []NativeSessionOperationAuthority{
		{},
		{AWSAccountID: "11112222333x", AWSRegion: valid.AWSRegion, OwnerID: valid.OwnerID, QURLAgentKeysTable: valid.QURLAgentKeysTable, SessionControlTable: valid.SessionControlTable},
		{AWSAccountID: valid.AWSAccountID, AWSRegion: "sandbox", OwnerID: valid.OwnerID, QURLAgentKeysTable: valid.QURLAgentKeysTable, SessionControlTable: valid.SessionControlTable},
		{AWSAccountID: valid.AWSAccountID, AWSRegion: valid.AWSRegion, OwnerID: " owner", QURLAgentKeysTable: valid.QURLAgentKeysTable, SessionControlTable: valid.SessionControlTable},
	}
	for _, authority := range tests {
		if _, err := newDurableNativeSessionOperations(&memoryNativeStore{}, authority); err == nil {
			t.Fatalf("invalid authority accepted: %+v", authority)
		}
	}
}
