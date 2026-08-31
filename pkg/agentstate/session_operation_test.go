package agentstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	qurl "github.com/layervai/qurl-go/qurl"

	"github.com/layervai/qurl-connector/internal/pinnedfs"
)

const testOperationProtectedResourceID = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcOtuxu2qhc3gt1E7BiEU0CLqEDlXDwzZq0JnESgMAwERX6y_XXF5Cn5SKITWIZQmUhCZ0pHHlVn7SmFUTAnTGQ"

func testSessionOperationRecord(status string) SessionOperationRecord {
	publicKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	endpointKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 32))
	return SessionOperationRecord{
		Schema: sessionOperationRecordSchema,
		Operation: qurl.NativeSessionOperation{
			AgentID: "agent-a", AgentKeySchema: 2, AgentPublicKeyB64: publicKey, AuthServiceID: "agent",
			BindingSchema: 2,
			BindingSHA256: "c5cc2a2b0273d2bca546d484411d917cf6cf5d46a46137a2e5460a0db66d428f",
			CellID:        "cell-01", ConnectorIDClaim: "", CredentialKind: "account",
			ExpiresAtMillis: 1_800_001_210_000,
			OperationID:     "3b2a3a9eabea3af78d8c317ea710e7f0601580163e25c98d50d5e2e17b68f3cc",
			OwnerID:         "auth0|canary-owner", PreparedAtMillis: 1_800_000_009_000,
			ProtectedResourceID: testOperationProtectedResourceID,
			ResourceID:          "resource-a",
			RunAttempt:          7, RunID: "0123456789abcdef", Schema: 2,
		},
		RecoveryEndpoint: qurl.NHPUDPEndpoint{
			Host: "cell0.example.test", Port: 443, ServerPublicKeyB64: endpointKey,
		},
		Status: status,
	}
}

func testSessionOperationWithRun(record SessionOperationRecord, runID string, runAttempt uint64) SessionOperationRecord {
	record.Operation.RunID = runID
	record.Operation.RunAttempt = runAttempt
	publicKey, _ := base64.StdEncoding.DecodeString(record.Operation.AgentPublicKeyB64)
	selector := sha256.New()
	_, _ = selector.Write([]byte("layerv/native-session-operation/v1\x00"))
	_, _ = selector.Write(publicKey)
	_, _ = selector.Write([]byte(runID))
	var attempt [8]byte
	binary.BigEndian.PutUint64(attempt[:], runAttempt)
	_, _ = selector.Write(attempt[:])
	record.Operation.OperationID = hex.EncodeToString(selector.Sum(nil))
	binding := struct {
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
		AgentID: record.Operation.AgentID, AgentKeySchema: record.Operation.AgentKeySchema,
		AgentPublicKeyB64: record.Operation.AgentPublicKeyB64, AuthServiceID: record.Operation.AuthServiceID,
		BindingSchema: record.Operation.BindingSchema, CellID: record.Operation.CellID,
		ConnectorIDClaim: record.Operation.ConnectorIDClaim, CredentialKind: record.Operation.CredentialKind,
		ExpiresAtMillis: record.Operation.ExpiresAtMillis, OperationID: record.Operation.OperationID,
		OwnerID: record.Operation.OwnerID, PreparedAtMillis: record.Operation.PreparedAtMillis,
		ProtectedResourceID: record.Operation.ProtectedResourceID,
		ResourceID:          record.Operation.ResourceID,
		RunAttempt:          record.Operation.RunAttempt, RunID: record.Operation.RunID,
	}
	raw, _ := json.Marshal(binding)
	digest := sha256.Sum256(raw)
	record.Operation.BindingSHA256 = hex.EncodeToString(digest[:])
	return record
}

func TestSDKStoreSessionOperationLifecycleIsCrashSafe(t *testing.T) {
	dir := filepath.Join(realSDKTempDir(t), "state")
	store, err := NewSDKStore(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	prepared := testSessionOperationRecord(SessionOperationPrepared)
	if err := store.CreateSessionOperation(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	name, err := sessionOperationFileName(prepared.Operation.ProtectedResourceID)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, name))
	if err != nil || !pinnedfs.PrivateModeMatches(info, sessionOperationFileMode) {
		t.Fatalf("operation file = %v, %v", info, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSDKStore(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.LoadSessionOperations(context.Background(), prepared.Operation.ProtectedResourceID)
	if err != nil || len(got) != 1 || !sameSessionOperationRecord(got[0], prepared) {
		t.Fatalf("reopened operations = %+v, err=%v", got, err)
	}
	dispatching := prepared
	dispatching.Status = SessionOperationDispatching
	if err := reopened.TransitionSessionOperation(context.Background(), prepared, dispatching); err != nil {
		t.Fatal(err)
	}
	mapped := dispatching
	mapped.Status = SessionOperationMapped
	mapped.Admission = &SessionOperationAdmission{
		CellID: "cell-01", SessionID: 91, SessionIssuedAtMillis: 1_800_000_010_000,
		RunID: "0123456789abcdef", RunAttempt: 7,
	}
	if err := reopened.TransitionSessionOperation(context.Background(), dispatching, mapped); err != nil {
		t.Fatal(err)
	}
	closing := mapped
	closing.Status = SessionOperationClosing
	if err := reopened.TransitionSessionOperation(context.Background(), mapped, closing); err != nil {
		t.Fatal(err)
	}
	closed := closing
	closed.Status = SessionOperationClosed
	if err := reopened.TransitionSessionOperation(context.Background(), closing, closed); err != nil {
		t.Fatal(err)
	}
	if err := reopened.DeleteSessionOperation(context.Background(), closed); err != nil {
		t.Fatal(err)
	}
	if records, err := reopened.LoadSessionOperations(context.Background(), prepared.Operation.ProtectedResourceID); err != nil || len(records) != 0 {
		t.Fatalf("terminal cleanup records=%+v err=%v", records, err)
	}
}

func TestSDKStoreEnumeratesJournalsAndRemovesCrashTemporaries(t *testing.T) {
	dir := filepath.Join(realSDKTempDir(t), "state")
	store, err := NewSDKStore(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	record := testSessionOperationRecord(SessionOperationPrepared)
	if err := store.CreateSessionOperation(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	name, err := sessionOperationFileName(record.Operation.ProtectedResourceID)
	if err != nil {
		t.Fatal(err)
	}
	temporaryName := "." + name + ".tmp-" + strings.Repeat("a", 16)
	if err := os.WriteFile(filepath.Join(dir, temporaryName), []byte("partial"), sessionOperationFileMode); err != nil {
		t.Fatal(err)
	}
	scan := store.ScanSessionOperationResources(context.Background())
	if scan.PermanentError != nil || scan.RetryableError != nil || len(scan.ResourceIDs) != 1 ||
		scan.ResourceIDs[0] != record.Operation.ProtectedResourceID {
		t.Fatalf("enumerated resources = %+v", scan)
	}
	if _, err := os.Lstat(filepath.Join(dir, temporaryName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphaned temporary file remains: %v", err)
	}
}

func TestSDKStoreRejectsJournalWhoseHashedFilenameDoesNotMatchResource(t *testing.T) {
	dir := filepath.Join(realSDKTempDir(t), "state")
	store, err := NewSDKStore(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	record := testSessionOperationRecord(SessionOperationPrepared)
	if err := store.CreateSessionOperation(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	name, err := sessionOperationFileName(record.Operation.ProtectedResourceID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	spoofedName, err := sessionOperationFileName("different-protected-resource")
	if err != nil {
		t.Fatal(err)
	}
	spoofedPath := filepath.Join(dir, spoofedName)
	if err := os.WriteFile(spoofedPath, raw, sessionOperationFileMode); err != nil {
		t.Fatal(err)
	}
	temporaryName := "." + name + ".tmp-" + strings.Repeat("b", 16)
	if err := os.WriteFile(filepath.Join(dir, temporaryName), []byte("partial"), sessionOperationFileMode); err != nil {
		t.Fatal(err)
	}
	scan := store.ScanSessionOperationResources(context.Background())
	if len(scan.ResourceIDs) != 1 || scan.ResourceIDs[0] != record.Operation.ProtectedResourceID ||
		!errors.Is(scan.PermanentError, ErrSessionOperationJournalCorrupt) || scan.RetryableError != nil {
		t.Fatalf("spoofed journal enumeration = %+v", scan)
	}
	if _, err := os.Stat(spoofedPath); err != nil {
		t.Fatalf("unsafe journal was not retained for diagnosis: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, temporaryName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphaned temporary file after corrupt sibling remains: %v", err)
	}
}

func TestSDKStoreSessionOperationRejectsStaleCASAndReplacementDelete(t *testing.T) {
	store, err := NewSDKStore(filepath.Join(realSDKTempDir(t), "state"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	prepared := testSessionOperationRecord(SessionOperationPrepared)
	if err := store.CreateSessionOperation(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	dispatching := prepared
	dispatching.Status = SessionOperationDispatching
	if err := store.TransitionSessionOperation(context.Background(), prepared, dispatching); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionSessionOperation(context.Background(), prepared, dispatching); !errors.Is(err, ErrSessionOperationConflict) {
		t.Fatalf("stale transition = %v", err)
	}
	terminal := dispatching
	terminal.Status = SessionOperationCanceled
	if err := store.DeleteSessionOperation(context.Background(), terminal); !errors.Is(err, ErrSessionOperationConflict) {
		t.Fatalf("uncommitted terminal delete = %v", err)
	}
}

func TestSDKStoreSessionOperationPersistsCancellationAndRecoveryBackoff(t *testing.T) {
	store, err := NewSDKStore(filepath.Join(realSDKTempDir(t), "state"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	prepared := testSessionOperationRecord(SessionOperationPrepared)
	if err := store.CreateSessionOperation(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	canceled := prepared
	canceled.Status = SessionOperationCanceled
	if err := store.TransitionSessionOperation(context.Background(), prepared, canceled); err != nil {
		t.Fatalf("PREPARED -> CANCELED: %v", err)
	}
	if err := store.DeleteSessionOperation(context.Background(), canceled); err != nil {
		t.Fatal(err)
	}

	prepared = testSessionOperationWithRun(prepared, "fedcba9876543210", 8)
	if err := store.CreateSessionOperation(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	dispatching := prepared
	dispatching.Status = SessionOperationDispatching
	if err := store.TransitionSessionOperation(context.Background(), prepared, dispatching); err != nil {
		t.Fatal(err)
	}
	attempt := dispatching
	attempt.RecoveryAttempt = 1
	attempt.RecoveryNotBeforeMilli = 1_800_000_010_100
	if err := store.TransitionSessionOperation(context.Background(), dispatching, attempt); err != nil {
		t.Fatalf("persist first recovery attempt: %v", err)
	}
	skipped := attempt
	skipped.RecoveryAttempt = 3
	skipped.RecoveryNotBeforeMilli++
	if err := store.TransitionSessionOperation(context.Background(), attempt, skipped); !errors.Is(err, ErrSessionOperationConflict) {
		t.Fatalf("skipped recovery attempt = %v", err)
	}
	regressed := attempt
	regressed.RecoveryNotBeforeMilli--
	if err := store.TransitionSessionOperation(context.Background(), attempt, regressed); !errors.Is(err, ErrSessionOperationConflict) {
		t.Fatalf("regressed recovery deadline = %v", err)
	}
	loaded, err := store.LoadSessionOperations(context.Background(), attempt.Operation.ProtectedResourceID)
	if err != nil || len(loaded) != 1 || !sameSessionOperationRecord(loaded[0], attempt) {
		t.Fatalf("persisted recovery backoff=%+v err=%v", loaded, err)
	}
}

func TestSDKStoreSessionOperationAllowsMakeBeforeBreak(t *testing.T) {
	store, err := NewSDKStore(filepath.Join(realSDKTempDir(t), "state"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	first := testSessionOperationRecord(SessionOperationPrepared)
	second := testSessionOperationWithRun(first, "fedcba9876543210", 8)
	if !validSessionOperationRecord(second) {
		t.Fatal("second operation fixture is invalid")
	}
	if err := store.CreateSessionOperation(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSessionOperation(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	records, err := store.LoadSessionOperations(context.Background(), first.Operation.ProtectedResourceID)
	if err != nil || len(records) != 2 || records[0].Operation.OperationID == records[1].Operation.OperationID {
		t.Fatalf("make-before-break records = %+v, err=%v", records, err)
	}
	firstDispatching := first
	firstDispatching.Status = SessionOperationDispatching
	if err := store.TransitionSessionOperation(context.Background(), first, firstDispatching); err != nil {
		t.Fatal(err)
	}
	firstCanceled := firstDispatching
	firstCanceled.Status = SessionOperationCanceled
	if err := store.TransitionSessionOperation(context.Background(), firstDispatching, firstCanceled); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteSessionOperation(context.Background(), firstCanceled); err != nil {
		t.Fatal(err)
	}
	records, err = store.LoadSessionOperations(context.Background(), first.Operation.ProtectedResourceID)
	if err != nil || len(records) != 1 || !sameSessionOperationRecord(records[0], second) {
		t.Fatalf("surviving replacement = %+v, err=%v", records, err)
	}
}

func TestSessionOperationRecordRejectsNoncanonicalOrTamperedState(t *testing.T) {
	record := testSessionOperationRecord(SessionOperationPrepared)
	journal := sessionOperationJournal{Schema: sessionOperationJournalSchema,
		ProtectedResourceID: record.Operation.ProtectedResourceID, Records: []SessionOperationRecord{record}}
	raw, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string][]byte{
		"whitespace": append([]byte(" "), raw...),
		"unknown":    append(bytes.TrimSuffix(bytes.Clone(raw), []byte("}")), []byte(`,"unknown":true}`)...),
		"duplicate":  bytes.Replace(raw, []byte(`"status":"PREPARED"`), []byte(`"status":"PREPARED","status":"PREPARED"`), 1),
		"operation":  bytes.Replace(raw, []byte(`"owner_id":"auth0|canary-owner"`), []byte(`"owner_id":"other"`), 1),
	}
	for name, mutation := range mutations {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeSessionOperationJournal(mutation); err == nil {
				t.Fatal("mutated operation record decoded")
			}
		})
	}
}

func TestSDKStoreSessionOperationRetainsCorruptJournal(t *testing.T) {
	dir := filepath.Join(realSDKTempDir(t), "state")
	store, err := NewSDKStore(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	record := testSessionOperationRecord(SessionOperationPrepared)
	name, err := sessionOperationFileName(record.Operation.ProtectedResourceID)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	const corrupt = `{"schema":2,"protected_resource_id":"incomplete"}`
	if err := os.WriteFile(path, []byte(corrupt), sessionOperationFileMode); err != nil {
		t.Fatal(err)
	}
	if records, err := store.LoadSessionOperations(context.Background(), record.Operation.ProtectedResourceID); records != nil || !errors.Is(err, ErrSessionOperationJournalCorrupt) {
		t.Fatalf("corrupt journal load = (%+v, %v), want retained corruption", records, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != corrupt {
		t.Fatalf("corrupt journal was changed: %q, %v", raw, err)
	}
}

func TestNewSessionOperationRecordRejectsGenericTrustBoundaryDrift(t *testing.T) {
	valid := testSessionOperationRecord(SessionOperationPrepared)
	for name, mutate := range map[string]func(*SessionOperationRecord){
		"empty operation": func(record *SessionOperationRecord) { record.Operation.OperationID = "" },
		"raw IP":          func(record *SessionOperationRecord) { record.RecoveryEndpoint.Host = "192.0.2.1" },
		"uppercase DNS":   func(record *SessionOperationRecord) { record.RecoveryEndpoint.Host = "Cell.example.test" },
		"nonstandard port": func(record *SessionOperationRecord) {
			record.RecoveryEndpoint.Port = 8443
		},
	} {
		t.Run(name, func(t *testing.T) {
			record := valid
			mutate(&record)
			if _, err := NewSessionOperationRecord(record.Operation, record.RecoveryEndpoint); !errors.Is(err, ErrSessionOperationConflict) {
				t.Fatalf("drifted initial record = %v", err)
			}
		})
	}
}

func TestSessionOperationFileNameDoesNotExposeResource(t *testing.T) {
	name, err := sessionOperationFileName(testOperationProtectedResourceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(name) != len("native_session_operation-")+64+len(".json") || bytes.Contains([]byte(name), []byte(testOperationProtectedResourceID)) {
		t.Fatalf("unsafe operation filename %q", name)
	}
}
