package agentstate

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	qurl "github.com/layervai/qurl-go/qurl"

	"github.com/layervai/qurl-connector/internal/pinnedfs"
)

const (
	sessionOperationRecordSchema  = 2
	sessionOperationJournalSchema = 2
	sessionOperationFileMaxBytes  = 64 << 10
	sessionOperationFileMode      = 0o600
	sessionOperationLockFile      = ".native_session_operations.lock"
	sessionOperationMaxRecords    = 8
	sessionOperationMaxStateFiles = 4096
	sessionOperationFilePrefix    = "native_session_operation-"
	sessionOperationFileSuffix    = ".json"

	SessionOperationPrepared    = "PREPARED"
	SessionOperationDispatching = "DISPATCHING"
	SessionOperationMapped      = "MAPPED"
	SessionOperationClosing     = "CLOSING"
	SessionOperationCanceled    = "CANCELED"
	SessionOperationClosed      = "CLOSED"
)

var (
	ErrSessionOperationConflict = errors.New("native session operation state conflict")
	// ErrSessionOperationCASLost means another writer changed or removed the
	// exact durable record before this writer committed. It remains a state
	// conflict for callers that do not need to distinguish safe CAS recovery.
	ErrSessionOperationCASLost = fmt.Errorf("%w: compare-and-swap lost", ErrSessionOperationConflict)
	// ErrSessionOperationJournalCorrupt means durable ambiguity cannot be
	// resolved safely. Callers must not delete the journal or open a replacement
	// session because the prior admission may still be live.
	ErrSessionOperationJournalCorrupt = errors.New("native session operation journal is corrupt")
)

// SessionOperationAdmission is the non-secret exact-session receipt retained
// after an authenticated admission. It carries no AC token.
type SessionOperationAdmission struct {
	CellID                string `json:"cell_id"`
	SessionID             uint64 `json:"session_id"`
	SessionIssuedAtMillis int64  `json:"session_issued_at_ms"`
	RunID                 string `json:"run_id"`
	RunAttempt            uint64 `json:"run_attempt"`
}

// SessionOperationRecord is one crash-safe native admission lifecycle. The
// exact operation and its source endpoint are committed before network I/O.
// A restarted process therefore recovers this operation instead of guessing
// whether the prior UDP exchange crossed the server boundary.
type SessionOperationRecord struct {
	Schema                 int                         `json:"schema"`
	Operation              qurl.NativeSessionOperation `json:"operation"`
	RecoveryEndpoint       qurl.NHPUDPEndpoint         `json:"recovery_endpoint"`
	Status                 string                      `json:"status"`
	Admission              *SessionOperationAdmission  `json:"admission,omitempty"`
	RecoveryAttempt        uint32                      `json:"recovery_attempt,omitempty"`
	RecoveryNotBeforeMilli int64                       `json:"recovery_not_before_ms,omitempty"`
}

// NewSessionOperationRecord builds the only valid initial durable record. The
// schema stays owned by this package so callers cannot accidentally pin a
// retired journal format. This feature is unreleased: a future qurl-go
// operation-schema change must add an explicit journal migration before this
// repository moves its exact qurl-go pin.
func NewSessionOperationRecord(operation qurl.NativeSessionOperation,
	recoveryEndpoint qurl.NHPUDPEndpoint,
) (SessionOperationRecord, error) {
	record := SessionOperationRecord{
		Schema: sessionOperationRecordSchema, Operation: operation,
		RecoveryEndpoint: recoveryEndpoint, Status: SessionOperationPrepared,
	}
	if !validOperation(operation) {
		return SessionOperationRecord{}, fmt.Errorf("%w: invalid initial operation", ErrSessionOperationConflict)
	}
	if !validRecoveryEndpoint(recoveryEndpoint) {
		return SessionOperationRecord{}, fmt.Errorf("%w: invalid initial recovery endpoint", ErrSessionOperationConflict)
	}
	return record, nil
}

type sessionOperationJournal struct {
	Schema              int                      `json:"schema"`
	ProtectedResourceID string                   `json:"protected_resource_id"`
	Records             []SessionOperationRecord `json:"records"`
}

// LoadSessionOperations reads every active operation for one protected
// resource while holding its cross-process lock. The list stays small because
// it contains only crash-recovery state and make-before-break admissions.
func (s *SDKStore) LoadSessionOperations(ctx context.Context, resourceID string) ([]SessionOperationRecord, error) {
	var records []SessionOperationRecord
	err := s.withSessionOperationLock(ctx, resourceID, func(namespace *pinnedfs.Directory, name string) error {
		journal, present, err := loadSessionOperationJournal(namespace, name)
		if err != nil || !present {
			return err
		}
		if journal.ProtectedResourceID != resourceID {
			return fmt.Errorf("%w: resource journal mismatch", ErrSessionOperationConflict)
		}
		records = append(records, journal.Records...)
		return nil
	})
	return records, err
}

// SessionOperationResourceScan separates permanent, fail-closed journal
// diagnostics from retryable namespace failures. Valid resources remain
// available even when a sibling journal needs operator attention.
type SessionOperationResourceScan struct {
	ResourceIDs    []string
	PermanentError error
	RetryableError error
}

// ScanSessionOperationResources returns every self-describing durable
// operation journal in the private SDK namespace. It also removes temporary
// journal files left by a process crash. The stable cross-process lock proves
// that a matching temporary file has no live writer.
func (s *SDKStore) ScanSessionOperationResources(ctx context.Context) (scan SessionOperationResourceScan) {
	lockErr := s.withSessionOperationNamespaceLock(ctx, func(namespace *pinnedfs.Directory) error {
		names, err := namespace.ReadDirNames(sessionOperationMaxStateFiles)
		if err != nil {
			return err
		}
		removedTemporary := false
		for _, name := range names {
			switch {
			case validSessionOperationFileName(name):
				journal, present, err := loadSessionOperationJournal(namespace, name)
				if err != nil {
					if errors.Is(err, ErrSessionOperationJournalCorrupt) {
						scan.PermanentError = errors.Join(scan.PermanentError, err)
					} else {
						scan.RetryableError = errors.Join(scan.RetryableError, err)
					}
					continue
				}
				if !present {
					scan.RetryableError = errors.Join(scan.RetryableError,
						fmt.Errorf("%w: enumerated journal disappeared", ErrSessionOperationConflict))
					continue
				}
				expected, err := sessionOperationFileName(journal.ProtectedResourceID)
				if err != nil || expected != name {
					scan.PermanentError = errors.Join(scan.PermanentError,
						fmt.Errorf("%w: resource journal filename mismatch", ErrSessionOperationJournalCorrupt), err)
					continue
				}
				scan.ResourceIDs = append(scan.ResourceIDs, journal.ProtectedResourceID)
			case validSessionOperationTemporaryFileName(name):
				entry, err := namespace.Lstat(name)
				if err != nil {
					scan.RetryableError = errors.Join(scan.RetryableError,
						fmt.Errorf("stat orphaned native session operation temporary file: %w", err))
					continue
				}
				if entry.Mode()&os.ModeSymlink != 0 || !entry.Mode().IsRegular() {
					scan.PermanentError = errors.Join(scan.PermanentError,
						fmt.Errorf("%w: orphaned native session operation temporary file %s has an unsafe shape",
							ErrSessionOperationJournalCorrupt, filepath.Join(namespace.Path(), name)))
					continue
				}
				if err := namespace.Remove(name); err != nil {
					scan.RetryableError = errors.Join(scan.RetryableError,
						fmt.Errorf("remove orphaned native session operation temporary file: %w", err))
					continue
				}
				removedTemporary = true
			}
		}
		if removedTemporary {
			if err := namespace.Sync(); err != nil {
				scan.RetryableError = errors.Join(scan.RetryableError,
					fmt.Errorf("sync orphaned native session operation cleanup: %w", err))
			}
		}
		if err := namespace.ValidateCurrent(); err != nil {
			scan.RetryableError = errors.Join(scan.RetryableError, err)
		}
		return nil
	})
	if lockErr != nil {
		scan.RetryableError = errors.Join(scan.RetryableError, lockErr)
	}
	return scan
}

// CreateSessionOperation appends a distinct PREPARED operation. A resource may
// have an old serving admission and one replacement during make-before-break.
func (s *SDKStore) CreateSessionOperation(ctx context.Context, record SessionOperationRecord) error {
	if record.Status != SessionOperationPrepared || !validSessionOperationRecord(record) {
		return fmt.Errorf("%w: invalid initial record", ErrSessionOperationConflict)
	}
	return s.withSessionOperationLock(ctx, record.Operation.ProtectedResourceID, func(namespace *pinnedfs.Directory, name string) error {
		journal, present, err := loadSessionOperationJournal(namespace, name)
		if err != nil {
			return err
		}
		if !present {
			journal = sessionOperationJournal{Schema: sessionOperationJournalSchema,
				ProtectedResourceID: record.Operation.ProtectedResourceID}
		}
		if journal.ProtectedResourceID != record.Operation.ProtectedResourceID || len(journal.Records) >= sessionOperationMaxRecords {
			return fmt.Errorf("%w: operation journal is full or mismatched", ErrSessionOperationConflict)
		}
		for _, current := range journal.Records {
			if current.Operation.OperationID == record.Operation.OperationID {
				return fmt.Errorf("%w: operation already exists", ErrSessionOperationConflict)
			}
		}
		journal.Records = append(journal.Records, record)
		return writeSessionOperationJournal(namespace, name, journal)
	})
}

// TransitionSessionOperation atomically replaces one exact record. The prior
// value is a compare-and-swap guard against another daemon or process.
func (s *SDKStore) TransitionSessionOperation(ctx context.Context, previous, next SessionOperationRecord) error {
	if previous.Operation.ProtectedResourceID == "" ||
		previous.Operation.ProtectedResourceID != next.Operation.ProtectedResourceID ||
		!validSessionOperationTransition(previous, next) {
		return fmt.Errorf("%w: invalid transition", ErrSessionOperationConflict)
	}
	return s.withSessionOperationLock(ctx, previous.Operation.ProtectedResourceID, func(namespace *pinnedfs.Directory, name string) error {
		journal, present, err := loadSessionOperationJournal(namespace, name)
		if err != nil {
			return err
		}
		index := findSessionOperationRecord(journal.Records, previous)
		if !present || journal.ProtectedResourceID != previous.Operation.ProtectedResourceID || index < 0 {
			return fmt.Errorf("%w: prior record changed", ErrSessionOperationCASLost)
		}
		journal.Records[index] = next
		return writeSessionOperationJournal(namespace, name, journal)
	})
}

// DeleteSessionOperation removes one exact terminal record. Keeping the
// compare-and-swap guard prevents cleanup from deleting a replacement.
func (s *SDKStore) DeleteSessionOperation(ctx context.Context, terminal SessionOperationRecord) error {
	if (terminal.Status != SessionOperationCanceled && terminal.Status != SessionOperationClosed) ||
		!validSessionOperationRecord(terminal) {
		return fmt.Errorf("%w: record is not a valid terminal", ErrSessionOperationConflict)
	}
	return s.withSessionOperationLock(ctx, terminal.Operation.ProtectedResourceID, func(namespace *pinnedfs.Directory, name string) error {
		journal, present, err := loadSessionOperationJournal(namespace, name)
		if err != nil {
			return err
		}
		index := findSessionOperationRecord(journal.Records, terminal)
		if !present || journal.ProtectedResourceID != terminal.Operation.ProtectedResourceID || index < 0 {
			return fmt.Errorf("%w: terminal record changed", ErrSessionOperationCASLost)
		}
		journal.Records = append(journal.Records[:index], journal.Records[index+1:]...)
		if len(journal.Records) > 0 {
			return writeSessionOperationJournal(namespace, name, journal)
		}
		if err := namespace.Remove(name); err != nil {
			return fmt.Errorf("remove native session operation: %w", err)
		}
		if err := namespace.Sync(); err != nil {
			return fmt.Errorf("sync native session operation removal: %w", err)
		}
		return namespace.ValidateCurrent()
	})
}

func (s *SDKStore) withSessionOperationLock(ctx context.Context, resourceID string, fn func(*pinnedfs.Directory, string) error) (retErr error) {
	name, err := sessionOperationFileName(resourceID)
	if err != nil {
		return err
	}
	return s.withSessionOperationNamespaceLock(ctx, func(namespace *pinnedfs.Directory) error {
		return fn(namespace, name)
	})
}

func (s *SDKStore) withSessionOperationNamespaceLock(ctx context.Context, fn func(*pinnedfs.Directory) error) (retErr error) {
	if s == nil || ctx == nil || fn == nil {
		return fmt.Errorf("%w: Connector SDK state store is not open", qurl.ErrAgentStateContinuity)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.validateContinuityLocked(); err != nil {
		return err
	}
	// One stable lock prevents an unbounded set of lock files. Each journal is
	// capped, so record search and rewrite stay bounded. Network I/O never runs
	// while this lock is held.
	lock, err := pinnedfs.AcquireExclusiveFileLock(ctx, s.namespace, sessionOperationLockFile, "native session operation lock", sessionOperationFileMode)
	if err != nil {
		return fmt.Errorf("lock native session operation: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, lock.Close()) }()
	if err := fn(s.namespace); err != nil {
		return err
	}
	if err := lock.ValidateCurrent(); err != nil {
		return fmt.Errorf("validate native session operation lock: %w", err)
	}
	return s.validateContinuityLocked()
}

func sessionOperationFileName(resourceID string) (string, error) {
	if resourceID == "" || strings.TrimSpace(resourceID) != resourceID || len(resourceID) > 4096 {
		return "", fmt.Errorf("%w: invalid protected resource", ErrSessionOperationConflict)
	}
	digest := sha256.Sum256([]byte("layerv/qurl-connector/native-session-operation/v1\x00" + resourceID))
	return sessionOperationFilePrefix + hex.EncodeToString(digest[:]) + sessionOperationFileSuffix, nil
}

func validSessionOperationFileName(name string) bool {
	if !strings.HasPrefix(name, sessionOperationFilePrefix) || !strings.HasSuffix(name, sessionOperationFileSuffix) {
		return false
	}
	digest := strings.TrimSuffix(strings.TrimPrefix(name, sessionOperationFilePrefix), sessionOperationFileSuffix)
	if len(digest) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(digest)
	return err == nil && hex.EncodeToString(decoded) == digest
}

func validSessionOperationTemporaryFileName(name string) bool {
	const temporaryMarker = ".tmp-"
	if !strings.HasPrefix(name, "."+sessionOperationFilePrefix) {
		return false
	}
	marker := strings.LastIndex(name, temporaryMarker)
	if marker < 0 || !validSessionOperationFileName(strings.TrimPrefix(name[:marker], ".")) {
		return false
	}
	suffix := name[marker+len(temporaryMarker):]
	decoded, err := hex.DecodeString(suffix)
	return err == nil && len(decoded) == 8 && hex.EncodeToString(decoded) == suffix
}

func loadSessionOperationJournal(namespace *pinnedfs.Directory, name string) (journal sessionOperationJournal, present bool, retErr error) {
	path := filepath.Join(namespace.Path(), name)
	entry, err := namespace.Lstat(name)
	if err != nil {
		if pinnedfs.IsNotExist(err) {
			return sessionOperationJournal{}, false, nil
		}
		return sessionOperationJournal{}, false, fmt.Errorf("stat native session operation %s: %w", path, err)
	}
	if entry.Mode()&os.ModeSymlink != 0 || !entry.Mode().IsRegular() {
		return sessionOperationJournal{}, false, fmt.Errorf("%w: native session operation %s must be a non-symlink regular file",
			ErrSessionOperationJournalCorrupt, path)
	}
	file, err := namespace.OpenFile(name, os.O_RDONLY|pinnedfs.SafeOpenFlags(), 0)
	if err != nil {
		return sessionOperationJournal{}, false, fmt.Errorf("open native session operation %s: %w", path, err)
	}
	defer func() {
		retErr = errors.Join(retErr, file.Close())
		if retErr != nil {
			journal = sessionOperationJournal{}
			present = false
		}
	}()
	info, err := pinnedfs.ValidateRegularFile(namespace, name, file, "native session operation", sessionOperationFileMode)
	if err != nil {
		return sessionOperationJournal{}, false, fmt.Errorf("%w: %w", ErrSessionOperationJournalCorrupt, err)
	}
	if info.Size() <= 0 || info.Size() > sessionOperationFileMaxBytes {
		return sessionOperationJournal{}, false, fmt.Errorf("%w: native session operation %s has invalid size %d",
			ErrSessionOperationJournalCorrupt, path, info.Size())
	}
	raw, err := io.ReadAll(io.LimitReader(file, sessionOperationFileMaxBytes+1))
	if err != nil {
		return sessionOperationJournal{}, false, fmt.Errorf("read native session operation %s: %w", path, err)
	}
	if len(raw) > sessionOperationFileMaxBytes {
		return sessionOperationJournal{}, false, fmt.Errorf("%w: native session operation %s exceeds %d bytes",
			ErrSessionOperationJournalCorrupt, path, sessionOperationFileMaxBytes)
	}
	if _, err := pinnedfs.ValidateRegularFile(namespace, name, file, "native session operation after read", sessionOperationFileMode); err != nil {
		return sessionOperationJournal{}, false, fmt.Errorf("%w: %w", ErrSessionOperationJournalCorrupt, err)
	}
	journal, err = decodeSessionOperationJournal(raw)
	if err != nil {
		return sessionOperationJournal{}, false, fmt.Errorf("%w: decode %s: %w",
			ErrSessionOperationJournalCorrupt, path, err)
	}
	return journal, true, nil
}

func decodeSessionOperationJournal(raw []byte) (sessionOperationJournal, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var journal sessionOperationJournal
	if err := decoder.Decode(&journal); err != nil {
		return sessionOperationJournal{}, err
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return sessionOperationJournal{}, err
	}
	canonical, err := json.Marshal(journal)
	if err != nil || !bytes.Equal(canonical, raw) || !validSessionOperationJournal(journal) {
		return sessionOperationJournal{}, errors.New("native session operation journal is not canonical")
	}
	return journal, nil
}

func validSessionOperationJournal(journal sessionOperationJournal) bool {
	if journal.Schema != sessionOperationJournalSchema || journal.ProtectedResourceID == "" ||
		len(journal.Records) == 0 || len(journal.Records) > sessionOperationMaxRecords {
		return false
	}
	seen := make(map[string]struct{}, len(journal.Records))
	for _, record := range journal.Records {
		if !validSessionOperationRecord(record) || record.Operation.ProtectedResourceID != journal.ProtectedResourceID {
			return false
		}
		if _, duplicate := seen[record.Operation.OperationID]; duplicate {
			return false
		}
		seen[record.Operation.OperationID] = struct{}{}
	}
	return true
}

func validSessionOperationRecord(record SessionOperationRecord) bool {
	if record.Schema != sessionOperationRecordSchema || !validOperation(record.Operation) ||
		!validRecoveryEndpoint(record.RecoveryEndpoint) ||
		(record.RecoveryAttempt == 0) != (record.RecoveryNotBeforeMilli == 0) ||
		record.RecoveryNotBeforeMilli < 0 {
		return false
	}
	switch record.Status {
	case SessionOperationPrepared, SessionOperationDispatching:
		return record.Admission == nil
	case SessionOperationMapped, SessionOperationClosing, SessionOperationClosed:
		return validSessionOperationAdmission(record.Admission, record.Operation)
	case SessionOperationCanceled:
		return record.Admission == nil
	default:
		return false
	}
}

func validOperation(operation qurl.NativeSessionOperation) bool {
	if operation.OperationID == "" {
		return false
	}
	raw, err := json.Marshal(operation)
	if err != nil {
		return false
	}
	var checked qurl.NativeSessionOperation
	return json.Unmarshal(raw, &checked) == nil && checked == operation
}

func validRecoveryEndpoint(endpoint qurl.NHPUDPEndpoint) bool {
	// Recovery is a native NHP protocol exchange. qurl-go deliberately fixes
	// that protocol to UDP/443; the deployment chooses the canonical DNS name.
	if !validRecoveryEndpointHost(endpoint.Host) || endpoint.Port != 443 {
		return false
	}
	key, err := base64.StdEncoding.Strict().DecodeString(endpoint.ServerPublicKeyB64)
	return err == nil && len(key) == 32 && base64.StdEncoding.EncodeToString(key) == endpoint.ServerPublicKeyB64
}

func validRecoveryEndpointHost(host string) bool {
	if host == "" || len(host) > 253 || strings.HasSuffix(host, ".") || net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func validSessionOperationAdmission(admission *SessionOperationAdmission, operation qurl.NativeSessionOperation) bool {
	return admission != nil && admission.CellID == operation.CellID && admission.SessionID != 0 &&
		admission.SessionIssuedAtMillis > 0 && admission.RunID == operation.RunID &&
		admission.RunAttempt == operation.RunAttempt
}

func validSessionOperationTransition(previous, next SessionOperationRecord) bool {
	if !validSessionOperationRecord(previous) || !validSessionOperationRecord(next) ||
		previous.Schema != next.Schema || previous.Operation != next.Operation || previous.RecoveryEndpoint != next.RecoveryEndpoint {
		return false
	}
	if previous.Admission != nil && (next.Admission == nil || *previous.Admission != *next.Admission) {
		return false
	}
	if !validSessionOperationRecoveryProgress(previous, next) {
		return false
	}
	switch previous.Status {
	case SessionOperationPrepared:
		return next.Status == SessionOperationDispatching || next.Status == SessionOperationCanceled
	case SessionOperationDispatching:
		return next.Status == SessionOperationDispatching || next.Status == SessionOperationMapped ||
			next.Status == SessionOperationCanceled || next.Status == SessionOperationClosing || next.Status == SessionOperationClosed
	case SessionOperationMapped:
		return next.Status == SessionOperationClosing || next.Status == SessionOperationClosed
	case SessionOperationClosing:
		return next.Status == SessionOperationClosing || next.Status == SessionOperationClosed
	default:
		return false
	}
}

func validSessionOperationRecoveryProgress(previous, next SessionOperationRecord) bool {
	if next.RecoveryAttempt < previous.RecoveryAttempt ||
		next.RecoveryNotBeforeMilli < previous.RecoveryNotBeforeMilli {
		return false
	}
	if next.RecoveryAttempt == previous.RecoveryAttempt {
		return next.RecoveryNotBeforeMilli == previous.RecoveryNotBeforeMilli
	}
	return next.RecoveryAttempt == previous.RecoveryAttempt+1 &&
		next.RecoveryNotBeforeMilli > previous.RecoveryNotBeforeMilli
}

func sameSessionOperationRecord(left, right SessionOperationRecord) bool {
	lraw, lerr := json.Marshal(left)
	rraw, rerr := json.Marshal(right)
	return lerr == nil && rerr == nil && bytes.Equal(lraw, rraw)
}

func findSessionOperationRecord(records []SessionOperationRecord, target SessionOperationRecord) int {
	for index, record := range records {
		if sameSessionOperationRecord(record, target) {
			return index
		}
	}
	return -1
}

func writeSessionOperationJournal(namespace *pinnedfs.Directory, name string, journal sessionOperationJournal) (retErr error) {
	if !validSessionOperationJournal(journal) {
		return fmt.Errorf("%w: invalid journal", ErrSessionOperationConflict)
	}
	data, err := json.Marshal(journal)
	if err != nil {
		return fmt.Errorf("encode native session operation: %w", err)
	}
	if len(data) > sessionOperationFileMaxBytes {
		return fmt.Errorf("native session operation exceeds %d bytes", sessionOperationFileMaxBytes)
	}
	if info, err := namespace.Lstat(name); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !pinnedfs.PrivateModeMatches(info, sessionOperationFileMode) {
			return fmt.Errorf("native session operation %s has an unsafe file shape", filepath.Join(namespace.Path(), name))
		}
	} else if !pinnedfs.IsNotExist(err) {
		return err
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return fmt.Errorf("generate native session operation temporary name: %w", err)
	}
	tmpName := "." + name + ".tmp-" + hex.EncodeToString(suffix[:])
	tmp, err := namespace.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL|pinnedfs.SafeOpenFlags(), sessionOperationFileMode)
	if err != nil {
		return fmt.Errorf("create native session operation temporary file: %w", err)
	}
	committed := false
	tmpOpen := true
	defer func() {
		if committed {
			if tmpOpen {
				retErr = errors.Join(retErr, tmp.Close())
			}
			return
		}
		var closeErr error
		if tmpOpen {
			closeErr = tmp.Close()
		}
		removeErr := namespace.Remove(tmpName)
		if pinnedfs.IsNotExist(removeErr) {
			removeErr = nil
		}
		retErr = errors.Join(retErr, closeErr, removeErr, namespace.Sync())
	}()
	if err := tmp.Chmod(sessionOperationFileMode); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if _, err := pinnedfs.ValidateRegularFile(namespace, tmpName, tmp, "temporary native session operation", sessionOperationFileMode); err != nil {
		return err
	}
	if err := namespace.Rename(tmpName, name); err != nil {
		return fmt.Errorf("commit native session operation: %w", err)
	}
	committed = true
	_, validationErr := pinnedfs.ValidateRegularFile(namespace, name, tmp, "committed native session operation", sessionOperationFileMode)
	closeErr := tmp.Close()
	tmpOpen = false
	syncErr := namespace.Sync()
	continuityErr := namespace.ValidateCurrent()
	return errors.Join(validationErr, closeErr, syncErr, continuityErr)
}
