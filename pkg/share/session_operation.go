package share

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	qurl "github.com/layervai/qurl-go/qurl"

	"github.com/layervai/qurl-connector/pkg/agentstate"
)

const (
	nativeSessionOperationLifetime    = 20 * time.Minute
	nativeSessionRecoveryInitialDelay = 100 * time.Millisecond
	nativeSessionRecoveryMaxDelay     = 2 * time.Second
	nativeSessionCleanupBudget        = 30 * time.Second
)

// NativeSessionOperationAuthority is authenticated account context used by
// durable session operations. It must come from the signed-in account, not
// from a CRID, a target-controlled API response, or an NHP packet. Deployment
// coordinates remain private to the NHP server.
type NativeSessionOperationAuthority struct {
	OwnerID string
}

type nativeSessionOperationController interface {
	RecoverPending(context.Context, *qurl.AgentRuntimeBinding, []byte, string, map[string]struct{}, []qurl.AgentRuntimeUDPOption) error
	RecoverOperation(context.Context, *qurl.AgentRuntimeBinding, []byte, string, string, []qurl.AgentRuntimeUDPOption) error
	PrepareDispatch(context.Context, *qurl.AgentRuntimeBinding, []byte, string, string, string, uint64) (*qurl.NativeSessionOperation, error)
	RecordMapped(context.Context, string, qurl.NativeSessionOperation, qurl.NativeSessionReceipt) error
	Retire(context.Context, *qurl.AgentRuntimeBinding, []byte, string, string, qurl.NativeSessionReceipt, []qurl.AgentRuntimeUDPOption) error
}

type durableNativeSessionOperations struct {
	store     nativeStateStore
	authority NativeSessionOperationAuthority
	clock     func() time.Time
}

var (
	prepareLiveNativeSessionOperation = qurl.PrepareLiveNativeSessionOperation
	recoverNativeSessionOperation     = qurl.RecoverNativeSessionOperation
	waitNativeSessionRecovery         = sleepWithContext
)

func newDurableNativeSessionOperations(store nativeStateStore, authority NativeSessionOperationAuthority) (*durableNativeSessionOperations, error) {
	if store == nil {
		return nil, errors.New("build native session operations: state store is closed")
	}
	if err := ValidateNativeSessionOperationAuthority(authority); err != nil {
		return nil, err
	}
	return &durableNativeSessionOperations{store: store, authority: authority, clock: time.Now}, nil
}

// ValidateNativeSessionOperationAuthority validates authenticated account
// context before a caller opens or hands off a native runtime.
func ValidateNativeSessionOperationAuthority(authority NativeSessionOperationAuthority) error {
	if authority.OwnerID == "" || len(authority.OwnerID) > 256 ||
		strings.TrimSpace(authority.OwnerID) != authority.OwnerID ||
		strings.ContainsAny(authority.OwnerID, "\r\n\x00") {
		return errors.New("build native session operations: owner ID is invalid")
	}
	return nil
}

func (d *durableNativeSessionOperations) PrepareDispatch(ctx context.Context, binding *qurl.AgentRuntimeBinding,
	privateKey []byte, knockResourceID, protectedResourceID, runID string, runAttempt uint64,
) (*qurl.NativeSessionOperation, error) {
	if ctx == nil || binding == nil || len(privateKey) != 32 {
		return nil, errors.New("prepare native session operation: runtime is incomplete")
	}
	now := d.clock().UTC()
	operation, recoveryEndpoint, err := prepareLiveNativeSessionOperation(ctx, binding, privateKey, qurl.NativeSessionOperationInput{
		ExpiresAtMillis: now.Add(nativeSessionOperationLifetime).UnixMilli(),
		OwnerID:         d.authority.OwnerID, PreparedAtMillis: now.UnixMilli(),
		ProtectedResourceID: protectedResourceID,
		ResourceID:          knockResourceID, RunAttempt: runAttempt, RunID: runID,
	})
	if err != nil {
		return nil, fmt.Errorf("prepare native session operation: %w", err)
	}
	record, err := agentstate.NewSessionOperationRecord(*operation, recoveryEndpoint)
	if err != nil {
		return nil, fmt.Errorf("build prepared native session operation: %w", err)
	}
	if err := d.store.CreateSessionOperation(ctx, record); err != nil {
		return nil, fmt.Errorf("persist prepared native session operation: %w", err)
	}
	// PREPARED makes local cancellation safe before any packet can leave.
	// DISPATCHING then records the ambiguity boundary before the caller sends
	// the knock. These are separate durable transitions by design.
	dispatching := record
	dispatching.Status = agentstate.SessionOperationDispatching
	if err := d.store.TransitionSessionOperation(ctx, record, dispatching); err != nil {
		return nil, fmt.Errorf("persist native session dispatch boundary: %w", err)
	}
	return operation, nil
}

func (d *durableNativeSessionOperations) RecordMapped(ctx context.Context, protectedResourceID string,
	operation qurl.NativeSessionOperation, receipt qurl.NativeSessionReceipt,
) error {
	record, present, err := d.loadOperation(ctx, protectedResourceID, operation.OperationID)
	if err != nil {
		return err
	}
	if !present || record.Status != agentstate.SessionOperationDispatching || record.Operation != operation {
		return fmt.Errorf("%w: dispatched operation changed before admission", agentstate.ErrSessionOperationConflict)
	}
	mapped := record
	mapped.Status = agentstate.SessionOperationMapped
	mapped.Admission = admissionFromReceipt(receipt)
	if err := d.store.TransitionSessionOperation(ctx, record, mapped); err != nil {
		return fmt.Errorf("persist mapped native session operation: %w", err)
	}
	return nil
}

func (d *durableNativeSessionOperations) RecoverPending(ctx context.Context, binding *qurl.AgentRuntimeBinding,
	privateKey []byte, protectedResourceID string, preserve map[string]struct{}, udpOptions []qurl.AgentRuntimeUDPOption,
) error {
	if ctx == nil || binding == nil || len(privateKey) != 32 {
		return errors.New("recover native session operation: runtime is incomplete")
	}
	// A resource gets one aggregate cleanup budget. RecoverOperation also
	// bounds direct callers, but its child deadline cannot extend this parent
	// while the journal contains several records.
	recoveryCtx, cancelRecovery := context.WithTimeout(ctx, nativeSessionCleanupBudget)
	defer cancelRecovery()
	records, err := d.store.LoadSessionOperations(recoveryCtx, protectedResourceID)
	if err != nil {
		return err
	}
	var recoveryErr error
	for _, record := range records {
		if _, keep := preserve[record.Operation.OperationID]; keep {
			continue
		}
		if err := d.RecoverOperation(recoveryCtx, binding, privateKey, protectedResourceID, record.Operation.OperationID, udpOptions); err != nil {
			recoveryErr = errors.Join(recoveryErr, err)
		}
	}
	return recoveryErr
}

func (d *durableNativeSessionOperations) RecoverOperation(ctx context.Context, binding *qurl.AgentRuntimeBinding,
	privateKey []byte, protectedResourceID, operationID string, udpOptions []qurl.AgentRuntimeUDPOption,
) error {
	if ctx == nil || binding == nil || len(privateKey) != 32 || operationID == "" {
		return errors.New("recover native session operation: runtime is incomplete")
	}
	recoveryCtx, cancelRecovery := context.WithTimeout(ctx, nativeSessionCleanupBudget)
	defer cancelRecovery()
	ctx = recoveryCtx
	for {
		record, present, err := d.loadOperation(ctx, protectedResourceID, operationID)
		if err != nil || !present {
			return err
		}
		switch record.Status {
		case agentstate.SessionOperationCanceled, agentstate.SessionOperationClosed:
			if err := d.store.DeleteSessionOperation(ctx, record); err != nil {
				complete, reconcileErr := d.reconcileRecoveryConflict(ctx, protectedResourceID, record, err)
				if reconcileErr != nil {
					return reconcileErr
				}
				if complete {
					return nil
				}
				continue
			}
			return nil
		case agentstate.SessionOperationPrepared:
			next := record
			next.Status = agentstate.SessionOperationCanceled
			if err := d.store.TransitionSessionOperation(ctx, record, next); err != nil {
				complete, reconcileErr := d.reconcileRecoveryConflict(ctx, protectedResourceID, record, err)
				if reconcileErr != nil {
					return reconcileErr
				}
				if complete {
					return nil
				}
				continue
			}
			if err := d.store.DeleteSessionOperation(ctx, next); err != nil {
				complete, reconcileErr := d.reconcileRecoveryConflict(ctx, protectedResourceID, next, err)
				if reconcileErr != nil {
					return reconcileErr
				}
				if complete {
					return nil
				}
				continue
			}
			return nil
		case agentstate.SessionOperationMapped:
			next := record
			next.Status = agentstate.SessionOperationClosing
			if err := d.store.TransitionSessionOperation(ctx, record, next); err != nil {
				complete, reconcileErr := d.reconcileRecoveryConflict(ctx, protectedResourceID, record, err)
				if reconcileErr != nil {
					return reconcileErr
				}
				if complete {
					return nil
				}
				continue
			}
			record = next
		case agentstate.SessionOperationDispatching, agentstate.SessionOperationClosing:
		default:
			return fmt.Errorf("%w: unsupported recovery state", agentstate.ErrSessionOperationConflict)
		}
		now := d.clock().UTC()
		if record.RecoveryNotBeforeMilli > now.UnixMilli() {
			waitMillis := record.RecoveryNotBeforeMilli - now.UnixMilli()
			if waitMillis > nativeSessionRecoveryMaxDelay.Milliseconds() {
				waitMillis = nativeSessionRecoveryMaxDelay.Milliseconds()
			}
			wait := time.Duration(waitMillis) * time.Millisecond
			// Persisted wall time can appear far in the future after a clock
			// correction. Enforce one bounded delay, then let the server remain the
			// recovery authority instead of waiting on the local clock indefinitely.
			if err := waitNativeSessionRecovery(ctx, wait); err != nil {
				return err
			}
			now = d.clock().UTC()
		}
		if record.RecoveryAttempt == ^uint32(0) {
			return errors.New("recover native session operation: recovery attempt counter is exhausted")
		}
		attempt := record
		attempt.RecoveryAttempt++
		nextAttemptMilli := now.Add(nativeSessionRecoveryBackoff(attempt.RecoveryAttempt)).UnixMilli()
		if nextAttemptMilli <= record.RecoveryNotBeforeMilli {
			if record.RecoveryNotBeforeMilli == math.MaxInt64 {
				return errors.New("recover native session operation: recovery deadline is exhausted")
			}
			nextAttemptMilli = record.RecoveryNotBeforeMilli + 1
		}
		attempt.RecoveryNotBeforeMilli = nextAttemptMilli
		if err := d.store.TransitionSessionOperation(ctx, record, attempt); err != nil {
			complete, reconcileErr := d.reconcileRecoveryConflict(ctx, protectedResourceID, record, err)
			if reconcileErr != nil {
				return fmt.Errorf("persist native session recovery backoff: %w", reconcileErr)
			}
			if complete {
				return nil
			}
			continue
		}
		record = attempt
		result, err := recoverNativeSessionOperation(ctx, binding, privateKey, record.Operation, record.RecoveryEndpoint, udpOptions...)
		if err != nil {
			var unexpected *qurl.NativeSessionOperationUnexpectedAdmissionError
			if !errors.As(err, &unexpected) {
				return fmt.Errorf("recover native session operation: %w", err)
			}
			if result == nil || !sameNativeSessionReceipt(result.UnexpectedAdmission, unexpected.SessionReceipt) {
				return fmt.Errorf("%w: unexpected recovery admission receipt is incomplete", agentstate.ErrSessionOperationConflict)
			}
			// A recovery KNK must not admit. If a compatible authority regresses,
			// preserve the authenticated receipt as MAPPED before any retry. The
			// next loop moves it to CLOSING and asks the same durable server
			// operation to retire it; no EXT fallback or replacement is created.
			if record.Status != agentstate.SessionOperationDispatching || record.Admission != nil {
				return fmt.Errorf("%w: recovery admitted over a non-dispatching operation", agentstate.ErrSessionOperationConflict)
			}
			mapped := record
			mapped.Status = agentstate.SessionOperationMapped
			mapped.Admission = admissionFromReceipt(*result.UnexpectedAdmission)
			if transitionErr := d.store.TransitionSessionOperation(ctx, record, mapped); transitionErr != nil {
				// This process holds an authenticated admission that is not durable.
				// A competing write cannot prove that exact session was retired, so
				// preserve the ambiguity and fail closed without another exchange.
				return fmt.Errorf("persist unexpected recovery admission: %w", transitionErr)
			}
			continue
		}
		if result == nil {
			return errors.New("recover native session operation: server returned no result")
		}
		if !result.Complete {
			continue
		}
		next := record
		if record.Admission == nil {
			next.Status = agentstate.SessionOperationCanceled
		} else {
			next.Status = agentstate.SessionOperationClosed
		}
		if err := d.store.TransitionSessionOperation(ctx, record, next); err != nil {
			complete, reconcileErr := d.reconcileRecoveryConflict(ctx, protectedResourceID, record, err)
			if reconcileErr != nil {
				return fmt.Errorf("persist recovered native session operation: %w", reconcileErr)
			}
			if complete {
				return nil
			}
			continue
		}
		if err := d.store.DeleteSessionOperation(ctx, next); err != nil {
			complete, reconcileErr := d.reconcileRecoveryConflict(ctx, protectedResourceID, next, err)
			if reconcileErr != nil {
				return reconcileErr
			}
			if complete {
				return nil
			}
			continue
		}
		return nil
	}
}

func (d *durableNativeSessionOperations) Retire(ctx context.Context, binding *qurl.AgentRuntimeBinding,
	privateKey []byte, protectedResourceID, operationID string, receipt qurl.NativeSessionReceipt,
	udpOptions []qurl.AgentRuntimeUDPOption,
) error {
	record, present, err := d.loadOperation(ctx, protectedResourceID, operationID)
	if err != nil {
		return err
	}
	if !present {
		// A prior call can complete the durable terminal deletion while its
		// caller loses the result. Retirement is therefore idempotent when the
		// exact operation is already absent.
		return nil
	}
	// CLOSED and journal deletion are separate durable transitions. A process
	// interruption or ambiguous local write can leave the authenticated CLOSED
	// tombstone in place; resume its deletion without another network exchange.
	if (record.Status != agentstate.SessionOperationMapped && record.Status != agentstate.SessionOperationClosing &&
		record.Status != agentstate.SessionOperationClosed) ||
		record.Admission == nil || *record.Admission != *admissionFromReceipt(receipt) {
		return fmt.Errorf("%w: live receipt does not match durable operation", agentstate.ErrSessionOperationConflict)
	}
	return d.RecoverOperation(ctx, binding, privateKey, protectedResourceID, operationID, udpOptions)
}

// reconcileRecoveryConflict resolves only an optimistic-write loss on the
// same durable operation. Absence means another recovery deleted the terminal
// record. A present record must be an exact, monotonic successor; any identity,
// receipt, or state divergence remains fail closed.
func (d *durableNativeSessionOperations) reconcileRecoveryConflict(ctx context.Context,
	protectedResourceID string, previous agentstate.SessionOperationRecord, writeErr error,
) (complete bool, retErr error) {
	if !onlySessionOperationCASLoss(writeErr) {
		return false, writeErr
	}
	current, present, err := d.loadOperation(ctx, protectedResourceID, previous.Operation.OperationID)
	if err != nil {
		return false, errors.Join(writeErr, err)
	}
	if !present {
		return true, nil
	}
	if !monotonicSessionOperationAdvance(previous, current) {
		return false, fmt.Errorf("%w: recovery journal did not advance monotonically",
			agentstate.ErrSessionOperationConflict)
	}
	return false, nil
}

func onlySessionOperationCASLoss(err error) bool {
	if err == nil {
		return false
	}
	type multiUnwrapper interface{ Unwrap() []error }
	if joined, ok := err.(multiUnwrapper); ok {
		causes := joined.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !onlySessionOperationCASLoss(cause) {
				return false
			}
		}
		return true
	}
	if err == agentstate.ErrSessionOperationCASLost { //nolint:errorlint // Exact sentinel is the allowlist boundary.
		return true
	}
	if cause := errors.Unwrap(err); cause != nil {
		return onlySessionOperationCASLoss(cause)
	}
	return false
}

func monotonicSessionOperationAdvance(previous, current agentstate.SessionOperationRecord) bool {
	if !sameSessionOperationIdentity(previous, current) || current.RecoveryAttempt < previous.RecoveryAttempt ||
		current.RecoveryNotBeforeMilli < previous.RecoveryNotBeforeMilli {
		return false
	}
	if previous.RecoveryAttempt == current.RecoveryAttempt &&
		previous.RecoveryNotBeforeMilli != current.RecoveryNotBeforeMilli {
		return false
	}
	if current.RecoveryAttempt > previous.RecoveryAttempt &&
		current.RecoveryNotBeforeMilli <= previous.RecoveryNotBeforeMilli {
		return false
	}
	if previous.Admission != nil &&
		(current.Admission == nil || *previous.Admission != *current.Admission) {
		return false
	}
	if current.Admission != nil &&
		(current.Admission.CellID != current.Operation.CellID || current.Admission.SessionID == 0 ||
			current.Admission.SessionIssuedAtMillis <= 0 || current.Admission.RunID != current.Operation.RunID ||
			current.Admission.RunAttempt != current.Operation.RunAttempt) {
		return false
	}
	switch current.Status {
	case agentstate.SessionOperationPrepared, agentstate.SessionOperationDispatching, agentstate.SessionOperationCanceled:
		if current.Admission != nil {
			return false
		}
	case agentstate.SessionOperationMapped, agentstate.SessionOperationClosing, agentstate.SessionOperationClosed:
		if current.Admission == nil {
			return false
		}
	default:
		return false
	}
	if !reachableSessionOperationStatus(previous.Status, current.Status) {
		return false
	}
	return previous.Status != current.Status || previous.RecoveryAttempt != current.RecoveryAttempt ||
		previous.RecoveryNotBeforeMilli != current.RecoveryNotBeforeMilli ||
		(previous.Admission == nil && current.Admission != nil)
}

// sameSessionOperationIdentity treats only lifecycle status, admission, and
// recovery progress as mutable. A future record field therefore stays
// immutable and fails closed here until its transition semantics are reviewed.
// Record shape and direct-transition rules remain owned by pkg/agentstate.
func sameSessionOperationIdentity(previous, current agentstate.SessionOperationRecord) bool {
	previous.Status, current.Status = "", ""
	previous.Admission, current.Admission = nil, nil
	previous.RecoveryAttempt, current.RecoveryAttempt = 0, 0
	previous.RecoveryNotBeforeMilli, current.RecoveryNotBeforeMilli = 0, 0
	return previous == current
}

func reachableSessionOperationStatus(previous, current string) bool {
	switch previous {
	case agentstate.SessionOperationPrepared:
		// Recovery selected a PREPARED operation for cancellation. A concurrent
		// dispatch or admission has a different intent and must fail closed.
		return current == agentstate.SessionOperationCanceled
	case agentstate.SessionOperationDispatching:
		return current == agentstate.SessionOperationDispatching || current == agentstate.SessionOperationMapped ||
			current == agentstate.SessionOperationClosing || current == agentstate.SessionOperationCanceled ||
			current == agentstate.SessionOperationClosed
	case agentstate.SessionOperationMapped:
		return current == agentstate.SessionOperationClosing || current == agentstate.SessionOperationClosed
	case agentstate.SessionOperationClosing:
		return current == agentstate.SessionOperationClosing || current == agentstate.SessionOperationClosed
	default:
		return false
	}
}

func sameNativeSessionReceipt(left *qurl.NativeSessionReceipt, right qurl.NativeSessionReceipt) bool {
	return left != nil && left.CellID == right.CellID && left.SessionID == right.SessionID &&
		left.SessionIssuedAtMillis == right.SessionIssuedAtMillis && left.RunID == right.RunID &&
		left.RunAttempt == right.RunAttempt
}

func nativeSessionRecoveryBackoff(attempt uint32) time.Duration {
	delay := nativeSessionRecoveryInitialDelay
	for step := uint32(1); step < attempt && delay < nativeSessionRecoveryMaxDelay; step++ {
		delay *= 2
		if delay > nativeSessionRecoveryMaxDelay {
			return nativeSessionRecoveryMaxDelay
		}
	}
	return delay
}

func (d *durableNativeSessionOperations) loadOperation(ctx context.Context, protectedResourceID,
	operationID string,
) (agentstate.SessionOperationRecord, bool, error) {
	records, err := d.store.LoadSessionOperations(ctx, protectedResourceID)
	if err != nil {
		return agentstate.SessionOperationRecord{}, false, err
	}
	for _, record := range records {
		if record.Operation.OperationID == operationID {
			return record, true, nil
		}
	}
	return agentstate.SessionOperationRecord{}, false, nil
}

func admissionFromReceipt(receipt qurl.NativeSessionReceipt) *agentstate.SessionOperationAdmission {
	return &agentstate.SessionOperationAdmission{
		CellID: receipt.CellID, SessionID: receipt.SessionID,
		SessionIssuedAtMillis: receipt.SessionIssuedAtMillis,
		RunID:                 receipt.RunID, RunAttempt: receipt.RunAttempt,
	}
}
