package share

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	qurl "github.com/layervai/qurl-go/qurl"
	"github.com/layervai/qurl-go/relayknock/nativeudp"

	"github.com/layervai/qurl-connector/pkg/agentstate"
)

const (
	nativeSessionOperationLifetime    = 20 * time.Minute
	nativeSessionRecoveryInitialDelay = 100 * time.Millisecond
	nativeSessionRecoveryMaxDelay     = 2 * time.Second
	nativeSessionCleanupBudget        = 30 * time.Second

	// nativeSessionRecoveryAbandonMargin is how far past its own expiry an
	// operation must be before a silent endpoint may count toward local
	// abandonment. It exceeds the SDK's exported absent-recovery margin
	// (qurl.NativeSessionOperationJournalMargin, the grace the server-side
	// absent-recovery deadline adds after expiry) plus one full cleanup budget
	// and the SDK's clock-skew allowance, so a late exchange that could still
	// change server state has had its chance. The relationship is pinned by
	// TestNativeSessionRecoveryAbandonMarginCoversServerRecoveryMargin.
	nativeSessionRecoveryAbandonMargin = 5 * time.Minute
	// nativeSessionRecoveryAbandonAttempts is the number of post-expiry recovery
	// exchanges that must end without any authenticated reply, against the
	// pinned endpoint and (when one exists) the current same-cell endpoint,
	// before the record is retired locally. Attempts are counted durably from
	// real failed exchanges only, never from elapsed wall time, so the bound
	// stands on its own when both endpoints are identical and a clock step can
	// never satisfy it.
	nativeSessionRecoveryAbandonAttempts = 5
	// nativeSessionRecoveryNoReplyMaxDelay caps the persisted backoff between
	// post-expiry no-reply attempts. It is the same ceiling the background
	// orphan-recovery loop already uses, so a stuck record stops being retried
	// by every caller on a two-second cadence.
	nativeSessionRecoveryNoReplyMaxDelay = nativeOrphanRecoveryMaxBackoff
)

// errNativeSessionRecoveryDeferred reports that a record past its expiry and
// failing with no reply is inside its persisted escalated backoff. No packet
// was sent. It is retryable: every caller keeps its own cadence and the next
// pass proceeds once the durable deadline has passed.
var errNativeSessionRecoveryDeferred = errors.New("recover native session operation: deferred by persisted no-reply backoff")

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
	// currentNativeAssignment reads the runtime's live placement, including any
	// lease renewal or relocation applied since the binding was built.
	currentNativeAssignment = func(binding *qurl.AgentRuntimeBinding) qurl.AgentAssignment { return binding.Assignment() }
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
			if record.PostExpiryNoReplyAttempts > 0 && waitMillis > nativeSessionRecoveryMaxDelay.Milliseconds() &&
				waitMillis <= nativeSessionRecoveryNoReplyMaxDelay.Milliseconds() {
				// A record past its expiry whose endpoints stay silent is on an
				// escalated persisted backoff. Honor it without sleeping inside the
				// caller's cleanup budget: no packet leaves before the deadline and
				// every caller retries on its own cadence. A longer wait can only
				// come from a clock correction and takes the bounded delay below.
				return fmt.Errorf("%w: next attempt in %s", errNativeSessionRecoveryDeferred,
					time.Duration(waitMillis)*time.Millisecond)
			}
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
		// countable stays true only while every endpoint this attempt reached
		// left a datagram unanswered; a re-fence leg that never got its chance
		// (resolver or socket failure) withdraws the pinned silence as evidence.
		countable := isNativeSessionCountableSilence(err)
		if err != nil && isNativeSessionNoReplyError(err) && ctx.Err() == nil {
			// The pinned endpoint stayed silent. After a server cohort roll the
			// cell's live endpoint moves to another host or server key while the
			// durable operation store stays shared within the cell, so give this
			// same attempt one more exchange against the current same-cell
			// endpoint before counting it as a failure. RecoverPending shares one
			// cleanup budget across a resource's records, so this second exchange
			// halves the per-pass recovery rate of a multi-record journal during a
			// roll; a starved sibling fails with the caller's deadline, which the
			// ctx.Err() guards keep out of the post-expiry count.
			if current, ok := nativeSessionRefenceEndpoint(binding, record); ok {
				refenced, refenceErr := recoverNativeSessionOperation(ctx, binding, privateKey, record.Operation, current, udpOptions...)
				switch {
				case nativeSessionEndpointAnswered(refenced, refenceErr) && ctx.Err() == nil:
					// The current endpoint answered. Pin it durably so the next pass
					// goes straight there; the pinned endpoint stays untouched until
					// then, exactly as if this exchange had never happened.
					moved := record
					moved.RecoveryEndpoint = current
					if transitionErr := d.store.TransitionSessionOperation(ctx, record, moved); transitionErr != nil {
						var unexpected *qurl.NativeSessionOperationUnexpectedAdmissionError
						if errors.As(refenceErr, &unexpected) {
							// Same rule as the MAPPED write below: an authenticated
							// admission that is not durable must fail closed.
							return fmt.Errorf("persist re-fenced recovery endpoint: %w", transitionErr)
						}
						complete, reconcileErr := d.reconcileRecoveryConflict(ctx, protectedResourceID, record, transitionErr)
						if reconcileErr != nil {
							return fmt.Errorf("persist re-fenced recovery endpoint: %w", reconcileErr)
						}
						if complete {
							return nil
						}
						continue
					}
					record = moved
					result, err = refenced, refenceErr
				case isNativeSessionNoReplyError(refenceErr) && ctx.Err() == nil:
					countable = countable && isNativeSessionCountableSilence(refenceErr)
				default:
					// Neither silence nor an answer the caller can still act on: the
					// caller went away or the exchange failed locally. That is no
					// evidence about either endpoint, so nothing is moved and nothing
					// is counted; every cause, including the caller's, is reported.
					return fmt.Errorf("recover native session operation: %w", errors.Join(err, refenceErr, ctx.Err()))
				}
			}
		}
		if err != nil {
			var unexpected *qurl.NativeSessionOperationUnexpectedAdmissionError
			if !errors.As(err, &unexpected) {
				if !countable || ctx.Err() != nil {
					return fmt.Errorf("recover native session operation: %w", err)
				}
				counted, disposition, countErr := d.countPostExpiryNoReply(ctx, protectedResourceID, record)
				if countErr != nil {
					return fmt.Errorf("persist native session recovery no-reply failure: %w", countErr)
				}
				switch disposition {
				case noReplyComplete:
					return nil
				case noReplyReload:
					continue
				case noReplyAbandon:
				default:
					return fmt.Errorf("recover native session operation: %w", err)
				}
				slog.WarnContext(ctx, "abandoning durable native session recovery: the operation is past its expiry and no cell endpoint has answered",
					"operation_id", counted.Operation.OperationID,
					"status", counted.Status,
					"expired_at_ms", counted.Operation.ExpiresAtMillis,
					"recovery_attempts", counted.RecoveryAttempt,
					"post_expiry_no_reply_attempts", counted.PostExpiryNoReplyAttempts,
					"pinned_endpoint", nativeSessionEndpointLabel(counted.RecoveryEndpoint),
					"current_endpoint", nativeSessionEndpointLabel(currentNativeAssignment(binding).Endpoint),
					"err", err)
				done, finishErr := d.finishOperation(ctx, protectedResourceID, counted, "persist abandoned native session operation")
				if finishErr != nil {
					return finishErr
				}
				if done {
					return nil
				}
				continue
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
		done, err := d.finishOperation(ctx, protectedResourceID, record, "persist recovered native session operation")
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
}

// finishOperation commits the legal terminal status for record and deletes the
// tombstone: CLOSED when an admission exists, CANCELED otherwise. The two
// durable steps stay separate so an interruption between them leaves a valid
// journal that the next pass finishes without another exchange. It returns
// (true, nil) once the journal no longer holds the operation and (false, nil)
// when a reconciled optimistic-write loss requires the caller to reload.
func (d *durableNativeSessionOperations) finishOperation(ctx context.Context, protectedResourceID string,
	record agentstate.SessionOperationRecord, transitionFailure string,
) (bool, error) {
	next := record
	if record.Admission == nil {
		next.Status = agentstate.SessionOperationCanceled
	} else {
		next.Status = agentstate.SessionOperationClosed
	}
	if err := d.store.TransitionSessionOperation(ctx, record, next); err != nil {
		complete, reconcileErr := d.reconcileRecoveryConflict(ctx, protectedResourceID, record, err)
		if reconcileErr != nil {
			return false, fmt.Errorf("%s: %w", transitionFailure, reconcileErr)
		}
		return complete, nil
	}
	if err := d.store.DeleteSessionOperation(ctx, next); err != nil {
		complete, reconcileErr := d.reconcileRecoveryConflict(ctx, protectedResourceID, next, err)
		if reconcileErr != nil {
			return false, reconcileErr
		}
		return complete, nil
	}
	return true, nil
}

type noReplyDisposition int

const (
	// noReplyRetry means the failure was not counted toward abandonment; the
	// caller returns the exchange error and a later pass retries.
	noReplyRetry noReplyDisposition = iota
	// noReplyReload means a concurrent recovery advanced the journal first.
	noReplyReload
	// noReplyComplete means the journal no longer holds the operation.
	noReplyComplete
	// noReplyAbandon means the durable post-expiry bound is reached.
	noReplyAbandon
)

// countPostExpiryNoReply durably records one recovery exchange that ended
// without any authenticated reply from either cell endpoint. Nothing is written
// while the operation is inside its expiry plus the abandon margin: those
// failures keep the existing behavior and the server stays the recovery
// authority. Past that margin the failure is counted and the record moves onto
// an escalated persisted backoff; the caller abandons only when the count
// reaches nativeSessionRecoveryAbandonAttempts.
func (d *durableNativeSessionOperations) countPostExpiryNoReply(ctx context.Context, protectedResourceID string,
	record agentstate.SessionOperationRecord,
) (agentstate.SessionOperationRecord, noReplyDisposition, error) {
	now := d.clock().UTC()
	if !nativeSessionOperationPastAbandonMargin(record.Operation, now) {
		return record, noReplyRetry, nil
	}
	if record.PostExpiryNoReplyAttempts == ^uint32(0) {
		return record, noReplyRetry, errors.New("post-expiry failure counter is exhausted")
	}
	failed := record
	failed.PostExpiryNoReplyAttempts++
	notBeforeMilli := now.Add(nativeSessionRecoveryNoReplyBackoff(failed.PostExpiryNoReplyAttempts)).UnixMilli()
	if notBeforeMilli <= record.RecoveryNotBeforeMilli {
		if record.RecoveryNotBeforeMilli == math.MaxInt64 {
			return record, noReplyRetry, errors.New("recovery deadline is exhausted")
		}
		notBeforeMilli = record.RecoveryNotBeforeMilli + 1
	}
	failed.RecoveryNotBeforeMilli = notBeforeMilli
	if err := d.store.TransitionSessionOperation(ctx, record, failed); err != nil {
		complete, reconcileErr := d.reconcileRecoveryConflict(ctx, protectedResourceID, record, err)
		if reconcileErr != nil {
			return record, noReplyRetry, reconcileErr
		}
		if complete {
			return record, noReplyComplete, nil
		}
		return record, noReplyReload, nil
	}
	if failed.PostExpiryNoReplyAttempts < nativeSessionRecoveryAbandonAttempts {
		return failed, noReplyRetry, nil
	}
	return failed, noReplyAbandon, nil
}

// nativeSessionOperationPastAbandonMargin reports whether now is later than
// the operation's own expiry by more than nativeSessionRecoveryAbandonMargin.
func nativeSessionOperationPastAbandonMargin(operation qurl.NativeSessionOperation, now time.Time) bool {
	expiry := operation.ExpiresAtMillis
	margin := nativeSessionRecoveryAbandonMargin.Milliseconds()
	return expiry > 0 && expiry <= math.MaxInt64-margin && now.UnixMilli() > expiry+margin
}

// nativeSessionRefenceEndpoint returns the runtime's current assignment
// endpoint when it serves the record's own cell but differs from the pinned
// recovery endpoint by host or server key. Recovery never crosses cells: a
// different cell does not hold this durable operation, so its answer would
// describe nothing. A malformed live endpoint is skipped rather than handed to
// the SDK, which would classify it as a permanent operation failure.
func nativeSessionRefenceEndpoint(binding *qurl.AgentRuntimeBinding, record agentstate.SessionOperationRecord) (qurl.NHPUDPEndpoint, bool) {
	current := currentNativeAssignment(binding)
	if current.CellID == "" || current.CellID != record.Operation.CellID ||
		current.Endpoint == record.RecoveryEndpoint ||
		!agentstate.ValidSessionOperationRecoveryEndpoint(current.Endpoint) {
		return qurl.NHPUDPEndpoint{}, false
	}
	return current.Endpoint, true
}

// isNativeSessionNoReplyError reports a recovery exchange that produced no
// authenticated server decision: nothing answered, the transport or resolver
// failed, the caller's deadline passed while waiting, or a datagram arrived
// that the pinned server key cannot authenticate (the signature of a rolled
// server key). It gates the re-fence: trying the cell's other endpoint is
// harmless on any of these. A typed deny, an unexpected admission, or a
// malformed authenticated reply is a decision and is never treated as silence.
// Caller cancellation is not evidence about the endpoint.
func isNativeSessionNoReplyError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var deny *qurl.ServerDenyError
	var unexpected *qurl.NativeSessionOperationUnexpectedAdmissionError
	if errors.As(err, &deny) || errors.As(err, &unexpected) {
		return false
	}
	return errors.Is(err, qurl.ErrEndpointNoReply) || errors.Is(err, nativeudp.ErrNoReply) ||
		errors.Is(err, nativeudp.ErrTransport) || errors.Is(err, nativeudp.ErrResolve) ||
		errors.Is(err, nativeudp.ErrServerUnauthenticated) || errors.Is(err, context.DeadlineExceeded)
}

// isNativeSessionCountableSilence is the narrower class that may count toward
// abandonment: the datagram left this host and nothing authenticated came
// back. A resolver or socket failure means the packet was never sent, so an
// offline connector accrues no post-expiry failures and keeps its handle on a
// session the server may still hold.
func isNativeSessionCountableSilence(err error) bool {
	if !isNativeSessionNoReplyError(err) {
		return false
	}
	return errors.Is(err, qurl.ErrEndpointNoReply) || errors.Is(err, nativeudp.ErrNoReply) ||
		errors.Is(err, nativeudp.ErrServerUnauthenticated) || errors.Is(err, context.DeadlineExceeded)
}

// nativeSessionEndpointAnswered reports positive evidence that an endpoint
// authenticated a reply: a recovery result, a typed deny, or an unexpected
// admission. The mere absence of silence is not an answer; a canceled caller
// or a local validation failure proves nothing about the endpoint.
func nativeSessionEndpointAnswered(result *qurl.NativeSessionOperationRecovery, err error) bool {
	if err == nil {
		return result != nil
	}
	var deny *qurl.ServerDenyError
	var unexpected *qurl.NativeSessionOperationUnexpectedAdmissionError
	return errors.As(err, &deny) || errors.As(err, &unexpected)
}

// nativeSessionRecoveryNoReplyBackoff escalates from twice the ordinary
// recovery ceiling up to the orphan-recovery ceiling: 4s, 8s, 16s, then 30s.
func nativeSessionRecoveryNoReplyBackoff(failures uint32) time.Duration {
	delay := nativeSessionRecoveryMaxDelay
	for step := uint32(0); step < failures && delay < nativeSessionRecoveryNoReplyMaxDelay; step++ {
		delay = min(delay*2, nativeSessionRecoveryNoReplyMaxDelay)
	}
	return delay
}

// nativeSessionEndpointLabel renders an endpoint for diagnostics: the host,
// port, and a short prefix of the public server key. It carries no secret.
func nativeSessionEndpointLabel(endpoint qurl.NHPUDPEndpoint) string {
	if endpoint.Host == "" {
		return "none"
	}
	prefix := endpoint.ServerPublicKeyB64
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	return fmt.Sprintf("%s:%d key=%s", endpoint.Host, endpoint.Port, prefix)
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
		current.RecoveryNotBeforeMilli < previous.RecoveryNotBeforeMilli ||
		current.PostExpiryNoReplyAttempts < previous.PostExpiryNoReplyAttempts ||
		!agentstate.ValidSessionOperationRecoveryEndpoint(current.RecoveryEndpoint) {
		return false
	}
	counted := current.RecoveryAttempt > previous.RecoveryAttempt ||
		current.PostExpiryNoReplyAttempts > previous.PostExpiryNoReplyAttempts
	if !counted && previous.RecoveryNotBeforeMilli != current.RecoveryNotBeforeMilli {
		return false
	}
	if counted && current.RecoveryNotBeforeMilli <= previous.RecoveryNotBeforeMilli {
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
	return previous.Status != current.Status || counted ||
		previous.RecoveryNotBeforeMilli != current.RecoveryNotBeforeMilli ||
		previous.RecoveryEndpoint != current.RecoveryEndpoint ||
		(previous.Admission == nil && current.Admission != nil)
}

// sameSessionOperationIdentity treats only lifecycle status, admission,
// recovery progress, and the same-cell recovery endpoint as mutable. A future
// record field therefore stays immutable and fails closed here until its
// transition semantics are reviewed. Record shape and direct-transition rules
// remain owned by pkg/agentstate.
func sameSessionOperationIdentity(previous, current agentstate.SessionOperationRecord) bool {
	previous.Status, current.Status = "", ""
	previous.Admission, current.Admission = nil, nil
	previous.RecoveryAttempt, current.RecoveryAttempt = 0, 0
	previous.RecoveryNotBeforeMilli, current.RecoveryNotBeforeMilli = 0, 0
	previous.PostExpiryNoReplyAttempts, current.PostExpiryNoReplyAttempts = 0, 0
	previous.RecoveryEndpoint, current.RecoveryEndpoint = qurl.NHPUDPEndpoint{}, qurl.NHPUDPEndpoint{}
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
