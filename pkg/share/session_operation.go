package share

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	qurl "github.com/layervai/qurl-go/qurl"

	"github.com/layervai/qurl-connector/pkg/agentstate"
)

const (
	nativeSessionOperationLifetime = 20 * time.Minute
	nativeSessionRecoveryDelay     = 100 * time.Millisecond
	nativeSessionCleanupBudget     = 30 * time.Second
)

// NativeSessionOperationAuthority is the non-secret deployment authority that
// binds native session operations to their durable control-plane tables and
// owner. It must come from trusted deployment configuration, not from a CRID,
// an API response controlled by the target, or an NHP packet.
type NativeSessionOperationAuthority struct {
	AWSAccountID        string
	AWSRegion           string
	OwnerID             string
	QURLAgentKeysTable  string
	SessionControlTable string
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

// ValidateNativeSessionOperationAuthority validates the complete non-secret
// deployment authority before a caller opens or hands off a native runtime.
// It is the shared contract for release-time configuration and admission.
func ValidateNativeSessionOperationAuthority(authority NativeSessionOperationAuthority) error {
	for name, value := range map[string]string{
		"AWS account ID": authority.AWSAccountID, "AWS region": authority.AWSRegion,
		"owner ID": authority.OwnerID, "qURL AgentKeys table": authority.QURLAgentKeysTable,
		"SessionControl table": authority.SessionControlTable,
	} {
		if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("build native session operations: %s is invalid", name)
		}
	}
	if len(authority.AWSAccountID) != 12 {
		return errors.New("build native session operations: AWS account ID is invalid")
	}
	for _, digit := range authority.AWSAccountID {
		if digit < '0' || digit > '9' {
			return errors.New("build native session operations: AWS account ID is invalid")
		}
	}
	if !validNativeSessionRegion(authority.AWSRegion) || !validNativeSessionTable(authority.QURLAgentKeysTable) ||
		!validNativeSessionTable(authority.SessionControlTable) || len(authority.OwnerID) > 256 {
		return errors.New("build native session operations: deployment authority is invalid")
	}
	return nil
}

func validNativeSessionRegion(region string) bool {
	parts := strings.Split(region, "-")
	if len(parts) != 3 || len(parts[0]) != 2 || parts[1] == "" || parts[2] == "" || parts[2][0] == '0' {
		return false
	}
	for _, part := range parts[:2] {
		for _, char := range part {
			if char < 'a' || char > 'z' {
				return false
			}
		}
	}
	for _, char := range parts[2] {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func validNativeSessionTable(table string) bool {
	if len(table) < 3 || len(table) > 255 {
		return false
	}
	for _, char := range table {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.", char) {
			return false
		}
	}
	return true
}

func (d *durableNativeSessionOperations) PrepareDispatch(ctx context.Context, binding *qurl.AgentRuntimeBinding,
	privateKey []byte, knockResourceID, protectedResourceID, runID string, runAttempt uint64,
) (*qurl.NativeSessionOperation, error) {
	if ctx == nil || binding == nil || len(privateKey) != 32 {
		return nil, errors.New("prepare native session operation: runtime is incomplete")
	}
	now := d.clock().UTC()
	operation, assignment, err := prepareLiveNativeSessionOperation(ctx, binding, privateKey, qurl.NativeSessionOperationInput{
		AWSAccountID: d.authority.AWSAccountID, AWSRegion: d.authority.AWSRegion,
		ExpiresAtMillis: now.Add(nativeSessionOperationLifetime).UnixMilli(),
		OwnerID:         d.authority.OwnerID, PreparedAtMillis: now.UnixMilli(),
		ProtectedResourceID: protectedResourceID, QURLAgentKeysTable: d.authority.QURLAgentKeysTable,
		ResourceID: knockResourceID, RunAttempt: runAttempt, RunID: runID,
		SessionControlTable: d.authority.SessionControlTable,
	})
	if err != nil {
		return nil, fmt.Errorf("prepare native session operation: %w", err)
	}
	record := agentstate.SessionOperationRecord{
		Schema: 1, Operation: *operation, RecoveryEndpoint: assignment.Endpoint,
		Status: agentstate.SessionOperationPrepared,
	}
	if err := d.store.CreateSessionOperation(ctx, record); err != nil {
		return nil, fmt.Errorf("persist prepared native session operation: %w", err)
	}
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
	records, err := d.store.LoadSessionOperations(ctx, protectedResourceID)
	if err != nil {
		return err
	}
	for _, record := range records {
		if _, keep := preserve[record.Operation.OperationID]; keep {
			continue
		}
		if err := d.RecoverOperation(ctx, binding, privateKey, protectedResourceID, record.Operation.OperationID, udpOptions); err != nil {
			return err
		}
	}
	return nil
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
			return d.store.DeleteSessionOperation(ctx, record)
		case agentstate.SessionOperationPrepared:
			next := record
			next.Status = agentstate.SessionOperationDispatching
			if err := d.store.TransitionSessionOperation(ctx, record, next); err != nil {
				return err
			}
			record = next
		case agentstate.SessionOperationMapped:
			next := record
			next.Status = agentstate.SessionOperationClosing
			if err := d.store.TransitionSessionOperation(ctx, record, next); err != nil {
				return err
			}
			record = next
		case agentstate.SessionOperationDispatching, agentstate.SessionOperationClosing:
		default:
			return fmt.Errorf("%w: unsupported recovery state", agentstate.ErrSessionOperationConflict)
		}
		result, err := recoverNativeSessionOperation(ctx, binding, privateKey, record.Operation, record.RecoveryEndpoint, udpOptions...)
		if err != nil {
			return fmt.Errorf("recover native session operation: %w", err)
		}
		next := record
		switch result.State {
		case agentstate.SessionOperationCanceled:
			next.Status = agentstate.SessionOperationCanceled
			next.Admission = nil
		case agentstate.SessionOperationClosing, agentstate.SessionOperationClosed:
			next.Status = result.State
			next.Admission = &agentstate.SessionOperationAdmission{
				CellID: result.CellID, SessionID: result.SessionID,
				SessionIssuedAtMillis: result.SessionIssuedAtMillis,
				RunID:                 result.RunID, RunAttempt: result.RunAttempt,
			}
		default:
			return errors.New("recover native session operation: server returned an invalid state")
		}
		if err := d.store.TransitionSessionOperation(ctx, record, next); err != nil {
			return fmt.Errorf("persist recovered native session operation: %w", err)
		}
		if next.Status == agentstate.SessionOperationCanceled || next.Status == agentstate.SessionOperationClosed {
			return d.store.DeleteSessionOperation(ctx, next)
		}
		if err := sleepWithContext(ctx, nativeSessionRecoveryDelay); err != nil {
			return err
		}
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
	if !present || record.Status != agentstate.SessionOperationMapped ||
		record.Admission == nil || *record.Admission != *admissionFromReceipt(receipt) {
		return fmt.Errorf("%w: live receipt does not match durable operation", agentstate.ErrSessionOperationConflict)
	}
	closing := record
	closing.Status = agentstate.SessionOperationClosing
	if err := d.store.TransitionSessionOperation(ctx, record, closing); err != nil {
		return err
	}
	_, retireErr := retireNativeSession(ctx, binding, privateKey, receipt, udpOptions...)
	recoverErr := d.RecoverOperation(ctx, binding, privateKey, protectedResourceID, operationID, udpOptions)
	if recoverErr == nil {
		return nil
	}
	return errors.Join(retireErr, recoverErr)
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

func nativeSessionCleanupContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), nativeSessionCleanupBudget)
}
