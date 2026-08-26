package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	qurlcrid "github.com/layervai/qurl-go/crid"
	qurl "github.com/layervai/qurl-go/qurl"

	"github.com/layervai/qurl-connector/internal/pinnedfs"
	"github.com/layervai/qurl-connector/pkg/agentstate"
	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

const (
	connectorIdentityCacheFile     = "connector_identities.json"
	connectorIdentityCacheLockFile = ".connector_identities.lock"
	legacyConnectorIdentityFile    = "tunnel_identities.json"
	connectorIdentityCacheVersion  = 2
	connectorIdentityCacheMaxBytes = 1 << 20
	connectorIdentityCacheMode     = 0o600
	connectorIdentityAgentIDMaxLen = 256
	connectorIdentityLockTimeout   = 30 * time.Second
)

var connectorIdentityLockWaitTimeout = connectorIdentityLockTimeout

type connectorIdentityCacheEntry struct {
	ID                 string `json:"id"`
	ResourceID         string `json:"resource_id"`
	CRID               string `json:"crid,omitempty"`
	ConnectorRoutingID string `json:"connector_routing_id"`
	KnockResourceID    string `json:"knock_resource_id"`
}

type connectorIdentityPendingRequest struct {
	ID                 string  `json:"id"`
	RequestNonce       string  `json:"request_nonce"`
	ExpectedResourceID *string `json:"expected_resource_id,omitempty"`
}

type connectorIdentityCacheEnvelope struct {
	Version         int                                `json:"version"`
	AgentID         *string                            `json:"agent_id"`
	Identities      *[]connectorIdentityCacheEntry     `json:"identities"`
	PendingRequests *[]connectorIdentityPendingRequest `json:"pending_requests"`
}

type connectorIdentityCache struct {
	agentID string
	byID    map[string]connectorIdentityCacheEntry
	pending map[string]connectorIdentityPendingRequest
}

type connectorIdentityCacheTxn struct {
	stateDir  string
	namespace *pinnedfs.Directory
	lock      *pinnedfs.FileLock
	readOnly  bool
}

var connectorIdentityCacheToken = func() chan struct{} {
	token := make(chan struct{}, 1)
	token <- struct{}{}
	return token
}()

type connectorIdentityCacheContextKey struct{}

var errConnectorIdentityCacheNotFound = errors.New("Connector identity cache not found")

func withConnectorIdentityCacheLock(stateDir string, fn func(*connectorIdentityCacheTxn) error) error {
	return withConnectorIdentityCacheLockContext(context.Background(), stateDir, func(_ context.Context, txn *connectorIdentityCacheTxn) error {
		return fn(txn)
	})
}

func withConnectorIdentityCacheLockContext(ctx context.Context, stateDir string, fn func(context.Context, *connectorIdentityCacheTxn) error) (retErr error) {
	if ctx == nil {
		return errors.New("Connector identity cache transaction context is nil")
	}
	if ctx.Value(connectorIdentityCacheContextKey{}) != nil {
		return errors.New("Connector identity cache transactions are non-reentrant")
	}
	lockCtx, cancel := context.WithTimeout(ctx, connectorIdentityLockWaitTimeout)
	defer cancel()
	select {
	case <-lockCtx.Done():
		return lockCtx.Err()
	case <-connectorIdentityCacheToken:
	}
	defer func() { connectorIdentityCacheToken <- struct{}{} }()

	stateDir = agentstate.ResolveDir(stateDir)
	// This is the first thing a fresh `run` does to the state directory, so it
	// is also where a hand-created 0755 directory would otherwise fail the 0700
	// mode check below. Tighten it to owner-only first (fresh-run onboarding
	// ergonomics); EnsurePrivate still performs the full pinned validation.
	if err := agentstate.EnsureDirMode(stateDir); err != nil {
		return fmt.Errorf("prepare Connector identity cache namespace: %w", err)
	}
	namespace, err := pinnedfs.EnsurePrivate(stateDir, 0o700)
	if err != nil {
		return fmt.Errorf("open Connector identity cache namespace: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, namespace.Close()) }()
	lockExists := true
	if _, err := namespace.Lstat(connectorIdentityCacheLockFile); pinnedfs.IsNotExist(err) {
		lockExists = false
		hasState, stateErr := connectorIdentityNamespaceHasState(namespace)
		if stateErr != nil {
			return stateErr
		}
		if hasState {
			return fmt.Errorf("Connector identity continuity state is missing its lock %s; refusing a mutating transaction", connectorIdentityCacheLockFile)
		}
	} else if err != nil {
		return fmt.Errorf("inspect Connector identity cache lock: %w", err)
	}
	acquireLock := pinnedfs.AcquireExclusiveFileLock
	if lockExists {
		// Never recreate a lock that disappeared after the preflight. A
		// process may still hold the renamed inode, so creation here would
		// split the transaction namespace.
		acquireLock = pinnedfs.AcquireExistingExclusiveFileLock
	}
	lock, err := acquireLock(lockCtx, namespace, connectorIdentityCacheLockFile, "Connector identity cache lock", connectorIdentityCacheMode)
	if err != nil {
		return fmt.Errorf("lock Connector identity cache transaction: %w", err)
	}
	cancel()
	defer func() { retErr = errors.Join(retErr, lock.Close()) }()
	txn := &connectorIdentityCacheTxn{stateDir: stateDir, namespace: namespace, lock: lock}
	if err := validateConnectorIdentityCacheNamespace(txn); err != nil {
		return err
	}
	// A prior rename may be visible after an uncertain directory-sync result.
	// Re-establish the retry durability barrier before the callback can trust
	// pending/resolved state for remote I/O or pruning.
	if err := syncConnectorIdentityCacheRetryBarrier(namespace); err != nil {
		return fmt.Errorf("establish cache retry durability: %w", err)
	}
	txnCtx := context.WithValue(ctx, connectorIdentityCacheContextKey{}, true)
	callbackErr := fn(txnCtx, txn)
	return errors.Join(callbackErr, validateConnectorIdentityCacheNamespace(txn))
}

func withConnectorIdentityCacheSnapshot(ctx context.Context, stateDir string, fn func(*connectorIdentityCacheTxn) error) (retErr error) {
	if ctx == nil {
		return errors.New("Connector identity cache snapshot context is nil")
	}
	if ctx.Value(connectorIdentityCacheContextKey{}) != nil {
		return errors.New("Connector identity cache transactions are non-reentrant")
	}
	ctx, cancel := context.WithTimeout(ctx, connectorIdentityLockTimeout)
	defer cancel()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-connectorIdentityCacheToken:
	}
	defer func() { connectorIdentityCacheToken <- struct{}{} }()

	stateDir = agentstate.ResolveDir(stateDir)
	namespace, err := pinnedfs.OpenPrivate(stateDir, 0o700)
	if err != nil {
		return fmt.Errorf("open read-only Connector identity cache namespace: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, namespace.Close()) }()
	if _, err := namespace.Lstat(connectorIdentityCacheLockFile); pinnedfs.IsNotExist(err) {
		hasState, stateErr := connectorIdentityNamespaceHasState(namespace)
		if stateErr != nil {
			return stateErr
		}
		if hasState {
			return fmt.Errorf("Connector identity continuity state is missing its lock %s; refusing an unlocked snapshot", connectorIdentityCacheLockFile)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect Connector identity cache lock: %w", err)
	}
	lock, err := pinnedfs.AcquireSharedFileLock(ctx, namespace, connectorIdentityCacheLockFile, "Connector identity cache lock", connectorIdentityCacheMode)
	if err != nil {
		return fmt.Errorf("lock read-only Connector identity cache snapshot: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, lock.Close()) }()
	txn := &connectorIdentityCacheTxn{stateDir: stateDir, namespace: namespace, lock: lock, readOnly: true}
	if err := validateConnectorIdentityCacheNamespace(txn); err != nil {
		return err
	}
	return errors.Join(fn(txn), validateConnectorIdentityCacheNamespace(txn))
}

func connectorIdentityNamespaceHasState(namespace *pinnedfs.Directory) (bool, error) {
	for _, name := range []string{
		connectorIdentityCacheFile,
		legacyConnectorIdentityFile,
		agentstate.AgentStateFile,
		agentstate.SealedAgentStateFile,
	} {
		_, err := namespace.Lstat(name)
		switch {
		case err == nil:
			return true, nil
		case pinnedfs.IsNotExist(err):
			continue
		default:
			return false, fmt.Errorf("inspect Connector continuity entry %s: %w", name, err)
		}
	}
	return false, nil
}

func ensureConnectorIdentityCacheInitialized(stateDir string) error {
	return withConnectorIdentityCacheLock(stateDir, func(txn *connectorIdentityCacheTxn) error {
		return ensureConnectorIdentityCacheInitializedLocked(txn)
	})
}

func loadConnectorIdentityCache(stateDir string) (*connectorIdentityCache, error) {
	var cache *connectorIdentityCache
	err := withConnectorIdentityCacheLock(stateDir, func(txn *connectorIdentityCacheTxn) error {
		if err := rejectLegacyConnectorIdentityStateLocked(txn); err != nil {
			return err
		}
		var err error
		cache, err = loadConnectorIdentityCacheUnlocked(txn)
		return err
	})
	return cache, err
}

func ensureConnectorIdentityCacheInitializedLocked(txn *connectorIdentityCacheTxn) error {
	if err := rejectLegacyConnectorIdentityStateLocked(txn); err != nil {
		return err
	}
	cache, err := loadConnectorIdentityCacheUnlocked(txn)
	if err == nil {
		// agent_id is itself continuity state even before the first resource is
		// ensured. A crash after binding this cache but before provisioning must
		// not let a missing native envelope enroll a new device and only discover
		// the cross-device mismatch after network I/O.
		if cache.hasContinuityState() {
			nativeState, stateErr := connectorNativeAgentStateExists(txn)
			if stateErr != nil {
				return fmt.Errorf("inspect native agent state for Connector identity continuity: %w", stateErr)
			}
			if !nativeState {
				return errors.New("Connector identity cache is bound or non-empty but native agent state is missing; refusing to bind persisted resource identities to a newly enrolled device")
			}
		}
		return nil
	}
	if !errors.Is(err, errConnectorIdentityCacheNotFound) {
		return err
	}
	if err := agentstate.ValidateSDKStoreLayout(txn.stateDir); err != nil {
		return fmt.Errorf("validate native agent state before initializing Connector identity cache: %w", err)
	}
	nativeState, err := connectorNativeAgentStateExists(txn)
	if err != nil {
		return fmt.Errorf("inspect native agent state before initializing Connector identity cache: %w", err)
	}
	if nativeState {
		return fmt.Errorf("Connector identity continuity state is missing while native agent state exists; refusing to recreate resource identities: restore %s from backup or deliberately reprovision the state volume", connectorIdentityCacheFile)
	}
	return saveConnectorIdentityCacheUnlocked(txn, &connectorIdentityCache{
		byID: make(map[string]connectorIdentityCacheEntry), pending: make(map[string]connectorIdentityPendingRequest),
	})
}

func hydrateConnectorResourceIDsReadOnlyContext(ctx context.Context, cfg *nhpconfig.Config) error {
	if cfg == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("Connector identity display context is nil")
	}
	stateDir := agentstate.ResolveDir("")
	if _, err := os.Lstat(stateDir); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect Connector state directory: %w", err)
	}
	return withConnectorIdentityCacheSnapshot(ctx, stateDir, func(txn *connectorIdentityCacheTxn) error {
		if err := rejectLegacyConnectorIdentityStateLocked(txn); err != nil {
			return err
		}
		if err := agentstate.ValidateSDKStoreLayoutReadOnly(txn.stateDir); err != nil {
			return fmt.Errorf("validate native agent state for Connector identity display: %w", err)
		}
		cache, err := loadConnectorIdentityCacheUnlocked(txn)
		if errors.Is(err, errConnectorIdentityCacheNotFound) {
			nativeState, stateErr := connectorNativeAgentStateExists(txn)
			if stateErr != nil {
				return fmt.Errorf("inspect native agent state for Connector identity continuity: %w", stateErr)
			}
			if nativeState {
				return fmt.Errorf("Connector identity continuity state is missing while native agent state exists; restore %s from backup or deliberately reprovision the state volume", connectorIdentityCacheFile)
			}
			return nil
		}
		if err != nil {
			return err
		}
		if cache.hasContinuityState() {
			nativeState, stateErr := connectorNativeAgentStateExists(txn)
			if stateErr != nil {
				return fmt.Errorf("inspect native agent state for Connector identity continuity: %w", stateErr)
			}
			if !nativeState {
				return errors.New("Connector identity cache is bound or non-empty but native agent state is missing; refusing to display identities without their owning device state")
			}
			// Display remains non-mutating, but showing a transplanted cache as if
			// it belonged to the current device is still unsafe. Use the SDK's
			// narrow reader so sealed providers authenticate and unseal the outer
			// binding without creating setup locks or repairing the filesystem.
			reader, readerErr := agentstate.OpenSDKStateReader(txn.stateDir, agentstate.ConfiguredAgentID())
			if readerErr != nil {
				return fmt.Errorf("open native agent state read-only for Connector identity display: %w", readerErr)
			}
			validateErr := validateConnectorCacheAgentState(ctx, reader, cache.agentID)
			if err := errors.Join(validateErr, reader.Close()); err != nil {
				return err
			}
		}
		// Read-only diagnostics still validate every configured identity
		// against the authenticated cache, but stale entries for routes no
		// longer present in YAML must not make list/status unavailable. The
		// mutating run path rejects those orphans before any resource traffic.
		if _, err := validateConfiguredConnectorIdentityGraph(cfg, cache); err != nil {
			return err
		}
		fallbackID := routeIDEnvFallback()
		for i := range cfg.Routes {
			if cfg.Routes[i].ResourceID != "" {
				continue
			}
			id := routeIDWithFallback(cfg, cfg.Routes[i], fallbackID)
			if binding, ok := cache.binding(id); ok {
				cfg.Routes[i].ResourceID = binding.ResourceID
				cfg.Routes[i].ConnectorRoutingID = binding.ConnectorRoutingID
				cfg.SetKnockResourceID(binding.ResourceID, binding.KnockResourceID)
			}
		}
		return nil
	})
}

func validateConnectorCacheAgentState(ctx context.Context, reader qurl.AgentStateReader, expectedAgentID string) error {
	if reader == nil {
		return errors.New("native agent state reader is nil")
	}
	if err := validateCachedAgentID(expectedAgentID); err != nil {
		return fmt.Errorf("Connector identity cache is not bound to a registered device: %w", err)
	}
	state, err := reader.LoadAgentState(ctx)
	if err != nil {
		return fmt.Errorf("load native agent identity for Connector cache binding: %w", err)
	}
	if state == nil {
		return errors.New("native agent identity store returned nil state")
	}
	actualAgentID := state.AgentID
	*state = qurl.AgentState{}
	if actualAgentID != expectedAgentID {
		return fmt.Errorf("Connector identity cache agent_id %s does not match native-state agent_id %s; refusing cross-device resource use", cachedAgentIDFingerprint(expectedAgentID), cachedAgentIDFingerprint(actualAgentID))
	}
	return nil
}

func rejectLegacyConnectorIdentityStateLocked(txn *connectorIdentityCacheTxn) error {
	legacyState, err := connectorLegacyIdentityStateExists(txn)
	if err != nil {
		return fmt.Errorf("inspect legacy Connector identity state: %w", err)
	}
	if legacyState {
		return fmt.Errorf("legacy %s found in %s; the native UDP Connector does not migrate legacy identity state: stop all Connector processes, empty this entire state directory, and enroll again", legacyConnectorIdentityFile, txn.stateDir)
	}
	return nil
}

func connectorNativeAgentStateExists(txn *connectorIdentityCacheTxn) (bool, error) {
	if txn == nil || txn.namespace == nil {
		return false, errors.New("Connector identity cache namespace is not open")
	}
	for _, name := range []string{agentstate.AgentStateFile, agentstate.SealedAgentStateFile} {
		_, err := txn.namespace.Lstat(name)
		switch {
		case err == nil:
			return true, nil
		case pinnedfs.IsNotExist(err):
			continue
		default:
			return false, err
		}
	}
	return false, nil
}

func connectorLegacyIdentityStateExists(txn *connectorIdentityCacheTxn) (bool, error) {
	if txn == nil || txn.namespace == nil {
		return false, errors.New("Connector identity cache namespace is not open")
	}
	_, err := txn.namespace.Lstat(legacyConnectorIdentityFile)
	switch {
	case err == nil:
		return true, nil
	case pinnedfs.IsNotExist(err):
		return false, nil
	default:
		return false, err
	}
}

func openConnectorIdentityCache(txn *connectorIdentityCacheTxn, name string) (*os.File, os.FileInfo, error) {
	if err := validateConnectorIdentityCacheNamespace(txn); err != nil {
		return nil, nil, err
	}
	file, err := txn.namespace.OpenFile(name, os.O_RDONLY|pinnedfs.SafeOpenFlags(), 0)
	if err != nil {
		if pinnedfs.IsNotExist(err) {
			return nil, nil, os.ErrNotExist
		}
		return nil, nil, err
	}
	info, err := pinnedfs.ValidateRegularFile(txn.namespace, name, file, "Connector identity cache", connectorIdentityCacheMode)
	if err != nil {
		return nil, nil, errors.Join(err, file.Close())
	}
	return file, info, nil
}

var syncConnectorIdentityCacheDir = func(namespace *pinnedfs.Directory) error {
	return namespace.Sync()
}
var syncConnectorIdentityCacheRetryBarrier = func(namespace *pinnedfs.Directory) error {
	return namespace.Sync()
}
var closeConnectorIdentityCacheTemp = func(file *os.File) error { return file.Close() }
var removeConnectorIdentityCacheTemp = func(namespace *pinnedfs.Directory, name string) error {
	return namespace.Remove(name)
}
var beforeConnectorIdentityCacheTempValidation = func(*connectorIdentityCacheTxn, string) {}
var beforeConnectorIdentityCachePostReadValidation = func(*connectorIdentityCacheTxn) {}

func writeConnectorIdentityCacheDurable(txn *connectorIdentityCacheTxn, name string, raw []byte, mode os.FileMode) (retErr error) {
	if err := validateConnectorIdentityCacheNamespace(txn); err != nil {
		return err
	}
	if txn.readOnly {
		return errors.New("cannot mutate a read-only Connector identity cache snapshot")
	}
	if file, _, err := openConnectorIdentityCache(txn, name); err == nil {
		if closeErr := file.Close(); closeErr != nil {
			return closeErr
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("open existing cache without following symlinks: %w", err)
	}

	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return fmt.Errorf("generate cache temporary name: %w", err)
	}
	tmpName := "." + name + ".tmp-" + hex.EncodeToString(suffix)
	tmp, err := txn.namespace.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL|pinnedfs.SafeOpenFlags(), mode)
	if err != nil {
		return fmt.Errorf("create cache temporary file: %w", err)
	}
	committed := false
	tmpOpen := true
	defer func() {
		if committed {
			if tmpOpen {
				retErr = errors.Join(retErr, closeConnectorIdentityCacheTemp(tmp))
			}
			return
		}
		var closeErr error
		if tmpOpen {
			closeErr = closeConnectorIdentityCacheTemp(tmp)
		}
		removeErr := removeConnectorIdentityCacheTemp(txn.namespace, tmpName)
		if pinnedfs.IsNotExist(removeErr) {
			removeErr = nil
		}
		syncErr := syncConnectorIdentityCacheDir(txn.namespace)
		retErr = errors.Join(retErr, closeErr, removeErr, syncErr)
	}()
	if err := tmp.Chmod(mode); err != nil {
		return fmt.Errorf("set cache temporary file permissions: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		return fmt.Errorf("write cache temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync cache temporary file: %w", err)
	}
	beforeConnectorIdentityCacheTempValidation(txn, tmpName)
	if _, err := pinnedfs.ValidateRegularFile(txn.namespace, tmpName, tmp, "temporary Connector identity cache", mode); err != nil {
		return err
	}
	if err := txn.namespace.Rename(tmpName, name); err != nil {
		return fmt.Errorf("commit cache rename: %w", err)
	}
	committed = true
	_, validationErr := pinnedfs.ValidateRegularFile(txn.namespace, name, tmp, "committed Connector identity cache", mode)
	closeErr := closeConnectorIdentityCacheTemp(tmp)
	tmpOpen = false
	syncErr := syncConnectorIdentityCacheDir(txn.namespace)
	continuityErr := validateConnectorIdentityCacheNamespace(txn)
	var wrappedSyncErr error
	if syncErr != nil {
		wrappedSyncErr = fmt.Errorf("cache rename committed but state-directory sync failed; durability is unknown: %w", syncErr)
	}
	return errors.Join(validationErr, closeErr, wrappedSyncErr, continuityErr)
}

func validateConnectorIdentityCacheNamespace(txn *connectorIdentityCacheTxn) error {
	if txn == nil || txn.namespace == nil || txn.lock == nil {
		return errors.New("Connector identity cache namespace is not open")
	}
	return errors.Join(txn.namespace.ValidateCurrent(), txn.lock.ValidateCurrent())
}

func loadConnectorIdentityCacheUnlocked(txn *connectorIdentityCacheTxn) (cache *connectorIdentityCache, retErr error) {
	path := filepath.Join(txn.stateDir, connectorIdentityCacheFile)
	file, info, err := openConnectorIdentityCache(txn, connectorIdentityCacheFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", errConnectorIdentityCacheNotFound, path)
		}
		return nil, fmt.Errorf("inspect Connector identity cache %s: %w", path, err)
	}
	defer func() { retErr = errors.Join(retErr, file.Close()) }()
	if info.Size() <= 0 || info.Size() > connectorIdentityCacheMaxBytes {
		return nil, fmt.Errorf("Connector identity cache %s size %d is outside 1..%d bytes", path, info.Size(), connectorIdentityCacheMaxBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(file, connectorIdentityCacheMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read Connector identity cache %s: %w", path, err)
	}
	if len(raw) > connectorIdentityCacheMaxBytes {
		return nil, fmt.Errorf("Connector identity cache %s exceeds %d-byte cap", path, connectorIdentityCacheMaxBytes)
	}
	beforeConnectorIdentityCachePostReadValidation(txn)
	if _, err := pinnedfs.ValidateRegularFile(txn.namespace, connectorIdentityCacheFile, file, "Connector identity cache after read", connectorIdentityCacheMode); err != nil {
		return nil, err
	}
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("decode Connector identity cache %s: document is not valid UTF-8", path)
	}
	if err := rejectConnectorIdentityCacheSurrogateEscapes(raw); err != nil {
		return nil, fmt.Errorf("decode Connector identity cache %s: %w", path, err)
	}
	if err := rejectDuplicateConnectorIdentityCacheKeys(raw); err != nil {
		return nil, fmt.Errorf("decode Connector identity cache %s: %w", path, err)
	}
	if err := rejectNonCanonicalConnectorIdentityCacheKeys(raw); err != nil {
		return nil, fmt.Errorf("decode Connector identity cache %s: %w", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var envelope connectorIdentityCacheEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode Connector identity cache %s: %w", path, err)
	}
	if err := requireConnectorIdentityCacheEOF(decoder); err != nil {
		return nil, fmt.Errorf("decode Connector identity cache %s: %w", path, err)
	}
	if envelope.Version != connectorIdentityCacheVersion {
		return nil, fmt.Errorf("Connector identity cache %s version is %d, want %d", path, envelope.Version, connectorIdentityCacheVersion)
	}
	if envelope.AgentID == nil {
		return nil, fmt.Errorf("Connector identity cache %s is missing agent_id", path)
	}
	if envelope.Identities == nil {
		return nil, fmt.Errorf("Connector identity cache %s is missing identities", path)
	}
	if envelope.PendingRequests == nil {
		return nil, fmt.Errorf("Connector identity cache %s is missing pending_requests", path)
	}

	cache = &connectorIdentityCache{
		agentID: *envelope.AgentID,
		byID:    make(map[string]connectorIdentityCacheEntry, len(*envelope.Identities)),
		pending: make(map[string]connectorIdentityPendingRequest, len(*envelope.PendingRequests)),
	}
	if cache.agentID != "" {
		if err := validateCachedAgentID(cache.agentID); err != nil {
			return nil, fmt.Errorf("Connector identity cache %s: %w", path, err)
		}
	}
	resourceOwners := make(map[string]string, len(*envelope.Identities))
	for i, entry := range *envelope.Identities {
		if err := nhpconfig.ValidateSlug(entry.ID); err != nil {
			return nil, fmt.Errorf("Connector identity cache %s identities[%d]: %w", path, i, err)
		}
		if err := validateCachedConnectorResourceID(entry.ResourceID); err != nil {
			return nil, fmt.Errorf("Connector identity cache %s identities[%d]: %w", path, i, err)
		}
		if err := validateCachedConnectorBinding(entry); err != nil {
			return nil, fmt.Errorf("Connector identity cache %s identities[%d]: %w", path, i, err)
		}
		if _, duplicate := cache.byID[entry.ID]; duplicate {
			return nil, fmt.Errorf("Connector identity cache %s has duplicate id %q", path, entry.ID)
		}
		if i > 0 && (*envelope.Identities)[i-1].ID >= entry.ID {
			return nil, fmt.Errorf("Connector identity cache %s identities must be strictly sorted by id", path)
		}
		if owner, duplicate := resourceOwners[entry.ResourceID]; duplicate {
			return nil, fmt.Errorf("Connector identity cache %s maps resource_id %q to both %q and %q", path, entry.ResourceID, owner, entry.ID)
		}
		cache.byID[entry.ID] = entry
		resourceOwners[entry.ResourceID] = entry.ID
	}
	for i, request := range *envelope.PendingRequests {
		if err := validateCachedConnectorRequest(request); err != nil {
			return nil, fmt.Errorf("Connector identity cache %s pending_requests[%d]: %w", path, i, err)
		}
		if _, duplicate := cache.pending[request.ID]; duplicate {
			return nil, fmt.Errorf("Connector identity cache %s has duplicate pending_request %q", path, request.ID)
		}
		if i > 0 && (*envelope.PendingRequests)[i-1].ID >= request.ID {
			return nil, fmt.Errorf("Connector identity cache %s pending_requests must be strictly sorted by id", path)
		}
		if binding, resolved := cache.byID[request.ID]; resolved {
			if request.ExpectedResourceID == nil || *request.ExpectedResourceID != binding.ResourceID {
				return nil, fmt.Errorf("Connector identity cache %s pending request %q does not assert its exact cached resource_id", path, request.ID)
			}
		}
		cache.pending[request.ID] = request
	}
	if cache.agentID == "" && (len(cache.byID) != 0 || len(cache.pending) != 0) {
		return nil, fmt.Errorf("Connector identity cache %s has continuity state without an agent_id binding", path)
	}
	return cache, nil
}

func requireConnectorIdentityCacheEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("contains multiple JSON values")
		}
		return err
	}
	return nil
}

const connectorIdentityCacheMaxJSONDepth = 8

// rejectConnectorIdentityCacheSurrogateEscapes closes encoding/json's other
// lossy input path: it silently replaces escaped UTF-16 surrogate code units
// with U+FFFD. The cache is exact continuity state, so accepting and later
// rewriting a different string would hide corruption. The encoder writes
// supplementary characters as UTF-8, making every surrogate escape
// non-canonical here (paired or otherwise).
func rejectConnectorIdentityCacheSurrogateEscapes(raw []byte) error {
	inString := false
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || i+1 >= len(raw) {
				continue
			}
			i++
			if raw[i] != 'u' || i+4 >= len(raw) {
				continue
			}
			var codeUnit uint16
			validHex := true
			for _, digit := range raw[i+1 : i+5] {
				codeUnit <<= 4
				switch {
				case digit >= '0' && digit <= '9':
					codeUnit |= uint16(digit - '0')
				case digit >= 'a' && digit <= 'f':
					codeUnit |= uint16(digit-'a') + 10
				case digit >= 'A' && digit <= 'F':
					codeUnit |= uint16(digit-'A') + 10
				default:
					validHex = false
				}
			}
			if validHex && codeUnit >= 0xD800 && codeUnit <= 0xDFFF {
				return errors.New("JSON string contains a non-canonical UTF-16 surrogate escape")
			}
			i += 4
		}
	}
	return nil
}

// rejectDuplicateConnectorIdentityCacheKeys walks the original JSON before
// encoding/json can collapse duplicate object members. The cache is continuity
// state: accepting two spellings of identities or pending_requests and silently
// choosing the last one would make crash recovery depend on parser behavior.
func rejectDuplicateConnectorIdentityCacheKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := walkConnectorIdentityCacheJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("contains multiple JSON values")
		}
		return err
	}
	return nil
}

func walkConnectorIdentityCacheJSONValue(decoder *json.Decoder, depth int) error {
	if depth > connectorIdentityCacheMaxJSONDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels", connectorIdentityCacheMaxJSONDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate field %q", key)
			}
			seen[key] = struct{}{}
			if err := walkConnectorIdentityCacheJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := walkConnectorIdentityCacheJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	return nil
}

// rejectNonCanonicalConnectorIdentityCacheKeys closes encoding/json's
// case-insensitive struct-field matching. DisallowUnknownFields alone accepts
// spellings such as "Version" and "Resource_ID"; continuity state instead has
// one exact wire spelling for every field.
func rejectNonCanonicalConnectorIdentityCacheKeys(raw []byte) error {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return err
	}
	for key := range envelope {
		switch key {
		case "version", "agent_id", "identities", "pending_requests":
		default:
			return fmt.Errorf("unknown field %q", key)
		}
	}

	identitiesRaw, ok := envelope["identities"]
	if !ok || bytes.Equal(bytes.TrimSpace(identitiesRaw), []byte("null")) {
		return nil // The typed decoder reports missing/null required fields.
	}
	var identities []json.RawMessage
	if err := json.Unmarshal(identitiesRaw, &identities); err != nil {
		return err
	}
	for i, rawEntry := range identities {
		var entry map[string]json.RawMessage
		if err := json.Unmarshal(rawEntry, &entry); err != nil {
			return fmt.Errorf("identities[%d]: %w", i, err)
		}
		for key := range entry {
			switch key {
			case "id", "resource_id", "crid", "connector_routing_id", "knock_resource_id":
			default:
				return fmt.Errorf("identities[%d]: unknown field %q", i, key)
			}
		}
		if value, present := entry["crid"]; present && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("identities[%d]: crid must be absent rather than null", i)
		}
	}
	pendingRaw, ok := envelope["pending_requests"]
	if !ok || bytes.Equal(bytes.TrimSpace(pendingRaw), []byte("null")) {
		return nil
	}
	var pending []json.RawMessage
	if err := json.Unmarshal(pendingRaw, &pending); err != nil {
		return err
	}
	for i, rawRequest := range pending {
		var request map[string]json.RawMessage
		if err := json.Unmarshal(rawRequest, &request); err != nil {
			return fmt.Errorf("pending_requests[%d]: %w", i, err)
		}
		for key := range request {
			switch key {
			case "id", "request_nonce", "expected_resource_id":
			default:
				return fmt.Errorf("pending_requests[%d]: unknown field %q", i, key)
			}
		}
		if value, present := request["expected_resource_id"]; present && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("pending_requests[%d]: expected_resource_id must be absent rather than null", i)
		}
	}
	return nil
}

func validateCachedIdentityString(field, value string) error {
	if value == "" || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return fmt.Errorf("%s must be non-empty exact UTF-8 without surrounding whitespace", field)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s must not contain control characters", field)
		}
	}
	return nil
}

func validateCachedAgentID(agentID string) error {
	if err := validateCachedIdentityString("agent_id", agentID); err != nil {
		return err
	}
	if len(agentID) > connectorIdentityAgentIDMaxLen {
		return fmt.Errorf("agent_id exceeds %d bytes", connectorIdentityAgentIDMaxLen)
	}
	return nil
}

func cachedAgentIDFingerprint(agentID string) string {
	digest := sha256.Sum256([]byte(agentID))
	return fmt.Sprintf("sha256:%x", digest[:8])
}

func validateCachedConnectorResourceID(resourceID string) error {
	if err := validateCachedIdentityString("resource_id", resourceID); err != nil {
		return err
	}
	der, err := base64.RawURLEncoding.Strict().DecodeString(resourceID)
	if err != nil || base64.RawURLEncoding.EncodeToString(der) != resourceID {
		return errors.New("resource_id must be canonical unpadded base64url")
	}
	publicKey, err := qurl.ParseP256PublicKeyDER(der)
	if err != nil {
		return fmt.Errorf("resource_id must encode a P-256 DER SPKI public key: %w", err)
	}
	canonical, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil || !bytes.Equal(canonical, der) {
		return errors.New("resource_id must use canonical P-256 DER SPKI encoding")
	}
	return nil
}

func validateCachedConnectorBinding(binding connectorIdentityCacheEntry) error {
	if err := nhpconfig.ValidateSlug(binding.ID); err != nil {
		return err
	}
	if err := validateCachedConnectorResourceID(binding.ResourceID); err != nil {
		return err
	}
	if err := nhpconfig.ValidateConnectorRoutingID(binding.ConnectorRoutingID); err != nil {
		return fmt.Errorf("connector_routing_id: %w", err)
	}
	if err := validateCachedKnockResourceID(binding.KnockResourceID); err != nil {
		return err
	}
	if binding.ResourceID == binding.KnockResourceID || binding.ConnectorRoutingID == binding.KnockResourceID {
		return errors.New("resource_id, connector_routing_id, and knock_resource_id must be distinct")
	}
	if binding.CRID != "" {
		der, err := base64.RawURLEncoding.Strict().DecodeString(binding.ResourceID)
		if err != nil {
			return errors.New("resource_id must be canonical before CRID validation")
		}
		matched, err := qurlcrid.KeyMatches(binding.CRID, der)
		if err != nil || !matched {
			return errors.New("crid must cryptographically match resource_id")
		}
	}
	return nil
}

func validateCachedKnockResourceID(value string) error {
	if err := validateCachedIdentityString("knock_resource_id", value); err != nil {
		return err
	}
	if len(value) > 64 {
		return errors.New("knock_resource_id exceeds 64 bytes")
	}
	return nil
}

func validateCachedConnectorRequest(request connectorIdentityPendingRequest) error {
	if err := nhpconfig.ValidateSlug(request.ID); err != nil {
		return err
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(request.RequestNonce)
	if err != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != request.RequestNonce {
		return errors.New("request_nonce must be canonical unpadded base64url of 32 bytes")
	}
	if request.ExpectedResourceID != nil {
		if *request.ExpectedResourceID == "" {
			return errors.New("expected_resource_id must be absent rather than empty")
		}
		if err := validateCachedConnectorResourceID(*request.ExpectedResourceID); err != nil {
			return fmt.Errorf("expected_resource_id: %w", err)
		}
	}
	return nil
}

func (c *connectorIdentityCache) resourceID(id string) (string, bool) {
	if c == nil {
		return "", false
	}
	binding, ok := c.byID[id]
	return binding.ResourceID, ok
}

func (c *connectorIdentityCache) binding(id string) (connectorIdentityCacheEntry, bool) {
	if c == nil {
		return connectorIdentityCacheEntry{}, false
	}
	binding, ok := c.byID[id]
	return binding, ok
}

func (c *connectorIdentityCache) isPending(id string) bool {
	if c == nil {
		return false
	}
	_, ok := c.pending[id]
	return ok
}

func (c *connectorIdentityCache) pendingRequest(id string) (connectorIdentityPendingRequest, bool) {
	if c == nil {
		return connectorIdentityPendingRequest{}, false
	}
	request, ok := c.pending[id]
	return request, ok
}

// hasContinuityState reports whether the cache carries any state that must be
// backed by an owning native agent envelope. A bound agent_id counts even
// before the first resource is provisioned, so a crash between bind and
// provisioning cannot let a missing envelope enroll a fresh device.
func (c *connectorIdentityCache) hasContinuityState() bool {
	return c.agentID != "" || len(c.byID) != 0 || len(c.pending) != 0
}

// rejectOrphanIdentities fails closed when the cache index or the pending
// journal holds an id that no configured route claims. An orphan means a route
// was removed from qurl-proxy.yaml without reconciling its remote resource, so
// startup must stop and point the operator at `qurl-connector remove`.
func (c *connectorIdentityCache) rejectOrphanIdentities(configuredIDs map[string]struct{}) error {
	for cachedID := range c.byID {
		if _, configured := configuredIDs[cachedID]; !configured {
			return fmt.Errorf("Connector identity cache contains orphan id %q not present in qurl-proxy.yaml; run `qurl-connector remove %s` to complete its safe remote deletion before starting", cachedID, cachedID)
		}
	}
	for pendingID := range c.pending {
		if _, configured := configuredIDs[pendingID]; !configured {
			return fmt.Errorf("Connector identity pending journal contains orphan id %q not present in qurl-proxy.yaml; run `qurl-connector remove %s` to reconcile it before starting", pendingID, pendingID)
		}
	}
	return nil
}

func (c *connectorIdentityCache) bindAgentIDLocked(txn *connectorIdentityCacheTxn, agentID string) error {
	if c == nil {
		return errors.New("Connector identity cache is nil")
	}
	if err := validateCachedAgentID(agentID); err != nil {
		return err
	}
	if c.agentID == agentID {
		return nil
	}
	if c.agentID != "" {
		return fmt.Errorf("Connector identity cache agent_id %s does not match current agent_id %s; refusing cross-device resource reuse", cachedAgentIDFingerprint(c.agentID), cachedAgentIDFingerprint(agentID))
	}
	if len(c.byID) != 0 || len(c.pending) != 0 {
		return errors.New("unbound Connector identity cache contains continuity state")
	}
	c.agentID = agentID
	if err := saveConnectorIdentityCacheUnlocked(txn, c); err != nil {
		c.agentID = ""
		return err
	}
	return nil
}

func (c *connectorIdentityCache) ensurePendingRequestLocked(txn *connectorIdentityCacheTxn, id, expectedResourceID string) (*qurl.NativeConnectorResourceRequest, error) {
	if c == nil {
		return nil, errors.New("Connector identity cache is nil")
	}
	if c.agentID == "" {
		return nil, errors.New("Connector identity cache must be bound to an agent_id before resource discovery")
	}
	if err := nhpconfig.ValidateSlug(id); err != nil {
		return nil, err
	}
	if c.pending == nil {
		c.pending = make(map[string]connectorIdentityPendingRequest)
	}
	if pending, present := c.pending[id]; present {
		gotExpected := ""
		if pending.ExpectedResourceID != nil {
			gotExpected = *pending.ExpectedResourceID
		}
		if gotExpected != expectedResourceID {
			return nil, fmt.Errorf("Connector id %q pending request expected resource_id %q, not %q", id, gotExpected, expectedResourceID)
		}
		return &qurl.NativeConnectorResourceRequest{
			ConnectorID: id, ExpectedResourceID: gotExpected, RequestNonce: pending.RequestNonce,
		}, nil
	}
	if binding, resolved := c.byID[id]; resolved && expectedResourceID != binding.ResourceID {
		return nil, fmt.Errorf("Connector id %q pending continuity request must assert cached resource_id %q, not %q", id, binding.ResourceID, expectedResourceID)
	}
	request, err := qurl.NewNativeConnectorResourceRequest(id, expectedResourceID)
	if err != nil {
		return nil, err
	}
	pending := connectorIdentityPendingRequest{ID: id, RequestNonce: request.RequestNonce}
	if expectedResourceID != "" {
		expected := expectedResourceID
		pending.ExpectedResourceID = &expected
	}
	c.pending[id] = pending
	if err := saveConnectorIdentityCacheUnlocked(txn, c); err != nil {
		delete(c.pending, id)
		return nil, err
	}
	return request, nil
}

func (c *connectorIdentityCache) clearPendingLocked(txn *connectorIdentityCacheTxn, id string) error {
	if !c.isPending(id) {
		return nil
	}
	request := c.pending[id]
	delete(c.pending, id)
	if err := saveConnectorIdentityCacheUnlocked(txn, c); err != nil {
		c.pending[id] = request
		return err
	}
	return nil
}

// recordResolutionLocked atomically persists the complete authenticated binding
// and clears the exact pending request while the caller holds the full process
// and cross-process identity-cache transaction lock.
func (c *connectorIdentityCache) recordResolutionLocked(txn *connectorIdentityCacheTxn, id string, resource *qurl.ConnectorResource) error {
	if c == nil {
		return errors.New("Connector identity cache is nil")
	}
	if resource == nil {
		return errors.New("Connector resource resolution is nil")
	}
	if c.agentID == "" {
		return errors.New("Connector identity cache must be bound to an agent_id before recording resources")
	}
	if resource.Slug != id {
		return fmt.Errorf("Connector id %q cannot record resource binding for %q", id, resource.Slug)
	}
	binding := connectorIdentityCacheEntry{
		ID: id, ResourceID: resource.ResourceID, CRID: resource.CRID,
		ConnectorRoutingID: resource.ConnectorRoutingID, KnockResourceID: resource.KnockResourceID,
	}
	if err := validateCachedConnectorBinding(binding); err != nil {
		return err
	}
	if existing, ok := c.byID[id]; ok {
		if existing.ResourceID != binding.ResourceID {
			return fmt.Errorf("Connector id %q is cached as resource_id %q, not %q", id, existing.ResourceID, binding.ResourceID)
		}
		if existing.ConnectorRoutingID != binding.ConnectorRoutingID || existing.KnockResourceID != binding.KnockResourceID {
			return fmt.Errorf("Connector id %q returned a changed routing or knock binding for resource_id %q", id, binding.ResourceID)
		}
		switch {
		case existing.CRID != "" && binding.CRID == "":
			// CRID is optional on the wire. Never erase a previously verified
			// key-matching value merely because a later response omitted it.
			binding.CRID = existing.CRID
		case existing.CRID != "" && binding.CRID != existing.CRID:
			return fmt.Errorf("Connector id %q returned a changed CRID for resource_id %q", id, binding.ResourceID)
		}
		// A warm-start continuity check that returns the exact binding is a
		// logical no-op. Avoid rewriting already-durable state: besides reducing
		// flash churn, this keeps a later config-prune failure attributable to
		// the prune itself instead of an unnecessary preflight cache sync.
		if existing == binding && !c.isPending(id) {
			return nil
		}
	}
	for existingID, existing := range c.byID {
		if existing.ResourceID == binding.ResourceID && existingID != id {
			return fmt.Errorf("resource_id %q is already cached for Connector id %q, not %q", binding.ResourceID, existingID, id)
		}
	}
	previous, hadBinding := c.byID[id]
	pending, wasPending := c.pending[id]
	c.byID[id] = binding
	delete(c.pending, id)
	if err := saveConnectorIdentityCacheUnlocked(txn, c); err != nil {
		if hadBinding {
			c.byID[id] = previous
		} else {
			delete(c.byID, id)
		}
		if wasPending {
			c.pending[id] = pending
		}
		return err
	}
	return nil
}

func (c *connectorIdentityCache) removeLocked(txn *connectorIdentityCacheTxn, id string) error {
	if c == nil {
		return errors.New("Connector identity cache is nil")
	}
	binding, resolved := c.byID[id]
	pendingRequest, pending := c.pending[id]
	if !resolved && !pending {
		return nil
	}
	delete(c.byID, id)
	delete(c.pending, id)
	if err := saveConnectorIdentityCacheUnlocked(txn, c); err != nil {
		if resolved {
			c.byID[id] = binding
		}
		if pending {
			c.pending[id] = pendingRequest
		}
		// A post-rename directory-sync failure means the pruned envelope may be
		// visible even though the caller must report failure. Re-publish the
		// exact pre-prune cache before returning so the explicit remove retry
		// retains a cache-only deletion fence. If recovery also fails, join both
		// errors; either visible envelope remains schema-valid and the next lock
		// acquisition re-establishes the durability barrier before acting.
		recoveryErr := saveConnectorIdentityCacheUnlocked(txn, c)
		if recoveryErr != nil {
			recoveryErr = fmt.Errorf("restore Connector identity after failed prune: %w", recoveryErr)
		}
		return errors.Join(err, recoveryErr)
	}
	return nil
}

func saveConnectorIdentityCacheUnlocked(txn *connectorIdentityCacheTxn, cache *connectorIdentityCache) error {
	if cache == nil {
		return errors.New("Connector identity cache is nil")
	}
	if cache.agentID != "" {
		if err := validateCachedAgentID(cache.agentID); err != nil {
			return err
		}
	} else if len(cache.byID) != 0 || len(cache.pending) != 0 {
		return errors.New("Connector identity cache continuity state requires an agent_id binding")
	}
	entries := make([]connectorIdentityCacheEntry, 0, len(cache.byID))
	for id, binding := range cache.byID {
		if binding.ID != id {
			return fmt.Errorf("Connector identity cache map key %q does not match binding id %q", id, binding.ID)
		}
		if err := validateCachedConnectorBinding(binding); err != nil {
			return err
		}
		entries = append(entries, binding)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	pending := make([]connectorIdentityPendingRequest, 0, len(cache.pending))
	for id, request := range cache.pending {
		if request.ID != id {
			return fmt.Errorf("Connector identity cache pending map key %q does not match request id %q", id, request.ID)
		}
		if err := validateCachedConnectorRequest(request); err != nil {
			return err
		}
		if binding, resolved := cache.byID[id]; resolved && (request.ExpectedResourceID == nil || *request.ExpectedResourceID != binding.ResourceID) {
			return fmt.Errorf("Connector id %q pending request must assert exact cached resource_id", id)
		}
		pending = append(pending, request)
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].ID < pending[j].ID })
	envelope := connectorIdentityCacheEnvelope{
		Version: connectorIdentityCacheVersion, AgentID: &cache.agentID,
		Identities: &entries, PendingRequests: &pending,
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("encode Connector identity cache: %w", err)
	}
	if len(raw) > connectorIdentityCacheMaxBytes {
		return fmt.Errorf("encoded Connector identity cache is %d bytes, exceeds %d-byte cap", len(raw), connectorIdentityCacheMaxBytes)
	}
	path := filepath.Join(txn.stateDir, connectorIdentityCacheFile)
	if err := writeConnectorIdentityCacheDurable(txn, connectorIdentityCacheFile, raw, connectorIdentityCacheMode); err != nil {
		return fmt.Errorf("write Connector identity cache %s: %w", path, err)
	}
	return nil
}
