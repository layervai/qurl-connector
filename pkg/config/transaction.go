package config

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/layervai/qurl-connector/internal/pinnedfs"
)

const (
	maxTransactionOpenAttempts   = 16
	configTransactionLockTimeout = 30 * time.Second
)

var configTransactionToken = func() chan struct{} {
	token := make(chan struct{}, 1)
	token <- struct{}{}
	return token
}()

var beforeConfigTempCommitValidation = func(*FileTransaction, string) {}
var beforeTransactionFileFinalValidation = func(string) {}
var afterConfigTransactionRead = func(*FileTransaction) {}
var closeConfigTransactionFile = func(file *os.File) error { return file.Close() }
var releaseConfigTransactionCandidate = releaseTransactionLock
var removeConfigTransactionTemp = func(namespace *pinnedfs.Directory, name string) error {
	return namespace.Remove(name)
}
var syncConfigTransactionNamespace = func(namespace *pinnedfs.Directory) error {
	return namespace.Sync()
}

// ErrConfigContinuityLockMissing reports an existing config whose canonical
// transaction lock is absent. Mutating callers must fail closed. Read-only
// callers may separately prove and retain an immutable snapshot without
// recreating the missing lock.
var ErrConfigContinuityLockMissing = errors.New("config continuity lock is missing")

// FileTransaction pins the canonical config parent and owns its advisory lock.
// Every read and write is relative to that retained directory handle.
type FileTransaction struct {
	namespace *pinnedfs.Directory
	path      string
	base      string
	lockName  string
	lockFile  *os.File
	once      sync.Once
	closeErr  error
	ownsToken bool
}

// AcquireFileTransaction locks path's canonical namespace. Close must be called
// for every successful acquisition. The default wait is bounded; callers with
// a command context should use AcquireFileTransactionContext.
func AcquireFileTransaction(path string) (*FileTransaction, error) {
	ctx, cancel := context.WithTimeout(context.Background(), configTransactionLockTimeout)
	defer cancel()
	return AcquireFileTransactionContext(ctx, path)
}

// AcquireFileTransactionContext is AcquireFileTransaction with a caller-owned
// cancellation boundary. Transactions are deliberately non-reentrant: code
// holding one must call tx.Load/tx.Save, never Acquire or top-level Save.
func AcquireFileTransactionContext(ctx context.Context, path string) (*FileTransaction, error) {
	if ctx == nil {
		return nil, errors.New("config transaction context is nil")
	}
	canonicalPath, err := CanonicalPath(path)
	if err != nil {
		return nil, fmt.Errorf("canonicalize config transaction path: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-configTransactionToken:
	}
	unlockOnError := true
	defer func() {
		if unlockOnError {
			configTransactionToken <- struct{}{}
		}
	}()

	// Existing customer config parents are opened without sync or mutation.
	// This is required for canonical Docker bind mounts: a non-root Connector
	// must be able to reach the explicit root-owned read-only sentinel without
	// first attempting a directory fsync. Only a genuinely absent parent takes
	// the create-and-sync path used by `add`.
	namespace, err := pinnedfs.OpenTrusted(filepath.Dir(canonicalPath))
	if pinnedfs.IsNotExist(err) {
		namespace, err = pinnedfs.Ensure(filepath.Dir(canonicalPath), 0o755)
	}
	if err != nil {
		return nil, fmt.Errorf("open config transaction namespace: %w", err)
	}
	if err := namespace.RequireOwnedNamespace(); err != nil {
		return nil, errors.Join(
			fmt.Errorf("validate config transaction namespace: %w", err),
			namespace.Close(),
		)
	}
	base := filepath.Base(canonicalPath)
	lockName := base + ".lock"
	configExists, err := transactionEntryExists(namespace, base)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("inspect config transaction entry: %w", err),
			namespace.Close(),
		)
	}
	lockExists, err := transactionEntryExists(namespace, lockName)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("inspect config transaction lock: %w", err),
			namespace.Close(),
		)
	}
	if configExists && !lockExists {
		return nil, errors.Join(
			fmt.Errorf("%w: config continuity state is missing its lock %s; refusing to create a replacement", ErrConfigContinuityLockMissing, lockName),
			namespace.Close(),
		)
	}
	lockFile, err := openTransactionLock(ctx, namespace, lockName, !lockExists)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("acquire config transaction lock: %w", err),
			namespace.Close(),
		)
	}

	tx := &FileTransaction{
		namespace: namespace,
		path:      canonicalPath,
		base:      base,
		lockName:  lockName,
		lockFile:  lockFile,
		ownsToken: true,
	}
	if err := tx.validateNamespace(); err != nil {
		return nil, errors.Join(
			fmt.Errorf("validate config transaction namespace: %w", err),
			releaseConfigTransactionCandidate(lockFile),
			namespace.Close(),
		)
	}
	unlockOnError = false
	return tx, nil
}

func transactionEntryExists(namespace *pinnedfs.Directory, name string) (bool, error) {
	_, err := namespace.Lstat(name)
	switch {
	case err == nil:
		return true, nil
	case pinnedfs.IsNotExist(err):
		return false, nil
	default:
		return false, err
	}
}

func openTransactionLock(ctx context.Context, namespace *pinnedfs.Directory, name string, allowCreate bool) (*os.File, error) {
	for range maxTransactionOpenAttempts {
		created := false
		file, err := namespace.OpenFile(name, os.O_RDWR|pinnedfs.SafeOpenFlags(), 0)
		if pinnedfs.IsNotExist(err) && allowCreate {
			file, err = namespace.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
			if errors.Is(err, os.ErrExist) {
				continue
			}
			created = err == nil
		}
		if err != nil {
			return nil, err
		}
		if created {
			err = file.Chmod(0o600)
		}
		if err != nil {
			return nil, errors.Join(
				fmt.Errorf("set config transaction lock permissions: %w", err),
				closeConfigTransactionFile(file),
			)
		}
		if err := validateTransactionFile(namespace, name, file, "config transaction lock", 0o600); err != nil {
			return nil, errors.Join(err, closeConfigTransactionFile(file))
		}
		if err := acquireTransactionLock(ctx, file); err != nil {
			return nil, errors.Join(err, closeConfigTransactionFile(file))
		}
		if err := validateTransactionFile(namespace, name, file, "config transaction lock", 0o600); err != nil {
			return nil, errors.Join(err, releaseConfigTransactionCandidate(file))
		}
		return file, nil
	}
	return nil, fmt.Errorf("config transaction lock changed during %d open attempts", maxTransactionOpenAttempts)
}

func validateTransactionFile(namespace *pinnedfs.Directory, name string, file *os.File, label string, mode os.FileMode) error {
	beforeTransactionFileFinalValidation(label)
	_, err := pinnedfs.ValidateRegularFile(namespace, name, file, label, mode)
	return wrapConfigFileValidationError(label, err)
}

func (tx *FileTransaction) validateNamespace() error {
	if tx == nil || tx.namespace == nil || tx.lockFile == nil {
		return errors.New("config transaction is closed")
	}
	if err := tx.namespace.ValidateCurrent(); err != nil {
		return err
	}
	return validateTransactionFile(tx.namespace, tx.lockName, tx.lockFile, "config transaction lock", 0o600)
}

// Path is the canonical config path owned by this transaction.
func (tx *FileTransaction) Path() string {
	if tx == nil {
		return ""
	}
	return tx.path
}

// Exists reports whether the transaction's config file currently exists.
func (tx *FileTransaction) Exists() (bool, error) {
	if err := tx.validateNamespace(); err != nil {
		return false, err
	}
	info, err := tx.namespace.Lstat(tx.base)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return false, errors.New("config entry must be a non-symlink regular file")
		}
		return true, nil
	case pinnedfs.IsNotExist(err):
		return false, nil
	default:
		return false, err
	}
}

// Load reads and decodes the config from the pinned namespace.
func (tx *FileTransaction) Load() (cfg *Config, retErr error) {
	if err := tx.validateNamespace(); err != nil {
		return nil, err
	}
	file, err := tx.namespace.OpenFile(tx.base, os.O_RDONLY|pinnedfs.SafeOpenFlags(), 0)
	if err != nil {
		return nil, fmt.Errorf("open config file %s: %w", tx.path, err)
	}
	defer func() {
		if err := closeConfigTransactionFile(file); err != nil {
			cfg = nil
			retErr = errors.Join(retErr, fmt.Errorf("close config file %s after read: %w", tx.path, err))
		}
	}()
	if err := validateTransactionFile(tx.namespace, tx.base, file, "config file", 0o600); err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(file)
	afterConfigTransactionRead(tx)
	postReadErr := validateTransactionFile(tx.namespace, tx.base, file, "config file after read", 0o600)
	namespaceErr := tx.validateNamespace()
	if readErr != nil || postReadErr != nil || namespaceErr != nil {
		return nil, errors.Join(
			wrapConfigReadError(tx.path, readErr),
			postReadErr,
			namespaceErr,
		)
	}
	return decodeConfig(data, tx.path)
}

func wrapConfigReadError(path string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("read config file %s: %w", path, err)
}

// Save atomically writes cfg through the pinned namespace. Namespace and lock
// identity are revalidated before the first mutation and again before commit.
func (tx *FileTransaction) Save(cfg *Config) error {
	data, err := marshalConfig(cfg)
	if err != nil {
		return err
	}
	return tx.saveMarshaled(data)
}

// ReplaceYAML validates and atomically stores one raw YAML document while
// preserving its comments and sparse shape. source is used only in validation
// diagnostics. Callers must already own this transaction.
func (tx *FileTransaction) ReplaceYAML(data []byte, source string) error {
	if _, err := decodeConfig(data, source); err != nil {
		return err
	}
	return tx.saveMarshaled(data)
}

func (tx *FileTransaction) saveMarshaled(data []byte) (retErr error) {
	if err := tx.validateNamespace(); err != nil {
		return fmt.Errorf("validate config transaction before save: %w", err)
	}
	if err := tx.validateExistingConfig(); err != nil {
		return err
	}

	tempName, file, err := tx.createTemp()
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	tempPresent := true
	defer func() {
		closeErr := closeConfigTransactionFile(file)
		if tempPresent {
			removeErr := removeConfigTransactionTemp(tx.namespace, tempName)
			syncErr := syncConfigTransactionNamespace(tx.namespace)
			retErr = errors.Join(
				retErr,
				wrapConfigCleanupError("close uncommitted temporary config", closeErr),
				wrapConfigCleanupError("remove uncommitted temporary config", removeErr),
				wrapConfigCleanupError("sync config namespace after temporary cleanup", syncErr),
			)
			return
		}
		retErr = errors.Join(retErr, wrapConfigCleanupError("close committed config", closeErr))
	}()

	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write temporary config: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync temporary config: %w", err)
	}
	beforeConfigTempCommitValidation(tx, tempName)
	if err := validateTransactionFile(tx.namespace, tempName, file, "temporary config file before commit", 0o600); err != nil {
		return err
	}
	if err := tx.validateNamespace(); err != nil {
		return fmt.Errorf("validate config transaction before commit: %w", err)
	}
	if err := tx.validateExistingConfig(); err != nil {
		return err
	}
	if err := tx.namespace.Rename(tempName, tx.base); err != nil {
		return fmt.Errorf("replace config file: %w", err)
	}
	tempPresent = false
	if err := syncConfigTransactionNamespace(tx.namespace); err != nil {
		return fmt.Errorf("sync config directory after replace: %w", err)
	}
	if err := tx.validateNamespace(); err != nil {
		return fmt.Errorf("validate config transaction after commit: %w", err)
	}
	if err := validateTransactionFile(tx.namespace, tx.base, file, "committed config file", 0o600); err != nil {
		return err
	}
	return nil
}

func wrapConfigCleanupError(action string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", action, err)
}

func (tx *FileTransaction) validateExistingConfig() error {
	entry, err := tx.namespace.Lstat(tx.base)
	if pinnedfs.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect existing config: %w", err)
	}
	if entry.Mode()&os.ModeSymlink != 0 || !entry.Mode().IsRegular() {
		return errors.New("existing config must be a non-symlink regular file")
	}
	file, err := tx.namespace.OpenFile(tx.base, os.O_RDONLY|pinnedfs.SafeOpenFlags(), 0)
	if err != nil {
		return fmt.Errorf("open existing config: %w", err)
	}
	defer file.Close()
	if err := validateTransactionFile(tx.namespace, tx.base, file, "existing config file", entry.Mode().Perm()); err != nil {
		return err
	}
	return nil
}

func (tx *FileTransaction) createTemp() (string, *os.File, error) {
	for range maxTransactionOpenAttempts {
		var suffix [12]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return "", nil, err
		}
		name := "." + tx.base + ".tmp-" + hex.EncodeToString(suffix[:])
		file, err := tx.namespace.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		if err := file.Chmod(0o600); err != nil {
			cleanupErr := cleanupCreatedConfigTemp(tx.namespace, name, file)
			return "", nil, errors.Join(err, cleanupErr)
		}
		if err := validateTransactionFile(tx.namespace, name, file, "temporary config file", 0o600); err != nil {
			cleanupErr := cleanupCreatedConfigTemp(tx.namespace, name, file)
			return "", nil, errors.Join(err, cleanupErr)
		}
		return name, file, nil
	}
	return "", nil, fmt.Errorf("temporary config name collided %d times", maxTransactionOpenAttempts)
}

func cleanupCreatedConfigTemp(namespace *pinnedfs.Directory, name string, file *os.File) error {
	return errors.Join(
		wrapConfigCleanupError("close rejected temporary config", closeConfigTransactionFile(file)),
		wrapConfigCleanupError("remove rejected temporary config", removeConfigTransactionTemp(namespace, name)),
		wrapConfigCleanupError("sync config namespace after rejected temporary cleanup", syncConfigTransactionNamespace(namespace)),
	)
}

// Close releases the advisory lock after proving it still names the same
// pinned namespace entry. Any continuity failure is returned to the caller.
func (tx *FileTransaction) Close() error {
	if tx == nil {
		return nil
	}
	tx.once.Do(func() {
		var continuityErr error
		if tx.namespace != nil && tx.lockFile != nil {
			continuityErr = tx.validateNamespace()
		}
		tx.closeErr = errors.Join(continuityErr, releaseTransactionLock(tx.lockFile))
		if tx.namespace != nil {
			tx.closeErr = errors.Join(tx.closeErr, tx.namespace.Close())
		}
		tx.lockFile = nil
		tx.namespace = nil
		if tx.ownsToken {
			tx.ownsToken = false
			configTransactionToken <- struct{}{}
		}
	})
	return tx.closeErr
}

// WithFileTransaction runs fn while path's canonical transaction lock is held.
// The callback must use tx.Load/tx.Save; recursively calling top-level Save or
// another Acquire is unsupported and waits only until its context expires.
func WithFileTransaction(path string, fn func(*FileTransaction) error) (retErr error) {
	ctx, cancel := context.WithTimeout(context.Background(), configTransactionLockTimeout)
	defer cancel()
	return WithFileTransactionContext(ctx, path, fn)
}

// WithFileTransactionContext is WithFileTransaction with caller cancellation.
func WithFileTransactionContext(ctx context.Context, path string, fn func(*FileTransaction) error) (retErr error) {
	if fn == nil {
		return errors.New("config transaction callback is nil")
	}
	tx, err := AcquireFileTransactionContext(ctx, path)
	if err != nil {
		return err
	}
	defer func() {
		retErr = errors.Join(retErr, tx.Close())
	}()
	return fn(tx)
}

// CanonicalPath resolves an existing config symlink to its target. For a new
// config, it resolves the longest existing ancestor and preserves the missing
// suffix so aliases cannot acquire different lock namespaces.
func CanonicalPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("config path is empty")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	candidate := filepath.Clean(abs)
	missing := make([]string, 0, 4)
	for {
		resolved, evalErr := filepath.EvalSymlinks(candidate)
		if evalErr == nil {
			parts := append([]string{resolved}, missing...)
			return filepath.Join(parts...), nil
		}
		if !errors.Is(evalErr, os.ErrNotExist) {
			return "", evalErr
		}
		info, lstatErr := os.Lstat(candidate) //nolint:gosec // detect a dangling final symlink while walking to an existing ancestor.
		if lstatErr == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("config symlink target does not exist: %w", evalErr)
			}
			return "", fmt.Errorf("resolve existing config path %s: %w", candidate, evalErr)
		}
		if !errors.Is(lstatErr, os.ErrNotExist) {
			return "", lstatErr
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return "", fmt.Errorf("resolve config path %s: no existing ancestor", abs)
		}
		missing = append([]string{filepath.Base(candidate)}, missing...)
		candidate = parent
	}
}
