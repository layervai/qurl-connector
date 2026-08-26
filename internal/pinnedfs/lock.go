package pinnedfs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
)

const maxLockOpenAttempts = 16

var closeFileLockCandidate = func(file *os.File) error { return file.Close() }
var chmodFileLockCandidate = func(file *os.File, mode os.FileMode) error { return file.Chmod(mode) }
var releaseFileLockCandidate = releaseAdvisoryLock
var beforeFileLockPostAcquireValidation = func(*Directory, string, *os.File) {}

// FileLock owns one advisory lock whose descriptor is continuously bound to a
// retained namespace entry.
type FileLock struct {
	namespace *Directory
	name      string
	label     string
	mode      os.FileMode
	file      *os.File
	once      sync.Once
	closeErr  error
}

// AcquireExclusiveFileLock opens or creates name and takes an exclusive,
// context-cancellable lock.
func AcquireExclusiveFileLock(ctx context.Context, namespace *Directory, name, label string, mode os.FileMode) (*FileLock, error) {
	return acquireFileLock(ctx, namespace, name, label, mode, true, false)
}

// AcquireExistingExclusiveFileLock opens an existing name without creating a
// replacement and takes an exclusive, context-cancellable lock. Callers use it
// after observing continuity state so a renamed lock cannot split the advisory
// lock namespace.
func AcquireExistingExclusiveFileLock(ctx context.Context, namespace *Directory, name, label string, mode os.FileMode) (*FileLock, error) {
	return acquireFileLock(ctx, namespace, name, label, mode, false, false)
}

// AcquireSharedFileLock opens an existing name without creating anything and
// takes a shared, context-cancellable lock.
func AcquireSharedFileLock(ctx context.Context, namespace *Directory, name, label string, mode os.FileMode) (*FileLock, error) {
	return acquireFileLock(ctx, namespace, name, label, mode, false, true)
}

func acquireFileLock(ctx context.Context, namespace *Directory, name, label string, mode os.FileMode, create, shared bool) (*FileLock, error) {
	if ctx == nil {
		return nil, errors.New("pinned file-lock context is nil")
	}
	if namespace == nil {
		return nil, errors.New("pinned file-lock namespace is nil")
	}
	for range maxLockOpenAttempts {
		flags := os.O_RDONLY | SafeOpenFlags()
		if !shared {
			flags = os.O_RDWR | SafeOpenFlags()
		}
		created := false
		file, err := namespace.OpenFile(name, flags, 0)
		if IsNotExist(err) && create {
			file, err = namespace.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL|SafeOpenFlags(), mode)
			if errors.Is(err, os.ErrExist) {
				continue
			}
			created = err == nil
		}
		if err != nil {
			return nil, err
		}
		if created {
			err := chmodFileLockCandidate(file, mode)
			if err != nil {
				permissionErr := fmt.Errorf("set %s permissions: %w", label, err)
				return nil, errors.Join(permissionErr, cleanupIncompleteFileLock(namespace, name, label, file))
			}
		}
		if _, err := ValidateRegularFile(namespace, name, file, label, mode); err != nil {
			return nil, errors.Join(err, closeFileLockCandidate(file))
		}
		if err := acquireAdvisoryLock(ctx, file, shared); err != nil {
			return nil, errors.Join(err, closeFileLockCandidate(file))
		}
		beforeFileLockPostAcquireValidation(namespace, name, file)
		if _, err := ValidateRegularFile(namespace, name, file, label, mode); err != nil {
			return nil, errors.Join(err, releaseFileLockCandidate(file))
		}
		return &FileLock{namespace: namespace, name: name, label: label, mode: mode, file: file}, nil
	}
	return nil, fmt.Errorf("%s changed during %d open attempts", label, maxLockOpenAttempts)
}

func cleanupIncompleteFileLock(namespace *Directory, name, label string, file *os.File) error {
	created, statErr := file.Stat()
	if statErr != nil {
		statErr = fmt.Errorf("capture incompletely initialized %s identity: %w", label, statErr)
	}
	closeErr := closeFileLockCandidate(file)
	if statErr != nil {
		return errors.Join(statErr, closeErr)
	}
	current, inspectErr := namespace.Lstat(name)
	if inspectErr != nil {
		return errors.Join(closeErr, fmt.Errorf("inspect incompletely initialized %s before cleanup: %w", label, inspectErr))
	}
	if !os.SameFile(created, current) {
		return errors.Join(closeErr, fmt.Errorf("%s entry changed before cleanup; preserving replacement", label))
	}
	if err := namespace.Remove(name); err != nil {
		return errors.Join(closeErr, fmt.Errorf("remove incompletely initialized %s: %w", label, err))
	}
	if err := namespace.Sync(); err != nil {
		return errors.Join(closeErr, fmt.Errorf("sync %s namespace after cleanup: %w", label, err))
	}
	return closeErr
}

// ValidateCurrent proves both namespace and descriptor-entry continuity.
func (l *FileLock) ValidateCurrent() error {
	if l == nil || l.file == nil || l.namespace == nil {
		return errors.New("pinned file lock is closed")
	}
	_, err := ValidateRegularFile(l.namespace, l.name, l.file, l.label, l.mode)
	return err
}

// Close validates immediately before releasing the advisory lock and joins all
// continuity, unlock, close, and post-close namespace errors.
func (l *FileLock) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		var beforeErr error
		if l.file != nil {
			beforeErr = l.ValidateCurrent()
		}
		releaseErr := releaseAdvisoryLock(l.file)
		var afterErr error
		if l.namespace != nil {
			afterErr = l.namespace.ValidateCurrent()
		}
		l.closeErr = errors.Join(beforeErr, releaseErr, afterErr)
		l.file = nil
	})
	return l.closeErr
}
