//go:build darwin || linux

package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/layervai/qurl-connector/internal/pinnedfs"
)

var afterImmutableConfigSnapshotRead = func(*ImmutableConfigSnapshot) {}
var closeImmutableConfigSnapshotFile = func(file *os.File) error { return file.Close() }

// ImmutableConfigSnapshot retains the config file and every directory handle
// from the filesystem root to its parent. It is the read-only counterpart to a
// FileTransaction for customer-managed bind mounts that cannot host a sibling
// lock file.
//
// The snapshot never creates, chmods, syncs, renames, or removes filesystem
// objects. Callers must retain it until they have acquired the next lock in
// their lock order, then close it and join the result.
type ImmutableConfigSnapshot struct {
	namespace *pinnedfs.Directory
	file      *os.File
	path      string
	base      string
	absent    string
	once      sync.Once
	closeErr  error
}

// OpenImmutableConfigSnapshot securely reads one immutable customer config.
// Every ancestor must be root/euid-owned and protected from replacement by
// unrelated users; the final parent and file must additionally be
// non-group/other-writable. The final file must be a single-link regular file.
func OpenImmutableConfigSnapshot(path string) (_ *Config, snapshot *ImmutableConfigSnapshot, retErr error) {
	canonicalPath, err := CanonicalPath(path)
	if err != nil {
		return nil, nil, fmt.Errorf("canonicalize immutable config snapshot path: %w", err)
	}
	namespace, err := pinnedfs.OpenTrusted(filepath.Dir(canonicalPath))
	if err != nil {
		return nil, nil, fmt.Errorf("open immutable config namespace: %w", err)
	}
	snapshot = &ImmutableConfigSnapshot{
		namespace: namespace,
		path:      canonicalPath,
		base:      filepath.Base(canonicalPath),
	}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, snapshot.Close())
			snapshot = nil
		}
	}()

	snapshot.file, err = namespace.OpenFile(snapshot.base, os.O_RDONLY|pinnedfs.SafeOpenFlags(), 0)
	if err != nil {
		return nil, snapshot, fmt.Errorf("open immutable config file %s: %w", canonicalPath, err)
	}
	if err := snapshot.ValidateCurrent(); err != nil {
		return nil, snapshot, err
	}
	data, readErr := io.ReadAll(snapshot.file)
	afterImmutableConfigSnapshotRead(snapshot)
	postReadErr := snapshot.ValidateCurrent()
	if readErr != nil || postReadErr != nil {
		return nil, snapshot, errors.Join(
			wrapConfigReadError(canonicalPath, readErr),
			postReadErr,
		)
	}
	cfg, err := decodeConfig(data, canonicalPath)
	if err != nil {
		return nil, snapshot, err
	}
	return cfg, snapshot, nil
}

// Path is the canonical path pinned by the snapshot.
func (s *ImmutableConfigSnapshot) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// ValidateCurrent proves ancestor, parent, descriptor, and namespace-entry
// continuity for the already-read config.
func (s *ImmutableConfigSnapshot) ValidateCurrent() error {
	if s == nil || s.namespace == nil || s.file == nil {
		return errors.New("immutable config snapshot is closed")
	}
	_, err := pinnedfs.ValidateTrustedReadOnlyFile(
		s.namespace,
		s.base,
		s.file,
		"immutable config file",
	)
	if err != nil || s.absent == "" {
		return err
	}
	_, siblingErr := s.namespace.Lstat(s.absent)
	switch {
	case siblingErr == nil:
		return fmt.Errorf("immutable config sibling %q exists", s.absent)
	case pinnedfs.IsNotExist(siblingErr):
		_, err = pinnedfs.ValidateTrustedReadOnlyFile(
			s.namespace,
			s.base,
			s.file,
			"immutable config file after sibling check",
		)
		return err
	default:
		return fmt.Errorf("inspect immutable config sibling %q: %w", s.absent, siblingErr)
	}
}

// RequireSiblingAbsent proves name is absent in the same pinned namespace and
// retains that requirement for every later ValidateCurrent and Close. It
// revalidates the config on both sides so callers cannot accept a sibling
// transaction lock after either the config or its namespace changed.
func (s *ImmutableConfigSnapshot) RequireSiblingAbsent(name string) error {
	if s == nil || s.namespace == nil {
		return errors.New("immutable config snapshot is closed")
	}
	if filepath.Base(name) != name || name == "." || name == "" {
		return fmt.Errorf("immutable config sibling name %q is invalid", name)
	}
	if err := s.ValidateCurrent(); err != nil {
		return err
	}
	_, err := s.namespace.Lstat(name)
	switch {
	case err == nil:
		return fmt.Errorf("immutable config sibling %q exists", name)
	case pinnedfs.IsNotExist(err):
		s.absent = name
		return s.ValidateCurrent()
	default:
		return fmt.Errorf("inspect immutable config sibling %q: %w", name, err)
	}
}

// Close revalidates continuity, closes the config descriptor, and releases all
// retained directory handles. Every failure is joined.
func (s *ImmutableConfigSnapshot) Close() error {
	if s == nil {
		return nil
	}
	s.once.Do(func() {
		var continuityErr error
		if s.namespace != nil && s.file != nil {
			continuityErr = s.ValidateCurrent()
		}
		var fileErr error
		if s.file != nil {
			fileErr = closeImmutableConfigSnapshotFile(s.file)
		}
		var namespaceErr error
		if s.namespace != nil {
			namespaceErr = s.namespace.Close()
		}
		s.closeErr = errors.Join(continuityErr, fileErr, namespaceErr)
		s.file = nil
		s.namespace = nil
	})
	return s.closeErr
}
