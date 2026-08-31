//go:build darwin || linux

package pinnedfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateRegularFileRejectsHardLink(t *testing.T) {
	root := realTempDir(t)
	path := filepath.Join(root, "state")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	namespace, err := OpenPrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer namespace.Close()
	file, err := namespace.OpenFile("state.json", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := os.Link(filepath.Join(path, "state.json"), filepath.Join(root, "alias.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateRegularFile(namespace, "state.json", file, "state", 0o600); err == nil || !strings.Contains(err.Error(), "link count") {
		t.Fatalf("ValidateRegularFile error = %v, want hard-link rejection", err)
	}
}

func TestValidateOwnerRegularFileAllowsModeRepairButKeepsFileSafety(t *testing.T) {
	root := realTempDir(t)
	path := filepath.Join(root, "state")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	namespace, err := OpenPrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer namespace.Close()
	file, err := namespace.OpenFile("state.json", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := ValidateOwnerRegularFile(namespace, "state.json", file, "state"); err != nil {
		t.Fatalf("ValidateOwnerRegularFile rejected repairable mode: %v", err)
	}
	alias := filepath.Join(root, "alias.json")
	if err := os.Link(filepath.Join(path, "state.json"), alias); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateOwnerRegularFile(namespace, "state.json", file, "state"); err == nil || !strings.Contains(err.Error(), "link count") {
		t.Fatalf("ValidateOwnerRegularFile hard-link error = %v", err)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(path, "state.json"), filepath.Join(path, "actual.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("actual.json", filepath.Join(path, "state.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateOwnerRegularFile(namespace, "state.json", file, "state"); err == nil || !strings.Contains(err.Error(), "non-symlink regular file") {
		t.Fatalf("ValidateOwnerRegularFile symlink error = %v", err)
	}
}

func TestFileLockHonorsCancellationAndDetectsEntryReplacement(t *testing.T) {
	root := realTempDir(t)
	path := filepath.Join(root, "state")
	namespace, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer namespace.Close()
	first, err := AcquireExclusiveFileLock(context.Background(), namespace, ".lock", "test lock", 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Millisecond)
	defer cancel()
	if second, err := AcquireExclusiveFileLock(ctx, namespace, ".lock", "test lock", 0o600); second != nil || !errors.Is(err, context.DeadlineExceeded) {
		if second != nil {
			_ = second.Close()
		}
		t.Fatalf("contended lock = (%v, %v), want deadline", second, err)
	}

	if err := os.Rename(filepath.Join(path, ".lock"), filepath.Join(path, ".lock-old")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, ".lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := first.ValidateCurrent(); err == nil || !strings.Contains(err.Error(), "matches") {
		t.Fatalf("ValidateCurrent after lock replacement = %v, want descriptor-entry rejection", err)
	}
}

func TestAcquireExistingExclusiveFileLockNeverCreatesReplacement(t *testing.T) {
	root := realTempDir(t)
	path := filepath.Join(root, "state")
	namespace, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer namespace.Close()

	lock, err := AcquireExistingExclusiveFileLock(context.Background(), namespace, ".lock", "test lock", 0o600)
	if lock != nil || !errors.Is(err, os.ErrNotExist) {
		if lock != nil {
			_ = lock.Close()
		}
		t.Fatalf("existing-only lock = (%v, %v), want nil and not-exist", lock, err)
	}
	if _, statErr := os.Lstat(filepath.Join(path, ".lock")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("existing-only lock created a replacement entry: %v", statErr)
	}
}

func TestFileLockAcquireJoinsPreValidationCloseError(t *testing.T) {
	root := realTempDir(t)
	path := filepath.Join(root, "state")
	namespace, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer namespace.Close()
	if err := os.WriteFile(filepath.Join(path, ".lock"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	closeErr := errors.New("injected candidate close failure")
	originalClose := closeFileLockCandidate
	closeFileLockCandidate = func(file *os.File) error {
		return errors.Join(file.Close(), closeErr)
	}
	t.Cleanup(func() { closeFileLockCandidate = originalClose })

	lock, err := AcquireExclusiveFileLock(context.Background(), namespace, ".lock", "test lock", 0o600)
	if lock != nil || err == nil || !strings.Contains(err.Error(), "mode is 0644") || !errors.Is(err, closeErr) {
		t.Fatalf("AcquireExclusiveFileLock = (%v, %v), want validation and joined close errors", lock, err)
	}
}

func TestFileLockAcquireRemovesNewFileWhenChmodFails(t *testing.T) {
	root := realTempDir(t)
	path := filepath.Join(root, "state")
	namespace, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer namespace.Close()

	chmodErr := errors.New("injected chmod failure")
	originalChmod := chmodFileLockCandidate
	chmodFileLockCandidate = func(*os.File, os.FileMode) error {
		return chmodErr
	}
	t.Cleanup(func() { chmodFileLockCandidate = originalChmod })

	lock, err := AcquireExclusiveFileLock(context.Background(), namespace, ".lock", "test lock", 0o600)
	if lock != nil || !errors.Is(err, chmodErr) {
		if lock != nil {
			_ = lock.Close()
		}
		t.Fatalf("AcquireExclusiveFileLock = (%v, %v), want injected chmod failure", lock, err)
	}
	if _, statErr := namespace.Lstat(".lock"); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("incompletely initialized lock still exists: %v", statErr)
	}

	chmodFileLockCandidate = originalChmod
	lock, err = AcquireExclusiveFileLock(context.Background(), namespace, ".lock", "test lock", 0o600)
	if err != nil {
		t.Fatalf("AcquireExclusiveFileLock after cleanup: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("close lock after cleanup: %v", err)
	}
}

func TestFileLockAcquirePreservesReplacementWhenChmodFailureRaces(t *testing.T) {
	root := realTempDir(t)
	path := filepath.Join(root, "state")
	namespace, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer namespace.Close()

	chmodErr := errors.New("injected chmod failure")
	var hookErr error
	originalChmod := chmodFileLockCandidate
	chmodFileLockCandidate = func(*os.File, os.FileMode) error {
		if err := namespace.Rename(".lock", ".lock-created"); err != nil {
			hookErr = err
			return errors.Join(chmodErr, err)
		}
		if err := os.WriteFile(filepath.Join(path, ".lock"), []byte("replacement"), 0o600); err != nil {
			hookErr = err
			return errors.Join(chmodErr, err)
		}
		return chmodErr
	}
	t.Cleanup(func() { chmodFileLockCandidate = originalChmod })

	lock, err := AcquireExclusiveFileLock(context.Background(), namespace, ".lock", "test lock", 0o600)
	if hookErr != nil {
		t.Fatal(hookErr)
	}
	if lock != nil || !errors.Is(err, chmodErr) || !strings.Contains(err.Error(), "preserving replacement") {
		if lock != nil {
			_ = lock.Close()
		}
		t.Fatalf("AcquireExclusiveFileLock = (%v, %v), want chmod and continuity failures", lock, err)
	}
	replacement, readErr := os.ReadFile(filepath.Join(path, ".lock"))
	if readErr != nil {
		t.Fatalf("read replacement lock: %v", readErr)
	}
	if string(replacement) != "replacement" {
		t.Fatalf("replacement lock = %q, want preserved content", replacement)
	}
}

func TestFileLockAcquireJoinsPostValidationReleaseError(t *testing.T) {
	root := realTempDir(t)
	path := filepath.Join(root, "state")
	namespace, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer namespace.Close()
	if err := os.WriteFile(filepath.Join(path, ".lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	releaseErr := errors.New("injected candidate release failure")
	originalHook := beforeFileLockPostAcquireValidation
	originalRelease := releaseFileLockCandidate
	beforeFileLockPostAcquireValidation = func(_ *Directory, _ string, file *os.File) {
		if err := file.Chmod(0o644); err != nil {
			t.Error(err)
		}
	}
	releaseFileLockCandidate = func(file *os.File) error {
		return errors.Join(releaseAdvisoryLock(file), releaseErr)
	}
	t.Cleanup(func() {
		beforeFileLockPostAcquireValidation = originalHook
		releaseFileLockCandidate = originalRelease
	})

	lock, err := AcquireExclusiveFileLock(context.Background(), namespace, ".lock", "test lock", 0o600)
	if lock != nil || err == nil || !strings.Contains(err.Error(), "mode is 0644") || !errors.Is(err, releaseErr) {
		t.Fatalf("AcquireExclusiveFileLock = (%v, %v), want validation and joined release errors", lock, err)
	}
}
