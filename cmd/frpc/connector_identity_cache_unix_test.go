//go:build darwin || linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/layervai/qurl-connector/internal/pinnedfs"
	"github.com/layervai/qurl-connector/pkg/agentstate"
	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

func TestConnectorIdentityCacheRejectsLegacyStateWithoutFollowingSymlinks(t *testing.T) {
	tests := map[string]func(*testing.T, string){
		"regular file": func(t *testing.T, path string) {
			t.Helper()
			if err := os.WriteFile(path, []byte(`{"legacy":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"dangling symlink": func(t *testing.T, path string) {
			t.Helper()
			if err := os.Symlink(filepath.Join(t.TempDir(), "missing-target"), path); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, create := range tests {
		t.Run(name, func(t *testing.T) {
			dir := newIdentityCacheTestDir(t)
			writeIdentityCacheLockForTest(t, dir)
			create(t, filepath.Join(dir, legacyConnectorIdentityFile))
			err := ensureConnectorIdentityCacheInitialized(dir)
			if err == nil || !containsAll(err.Error(), legacyConnectorIdentityFile, "empty this entire state directory", "enroll again") {
				t.Fatalf("ensure cache error = %v, want actionable legacy-state reset failure", err)
			}
			if _, statErr := os.Lstat(filepath.Join(dir, connectorIdentityCacheFile)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("canonical cache was created despite legacy state: %v", statErr)
			}
		})
	}
}

func TestConnectorIdentityCacheFIFOIsRejectedWithoutBlocking(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	writeIdentityCacheLockForTest(t, dir)
	if err := unix.Mkfifo(filepath.Join(dir, connectorIdentityCacheFile), 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := loadConnectorIdentityCache(dir)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("FIFO cache error = %v, want non-regular rejection", err)
		}
	case <-time.After(time.Second):
		t.Fatal("opening FIFO cache blocked instead of using O_NONBLOCK")
	}
}

func TestConnectorIdentityCacheDirectorySyncFailureLeavesCommittedMapping(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
		t.Fatal(err)
	}
	bindConnectorIdentityCacheForTest(t, dir)
	if err := withConnectorIdentityCacheLock(dir, func(txn *connectorIdentityCacheTxn) error {
		cache, err := loadConnectorIdentityCacheUnlocked(txn)
		if err != nil {
			return err
		}
		return markTestConnectorRequestLocked(cache, txn, "web")
	}); err != nil {
		t.Fatal(err)
	}
	originalSync := syncConnectorIdentityCacheDir
	t.Cleanup(func() { syncConnectorIdentityCacheDir = originalSync })
	syncConnectorIdentityCacheDir = func(*pinnedfs.Directory) error { return errors.New("injected directory sync failure") }
	err := withConnectorIdentityCacheLock(dir, func(txn *connectorIdentityCacheTxn) error {
		cache, err := loadConnectorIdentityCacheUnlocked(txn)
		if err != nil {
			return err
		}
		return recordTestConnectorBindingLocked(cache, txn, "web", testPublicResourceID)
	})
	syncConnectorIdentityCacheDir = originalSync
	if err == nil || !containsAll(err.Error(), "committed", "durability is unknown", "injected directory sync failure") {
		t.Fatalf("record error = %v, want post-rename durability-unknown error", err)
	}
	cache, err := loadConnectorIdentityCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := cache.resourceID("web"); !ok || got != testPublicResourceID || cache.isPending("web") {
		t.Fatalf("committed mapping = %q, present=%v pending=%v", got, ok, cache.isPending("web"))
	}
}

func TestConnectorIdentityCacheRetryBarrierPrecedesPruneAfterSyncFailure(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
		t.Fatal(err)
	}
	bindConnectorIdentityCacheForTest(t, dir)
	if err := withConnectorIdentityCacheLock(dir, func(txn *connectorIdentityCacheTxn) error {
		cache, err := loadConnectorIdentityCacheUnlocked(txn)
		if err != nil {
			return err
		}
		return markTestConnectorRequestLocked(cache, txn, "web")
	}); err != nil {
		t.Fatal(err)
	}

	// recordLocked commits pending -> resolved with rename before reporting a
	// failed directory sync. The retry must not trust or prune that visible
	// resolved state until it has successfully re-synced the pinned directory.
	originalWriteSync := syncConnectorIdentityCacheDir
	t.Cleanup(func() { syncConnectorIdentityCacheDir = originalWriteSync })
	wantErr := errors.New("injected post-rename sync failure")
	syncConnectorIdentityCacheDir = func(*pinnedfs.Directory) error { return wantErr }
	err := withConnectorIdentityCacheLock(dir, func(txn *connectorIdentityCacheTxn) error {
		cache, err := loadConnectorIdentityCacheUnlocked(txn)
		if err != nil {
			return err
		}
		return recordTestConnectorBindingLocked(cache, txn, "web", testPublicResourceID)
	})
	syncConnectorIdentityCacheDir = originalWriteSync
	if !errors.Is(err, wantErr) {
		t.Fatalf("record error = %v, want injected post-rename sync failure", err)
	}

	originalBarrier := syncConnectorIdentityCacheRetryBarrier
	t.Cleanup(func() { syncConnectorIdentityCacheRetryBarrier = originalBarrier })
	callbackRan := false
	syncConnectorIdentityCacheRetryBarrier = func(*pinnedfs.Directory) error {
		return errors.New("injected retry barrier failure")
	}
	err = withConnectorIdentityCacheLock(dir, func(*connectorIdentityCacheTxn) error {
		callbackRan = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "injected retry barrier failure") {
		t.Fatalf("failed barrier error = %v, want injected failure", err)
	}
	if callbackRan {
		t.Fatal("cache transaction callback ran after retry barrier failure")
	}

	barrierEstablished := false
	syncConnectorIdentityCacheRetryBarrier = func(namespace *pinnedfs.Directory) error {
		if err := originalBarrier(namespace); err != nil {
			return err
		}
		barrierEstablished = true
		return nil
	}
	if err := withConnectorIdentityCacheLock(dir, func(txn *connectorIdentityCacheTxn) error {
		if !barrierEstablished {
			t.Fatal("retry callback entered before cache directory was re-synced")
		}
		callbackRan = true
		cache, err := loadConnectorIdentityCacheUnlocked(txn)
		if err != nil {
			return err
		}
		if got, ok := cache.resourceID("web"); !ok || got != testPublicResourceID || cache.isPending("web") {
			t.Fatalf("visible retry state = %q present=%v pending=%v", got, ok, cache.isPending("web"))
		}
		return cache.removeLocked(txn, "web")
	}); err != nil {
		t.Fatal(err)
	}
	if !callbackRan {
		t.Fatal("retry callback did not run after cache durability barrier")
	}
}

func TestConnectorIdentityCacheTransactionRejectsStateDirectoryReplacement(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
		t.Fatal(err)
	}
	bindConnectorIdentityCacheForTest(t, dir)
	movedDir := dir + "-moved"
	err := withConnectorIdentityCacheLock(dir, func(txn *connectorIdentityCacheTxn) error {
		cache, err := loadConnectorIdentityCacheUnlocked(txn)
		if err != nil {
			return err
		}
		if err := os.Rename(dir, movedDir); err != nil {
			return err
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			return err
		}
		return markTestConnectorRequestLocked(cache, txn, "web")
	})
	if err == nil || !strings.Contains(err.Error(), "was replaced") {
		t.Fatalf("mark pending after state-directory replacement = %v, want continuity rejection", err)
	}
	raw, readErr := os.ReadFile(filepath.Join(movedDir, connectorIdentityCacheFile))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if strings.Contains(string(raw), `"pending_requests":[{"id":"web","request_nonce":`) {
		t.Fatalf("displaced cache was mutated after continuity loss: %s", raw)
	}
	if _, err := os.Lstat(filepath.Join(dir, connectorIdentityCacheFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement directory was mutated: %v", err)
	}
}

func TestConnectorIdentityCacheDurableWriteForcesModeDespiteUmask(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
		t.Fatal(err)
	}
	bindConnectorIdentityCacheForTest(t, dir)
	originalUmask := unix.Umask(0o777)
	t.Cleanup(func() { unix.Umask(originalUmask) })
	if err := withConnectorIdentityCacheLock(dir, func(txn *connectorIdentityCacheTxn) error {
		cache, err := loadConnectorIdentityCacheUnlocked(txn)
		if err != nil {
			return err
		}
		return markTestConnectorRequestLocked(cache, txn, "web")
	}); err != nil {
		t.Fatal(err)
	}
	unix.Umask(originalUmask)
	info, err := os.Stat(filepath.Join(dir, connectorIdentityCacheFile))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != connectorIdentityCacheMode {
		t.Fatalf("cache mode = %04o, want %04o", got, connectorIdentityCacheMode)
	}
}

func TestConnectorIdentityCacheColdStartForcesModesDespiteUmask(t *testing.T) {
	dir := filepath.Join(realPrivateConnectorTestDir(t), "new-state")
	originalUmask := unix.Umask(0o777)
	t.Cleanup(func() { unix.Umask(originalUmask) })
	if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
		t.Fatal(err)
	}
	unix.Umask(originalUmask)
	for path, want := range map[string]os.FileMode{
		dir: 0o700,
		filepath.Join(dir, connectorIdentityCacheLockFile): 0o600,
		filepath.Join(dir, connectorIdentityCacheFile):     0o600,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s mode = %04o, want %04o", filepath.Base(path), got, want)
		}
	}
}

func TestConnectorIdentityCacheTransactionIsContextBoundAndNonReentrant(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	err := withConnectorIdentityCacheLockContext(context.Background(), dir, func(txnCtx context.Context, _ *connectorIdentityCacheTxn) error {
		return withConnectorIdentityCacheLockContext(txnCtx, dir, func(context.Context, *connectorIdentityCacheTxn) error {
			return nil
		})
	})
	if err == nil || !strings.Contains(err.Error(), "non-reentrant") {
		t.Fatalf("recursive cache transaction = %v, want prompt non-reentrant failure", err)
	}
}

func TestConnectorIdentityCacheTransactionWaitHonorsContext(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- withConnectorIdentityCacheLockContext(context.Background(), dir, func(context.Context, *connectorIdentityCacheTxn) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Millisecond)
	defer cancel()
	err := withConnectorIdentityCacheLockContext(ctx, dir, func(context.Context, *connectorIdentityCacheTxn) error {
		t.Fatal("contended transaction callback ran")
		return nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended cache transaction = %v, want context deadline", err)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestConnectorIdentityCacheLockDeadlineDoesNotBoundCallback(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	originalTimeout := connectorIdentityLockWaitTimeout
	connectorIdentityLockWaitTimeout = time.Second
	t.Cleanup(func() { connectorIdentityLockWaitTimeout = originalTimeout })

	err := withConnectorIdentityCacheLockContext(context.Background(), dir, func(txnCtx context.Context, _ *connectorIdentityCacheTxn) error {
		if deadline, ok := txnCtx.Deadline(); ok {
			return fmt.Errorf("transaction callback inherited lock-acquisition deadline %s", deadline)
		}
		if err := txnCtx.Err(); err != nil {
			return fmt.Errorf("transaction callback inherited canceled lock-acquisition context: %w", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestConnectorIdentityCacheReadOnlySnapshotCreatesNoArtifacts(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	t.Setenv(agentstate.EnvStateDirPrimary, dir)
	cfg := &nhpconfig.Config{}
	if err := hydrateConnectorResourceIDsReadOnlyContext(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("read-only hydration created state artifacts: %v", entries)
	}
}

func TestConnectorIdentityCacheReadOnlySnapshotRejectsCacheWithoutLock(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	t.Setenv(agentstate.EnvStateDirPrimary, dir)
	if err := os.WriteFile(
		filepath.Join(dir, connectorIdentityCacheFile),
		[]byte(`{"version":2,"agent_id":"","identities":[],"pending_requests":[]}`),
		connectorIdentityCacheMode,
	); err != nil {
		t.Fatal(err)
	}
	err := hydrateConnectorResourceIDsReadOnlyContext(context.Background(), &nhpconfig.Config{})
	if err == nil || !containsAll(err.Error(), "continuity state is missing", connectorIdentityCacheLockFile) {
		t.Fatalf("read-only cache-without-lock error = %v, want missing lock", err)
	}
}

func TestConnectorIdentityCacheMutationRejectsCacheWithoutLock(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	if err := os.WriteFile(
		filepath.Join(dir, connectorIdentityCacheFile),
		[]byte(`{"version":2,"agent_id":"","identities":[],"pending_requests":[]}`),
		connectorIdentityCacheMode,
	); err != nil {
		t.Fatal(err)
	}
	callbackRan := false
	err := withConnectorIdentityCacheLock(dir, func(*connectorIdentityCacheTxn) error {
		callbackRan = true
		return nil
	})
	if err == nil || !containsAll(err.Error(), "continuity state is missing", connectorIdentityCacheLockFile, "mutating transaction") {
		t.Fatalf("mutating cache-without-lock error = %v, want missing lock", err)
	}
	if callbackRan {
		t.Fatal("mutating cache-without-lock callback ran")
	}
	if _, statErr := os.Lstat(filepath.Join(dir, connectorIdentityCacheLockFile)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("mutating cache-without-lock created replacement lock: %v", statErr)
	}
}

func TestConnectorIdentityCacheMutationDoesNotReplaceRenamedHeldLock(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
		t.Fatal(err)
	}
	namespace, err := pinnedfs.EnsurePrivate(dir, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	heldLock, err := pinnedfs.AcquireExclusiveFileLock(
		context.Background(),
		namespace,
		connectorIdentityCacheLockFile,
		"Connector identity cache lock",
		connectorIdentityCacheMode,
	)
	if err != nil {
		_ = namespace.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = heldLock.Close()
		_ = namespace.Close()
	})
	if err := os.Rename(filepath.Join(dir, connectorIdentityCacheLockFile), filepath.Join(dir, "held-lock-old")); err != nil {
		t.Fatal(err)
	}

	callbackRan := false
	err = withConnectorIdentityCacheLock(dir, func(*connectorIdentityCacheTxn) error {
		callbackRan = true
		return nil
	})
	if err == nil || !containsAll(err.Error(), "continuity state is missing", connectorIdentityCacheLockFile, "mutating transaction") {
		t.Fatalf("transaction with renamed held lock = %v, want missing lock", err)
	}
	if callbackRan {
		t.Fatal("transaction with renamed held lock callback ran")
	}
	if _, statErr := os.Lstat(filepath.Join(dir, connectorIdentityCacheLockFile)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("transaction with renamed held lock created replacement lock: %v", statErr)
	}
}

func TestConnectorIdentityCacheRejectsHardLinkedCacheAndReplacedLock(t *testing.T) {
	t.Run("hard-linked cache", func(t *testing.T) {
		dir := newIdentityCacheTestDir(t)
		if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(filepath.Join(dir, connectorIdentityCacheFile), filepath.Join(dir, "cache-alias")); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConnectorIdentityCache(dir); err == nil || !strings.Contains(err.Error(), "link count") {
			t.Fatalf("hard-linked cache load = %v, want link-count rejection", err)
		}
	})

	t.Run("replaced lock", func(t *testing.T) {
		dir := newIdentityCacheTestDir(t)
		err := withConnectorIdentityCacheLock(dir, func(*connectorIdentityCacheTxn) error {
			if err := os.Rename(filepath.Join(dir, connectorIdentityCacheLockFile), filepath.Join(dir, "lock-old")); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(dir, connectorIdentityCacheLockFile), nil, connectorIdentityCacheMode)
		})
		if err == nil || !strings.Contains(err.Error(), "matches") {
			t.Fatalf("transaction after lock replacement = %v, want descriptor-entry rejection", err)
		}
	})
}

func TestConnectorIdentityCacheRejectsAncestorReplacementBeforeMutation(t *testing.T) {
	root := realPrivateConnectorTestDir(t)
	ancestor := filepath.Join(root, "ancestor")
	dir := filepath.Join(ancestor, "state")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
		t.Fatal(err)
	}
	moved := ancestor + "-old"
	err := withConnectorIdentityCacheLock(dir, func(txn *connectorIdentityCacheTxn) error {
		cache, err := loadConnectorIdentityCacheUnlocked(txn)
		if err != nil {
			return err
		}
		if err := os.Rename(ancestor, moved); err != nil {
			return err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		return cache.bindAgentIDLocked(txn, testConnectorCacheAgentID)
	})
	if err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("mutation after ancestor replacement = %v, want continuity rejection", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, connectorIdentityCacheFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement ancestor received cache mutation: %v", err)
	}
}

func TestConnectorIdentityCacheDetectsReadAndTempEntrySubstitution(t *testing.T) {
	t.Run("after read", func(t *testing.T) {
		dir := newIdentityCacheTestDir(t)
		if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
			t.Fatal(err)
		}
		original := beforeConnectorIdentityCachePostReadValidation
		t.Cleanup(func() { beforeConnectorIdentityCachePostReadValidation = original })
		beforeConnectorIdentityCachePostReadValidation = func(*connectorIdentityCacheTxn) {
			beforeConnectorIdentityCachePostReadValidation = original
			path := filepath.Join(dir, connectorIdentityCacheFile)
			if err := os.Rename(path, path+".old"); err != nil {
				t.Error(err)
				return
			}
			if err := os.WriteFile(path, []byte(`{"version":2,"agent_id":"","identities":[],"pending_requests":[]}`), connectorIdentityCacheMode); err != nil {
				t.Error(err)
			}
		}
		if _, err := loadConnectorIdentityCache(dir); err == nil || !strings.Contains(err.Error(), "matches") {
			t.Fatalf("cache read after entry substitution = %v, want descriptor-entry rejection", err)
		}
	})

	t.Run("temporary entry", func(t *testing.T) {
		dir := newIdentityCacheTestDir(t)
		if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
			t.Fatal(err)
		}
		original := beforeConnectorIdentityCacheTempValidation
		t.Cleanup(func() { beforeConnectorIdentityCacheTempValidation = original })
		beforeConnectorIdentityCacheTempValidation = func(_ *connectorIdentityCacheTxn, name string) {
			beforeConnectorIdentityCacheTempValidation = original
			path := filepath.Join(dir, name)
			if err := os.Rename(path, path+".old"); err != nil {
				t.Error(err)
				return
			}
			if err := os.WriteFile(path, []byte("attacker replacement"), connectorIdentityCacheMode); err != nil {
				t.Error(err)
			}
		}
		err := withConnectorIdentityCacheLock(dir, func(txn *connectorIdentityCacheTxn) error {
			cache, err := loadConnectorIdentityCacheUnlocked(txn)
			if err != nil {
				return err
			}
			return cache.bindAgentIDLocked(txn, testConnectorCacheAgentID)
		})
		if err == nil || !strings.Contains(err.Error(), "matches") {
			t.Fatalf("cache write after temp substitution = %v, want descriptor-entry rejection", err)
		}
		cache, loadErr := loadConnectorIdentityCache(dir)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		if cache.agentID != "" {
			t.Fatalf("failed temp commit changed canonical cache binding to %q", cache.agentID)
		}
	})
}

func TestConnectorIdentityCacheTempFailureJoinsCloseRemoveAndCleanupSync(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
		t.Fatal(err)
	}
	closeErr := errors.New("injected cache temp close failure")
	removeErr := errors.New("injected cache temp remove failure")
	syncErr := errors.New("injected cache temp cleanup sync failure")
	originalValidation := beforeConnectorIdentityCacheTempValidation
	originalClose := closeConnectorIdentityCacheTemp
	originalRemove := removeConnectorIdentityCacheTemp
	originalSync := syncConnectorIdentityCacheDir
	t.Cleanup(func() {
		beforeConnectorIdentityCacheTempValidation = originalValidation
		closeConnectorIdentityCacheTemp = originalClose
		removeConnectorIdentityCacheTemp = originalRemove
		syncConnectorIdentityCacheDir = originalSync
	})
	beforeConnectorIdentityCacheTempValidation = func(_ *connectorIdentityCacheTxn, name string) {
		if err := os.Chmod(filepath.Join(dir, name), 0o644); err != nil {
			t.Error(err)
		}
	}
	closeConnectorIdentityCacheTemp = func(file *os.File) error {
		return errors.Join(file.Close(), closeErr)
	}
	removed := false
	removeConnectorIdentityCacheTemp = func(namespace *pinnedfs.Directory, name string) error {
		err := namespace.Remove(name)
		if err == nil {
			removed = true
		}
		return errors.Join(err, removeErr)
	}
	syncConnectorIdentityCacheDir = func(namespace *pinnedfs.Directory) error {
		if removed {
			return errors.Join(originalSync(namespace), syncErr)
		}
		return originalSync(namespace)
	}
	err := withConnectorIdentityCacheLock(dir, func(txn *connectorIdentityCacheTxn) error {
		cache, err := loadConnectorIdentityCacheUnlocked(txn)
		if err != nil {
			return err
		}
		return cache.bindAgentIDLocked(txn, testConnectorCacheAgentID)
	})
	if err == nil || !strings.Contains(err.Error(), "mode is 0644") || !errors.Is(err, closeErr) || !errors.Is(err, removeErr) || !errors.Is(err, syncErr) {
		t.Fatalf("cache temp cleanup error = %v, want validation + joined close/remove/sync failures", err)
	}
	// Exercise the successful-remove cleanup branch separately from the joined
	// remove-error path above.
	closeConnectorIdentityCacheTemp = originalClose
	removeConnectorIdentityCacheTemp = originalRemove
	syncConnectorIdentityCacheDir = func(namespace *pinnedfs.Directory) error {
		return errors.Join(originalSync(namespace), syncErr)
	}
	err = withConnectorIdentityCacheLock(dir, func(txn *connectorIdentityCacheTxn) error {
		cache, err := loadConnectorIdentityCacheUnlocked(txn)
		if err != nil {
			return err
		}
		return cache.bindAgentIDLocked(txn, testConnectorCacheAgentID)
	})
	if !errors.Is(err, syncErr) {
		t.Fatalf("cache temp cleanup sync error = %v, want joined cleanup sync failure", err)
	}
}

func containsAll(value string, wants ...string) bool {
	for _, want := range wants {
		if !strings.Contains(value, want) {
			return false
		}
	}
	return true
}
