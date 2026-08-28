//go:build darwin || linux

package pinnedfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func realTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestEnsurePrivateSyncsEveryNestedPathEdge(t *testing.T) {
	root := realTempDir(t)
	path := filepath.Join(root, "one", "two", "state")
	originalSync := syncPinnedParent
	t.Cleanup(func() { syncPinnedParent = originalSync })

	var synced []string
	syncPinnedParent = func(_ *os.Root, edgePath string) error {
		synced = append(synced, edgePath)
		return nil
	}

	dir, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	for _, want := range []string{
		filepath.Join(root, "one"),
		filepath.Join(root, "one", "two"),
		path,
	} {
		if countPath(synced, want) != 1 {
			t.Fatalf("sync count for %s = %d, want 1; all=%v", want, countPath(synced, want), synced)
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("state directory mode = %04o, want 0700", got)
	}
}

func TestEnsurePrivateRetryResyncsExistingEdgesAfterFailure(t *testing.T) {
	root := realTempDir(t)
	path := filepath.Join(root, "nested", "state")
	wantErr := errors.New("injected parent sync failure")
	originalSync := syncPinnedParent
	t.Cleanup(func() { syncPinnedParent = originalSync })

	counts := make(map[string]int)
	fail := true
	syncPinnedParent = func(_ *os.Root, edgePath string) error {
		counts[edgePath]++
		if edgePath == path && fail {
			fail = false
			return wantErr
		}
		return nil
	}
	if dir, err := EnsurePrivate(path, 0o700); dir != nil || !errors.Is(err, wantErr) {
		if dir != nil {
			_ = dir.Close()
		}
		t.Fatalf("first EnsurePrivate = (%v, %v), want nil and %v", dir, err, wantErr)
	}
	if info, err := os.Lstat(path); err != nil || !info.IsDir() {
		t.Fatalf("failed first attempt did not leave a retryable visible directory: info=%v err=%v", info, err)
	}

	dir, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatalf("retry EnsurePrivate: %v", err)
	}
	defer dir.Close()
	for _, edge := range []string{filepath.Join(root, "nested"), path} {
		if counts[edge] != 2 {
			t.Fatalf("sync count for retry edge %s = %d, want 2; all=%v", edge, counts[edge], counts)
		}
	}
}

func TestEnsurePrivateJoinsPermissionCleanupFailures(t *testing.T) {
	root := realTempDir(t)
	path := filepath.Join(root, "state")
	chmodErr := errors.New("injected chmod failure")
	removeErr := errors.New("injected remove failure")
	syncErr := errors.New("injected cleanup sync failure")
	originalChmod := chmodPinnedChild
	originalRemove := removePinnedChild
	originalSync := syncPinnedParent
	t.Cleanup(func() {
		chmodPinnedChild = originalChmod
		removePinnedChild = originalRemove
		syncPinnedParent = originalSync
	})

	chmodPinnedChild = func(_ *os.Root, _ string, _ os.FileMode) error {
		return chmodErr
	}
	removePinnedChild = func(_ *os.Root, _ string) error {
		return removeErr
	}
	syncPinnedParent = func(_ *os.Root, edgePath string) error {
		if edgePath == path {
			return syncErr
		}
		return nil
	}

	dir, err := EnsurePrivate(path, 0o700)
	if dir != nil {
		_ = dir.Close()
	}
	for _, want := range []error{chmodErr, removeErr, syncErr} {
		if !errors.Is(err, want) {
			t.Fatalf("EnsurePrivate error = %v, want joined %v", err, want)
		}
	}
}

func TestEnsurePrivateSyncsParentAfterPermissionCleanup(t *testing.T) {
	root := realTempDir(t)
	path := filepath.Join(root, "state")
	chmodErr := errors.New("injected chmod failure")
	syncErr := errors.New("injected cleanup sync failure")
	originalChmod := chmodPinnedChild
	originalRemove := removePinnedChild
	originalSync := syncPinnedParent
	t.Cleanup(func() {
		chmodPinnedChild = originalChmod
		removePinnedChild = originalRemove
		syncPinnedParent = originalSync
	})

	chmodPinnedChild = func(_ *os.Root, _ string, _ os.FileMode) error {
		return chmodErr
	}
	removePinnedChild = func(parent *os.Root, name string) error {
		return parent.Remove(name)
	}
	syncPinnedParent = func(_ *os.Root, edgePath string) error {
		if edgePath == path {
			return syncErr
		}
		return nil
	}

	dir, err := EnsurePrivate(path, 0o700)
	if dir != nil {
		_ = dir.Close()
	}
	if !errors.Is(err, chmodErr) || !errors.Is(err, syncErr) {
		t.Fatalf("EnsurePrivate error = %v, want chmod and cleanup sync failures", err)
	}
	if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("permission-failure cleanup left directory present: %v", statErr)
	}
}

func TestOpenPrivateDoesNotSyncExistingEdges(t *testing.T) {
	root := realTempDir(t)
	path := filepath.Join(root, "state")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	originalSync := syncPinnedParent
	t.Cleanup(func() { syncPinnedParent = originalSync })
	syncPinnedParent = func(_ *os.Root, edgePath string) error {
		return fmt.Errorf("unexpected read-only sync of %s", edgePath)
	}
	dir, err := OpenPrivate(path, 0o700)
	if err != nil {
		t.Fatalf("OpenPrivate performed a write-side sync: %v", err)
	}
	if err := dir.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEnsurePrivateRejectsWritableNonStickyAncestor(t *testing.T) {
	root := realTempDir(t)
	unsafe := filepath.Join(root, "unsafe")
	if err := os.Mkdir(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	if dir, err := EnsurePrivate(filepath.Join(unsafe, "state"), 0o700); err == nil || !strings.Contains(err.Error(), "unsafe mode") {
		if dir != nil {
			_ = dir.Close()
		}
		t.Fatalf("EnsurePrivate error = %v, want unsafe ancestor rejection", err)
	}
}

func TestDirectoryRejectsFinalNamespaceReplacement(t *testing.T) {
	root := realTempDir(t)
	path := filepath.Join(root, "state")
	dir, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()

	moved := filepath.Join(root, "state-old")
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := dir.ValidateCurrent(); err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("ValidateCurrent error = %v, want namespace replacement", err)
	}
	if _, err := dir.OpenFile("lock", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600); err == nil {
		t.Fatal("mutation through replaced state-directory namespace succeeded")
	}
	if _, err := os.Lstat(filepath.Join(path, "lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement namespace was mutated: %v", err)
	}
}

func TestEnsurePrivateRejectsSymlinkedAncestor(t *testing.T) {
	root := realTempDir(t)
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked-parent")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if dir, err := EnsurePrivate(filepath.Join(link, "state"), 0o700); err == nil {
		_ = dir.Close()
		t.Fatal("EnsurePrivate accepted a symlinked ancestor")
	}
}

func TestEnsurePrivateDetectsAncestorSwapDuringTraversal(t *testing.T) {
	root := realTempDir(t)
	ancestor := filepath.Join(root, "ancestor")
	path := filepath.Join(ancestor, "state")
	originalSync := syncPinnedParent
	t.Cleanup(func() { syncPinnedParent = originalSync })

	swapped := false
	syncPinnedParent = func(_ *os.Root, edgePath string) error {
		if edgePath == ancestor && !swapped {
			swapped = true
			if err := os.Rename(ancestor, ancestor+"-old"); err != nil {
				return err
			}
			return os.Mkdir(ancestor, 0o700)
		}
		return nil
	}
	if dir, err := EnsurePrivate(path, 0o700); err == nil || !strings.Contains(err.Error(), "replaced") {
		if dir != nil {
			_ = dir.Close()
		}
		t.Fatalf("EnsurePrivate error = %v, want ancestor replacement", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement ancestor was traversed after swap: %v", err)
	}
}

func TestDirectoryReadDirNamesHandlesEmptySortedAndBoundedNamespaces(t *testing.T) {
	root := realTempDir(t)
	path := filepath.Join(root, "state")
	dir, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()

	names, err := dir.ReadDirNames(2)
	if err != nil || len(names) != 0 {
		t.Fatalf("empty ReadDirNames = %v, %v, want empty success", names, err)
	}
	for _, name := range []string{"zeta", "alpha"} {
		if err := os.WriteFile(filepath.Join(path, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	names, err = dir.ReadDirNames(2)
	if err != nil || strings.Join(names, ",") != "alpha,zeta" {
		t.Fatalf("sorted ReadDirNames = %v, %v", names, err)
	}
	if err := os.WriteFile(filepath.Join(path, "third"), []byte("third"), 0o600); err != nil {
		t.Fatal(err)
	}
	if names, err := dir.ReadDirNames(2); err == nil || !strings.Contains(err.Error(), "more than 2") {
		t.Fatalf("over-limit ReadDirNames = %v, %v", names, err)
	}
}

func countPath(paths []string, want string) int {
	count := 0
	for _, path := range paths {
		if path == want {
			count++
		}
	}
	return count
}
