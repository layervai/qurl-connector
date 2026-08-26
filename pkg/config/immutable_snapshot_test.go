//go:build darwin || linux

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const immutableSnapshotTestYAML = "routes:\n  - id: customer-web\n    type: http\n    local_ip: 127.0.0.1\n    local_port: 8080\n"

func writeImmutableSnapshotFixture(t *testing.T, dirMode, fileMode os.FileMode) string {
	t.Helper()
	parent := filepath.Join(t.TempDir(), "work")
	if err := os.Mkdir(parent, dirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, dirMode); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "qurl-proxy.yaml")
	if err := os.WriteFile(path, []byte(immutableSnapshotTestYAML), fileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, fileMode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestImmutableConfigSnapshotReadsWithoutCreatingArtifacts(t *testing.T) {
	path := writeImmutableSnapshotFixture(t, 0o755, 0o444)
	parent := filepath.Dir(path)
	before, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	beforeEntries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}

	cfg, snapshot, err := OpenImmutableConfigSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Routes) != 1 || cfg.Routes[0].ID != "customer-web" {
		t.Fatalf("decoded config = %#v", cfg)
	}
	if err := snapshot.RequireSiblingAbsent(filepath.Base(path) + ".lock"); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Close(); err != nil {
		t.Fatal(err)
	}

	after, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	afterEntries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("immutable snapshot changed parent mtime: before=%v after=%v", before.ModTime(), after.ModTime())
	}
	if len(afterEntries) != len(beforeEntries) {
		t.Fatalf("immutable snapshot changed directory entries: before=%v after=%v", beforeEntries, afterEntries)
	}
	if _, err := os.Lstat(path + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("immutable snapshot created sibling lock: %v", err)
	}
}

func TestImmutableConfigSnapshotRejectsUnsafeWritableNamespaceAndFile(t *testing.T) {
	t.Run("final namespace", func(t *testing.T) {
		path := writeImmutableSnapshotFixture(t, 0o777, 0o444)
		if _, snapshot, err := OpenImmutableConfigSnapshot(path); err == nil || !strings.Contains(err.Error(), "unsafe mode 0777") {
			if snapshot != nil {
				_ = snapshot.Close()
			}
			t.Fatalf("OpenImmutableConfigSnapshot error = %v, want writable namespace rejection", err)
		}
	})
	t.Run("ancestor namespace", func(t *testing.T) {
		unsafe := filepath.Join(t.TempDir(), "unsafe")
		final := filepath.Join(unsafe, "work")
		if err := os.MkdirAll(final, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(unsafe, 0o777); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(unsafe, 0o700) })
		path := filepath.Join(final, "qurl-proxy.yaml")
		if err := os.WriteFile(path, []byte(immutableSnapshotTestYAML), 0o444); err != nil {
			t.Fatal(err)
		}
		if _, snapshot, err := OpenImmutableConfigSnapshot(path); err == nil || !strings.Contains(err.Error(), "unsafe mode 0777") {
			if snapshot != nil {
				_ = snapshot.Close()
			}
			t.Fatalf("OpenImmutableConfigSnapshot error = %v, want writable ancestor rejection", err)
		}
	})
	t.Run("file", func(t *testing.T) {
		path := writeImmutableSnapshotFixture(t, 0o755, 0o666)
		if _, snapshot, err := OpenImmutableConfigSnapshot(path); err == nil || !strings.Contains(err.Error(), "unsafe writable mode 0666") {
			if snapshot != nil {
				_ = snapshot.Close()
			}
			t.Fatalf("OpenImmutableConfigSnapshot error = %v, want writable file rejection", err)
		}
	})
}

func TestImmutableConfigSnapshotRejectsHardLinkedFile(t *testing.T) {
	path := writeImmutableSnapshotFixture(t, 0o755, 0o444)
	if err := os.Link(path, filepath.Join(filepath.Dir(path), "alias.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, snapshot, err := OpenImmutableConfigSnapshot(path); err == nil || !strings.Contains(err.Error(), "link count is 2") {
		if snapshot != nil {
			_ = snapshot.Close()
		}
		t.Fatalf("OpenImmutableConfigSnapshot error = %v, want hard-link rejection", err)
	}
}

func TestImmutableConfigSnapshotRejectsReplacementDuringRead(t *testing.T) {
	path := writeImmutableSnapshotFixture(t, 0o755, 0o444)
	originalHook := afterImmutableConfigSnapshotRead
	afterImmutableConfigSnapshotRead = func(*ImmutableConfigSnapshot) {
		if err := os.Rename(path, path+".old"); err != nil {
			t.Error(err)
			return
		}
		if err := os.WriteFile(path, []byte(immutableSnapshotTestYAML), 0o444); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { afterImmutableConfigSnapshotRead = originalHook })

	cfg, snapshot, err := OpenImmutableConfigSnapshot(path)
	if cfg != nil || snapshot != nil || err == nil || !strings.Contains(err.Error(), "descriptor") {
		t.Fatalf("OpenImmutableConfigSnapshot = (%#v, %v, %v), want replacement rejection", cfg, snapshot, err)
	}
}

func TestImmutableConfigSnapshotRejectsSiblingLockAppearance(t *testing.T) {
	path := writeImmutableSnapshotFixture(t, 0o755, 0o444)
	_, snapshot, err := OpenImmutableConfigSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	lockName := filepath.Base(path) + ".lock"
	if err := snapshot.RequireSiblingAbsent(lockName); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), lockName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Close(); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("Close error = %v, want retained lock-absence rejection", err)
	}
}

func TestImmutableConfigSnapshotCloseJoinsContinuityAndCloseFailures(t *testing.T) {
	path := writeImmutableSnapshotFixture(t, 0o755, 0o444)
	_, snapshot, err := OpenImmutableConfigSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	closeErr := errors.New("injected immutable config close failure")
	originalClose := closeImmutableConfigSnapshotFile
	closeImmutableConfigSnapshotFile = func(file *os.File) error {
		return errors.Join(file.Close(), closeErr)
	}
	t.Cleanup(func() { closeImmutableConfigSnapshotFile = originalClose })

	err = snapshot.Close()
	if !errors.Is(err, closeErr) || !strings.Contains(err.Error(), "immutable config") {
		t.Fatalf("Close error = %v, want joined continuity and close failures", err)
	}
}
