package atomicfile

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestWrite_CreatesFileWithContents pins the happy path.
func TestWrite_CreatesFileWithContents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.bin")
	want := []byte("hello, atomic world\n")

	if err := Write(path, want, 0o600); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("read back %q, want %q", got, want)
	}
}

// TestWrite_OverwritesExisting pins the rename-replaces-target
// invariant — the call point relies on this for idempotent re-writes
// of the connector_identities.json cache.
func TestWrite_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.bin")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Errorf("contents = %q, want new", got)
	}
}

// TestWrite_AppliesMode pins the chmod step — both callers depend on
// 0600/0700-style modes for posture isolation.
func TestWrite_AppliesMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file mode bits not meaningful on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "out.bin")
	if err := Write(path, []byte("x"), 0o640); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o640 {
		t.Errorf("mode = %o, want 0640", perm)
	}
}

// TestWrite_NoTempLeftBehind pins the cleanup-on-success path: a
// successful Write must leave no `.tmp-*` siblings (a retry tripping
// over them would surface as a spurious "file exists" later).
func TestWrite_NoTempLeftBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.bin")
	if err := Write(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "out.bin" {
			t.Errorf("unexpected leftover file in dir after Write: %q", e.Name())
		}
	}
}

// TestWrite_MissingDirReturnsError pins the failure shape: a write
// to a directory that doesn't exist surfaces as a not-exist error
// rather than silently no-op or panicking.
func TestWrite_MissingDirReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope", "out.bin")
	err := Write(path, []byte("x"), 0o600)
	if err == nil {
		t.Fatal("expected error when parent directory doesn't exist, got nil")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("error = %v, want one wrapping fs.ErrNotExist", err)
	}
}
