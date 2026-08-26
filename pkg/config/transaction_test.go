//go:build darwin || linux

package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/layervai/qurl-connector/internal/pinnedfs"
)

func testTransactionConfig(id string) *Config {
	return &Config{
		Server: ServerConfig{Addr: "proxy.example.com", Port: 7000},
		Routes: []Route{{
			ID:        id,
			Type:      RouteTypeHTTP,
			LocalIP:   "127.0.0.1",
			LocalPort: 8080,
			TargetURL: "http://127.0.0.1:8080",
		}},
	}
}

func TestZeroFileTransactionCloseIsSafe(t *testing.T) {
	if err := (&FileTransaction{}).Close(); err != nil {
		t.Fatalf("zero FileTransaction Close error = %v", err)
	}
}

func TestAcquireFileTransactionContextCancelsProcessLockWait(t *testing.T) {
	root := t.TempDir()
	held, err := AcquireFileTransaction(filepath.Join(root, "held.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if tx, err := AcquireFileTransactionContext(ctx, filepath.Join(root, "waiting.yaml")); tx != nil || !errors.Is(err, context.DeadlineExceeded) {
		if tx != nil {
			_ = tx.Close()
		}
		t.Fatalf("contended acquire = (%v, %v), want nil and context deadline", tx, err)
	}
}

func TestFileTransactionRejectsWritableParentBeforeLockCreation(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
	path := filepath.Join(parent, "qurl-proxy.yaml")

	if tx, err := AcquireFileTransaction(path); err == nil ||
		(!strings.Contains(err.Error(), "no group/other write") && !strings.Contains(err.Error(), "unsafe mode")) {
		if tx != nil {
			_ = tx.Close()
		}
		t.Fatalf("AcquireFileTransaction error = %v, want writable-parent rejection", err)
	}
	if _, err := os.Lstat(path + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock created in rejected writable parent: %v", err)
	}
}

func TestConfigTransactionLockAcquireJoinsValidationCloseFailure(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "qurl-proxy.yaml")
	if err := os.WriteFile(path+".lock", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	closeErr := errors.New("injected config lock candidate close failure")
	originalClose := closeConfigTransactionFile
	closeConfigTransactionFile = func(file *os.File) error {
		return errors.Join(file.Close(), closeErr)
	}
	t.Cleanup(func() { closeConfigTransactionFile = originalClose })

	tx, err := AcquireFileTransaction(path)
	if tx != nil || err == nil || !strings.Contains(err.Error(), "mode is 0644") || !errors.Is(err, closeErr) {
		t.Fatalf("AcquireFileTransaction = (%v, %v), want validation and joined close errors", tx, err)
	}
}

func TestConfigTransactionLockAcquireJoinsPostValidationReleaseFailure(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "qurl-proxy.yaml")
	if err := os.WriteFile(path+".lock", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	releaseErr := errors.New("injected config lock candidate release failure")
	originalHook := beforeTransactionFileFinalValidation
	originalRelease := releaseConfigTransactionCandidate
	validationCount := 0
	beforeTransactionFileFinalValidation = func(label string) {
		if label != "config transaction lock" {
			return
		}
		validationCount++
		if validationCount == 2 {
			if err := os.Chmod(path+".lock", 0o644); err != nil {
				t.Error(err)
			}
		}
	}
	releaseConfigTransactionCandidate = func(file *os.File) error {
		return errors.Join(releaseTransactionLock(file), releaseErr)
	}
	t.Cleanup(func() {
		beforeTransactionFileFinalValidation = originalHook
		releaseConfigTransactionCandidate = originalRelease
	})

	tx, err := AcquireFileTransaction(path)
	if tx != nil || err == nil || !strings.Contains(err.Error(), "mode is 0644") || !errors.Is(err, releaseErr) {
		t.Fatalf("AcquireFileTransaction = (%v, %v), want validation and joined release errors", tx, err)
	}
}

func TestFileTransactionRoundTripUsesPinnedNamespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "qurl-proxy.yaml")
	canonicalPath, err := CanonicalPath(path)
	if err != nil {
		t.Fatal(err)
	}
	err = WithFileTransaction(path, func(tx *FileTransaction) error {
		if tx.Path() != canonicalPath {
			t.Fatalf("transaction path = %q, want %q", tx.Path(), canonicalPath)
		}
		exists, err := tx.Exists()
		if err != nil {
			return err
		}
		if exists {
			t.Fatal("new config unexpectedly exists")
		}
		if err := tx.Save(testTransactionConfig("one")); err != nil {
			return err
		}
		loaded, err := tx.Load()
		if err != nil {
			return err
		}
		if len(loaded.Routes) != 1 || loaded.Routes[0].ID != "one" {
			t.Fatalf("loaded routes = %#v", loaded.Routes)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("config mode = %04o, want 0600", got)
	}
}

func TestFileTransactionRevalidatesTempDescriptorBeforeRename(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "qurl-proxy.yaml")
	if err := Save(testTransactionConfig("before"), path); err != nil {
		t.Fatal(err)
	}
	originalHook := beforeConfigTempCommitValidation
	t.Cleanup(func() { beforeConfigTempCommitValidation = originalHook })
	beforeConfigTempCommitValidation = func(tx *FileTransaction, tempName string) {
		if err := os.Rename(filepath.Join(filepath.Dir(tx.Path()), tempName), filepath.Join(filepath.Dir(tx.Path()), tempName+".old")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(filepath.Dir(tx.Path()), tempName), []byte("replacement"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	tx, err := AcquireFileTransaction(path)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	if err := tx.Save(testTransactionConfig("after")); err == nil || !strings.Contains(err.Error(), "descriptor no longer matches") {
		t.Fatalf("Save error = %v, want temp descriptor-entry mismatch", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "after") {
		t.Fatal("config changed after temp entry replacement")
	}
}

func TestFileTransactionLoadRevalidatesConfigAfterRead(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "qurl-proxy.yaml")
	if err := Save(testTransactionConfig("before"), path); err != nil {
		t.Fatal(err)
	}
	tx, err := AcquireFileTransaction(path)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()

	originalHook := afterConfigTransactionRead
	t.Cleanup(func() { afterConfigTransactionRead = originalHook })
	afterConfigTransactionRead = func(*FileTransaction) {
		afterConfigTransactionRead = func(*FileTransaction) {}
		if err := os.Rename(path, path+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if cfg, err := tx.Load(); cfg != nil || err == nil || !strings.Contains(err.Error(), "no longer matches") {
		t.Fatalf("Load = (%v, %v), want nil and post-read identity failure", cfg, err)
	}
}

func TestFileTransactionLoadJoinsCloseFailure(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "qurl-proxy.yaml")
	if err := Save(testTransactionConfig("before"), path); err != nil {
		t.Fatal(err)
	}
	tx, err := AcquireFileTransaction(path)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()

	wantErr := errors.New("injected read close failure")
	originalClose := closeConfigTransactionFile
	t.Cleanup(func() { closeConfigTransactionFile = originalClose })
	closeConfigTransactionFile = func(file *os.File) error {
		return errors.Join(file.Close(), wantErr)
	}
	if cfg, err := tx.Load(); cfg != nil || !errors.Is(err, wantErr) {
		t.Fatalf("Load = (%v, %v), want nil and close failure", cfg, err)
	}
}

func TestFileTransactionJoinsDeferredTempCleanupFailures(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "qurl-proxy.yaml")
	if err := Save(testTransactionConfig("before"), path); err != nil {
		t.Fatal(err)
	}
	tx, err := AcquireFileTransaction(path)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()

	closeErr := errors.New("injected temp close failure")
	removeErr := errors.New("injected temp remove failure")
	syncErr := errors.New("injected temp cleanup sync failure")
	originalHook := beforeConfigTempCommitValidation
	originalClose := closeConfigTransactionFile
	originalRemove := removeConfigTransactionTemp
	originalSync := syncConfigTransactionNamespace
	t.Cleanup(func() {
		beforeConfigTempCommitValidation = originalHook
		closeConfigTransactionFile = originalClose
		removeConfigTransactionTemp = originalRemove
		syncConfigTransactionNamespace = originalSync
	})
	beforeConfigTempCommitValidation = func(tx *FileTransaction, tempName string) {
		if err := os.Link(
			filepath.Join(filepath.Dir(tx.Path()), tempName),
			filepath.Join(filepath.Dir(tx.Path()), tempName+".alias"),
		); err != nil {
			t.Fatal(err)
		}
	}
	closeConfigTransactionFile = func(file *os.File) error {
		return errors.Join(file.Close(), closeErr)
	}
	removeConfigTransactionTemp = func(namespace *pinnedfs.Directory, name string) error {
		return errors.Join(namespace.Remove(name), removeErr)
	}
	syncConfigTransactionNamespace = func(namespace *pinnedfs.Directory) error {
		return errors.Join(namespace.Sync(), syncErr)
	}

	err = tx.Save(testTransactionConfig("after"))
	for _, want := range []error{closeErr, removeErr, syncErr} {
		if !errors.Is(err, want) {
			t.Fatalf("Save error = %v, want joined %v", err, want)
		}
	}
	if err == nil || !strings.Contains(err.Error(), "link count is 2") {
		t.Fatalf("Save error = %v, want primary temp validation failure", err)
	}
}

func TestCreateTempJoinsRejectedTempCleanupFailures(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "qurl-proxy.yaml")
	tx, err := AcquireFileTransaction(path)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()

	closeErr := errors.New("injected rejected-temp close failure")
	removeErr := errors.New("injected rejected-temp remove failure")
	syncErr := errors.New("injected rejected-temp sync failure")
	originalFinalHook := beforeTransactionFileFinalValidation
	originalClose := closeConfigTransactionFile
	originalRemove := removeConfigTransactionTemp
	originalSync := syncConfigTransactionNamespace
	t.Cleanup(func() {
		beforeTransactionFileFinalValidation = originalFinalHook
		closeConfigTransactionFile = originalClose
		removeConfigTransactionTemp = originalRemove
		syncConfigTransactionNamespace = originalSync
	})
	mutated := false
	beforeTransactionFileFinalValidation = func(label string) {
		if label != "temporary config file" || mutated {
			return
		}
		mutated = true
		matches, globErr := filepath.Glob(filepath.Join(parent, ".qurl-proxy.yaml.tmp-*"))
		if globErr != nil || len(matches) != 1 {
			t.Fatalf("temporary config lookup = %v, %v", matches, globErr)
		}
		if err := os.Chmod(matches[0], 0o644); err != nil {
			t.Fatal(err)
		}
	}
	closeConfigTransactionFile = func(file *os.File) error {
		return errors.Join(file.Close(), closeErr)
	}
	removeConfigTransactionTemp = func(namespace *pinnedfs.Directory, name string) error {
		return errors.Join(namespace.Remove(name), removeErr)
	}
	syncConfigTransactionNamespace = func(namespace *pinnedfs.Directory) error {
		return errors.Join(namespace.Sync(), syncErr)
	}

	name, file, err := tx.createTemp()
	if name != "" || file != nil {
		t.Fatalf("createTemp returned live temp (%q, %v) after rejection", name, file)
	}
	for _, want := range []error{closeErr, removeErr, syncErr} {
		if !errors.Is(err, want) {
			t.Fatalf("createTemp error = %v, want joined %v", err, want)
		}
	}
	if err == nil || !strings.Contains(err.Error(), "mode is 0644, want 0600") {
		t.Fatalf("createTemp error = %v, want final mode failure", err)
	}
}

func TestValidateTransactionFileUsesFinalStableSnapshot(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
		want   string
	}{
		{
			name: "late hard link",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Link(path, path+".alias"); err != nil {
					t.Fatal(err)
				}
			},
			want: "link count is 2",
		},
		{
			name: "late chmod",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: "mode is 0644, want 0600",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, "qurl-proxy.yaml")
			if err := Save(testTransactionConfig("before"), path); err != nil {
				t.Fatal(err)
			}
			tx, err := AcquireFileTransaction(path)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Close()

			originalHook := beforeTransactionFileFinalValidation
			t.Cleanup(func() { beforeTransactionFileFinalValidation = originalHook })
			mutated := false
			beforeTransactionFileFinalValidation = func(label string) {
				if label == "existing config file" && !mutated {
					mutated = true
					tt.mutate(t, path)
				}
			}
			if err := tx.Save(testTransactionConfig("after")); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Save error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateTransactionFileValidatesFinalNamespaceSnapshot(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
		want   string
	}{
		{
			name: "hard link after final descriptor stat",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Link(path, path+".alias"); err != nil {
					t.Fatal(err)
				}
			},
			want: "final entry link count is 2",
		},
		{
			name: "chmod after final descriptor stat",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: "final entry mode is 0644, want 0600",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, "qurl-proxy.yaml")
			if err := Save(testTransactionConfig("before"), path); err != nil {
				t.Fatal(err)
			}
			tx, err := AcquireFileTransaction(path)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Close()

			originalHook := beforeTransactionFileFinalEntryValidation
			t.Cleanup(func() { beforeTransactionFileFinalEntryValidation = originalHook })
			mutated := false
			beforeTransactionFileFinalEntryValidation = func(label string) {
				if label == "existing config file" && !mutated {
					mutated = true
					tt.mutate(t, path)
				}
			}
			if err := tx.Save(testTransactionConfig("after")); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Save error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestFileTransactionRejectsParentReplacementBeforeMutation(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "config")
	path := filepath.Join(parent, "qurl-proxy.yaml")
	if err := Save(testTransactionConfig("before"), path); err != nil {
		t.Fatal(err)
	}
	tx, err := AcquireFileTransaction(path)
	if err != nil {
		t.Fatal(err)
	}

	oldParent := filepath.Join(root, "config-old")
	if err := os.Rename(parent, oldParent); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := tx.Save(testTransactionConfig("after")); err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("Save error = %v, want parent replacement", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement namespace was mutated: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(oldParent, filepath.Base(path)))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "after") {
		t.Fatal("orphaned original namespace was mutated after replacement")
	}
	if err := tx.Close(); err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("Close error = %v, want parent replacement", err)
	}
}

func TestFileTransactionRejectsLockEntryReplacementBeforeMutation(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "qurl-proxy.yaml")
	if err := Save(testTransactionConfig("before"), path); err != nil {
		t.Fatal(err)
	}
	tx, err := AcquireFileTransaction(path)
	if err != nil {
		t.Fatal(err)
	}

	lockPath := path + ".lock"
	if err := os.Rename(lockPath, lockPath+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := tx.Save(testTransactionConfig("after")); err == nil || !strings.Contains(err.Error(), "descriptor no longer matches") {
		t.Fatalf("Save error = %v, want lock identity failure", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "after") {
		t.Fatal("config mutated after lock namespace split")
	}
	if err := tx.Close(); err == nil || !strings.Contains(err.Error(), "descriptor no longer matches") {
		t.Fatalf("Close error = %v, want lock identity failure", err)
	}
}

func TestFileTransactionRejectsConfigWithoutContinuityLock(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "qurl-proxy.yaml")
	if err := Save(testTransactionConfig("before"), path); err != nil {
		t.Fatal(err)
	}
	lockPath := path + ".lock"
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}

	tx, err := AcquireFileTransaction(path)
	if tx != nil || !errors.Is(err, ErrConfigContinuityLockMissing) || !strings.Contains(err.Error(), "continuity state is missing its lock") {
		if tx != nil {
			_ = tx.Close()
		}
		t.Fatalf("AcquireFileTransaction = (%v, %v), want missing-lock rejection", tx, err)
	}
	if _, statErr := os.Lstat(lockPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed transaction recreated missing lock: %v", statErr)
	}
}

func TestFileTransactionRejectsHardLinkedLock(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "qurl-proxy.yaml")
	lockPath := path + ".lock"
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(lockPath, lockPath+".alias"); err != nil {
		t.Fatal(err)
	}
	if tx, err := AcquireFileTransaction(path); err == nil || !strings.Contains(err.Error(), "link count is 2") {
		if tx != nil {
			_ = tx.Close()
		}
		t.Fatalf("AcquireFileTransaction error = %v, want hard-link rejection", err)
	}
}

func TestFileTransactionRejectsSymlinkedLock(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "qurl-proxy.yaml")
	target := filepath.Join(parent, "lock-target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path+".lock"); err != nil {
		t.Fatal(err)
	}
	if tx, err := AcquireFileTransaction(path); err == nil {
		if tx != nil {
			_ = tx.Close()
		}
		t.Fatal("AcquireFileTransaction accepted a symlinked lock")
	}
}

func TestFileTransactionRejectsHardLinkedConfigBeforeReplacement(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "qurl-proxy.yaml")
	if err := Save(testTransactionConfig("before"), path); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, path+".alias"); err != nil {
		t.Fatal(err)
	}
	tx, err := AcquireFileTransaction(path)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	if err := tx.Save(testTransactionConfig("after")); err == nil || !strings.Contains(err.Error(), "link count is 2") {
		t.Fatalf("Save error = %v, want hard-link rejection", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "after") {
		t.Fatal("hard-linked config was replaced")
	}
}
