package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

const validDesktopConfig = `server:
  public_domain: qurl.site
admin:
  enabled: true
  addr: 127.0.0.1
  port: 7400
  password: test-only-admin-password
routes: []
`

func TestReplaceDesktopConfigCreatesContinuityState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl-proxy.yaml")
	if err := replaceDesktopConfig(context.Background(), path, strings.NewReader(validDesktopConfig)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".lock"); err != nil {
		t.Fatalf("config lock: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != validDesktopConfig {
		t.Fatalf("Desktop config shape changed:\n%s", raw)
	}
	cfg, err := nhpconfig.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Admin.Enabled || cfg.Admin.Password == "" {
		t.Fatalf("Desktop admin config not preserved: %+v", cfg.Admin)
	}
}

func TestReplaceDesktopConfigRejectsMissingContinuityLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl-proxy.yaml")
	if err := replaceDesktopConfig(context.Background(), path, strings.NewReader(validDesktopConfig)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path + ".lock"); err != nil {
		t.Fatal(err)
	}
	err := replaceDesktopConfig(context.Background(), path, strings.NewReader(validDesktopConfig))
	if !errors.Is(err, nhpconfig.ErrConfigContinuityLockMissing) {
		t.Fatalf("replaceDesktopConfig error = %v, want ErrConfigContinuityLockMissing", err)
	}
}

func TestReplaceDesktopConfigValidatesBeforeMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl-proxy.yaml")
	if err := replaceDesktopConfig(context.Background(), path, strings.NewReader(validDesktopConfig)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	err = replaceDesktopConfig(context.Background(), path, strings.NewReader("unknown: true\n"))
	if err == nil || !strings.Contains(err.Error(), "replace Desktop config") {
		t.Fatalf("replaceDesktopConfig error = %v, want validation error", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("invalid Desktop config mutated the existing file")
	}
}

func TestReplaceDesktopConfigRejectsOversizeInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl-proxy.yaml")
	err := replaceDesktopConfig(
		context.Background(),
		path,
		strings.NewReader(strings.Repeat("x", desktopConfigMaxBytes+1)),
	)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("replaceDesktopConfig error = %v, want size rejection", err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("oversize input created config: %v", statErr)
	}
}

func TestReplaceDesktopConfigBoundsStalledInput(t *testing.T) {
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = writer.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	started := time.Now()
	err := replaceDesktopConfig(ctx, filepath.Join(t.TempDir(), "qurl-proxy.yaml"), reader)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("replaceDesktopConfig error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("stalled Desktop config read returned after %v, want within 1s", elapsed)
	}
}

func TestReplaceDesktopConfigBoundsHeldLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl-proxy.yaml")
	originalTimeout := connectorConfigLockWaitTimeout
	connectorConfigLockWaitTimeout = 25 * time.Millisecond
	t.Cleanup(func() { connectorConfigLockWaitTimeout = originalTimeout })

	lockHeld := make(chan struct{})
	releaseLock := make(chan struct{})
	holderErr := make(chan error, 1)
	released := false
	t.Cleanup(func() {
		if !released {
			close(releaseLock)
		}
	})
	go func() {
		holderErr <- nhpconfig.WithFileTransactionContext(context.Background(), path, func(_ *nhpconfig.FileTransaction) error {
			close(lockHeld)
			<-releaseLock
			return nil
		})
	}()

	select {
	case <-lockHeld:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for config lock holder")
	}

	started := time.Now()
	err := replaceDesktopConfig(context.Background(), path, strings.NewReader(validDesktopConfig))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("replaceDesktopConfig error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("held config lock returned after %v, want within 1s", elapsed)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("held config lock allowed config mutation: %v", statErr)
	}

	close(releaseLock)
	released = true
	select {
	case err := <-holderErr:
		if err != nil {
			t.Fatalf("config lock holder: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for config lock holder to exit")
	}
}
