//go:build darwin || linux

package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAcquireTransactionLockHonorsContextWhileExternallyContended(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	first, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		_ = first.Close()
		t.Fatal(err)
	}
	if err := acquireTransactionLock(context.Background(), first); err != nil {
		_ = first.Close()
		_ = second.Close()
		t.Fatal(err)
	}
	defer func() { _ = releaseTransactionLock(first) }()
	defer second.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := acquireTransactionLock(ctx, second); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended lock error = %v, want context deadline", err)
	}
}
