//go:build windows

package config

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestWindowsFileTransactionSerializesAndCancels(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl", "qurl-proxy.yaml")
	first, err := AcquireFileTransaction(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	// Bypass the in-process token so this test reaches the native advisory
	// lock just as an independent qurl process would.
	configTransactionToken <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	second, err := AcquireFileTransactionContext(ctx, path)
	if second != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended Windows transaction = (%v, %v), want deadline", second, err)
	}
	// The failed second acquisition returned its borrowed token. Remove that
	// test-only duplicate before the first transaction closes and returns the
	// real token.
	<-configTransactionToken
}
