//go:build windows

package config

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func windowsTransactionConfig(id string) *Config {
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

func TestWindowsFileTransactionRoundTripAndAtomicReplace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl", "qurl-proxy.yaml")
	tx, err := AcquireFileTransaction(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Close(); err != nil {
			t.Errorf("close Windows config transaction: %v", err)
		}
	}()

	if err := tx.Save(windowsTransactionConfig("first")); err != nil {
		t.Fatalf("initial Windows config save: %v", err)
	}
	first, err := tx.Load()
	if err != nil {
		t.Fatalf("initial Windows config load: %v", err)
	}
	if len(first.Routes) != 1 || first.Routes[0].ID != "first" {
		t.Fatalf("initial Windows config route = %#v, want first", first.Routes)
	}

	if err := tx.Save(windowsTransactionConfig("replacement")); err != nil {
		t.Fatalf("atomic Windows config replacement: %v", err)
	}
	replacement, err := tx.Load()
	if err != nil {
		t.Fatalf("replacement Windows config load: %v", err)
	}
	if len(replacement.Routes) != 1 || replacement.Routes[0].ID != "replacement" {
		t.Fatalf("replacement Windows config route = %#v, want replacement", replacement.Routes)
	}
}
