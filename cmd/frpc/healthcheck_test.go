package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProbeConnectorHealth(t *testing.T) {
	t.Run("exact local endpoint is healthy", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != connectorHealthPath {
				t.Errorf("health request = %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		t.Setenv(envConnectorHealthAddr, strings.TrimPrefix(server.URL, "http://"))

		if err := probeConnectorHealth(context.Background()); err != nil {
			t.Fatalf("probeConnectorHealth() error = %v", err)
		}
	})

	t.Run("non-loopback target fails closed", func(t *testing.T) {
		t.Setenv(envConnectorHealthAddr, "169.254.169.254:80")
		if err := probeConnectorHealth(context.Background()); err == nil || !strings.Contains(err.Error(), "literal loopback IP") {
			t.Fatalf("probeConnectorHealth() error = %v, want loopback rejection", err)
		}
	})

	t.Run("redirect fails closed", func(t *testing.T) {
		server := httptest.NewServer(http.RedirectHandler("/healthz", http.StatusTemporaryRedirect))
		defer server.Close()
		t.Setenv(envConnectorHealthAddr, strings.TrimPrefix(server.URL, "http://"))

		if err := probeConnectorHealth(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTP 307") {
			t.Fatalf("probeConnectorHealth() error = %v, want redirect rejection", err)
		}
	})

	t.Run("canceled probe fails closed", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		defer server.Close()
		t.Setenv(envConnectorHealthAddr, strings.TrimPrefix(server.URL, "http://"))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := probeConnectorHealth(ctx); err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("probeConnectorHealth() error = %v, want context cancellation", err)
		}
	})
}
