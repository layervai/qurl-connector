package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunWithConnectorHealthServesLiveRunnerState(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	t.Setenv(envConnectorHealthAddr, addr)
	previousListen := listenConnectorHealth
	listenConnectorHealth = func(_, _ string) (net.Listener, error) { return listener, nil }
	t.Cleanup(func() { listenConnectorHealth = previousListen })

	ctx, cancel := context.WithCancel(context.Background())
	var ready atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- runWithConnectorHealth(ctx, ready.Load, func(runCtx context.Context) error {
			<-runCtx.Done()
			return runCtx.Err()
		})
	}()

	waitFor(t, time.Second, func() bool {
		err := probeConnectorHealth(context.Background())
		return err != nil && strings.Contains(err.Error(), "HTTP 503")
	}, "not-ready runtime health response")
	ready.Store(true)
	waitFor(t, time.Second, func() bool {
		return probeConnectorHealth(context.Background()) == nil
	}, "ready runtime health response")
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("runWithConnectorHealth returned %v, want context cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runWithConnectorHealth did not stop")
	}
}
