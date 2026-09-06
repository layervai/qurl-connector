package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnectorHealthHandlerMethods(t *testing.T) {
	for _, test := range []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantAllow  string
	}{
		{name: "get", method: http.MethodGet, path: connectorHealthPath, wantStatus: http.StatusNoContent},
		{name: "head", method: http.MethodHead, path: connectorHealthPath, wantStatus: http.StatusNoContent},
		{name: "wrong method", method: http.MethodPost, path: connectorHealthPath, wantStatus: http.StatusMethodNotAllowed, wantAllow: "GET, HEAD"},
		{name: "wrong path", method: http.MethodGet, path: "/", wantStatus: http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			connectorHealthHandler(func() bool { return true }).ServeHTTP(recorder, httptest.NewRequest(test.method, test.path, nil))
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, test.wantStatus)
			}
			if allow := recorder.Header().Get("Allow"); allow != test.wantAllow {
				t.Fatalf("Allow = %q, want %q", allow, test.wantAllow)
			}
		})
	}
}

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
