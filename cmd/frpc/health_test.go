package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnectorHealthAddress(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		t.Setenv(envConnectorHealthAddr, "restored after test")
		if err := os.Unsetenv(envConnectorHealthAddr); err != nil {
			t.Fatal(err)
		}
		addr, configured, err := connectorHealthAddress()
		if err != nil || configured || addr != "" {
			t.Fatalf("connectorHealthAddress() = %q, %t, %v; want disabled", addr, configured, err)
		}
	})

	for _, test := range []struct {
		name string
		raw  string
		want string
	}{
		{name: "IPv4 loopback", raw: "127.0.0.1:7401", want: "127.0.0.1:7401"},
		{name: "IPv6 loopback", raw: "[::1]:7401", want: "[::1]:7401"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(envConnectorHealthAddr, test.raw)
			addr, configured, err := connectorHealthAddress()
			if err != nil || !configured || addr != test.want {
				t.Fatalf("connectorHealthAddress() = %q, %t, %v; want %q, true, nil", addr, configured, err, test.want)
			}
		})
	}

	for _, test := range []struct {
		name string
		raw  string
	}{
		{name: "empty", raw: ""},
		{name: "surrounding whitespace", raw: " 127.0.0.1:7401"},
		{name: "wildcard", raw: "0.0.0.0:7401"},
		{name: "hostname", raw: "example.com:7401"},
		{name: "zero port", raw: "127.0.0.1:0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(envConnectorHealthAddr, test.raw)
			if _, configured, err := connectorHealthAddress(); err == nil || !configured {
				t.Fatalf("connectorHealthAddress accepted %q", test.raw)
			}
		})
	}
}

func TestRunConnectorCommandRejectsHealthAddressBeforeConfigDiscovery(t *testing.T) {
	t.Setenv(envConnectorHealthAddr, "0.0.0.0:7401")
	previousCfg := cfgFile
	cfgFile = "/config/path/must/not/be/read"
	t.Cleanup(func() { cfgFile = previousCfg })

	err := runConnectorCommand(context.Background())
	if err == nil || !strings.Contains(err.Error(), "host must be a loopback IP") {
		t.Fatalf("runConnectorCommand() error = %v, want early health-address rejection", err)
	}
}

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
			if marker := recorder.Header().Get(connectorHealthHeader); marker != "1" {
				t.Fatalf("%s = %q, want 1", connectorHealthHeader, marker)
			}
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
		return err != nil && err.Error() == "connector routes are not ready"
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

func TestRunWithConnectorHealthDisabledRunsDirectly(t *testing.T) {
	t.Setenv(envConnectorHealthAddr, "restored after test")
	if err := os.Unsetenv(envConnectorHealthAddr); err != nil {
		t.Fatal(err)
	}
	previousListen := listenConnectorHealth
	listenConnectorHealth = func(_, _ string) (net.Listener, error) {
		t.Error("health listener bound while the endpoint was disabled")
		return nil, errors.New("must not listen")
	}
	t.Cleanup(func() { listenConnectorHealth = previousListen })

	want := errors.New("runtime result")
	called := false
	err := runWithConnectorHealth(context.Background(), func() bool { return false }, func(context.Context) error {
		called = true
		return want
	})
	if !called {
		t.Fatal("disabled health wrapper did not run the Connector")
	}
	if !errors.Is(err, want) {
		t.Fatalf("runWithConnectorHealth() error = %v, want runtime error %v", err, want)
	}
}

func TestProbeConnectorHealthDistinguishesWrongEndpoint(t *testing.T) {
	for _, test := range []struct {
		name             string
		status           int
		connectorRuntime bool
		wantError        string
	}{
		{name: "unready runtime", status: http.StatusServiceUnavailable, connectorRuntime: true, wantError: "connector routes are not ready"},
		{name: "foreign 404", status: http.StatusNotFound, wantError: "did not come from a qurl-connector runtime"},
		{name: "foreign 204", status: http.StatusNoContent, wantError: "did not come from a qurl-connector runtime"},
		{name: "foreign 503", status: http.StatusServiceUnavailable, wantError: "did not come from a qurl-connector runtime"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if test.connectorRuntime {
					w.Header().Set(connectorHealthHeader, "1")
				}
				w.WriteHeader(test.status)
			}))
			t.Cleanup(server.Close)
			t.Setenv(envConnectorHealthAddr, server.Listener.Addr().String())
			err := probeConnectorHealth(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("probeConnectorHealth() error = %v, want text %q", err, test.wantError)
			}
		})
	}
}
