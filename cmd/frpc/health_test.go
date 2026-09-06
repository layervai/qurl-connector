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
		{name: "port above range", raw: "127.0.0.1:70000"},
		{name: "non-numeric port", raw: "127.0.0.1:http"},
		{name: "missing port", raw: "127.0.0.1"},
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

func TestRunConnectorCommandClaimsHealthListenerBeforeConfigDiscovery(t *testing.T) {
	t.Setenv(envConnectorHealthAddr, "127.0.0.1:7401")
	previousCfg := cfgFile
	cfgFile = "/config/path/must/not/be/read"
	t.Cleanup(func() { cfgFile = previousCfg })
	previousListen := listenConnectorHealth
	want := errors.New("address already in use")
	listenConnectorHealth = func(_, _ string) (net.Listener, error) { return nil, want }
	t.Cleanup(func() { listenConnectorHealth = previousListen })

	err := runConnectorCommand(context.Background())
	if !errors.Is(err, want) {
		t.Fatalf("runConnectorCommand() error = %v, want early listener error %v", err, want)
	}
}

func TestConnectorHealthHandlerMethods(t *testing.T) {
	for _, test := range []struct {
		name       string
		method     string
		path       string
		host       string
		wantStatus int
		wantAllow  string
	}{
		{name: "get", method: http.MethodGet, path: connectorHealthPath, wantStatus: http.StatusNoContent},
		{name: "head", method: http.MethodHead, path: connectorHealthPath, wantStatus: http.StatusNoContent},
		{name: "wrong method", method: http.MethodPost, path: connectorHealthPath, wantStatus: http.StatusMethodNotAllowed, wantAllow: "GET, HEAD"},
		{name: "wrong path", method: http.MethodGet, path: "/", wantStatus: http.StatusNotFound},
		{name: "wrong host", method: http.MethodGet, path: connectorHealthPath, host: "attacker.example", wantStatus: http.StatusMisdirectedRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(test.method, test.path, nil)
			if test.host != "" {
				request.Host = test.host
			}
			connectorHealthHandler("example.com", func() bool { return true }).ServeHTTP(recorder, request)
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
		return errors.Is(err, errConnectorRoutesNotReady)
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

func TestRunWithConnectorHealthRejectsNilInputs(t *testing.T) {
	if err := runWithConnectorHealth(nil, func() bool { return false }, func(context.Context) error { return nil }); err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("nil context error = %v", err)
	}

	t.Setenv(envConnectorHealthAddr, "127.0.0.1:7401")
	previousListen := listenConnectorHealth
	listenConnectorHealth = func(_, _ string) (net.Listener, error) {
		t.Error("listener bound with a nil readiness callback")
		return nil, errors.New("must not listen")
	}
	t.Cleanup(func() { listenConnectorHealth = previousListen })
	if err := runWithConnectorHealth(context.Background(), nil, func(context.Context) error { return nil }); err == nil || !strings.Contains(err.Error(), "callback is nil") {
		t.Fatalf("nil readiness callback error = %v", err)
	}
}

func TestRunWithConnectorHealthAllowsCleanEnabledRuntimeExit(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(envConnectorHealthAddr, listener.Addr().String())
	previousListen := listenConnectorHealth
	listenConnectorHealth = func(_, _ string) (net.Listener, error) { return listener, nil }
	t.Cleanup(func() { listenConnectorHealth = previousListen })

	if err := runWithConnectorHealth(context.Background(), func() bool { return true }, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("clean enabled runtime exit = %v", err)
	}
}

func TestRunWithConnectorHealthForcesCloseAfterShutdownDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	t.Setenv(envConnectorHealthAddr, addr)
	previousListen := listenConnectorHealth
	listenConnectorHealth = func(_, _ string) (net.Listener, error) { return listener, nil }
	t.Cleanup(func() { listenConnectorHealth = previousListen })

	readyEntered := make(chan struct{})
	releaseReady := make(chan struct{})
	defer func() {
		select {
		case <-releaseReady:
		default:
			close(releaseReady)
		}
	}()
	readyDone := make(chan struct{})
	requestDone := make(chan error, 1)
	started := time.Now()
	err = runWithConnectorHealth(context.Background(), func() bool {
		close(readyEntered)
		<-releaseReady
		close(readyDone)
		return true
	}, func(context.Context) error {
		go func() {
			resp, requestErr := http.Get("http://" + addr + connectorHealthPath) //nolint:gosec,noctx // Local test request is closed by the server under test.
			if resp != nil {
				_ = resp.Body.Close()
			}
			requestDone <- requestErr
		}()
		select {
		case <-readyEntered:
			return nil
		case <-time.After(time.Second):
			return errors.New("readiness handler did not start")
		}
	})
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("runWithConnectorHealth() after forced close = %v", err)
	}
	if elapsed < time.Second || elapsed > 2*time.Second {
		t.Fatalf("forced close took %s, want the one-second shutdown bound", elapsed)
	}
	select {
	case requestErr := <-requestDone:
		if requestErr == nil {
			t.Fatal("active request completed without the forced server close")
		}
	case <-time.After(time.Second):
		t.Fatal("forced server close did not release the active request")
	}
	close(releaseReady)
	select {
	case <-readyDone:
	case <-time.After(time.Second):
		t.Fatal("readiness callback did not finish after release")
	}
}

type failedConnectorHealthListener struct {
	err error
}

func (l *failedConnectorHealthListener) Accept() (net.Conn, error) { return nil, l.err }
func (*failedConnectorHealthListener) Close() error                { return nil }
func (*failedConnectorHealthListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7401}
}

func TestRunWithConnectorHealthStopsRuntimeWhenListenerFails(t *testing.T) {
	t.Setenv(envConnectorHealthAddr, "127.0.0.1:7401")
	previousListen := listenConnectorHealth
	want := errors.New("listener failed")
	listenConnectorHealth = func(_, _ string) (net.Listener, error) {
		return &failedConnectorHealthListener{err: want}, nil
	}
	t.Cleanup(func() { listenConnectorHealth = previousListen })

	runtimeCanceled := false
	err := runWithConnectorHealth(context.Background(), func() bool { return false }, func(ctx context.Context) error {
		<-ctx.Done()
		runtimeCanceled = true
		// runConnectorCommandBody joins its result with deferred close
		// results, even when those results are nil.
		return errors.Join(ctx.Err(), nil)
	})
	if !runtimeCanceled {
		t.Fatal("runtime kept running after its readiness listener failed")
	}
	if !errors.Is(err, want) || !strings.Contains(err.Error(), "serve Connector health") {
		t.Fatalf("runWithConnectorHealth() error = %v, want wrapped listener error %v", err, want)
	}
	if errors.Is(err, context.Canceled) {
		t.Fatalf("listener failure matched context.Canceled: %v", err)
	}
}

func TestProbeConnectorHealthReportsDisabledEndpoint(t *testing.T) {
	t.Setenv(envConnectorHealthAddr, "restored after test")
	if err := os.Unsetenv(envConnectorHealthAddr); err != nil {
		t.Fatal(err)
	}

	err := probeConnectorHealth(context.Background())
	if err == nil || !strings.Contains(err.Error(), "connector readiness is disabled") {
		t.Fatalf("probeConnectorHealth() error = %v, want disabled-endpoint diagnostic", err)
	}
	if errors.Is(err, errConnectorRoutesNotReady) {
		t.Fatalf("disabled endpoint was reported as a live unready runtime: %v", err)
	}
}

func TestRunWithConnectorHealthPreservesRuntimeFailureJoinedWithCancellation(t *testing.T) {
	t.Setenv(envConnectorHealthAddr, "127.0.0.1:7401")
	previousListen := listenConnectorHealth
	wantListener := errors.New("listener failed")
	listenConnectorHealth = func(_, _ string) (net.Listener, error) {
		return &failedConnectorHealthListener{err: wantListener}, nil
	}
	t.Cleanup(func() { listenConnectorHealth = previousListen })

	wantShutdown := errors.New("admission retirement failed")
	err := runWithConnectorHealth(context.Background(), func() bool { return false }, func(ctx context.Context) error {
		<-ctx.Done()
		return errors.Join(ctx.Err(), wantShutdown)
	})
	if !errors.Is(err, wantListener) {
		t.Fatalf("runWithConnectorHealth() error = %v, want listener error %v", err, wantListener)
	}
	if !errors.Is(err, wantShutdown) {
		t.Fatalf("runWithConnectorHealth() error = %v, want runtime shutdown error %v", err, wantShutdown)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runWithConnectorHealth() error = %v, want joined context cancellation", err)
	}
}

func TestProbeConnectorHealthDistinguishesWrongEndpoint(t *testing.T) {
	for _, test := range []struct {
		name             string
		status           int
		connectorRuntime bool
		wantError        string
		wantIs           error
	}{
		{name: "unready runtime", status: http.StatusServiceUnavailable, connectorRuntime: true, wantError: "connector routes are not ready", wantIs: errConnectorRoutesNotReady},
		{name: "unexpected runtime reply", status: http.StatusNotFound, connectorRuntime: true, wantError: "likely different versions"},
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
			if test.wantIs != nil && !errors.Is(err, test.wantIs) {
				t.Fatalf("probeConnectorHealth() error = %v, want errors.Is(_, %v)", err, test.wantIs)
			}
		})
	}
}

func TestProbeConnectorHealthRefusesRedirects(t *testing.T) {
	var followed atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		followed.Store(true)
		w.Header().Set(connectorHealthHeader, "1")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	t.Cleanup(redirect.Close)
	t.Setenv(envConnectorHealthAddr, redirect.Listener.Addr().String())

	err := probeConnectorHealth(context.Background())
	if err == nil || !strings.Contains(err.Error(), "did not come from a qurl-connector runtime") {
		t.Fatalf("probeConnectorHealth() error = %v, want foreign-listener error", err)
	}
	if followed.Load() {
		t.Fatal("readiness probe followed a redirect away from its loopback listener")
	}
}

func TestProbeConnectorHealthBoundsAStalledListener(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		entered <- struct{}{}
		<-release
	}))
	t.Cleanup(func() {
		close(release)
		server.Close()
	})
	t.Setenv(envConnectorHealthAddr, server.Listener.Addr().String())

	started := time.Now()
	err := probeConnectorHealth(context.Background())
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("probeConnectorHealth() error = %v, want context deadline exceeded", err)
	}
	select {
	case <-entered:
	default:
		t.Fatal("stalled listener never received the readiness request")
	}
	if elapsed < connectorHealthTimeout/2 || elapsed >= 2*time.Second {
		t.Fatalf("stalled readiness probe took %s, want bounded near %s and below the documented 2s supervisor timeout", elapsed, connectorHealthTimeout)
	}
}
