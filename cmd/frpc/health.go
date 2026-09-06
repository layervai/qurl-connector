package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	envConnectorHealthAddr = "QURL_CONNECTOR_HEALTH_ADDR"
	connectorHealthPath    = "/readyz"
	connectorHealthHeader  = "X-Qurl-Connector-Readyz"
	connectorHealthTimeout = 750 * time.Millisecond
)

var listenConnectorHealth = net.Listen

// This HTTP adapter is intentionally local to the diagnostic cmd/frpc
// command. pkg/share.SessionGroupRunner.RoutesReady is the reusable runtime
// signal. This repository does not distribute cmd/frpc, so a deployment that
// uses this adapter must own and verify the binary or container artifact.

// errConnectorRoutesNotReady keeps the handler and probe's expected unhealthy
// result aligned and lets tests distinguish it from transport or configuration
// failures.
var errConnectorRoutesNotReady = errors.New("connector routes are not ready")

// joinedCancellationOnly recognizes errors.Join's production shutdown shape
// without discarding a real error that happened while cancellation propagated.
func joinedCancellationOnly(err error) bool {
	if err == context.Canceled { //nolint:errorlint // Only the exact cancellation leaf is discardable.
		return true
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return false
	}
	children := joined.Unwrap()
	if len(children) == 0 {
		return false
	}
	for _, child := range children {
		if !joinedCancellationOnly(child) {
			return false
		}
	}
	return true
}

func connectorHealthAddress() (string, bool, error) {
	raw, configured := os.LookupEnv(envConnectorHealthAddr)
	if !configured {
		return "", false, nil
	}
	if raw == "" || raw != strings.TrimSpace(raw) {
		return "", true, fmt.Errorf("%s must be a non-empty loopback IP and port without surrounding whitespace", envConnectorHealthAddr)
	}
	host, portText, err := net.SplitHostPort(raw)
	if err != nil {
		return "", true, fmt.Errorf("parse %s: %w", envConnectorHealthAddr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", true, fmt.Errorf("%s host must be a loopback IP", envConnectorHealthAddr)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", true, fmt.Errorf("%s port must be in 1-65535", envConnectorHealthAddr)
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), true, nil
}

func connectorHealthHandler(ready func() bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set(connectorHealthHeader, "1")
		if r.URL.Path != connectorHealthPath {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !ready() {
			http.Error(w, errConnectorRoutesNotReady.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// runWithConnectorHealth exposes only one process-local readiness bit. The
// bit comes directly from SessionGroupRunner.RoutesReady; this server does not
// reconstruct route state from FRP names or keep a second route table.
func runWithConnectorHealth(ctx context.Context, ready func() bool, run func(context.Context) error) error {
	if ctx == nil {
		return errors.New("Connector health context is nil")
	}
	addr, configured, err := connectorHealthAddress()
	if err != nil {
		return err
	}
	if !configured {
		return run(ctx)
	}
	if ready == nil {
		return errors.New("Connector health readiness callback is nil")
	}

	listener, err := listenConnectorHealth("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen for Connector health on %s: %w", addr, err)
	}
	server := &http.Server{
		Handler:           connectorHealthHandler(ready),
		ReadHeaderTimeout: time.Second,
		ReadTimeout:       time.Second,
		WriteTimeout:      time.Second,
		IdleTimeout:       time.Second,
	}
	runCtx, cancel := context.WithCancelCause(ctx)
	serveErr := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		if err != nil {
			err = fmt.Errorf("serve Connector health: %w", err)
			cancel(err)
		}
		serveErr <- err
	}()

	runErr := run(runCtx)
	cancel(runErr)
	shutdownCtx, stopShutdown := context.WithTimeout(context.Background(), time.Second)
	shutdownErr := server.Shutdown(shutdownCtx)
	stopShutdown()
	if errors.Is(shutdownErr, context.DeadlineExceeded) {
		// The forced server close below is the shutdown guarantee. A probe
		// connection that outlives the graceful-drain deadline is not a
		// Connector runtime failure.
		shutdownErr = nil
	}
	// Shutdown can race Serve before Serve records the listener, and a
	// connection can outlive the graceful-drain deadline. Close covers both:
	// it closes the listener and every remaining connection, so Serve returns.
	// The production readiness callback only locks and copies local state; an
	// arbitrary callback that blocks forever is outside this helper's contract.
	_ = server.Close()
	serverErr := <-serveErr
	if serverErr != nil && errors.Is(context.Cause(runCtx), serverErr) && joinedCancellationOnly(runErr) {
		// The wrapper caused this cancellation to stop the runtime after its
		// health listener failed. The actionable cause is serverErr; keeping
		// both would let a caller mistake the failure for a clean cancellation.
		// The production runtime returns a one-element errors.Join after its
		// deferred closes; preserve any join that also carries a real failure.
		runErr = nil
	}
	return errors.Join(runErr, shutdownErr, serverErr)
}

func probeConnectorHealth(ctx context.Context) error {
	addr, configured, err := connectorHealthAddress()
	if err != nil {
		return err
	}
	if !configured {
		return fmt.Errorf("connector readiness is disabled; set %s to a loopback IP and port in both the run and probe processes", envConnectorHealthAddr)
	}
	requestCtx, cancel := context.WithTimeout(ctx, connectorHealthTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, "http://"+addr+connectorHealthPath, nil)
	if err != nil {
		return fmt.Errorf("create Connector readiness request: %w", err)
	}
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("probe Connector readiness: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.Header.Get(connectorHealthHeader) != "1" {
		return fmt.Errorf("reply from http://%s%s did not come from a qurl-connector runtime; %s may point at another local listener",
			addr, connectorHealthPath, envConnectorHealthAddr)
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		return errConnectorRoutesNotReady
	}
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected reply from http://%s%s (HTTP %d); the listener identified itself as a qurl-connector runtime, so the probe and running Connector are likely different versions",
			addr, connectorHealthPath, resp.StatusCode)
	}
	return nil
}
