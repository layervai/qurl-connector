package main

import (
	"context"
	"errors"
	"fmt"
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
	connectorHealthTimeout = 750 * time.Millisecond
)

var listenConnectorHealth = net.Listen

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
			http.Error(w, "connector routes are not ready", http.StatusServiceUnavailable)
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

	listener, err := listenConnectorHealth("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen for Connector health on %s: %w", addr, err)
	}
	server := &http.Server{
		Handler:           connectorHealthHandler(ready),
		ReadHeaderTimeout: time.Second,
		IdleTimeout:       time.Second,
	}
	runCtx, cancel := context.WithCancelCause(ctx)
	serveErr := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
		if err != nil {
			cancel(fmt.Errorf("serve Connector health: %w", err))
		}
	}()

	runErr := run(runCtx)
	cancel(runErr)
	shutdownCtx, stopShutdown := context.WithTimeout(context.Background(), time.Second)
	shutdownErr := server.Shutdown(shutdownCtx)
	stopShutdown()
	// Shutdown can race Serve before Serve records the listener. Closing the
	// listener itself guarantees the server goroutine always returns.
	_ = listener.Close()
	return errors.Join(runErr, shutdownErr, <-serveErr)
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
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("probe Connector readiness: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("connector routes are not ready (HTTP %d)", resp.StatusCode)
	}
	return nil
}
