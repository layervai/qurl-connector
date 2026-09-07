package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	envConnectorHealthAddr = "QURL_CONNECTOR_HEALTH_ADDR"
	connectorHealthPath    = "/healthz"
	connectorHealthTimeout = 750 * time.Millisecond
)

var healthcheckCmd = &cobra.Command{
	Use:           "healthcheck",
	Short:         "Check the local qURL Connector process",
	Args:          cobra.NoArgs,
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return probeConnectorHealth(commandContext(cmd))
	},
}

func connectorHealthAddress() (string, error) {
	raw, ok := os.LookupEnv(envConnectorHealthAddr)
	if !ok || raw == "" {
		return "", fmt.Errorf("%s must name the enabled local admin listener", envConnectorHealthAddr)
	}
	if raw != strings.TrimSpace(raw) {
		return "", fmt.Errorf("%s must not contain surrounding whitespace", envConnectorHealthAddr)
	}
	host, portText, err := net.SplitHostPort(raw)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", envConnectorHealthAddr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("%s host must be a literal loopback IP", envConnectorHealthAddr)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("%s port must be in 1-65535", envConnectorHealthAddr)
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}

func probeConnectorHealth(ctx context.Context) error {
	addr, err := connectorHealthAddress()
	if err != nil {
		return err
	}
	probeCtx, cancel := context.WithTimeout(ctx, connectorHealthTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, "http://"+addr+connectorHealthPath, nil)
	if err != nil {
		return fmt.Errorf("create Connector health request: %w", err)
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("probe Connector health: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Connector health returned HTTP %d", resp.StatusCode)
	}
	return nil
}
