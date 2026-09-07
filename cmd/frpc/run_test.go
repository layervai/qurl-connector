package main

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fatedier/frp/assets"
	frpclient "github.com/fatedier/frp/client"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/config/v1/validation"
	"github.com/fatedier/frp/pkg/policy/security"

	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

func TestFRPClientCommonDefaultsAuthToToken(t *testing.T) {
	loginFailExit := false
	common := &v1.ClientCommonConfig{ServerAddr: "frp.example", ServerPort: 7000, LoginFailExit: &loginFailExit}
	common.Transport.Protocol = "tcp"
	common.Transport.DialServerKeepAlive = 60
	common.Transport.DialServerTimeout = 10
	common.Log.Level = "info"
	if err := common.Complete(); err != nil {
		t.Fatal(err)
	}
	if common.Auth.Method != v1.AuthMethodToken {
		t.Fatalf("FRP auth method = %q, want %q", common.Auth.Method, v1.AuthMethodToken)
	}
	if _, err := validation.ValidateAllClientConfig(common, nil, nil, &security.UnsafeFeatures{}); err != nil {
		t.Fatalf("validate completed FRP common config: %v", err)
	}
}

func TestStartFRPFromConfigRejectsInvalidLogLevel(t *testing.T) {
	oldLevel := logLevel
	logLevel = "loud"
	t.Cleanup(func() { logLevel = oldLevel })
	disabled := false
	err := startFRPFromConfig(context.Background(), "", "machine", &nhpconfig.Config{
		Server: nhpconfig.ServerConfig{Protocol: "tcp"},
		Audit:  nhpconfig.AuditConfig{Enabled: &disabled},
	}, "agent", nil)
	if err == nil || !strings.Contains(err.Error(), "invalid log level") {
		t.Fatalf("startFRPFromConfig error = %v, want invalid log level", err)
	}
}

func TestAdminAuthPassword(t *testing.T) {
	t.Run("uses Desktop secret", func(t *testing.T) {
		got, err := adminAuthPassword(&nhpconfig.AdminConfig{Password: "desktop-secret"})
		if err != nil || got != "desktop-secret" {
			t.Fatalf("adminAuthPassword = %q, %v", got, err)
		}
	})
	t.Run("rejects unknown machine fallback", func(t *testing.T) {
		setCachedMachineIDForTest(t, unknownMachineID)
		if _, err := adminAuthPassword(&nhpconfig.AdminConfig{}); err == nil {
			t.Fatal("adminAuthPassword accepted an unknown machine ID")
		}
	})
}

func TestAdminAPIWorksWithoutDashboardAssets(t *testing.T) {
	if assets.FileSystem != nil {
		t.Fatal("connector binary registered FRP dashboard assets; the embedded web UI must stay unlinked")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	adminPort := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	loginFailExit := false
	common := &v1.ClientCommonConfig{ServerAddr: "127.0.0.1", ServerPort: 1, LoginFailExit: &loginFailExit}
	common.Log.Level = "error"
	common.WebServer.Addr, common.WebServer.Port = "127.0.0.1", adminPort
	common.WebServer.User, common.WebServer.Password = "admin", "secret"
	service, err := frpclient.NewService(frpclient.ServiceOptions{
		Common: common, ConfigSourceAggregator: source.NewAggregator(source.NewConfigSource()),
		UnsafeFeatures: &security.UnsafeFeatures{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = service.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			service.Close()
		}
	})

	baseURL := "http://127.0.0.1:" + strconv.Itoa(adminPort)
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, requestErr := client.Get(baseURL + "/healthz")
		if requestErr == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("admin listener did not start: %v", requestErr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	for _, check := range []struct {
		path string
		want int
	}{{"/", http.StatusNotFound}, {"/api/status", http.StatusOK}} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+check.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("admin", "secret")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", check.path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != check.want {
			t.Errorf("GET %s status = %d, want %d", check.path, resp.StatusCode, check.want)
		}
	}
}
